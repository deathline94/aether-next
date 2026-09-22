#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use parking_lot::Mutex;

/// Structured shell/IPC error.
///
/// Every shell helper used to return `Result<_, CommandError>`, so a caller could only
/// branch on prose (`msg.contains("not found")`) and the frontend received an
/// opaque rejection it had to stringify. `code` is the machine-readable half.
///
/// It serialises as the message string on purpose: the shipped frontend still
/// does `String(e)`, so the wire shape stays compatible until typed
/// (`tauri-specta`) bindings replace those calls in spec 016.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandError {
    pub code: &'static str,
    pub message: String,
}

impl CommandError {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self { code, message: message.into() }
    }
}

impl std::fmt::Display for CommandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for CommandError {}

impl Serialize for CommandError {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.message)
    }
}

impl From<String> for CommandError {
    fn from(message: String) -> Self {
        Self { code: "internal", message }
    }
}

impl From<&str> for CommandError {
    fn from(message: &str) -> Self {
        Self { code: "internal", message: message.to_string() }
    }
}

impl From<serde_json::Error> for CommandError {
    fn from(e: serde_json::Error) -> Self {
        Self { code: "encode", message: e.to_string() }
    }
}

impl From<tauri::Error> for CommandError {
    fn from(e: tauri::Error) -> Self {
        Self { code: "shell", message: e.to_string() }
    }
}

impl From<ureq::Error> for CommandError {
    fn from(e: ureq::Error) -> Self {
        Self { code: "network", message: e.to_string() }
    }
}

impl From<BinaryTrustError> for CommandError {
    fn from(e: BinaryTrustError) -> Self {
        let code = match e {
            BinaryTrustError::Authenticode(_, _) => "authenticode",
            BinaryTrustError::PublisherMismatch { .. } => "publisher_mismatch",
            BinaryTrustError::HashMismatch { .. } => "hash_mismatch",
            BinaryTrustError::MissingHash { .. } => "missing_hash",
            BinaryTrustError::AnchorNotPublished { .. } => "anchor_not_published",
            BinaryTrustError::Validation(_) => "validation",
        };
        Self { code, message: e.to_string() }
    }
}

impl From<std::io::Error> for CommandError {
    fn from(e: std::io::Error) -> Self {
        let code = match e.kind() {
            std::io::ErrorKind::NotFound => "not_found",
            std::io::ErrorKind::PermissionDenied => "permission_denied",
            std::io::ErrorKind::AlreadyExists => "already_exists",
            _ => "io",
        };
        Self { code, message: e.to_string() }
    }
}

use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
};
use tauri::{
    menu::{Menu, MenuItem},
    path::BaseDirectory,
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    AppHandle, Emitter, Manager, State,
};
use zeroize::Zeroize;

#[cfg(windows)]
pub fn restrict_directory_acl(path: &Path) -> Result<(), CommandError> {
    // Fail closed. The previous `if let Ok(user)` skipped the whole ACL whenever
    // `%USERNAME%` was unavailable, so the file that gates every other secret
    // kept whatever the directory handed out. A SID-derived principal is the
    // follow-up (the engine already does this); the name is unambiguous for the
    // non-elevated case that reads these files.
    #[allow(clippy::disallowed_methods)]
    let user = std::env::var("USERNAME").map_err(|e| {
        CommandError::new("internal", format!("cannot determine ACL principal: {e}"))
    })?;
    {
        let is_dir = path.is_dir();
        let user_perm = if is_dir {
            format!("{user}:(OI)(CI)F")
        } else {
            format!("{user}:F")
        };
        let sys_perm = if is_dir {
            "SYSTEM:(OI)(CI)F"
        } else {
            "SYSTEM:F"
        };
        let output = std::process::Command::new("icacls")
            .arg(path.as_os_str())
            .arg("/inheritance:r")
            .arg("/grant:r")
            .arg(&user_perm)
            .arg("/grant:r")
            .arg(sys_perm)
            .output()
            .map_err(|e| format!("failed to execute icacls on {}: {e}", path.display()))?;
        if !output.status.success() {
            let err = String::from_utf8_lossy(&output.stderr);
            return Err(format!(
                "icacls failed to restrict permissions on {}: {}",
                path.display(),
                err.trim()
            ).into());
        }
    }
    Ok(())
}

#[cfg(not(windows))]
pub fn restrict_directory_acl(_path: &Path) -> Result<(), CommandError> {
    Ok(())
}

pub mod dpapi {
    use crate::CommandError;

    use std::path::Path;
    use zeroize::Zeroize;

    #[cfg(windows)]
    use std::ptr;
    #[cfg(windows)]
    use windows_sys::Win32::Foundation::LocalFree;
    #[cfg(windows)]
    use windows_sys::Win32::Security::Cryptography::{
        CryptProtectData, CryptUnprotectData, CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN,
    };

    /// Which OS secret store can wrap the master key right now.
    ///
    /// The point of naming it is that the wrapping is then a *choice made in one
    /// place*. Until now the off-Windows `encrypt`/`decrypt` were the identity
    /// function, so "encrypted at rest" was true on one platform and false
    /// everywhere else — and the tests that would have shown it are all
    /// `#[cfg(windows)]`, so the failure was invisible by construction.
    #[derive(Copy, Clone, Debug, PartialEq, Eq)]
    pub enum KeyService {
        /// Windows Data Protection API, scoped to the current user and process.
        #[cfg(windows)]
        Dpapi,
        /// Nothing available: an honest `None`, not a silent pass-through.
        None,
    }

    pub fn service() -> KeyService {
        #[cfg(windows)]
        {
            KeyService::Dpapi
        }
        #[cfg(not(windows))]
        {
            // Keychain (macOS) and libsecret (Linux) are the remaining sources —
            // specs/015 T096. Adding them means adding a variant here and a real
            // arm below; there is no path that stores a key unwrapped.
            KeyService::None
        }
    }

    fn no_key_service() -> CommandError {
        CommandError::new(
            "key_service_unavailable",
            "this platform has no OS-backed secret store, and the configuration master key is \
             never written unwrapped; run on Windows or add the Keychain/libsecret key source",
        )
    }

    pub fn encrypt_with(data: &[u8], svc: KeyService) -> Result<Vec<u8>, CommandError> {
        match svc {
            #[cfg(windows)]
            KeyService::Dpapi => {
                let in_blob = CRYPT_INTEGER_BLOB {
                    cbData: data.len() as u32,
                    pbData: data.as_ptr() as *mut u8,
                };
                let mut out_blob = CRYPT_INTEGER_BLOB {
                    cbData: 0,
                    pbData: ptr::null_mut(),
                };

                let res = unsafe {
                    CryptProtectData(
                        &in_blob,
                        ptr::null(),
                        ptr::null(),
                        ptr::null(),
                        ptr::null(),
                        CRYPTPROTECT_UI_FORBIDDEN,
                        &mut out_blob,
                    )
                };

                if res == 0 {
                    let err = std::io::Error::last_os_error();
                    return Err(format!("CryptProtectData failed: {err}").into());
                }

                let encrypted = unsafe {
                    std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize).to_vec()
                };

                unsafe {
                    LocalFree(out_blob.pbData as _);
                }

                Ok(encrypted)
            }
            KeyService::None => Err(no_key_service()),
        }
    }

    pub fn decrypt_with(data: &[u8], svc: KeyService) -> Result<Vec<u8>, CommandError> {
        match svc {
            #[cfg(windows)]
            KeyService::Dpapi => {
                let in_blob = CRYPT_INTEGER_BLOB {
                    cbData: data.len() as u32,
                    pbData: data.as_ptr() as *mut u8,
                };
                let mut out_blob = CRYPT_INTEGER_BLOB {
                    cbData: 0,
                    pbData: ptr::null_mut(),
                };

                let res = unsafe {
                    CryptUnprotectData(
                        &in_blob,
                        ptr::null_mut(),
                        ptr::null(),
                        ptr::null(),
                        ptr::null(),
                        CRYPTPROTECT_UI_FORBIDDEN,
                        &mut out_blob,
                    )
                };

                if res == 0 {
                    let err = std::io::Error::last_os_error();
                    return Err(format!("CryptUnprotectData failed: {err}").into());
                }

                let decrypted = unsafe {
                    std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize).to_vec()
                };

                unsafe {
                    if !out_blob.pbData.is_null() && out_blob.cbData > 0 {
                        let slice =
                            std::slice::from_raw_parts_mut(out_blob.pbData, out_blob.cbData as usize);
                        slice.zeroize();
                    }
                    LocalFree(out_blob.pbData as _);
                }

                Ok(decrypted)
            }
            KeyService::None => Err(no_key_service()),
        }
    }

    pub fn encrypt(data: &[u8]) -> Result<Vec<u8>, CommandError> {
        encrypt_with(data, service())
    }

    pub fn decrypt(data: &[u8]) -> Result<Vec<u8>, CommandError> {
        decrypt_with(data, service())
    }

    const DPAPI_MAGIC: &[u8] = b"DP01";

    /// Derives or retrieves the 32-byte DPAPI-protected configuration master key.
    /// Returns the base64-encoded string representation for `AETHER_CONFIG_KEY`.
    pub fn get_or_create_dpapi_config_key(app_data_dir: &Path) -> Result<String, CommandError> {
        use base64::Engine;
        let key_file = app_data_dir.join("config_key.dpapi");
        if key_file.exists() {
            let raw = std::fs::read(&key_file)
                .map_err(|e| format!("failed reading {}: {e}", key_file.display()))?;
            if !raw.starts_with(DPAPI_MAGIC) {
                return Err(format!("invalid DPAPI key envelope header in {}", key_file.display()).into());
            }
            let mut decrypted = decrypt(&raw[DPAPI_MAGIC.len()..])?;
            if decrypted.len() != 32 {
                decrypted.zeroize();
                return Err("decrypted master key must be 32 bytes".into());
            }
            let b64 = base64::engine::general_purpose::STANDARD.encode(&decrypted);
            decrypted.zeroize();
            return Ok(b64);
        }

        // Generate new 32-byte key
        let mut raw_key = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut raw_key);

        let ciphertext = encrypt(&raw_key)?;
        let mut envelope = Vec::with_capacity(DPAPI_MAGIC.len() + ciphertext.len());
        envelope.extend_from_slice(DPAPI_MAGIC);
        envelope.extend_from_slice(&ciphertext);

        let tmp_file = app_data_dir.join(format!(
            "config_key.dpapi.{}.{}.tmp",
            std::process::id(),
            rand::random::<u32>()
        ));
        std::fs::create_dir_all(app_data_dir)
            .map_err(|e| format!("cannot create dir {}: {e}", app_data_dir.display()))?;
        {
            // Created exclusively and, off Windows, owner-only from the first
            // byte: `restrict_directory_acl` is a no-op there, so without an
            // explicit mode the master key landed with the process umask
            // (0644 is the common case) while `encrypt()` was the identity
            // function — every user on the machine could read the thing that
            // decrypts every identity on disk.
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                let mut f = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&tmp_file)
                    .map_err(|e| format!("cannot write {}: {e}", tmp_file.display()))?;
                std::io::Write::write_all(&mut f, &envelope)
                    .map_err(|e| format!("cannot write {}: {e}", tmp_file.display()))?;
                f.sync_all().map_err(|e| format!("cannot flush {}: {e}", tmp_file.display()))?;
            }
            #[cfg(not(unix))]
            {
                let mut opts = std::fs::OpenOptions::new();
                opts.write(true).create_new(true);
                let mut f = opts
                    .open(&tmp_file)
                    .map_err(|e| format!("cannot write {}: {e}", tmp_file.display()))?;
                std::io::Write::write_all(&mut f, &envelope)
                    .map_err(|e| format!("cannot write {}: {e}", tmp_file.display()))?;
                f.sync_all().map_err(|e| format!("cannot flush {}: {e}", tmp_file.display()))?;
            }
        }
        // Restrict ACL on the tmp file before rename; fail closed and cleanup on failure
        if let Err(e) = super::restrict_directory_acl(&tmp_file) {
            let _ = std::fs::remove_file(&tmp_file);
            return Err(format!("cannot restrict ACL on {}: {e}", tmp_file.display()).into());
        }

        if let Err(e) = std::fs::rename(&tmp_file, &key_file) {
            let _ = std::fs::remove_file(&tmp_file);
            return Err(format!("cannot rename to {}: {e}", key_file.display()).into());
        }

        let _ = super::restrict_directory_acl(&key_file);

        let b64 = base64::engine::general_purpose::STANDARD.encode(raw_key);
        raw_key.zeroize();
        Ok(b64)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Settings {
    protocol: String,
    transport: String,
    scan_mode: String,
    ip_version: String,
    noize: String,
    /// Custom obfuscation: junk packet count (when noize == custom).
    noize_jc: u32,
    /// Custom obfuscation: min junk size.
    noize_jmin: u32,
    /// Custom obfuscation: max junk size.
    noize_jmax: u32,
    /// Custom obfuscation: interval between junk packets (ms).
    noize_interval_ms: u32,
    routing_mode: String,
    socks_port: u16,
    http_port: u16,
    start_minimized: bool,
    launch_at_login: bool,
    engine_path: String,
    /// Forced peer endpoint (set by Scanner "Connect Direct").
    #[serde(default)]
    peer: String,
    /// H3 anti-DPI: split the QUIC Initial ClientHello across two datagrams so
    /// on-path DPI can't read the SNI from the first Initial packet.
    #[serde(default)]
    quic_initial_frag: bool,
    /// H3 anti-DPI: bytes of ClientHello CRYPTO carried in the first Initial.
    #[serde(default = "default_quic_frag_size")]
    quic_initial_frag_size: u32,
}

fn default_quic_frag_size() -> u32 {
    96
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            protocol: "masque".into(),
            transport: "h2".into(),
            // Prefer balanced over turbo: better edge RTT → higher throughput.
            scan_mode: "balanced".into(),
            ip_version: "v4".into(),
            noize: "off".into(),
            noize_jc: 5,
            noize_jmin: 50,
            noize_jmax: 128,
            noize_interval_ms: 0,
            routing_mode: "system-proxy".into(),
            socks_port: 1819,
            http_port: 1820,
            start_minimized: false,
            launch_at_login: false,
            engine_path: String::new(),
            peer: String::new(),
            quic_initial_frag: false,
            quic_initial_frag_size: 96,
        }
    }
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct RuntimeState {
    status: String,
    detail: String,
    pid: Option<u32>,
    endpoint: Option<String>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct LogEvent {
    level: String,
    message: String,
}

struct AppState {
    child: Mutex<Option<Child>>,
    scan_child: Mutex<Option<Child>>,
    runtime: Mutex<RuntimeState>,
    proxy_enabled: AtomicBool,
    #[cfg(windows)]
    proxy_snapshot: Mutex<Option<windows_proxy::ProxySnapshot>>,
    connected_once: AtomicBool,
    connecting: AtomicBool,
    generation: AtomicU64,
    operation: Mutex<()>,
    #[cfg(windows)]
    job: Mutex<Option<engine_job::Job>>,
}

/// M8 fix: the engine child runs inside a kill-on-close Job Object. If the GUI
// is force-killed or crashes, the kernel closes the job handle and the engine
// dies with it instead of surviving as an orphan holding ports 1819/1820 and
// the system-proxy registry while every future launch fails to bind.
#[cfg(windows)]
mod engine_job {
    use crate::CommandError;

    use std::os::windows::io::AsRawHandle;
    use std::process::Child;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
        SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    };

    /// Stored as isize so `Job` stays Send+Sync (HANDLE is a raw pointer in
    /// windows-sys 0.61, which would poison AppState's Send bound).
    pub struct Job(isize);

    impl Job {
        pub fn create() -> Result<Self, CommandError> {
            let handle = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
            if handle.is_null() {
                return Err("CreateJobObjectW failed".into());
            }
            let mut info = unsafe { std::mem::zeroed::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() };
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            let ok = unsafe {
                SetInformationJobObject(
                    handle,
                    JobObjectExtendedLimitInformation,
                    &info as *const _ as *const core::ffi::c_void,
                    std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                )
            };
            if ok == 0 {
                unsafe { CloseHandle(handle) };
                return Err("SetInformationJobObject failed".into());
            }
            Ok(Job(handle as isize))
        }

        pub fn assign_child(&self, child: &Child) -> Result<(), CommandError> {
            let ok = unsafe {
                AssignProcessToJobObject(self.0 as HANDLE, child.as_raw_handle() as HANDLE)
            };
            if ok == 0 {
                Err("AssignProcessToJobObject failed".into())
            } else {
                Ok(())
            }
        }
    }

    impl Drop for Job {
        fn drop(&mut self) {
            // Closing the job handle kills any process still inside it.
            unsafe { CloseHandle(self.0 as HANDLE) };
        }
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            child: Mutex::new(None),
            scan_child: Mutex::new(None),
            runtime: Mutex::new(RuntimeState {
                status: "disconnected".into(),
                detail: "Ready".into(),
                pid: None,
                endpoint: None,
            }),
            proxy_enabled: AtomicBool::new(false),
            #[cfg(windows)]
            proxy_snapshot: Mutex::new(None),
            connected_once: AtomicBool::new(false),
            connecting: AtomicBool::new(false),
            generation: AtomicU64::new(0),
            operation: Mutex::new(()),
            #[cfg(windows)]
            job: Mutex::new(None),
        }
    }
}

fn config_dir(app: &AppHandle) -> Result<PathBuf, CommandError> {
    app.path().app_config_dir().map_err(CommandError::from)
}

fn settings_path(app: &AppHandle) -> Result<PathBuf, CommandError> {
    Ok(config_dir(app)?.join("settings.json"))
}

#[cfg(windows)]
/// `--repair-proxy`: recovery entry point for a user whose system proxy still
/// points at an engine that died. The app restores the registry state and exits
/// instead of opening a window they would have to fight with.
fn repair_proxy_requested() -> bool {
    std::env::args().any(|a| a == "--repair-proxy")
}

fn proxy_recovery_path(app: &AppHandle) -> Result<PathBuf, CommandError> {
    Ok(config_dir(app)?.join("proxy-recovery.json"))
}

fn load_settings_file(app: &AppHandle) -> Settings {
    let Ok(path) = settings_path(app) else {
        return Settings::default();
    };
    if !path.exists() {
        return Settings::default();
    }
    match fs::read_to_string(&path) {
        Ok(text) => match serde_json::from_str::<Settings>(&text) {
            Ok(s) => s,
            Err(e) => {
                // Corrupt settings: keep file, use defaults, surface in log via stderr.
                eprintln!("settings.json invalid ({e}); using defaults");
                Settings::default()
            }
        },
        Err(e) => {
            eprintln!("settings.json unreadable ({e}); using defaults");
            Settings::default()
        }
    }
}

fn save_settings_file(app: &AppHandle, settings: &Settings) -> Result<(), CommandError> {
    let path = settings_path(app)?;
    let parent = path.parent().ok_or("invalid config path")?;
    fs::create_dir_all(parent).map_err(CommandError::from)?;
    restrict_directory_acl(parent)?;
    let json = serde_json::to_string_pretty(settings).map_err(CommandError::from)?;
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, json).map_err(CommandError::from)?;
    fs::rename(&tmp, &path).map_err(CommandError::from)
}

fn emit_state(
    app: &AppHandle,
    state: &AppState,
    status: &str,
    detail: &str,
    pid: Option<u32>,
    endpoint: Option<String>,
) {
    let value = RuntimeState {
        status: status.into(),
        detail: detail.into(),
        pid,
        endpoint,
    };
    *state.runtime.lock() = value.clone();
    let _ = app.emit("session://state", value);
}

fn parse_endpoint(line: &str) -> Option<String> {
    for marker in [
        "selected MASQUE gateway ",
        "selected WireGuard endpoint ",
        "using cloudflare edge ",
        "using forced peer ",
    ] {
        if let Some(rest) = line.split(marker).nth(1) {
            let token = rest
                .split_whitespace()
                .next()
                .unwrap_or("")
                .trim_matches(|c: char| c == '(' || c == ')' || c == ',');
            if !token.is_empty() {
                return Some(token.to_string());
            }
        }
    }
    None
}

fn validate_settings(settings: &Settings) -> Result<(), CommandError> {
    for (name, port) in [
        ("HTTP", settings.http_port),
        ("SOCKS5", settings.socks_port),
    ] {
        if !(1024..=65535).contains(&port) {
            return Err(format!("{name} port must be 1024–65535 (got {port})").into());
        }
    }
    if settings.http_port == settings.socks_port {
        return Err("HTTP and SOCKS5 ports must differ".into());
    }
    let allow = |field: &str, val: &str, opts: &[&str]| -> Result<(), CommandError> {
        if opts.iter().any(|o| o.eq_ignore_ascii_case(val.trim())) {
            Ok(())
        } else {
            Err(format!("{field} must be one of: {}", opts.join(", ")).into())
        }
    };
    allow(
        "protocol",
        &settings.protocol,
        &["masque", "wireguard", "warp", "gool"],
    )?;
    allow("transport", &settings.transport, &["h3", "h2", "auto"])?;
    allow(
        "scan_mode",
        &settings.scan_mode,
        &[
            "turbo",
            "balanced",
            "thorough",
            "stealth",
            "fast",
            "deep",
            "thorogh",
            "auto",
            "ironclad",
        ],
    )?;
    allow(
        "ip_version",
        &settings.ip_version,
        &["auto", "4", "6", "v4", "v6", "ipv4", "ipv6", "dual"],
    )?;
    allow(
        "noize",
        &settings.noize,
        &[
            "off",
            "none",
            "light",
            "low",
            "medium",
            "balanced",
            "firewall",
            "default",
            "high",
            "gfw",
            "max",
            "aggressive",
            "heavy",
            "custom",
        ],
    )?;
    if settings.noize.eq_ignore_ascii_case("custom") {
        if settings.noize_jmax < settings.noize_jmin {
            return Err("custom obfuscation: max size must be >= min size".into());
        }
        if settings.noize_jc > 64 || settings.noize_jmax > 2048 || settings.noize_interval_ms > 5000
        {
            return Err("custom obfuscation values out of range".into());
        }
    }
    allow(
        "routing_mode",
        &settings.routing_mode,
        &["proxy-only", "system-proxy", "tun"],
    )?;
    Ok(())
}

/// Prefer structured `AETHER_EVENT {...}` lines; fall back to log markers.
fn handle_engine_line(
    app: &AppHandle,
    line: &str,
    settings: &Settings,
    socks_seen: &AtomicBool,
    tunnel_seen: &AtomicBool,
    tun_seen: &AtomicBool,
) {
    let want_tun = settings.routing_mode == "tun";
    if let Some(json) = line.split("AETHER_EVENT ").nth(1) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(json.trim()) {
            let ty = v.get("type").and_then(|t| t.as_str()).unwrap_or("");
            match ty {
                "endpoint_selected" => {
                    if let Some(addr) = v.get("addr").and_then(|a| a.as_str()) {
                        let state = app.state::<AppState>();
                        let mut rt = state.runtime.lock();
                        rt.endpoint = Some(addr.to_string());
                        let snap = rt.clone();
                        drop(rt);
                        let _ = app.emit("session://state", snap);
                    }
                }
                "proxy_ready" => {
                    socks_seen.store(true, Ordering::SeqCst);
                }
                "tunnel_ready" => {
                    tunnel_seen.store(true, Ordering::SeqCst);
                }
                "tun_ready" => {
                    tun_seen.store(true, Ordering::SeqCst);
                    // Full-system path: TUN up implies kernel bridge is usable.
                    tunnel_seen.store(true, Ordering::SeqCst);
                }
                "connected" => {
                    // Crypto + proxies only. Never treat as TUN-ready (false "connected"
                    // when WinTUN routes are still missing).
                    socks_seen.store(true, Ordering::SeqCst);
                    tunnel_seen.store(true, Ordering::SeqCst);
                }
                "error" => {
                    let msg = v
                        .get("message")
                        .and_then(|m| m.as_str())
                        .unwrap_or("Connection failed")
                        .to_string();
                    emit_log(app, format!("engine error: {msg}"));
                    let state = app.state::<AppState>();
                    let endpoint = state.runtime.lock().endpoint.clone();
                    
                    // 1) Paint the banner.
                    emit_state(app, &state, "error", &msg, None, endpoint);

                    // 2) Tear the session down so the next Connect is allowed WITHOUT
                    //    dismissing the banner. watch_child's `already_error` guard keeps
                    //    the error banner visible when the child finally exits.
                    state.generation.fetch_add(1, Ordering::SeqCst);
                    state.connecting.store(false, Ordering::SeqCst);
                    let child = state.child.lock().take();
                    if let Some(mut child) = child {
                        if let Some(mut stdin) = child.stdin.take() {
                            use std::io::Write;
                            let _ = stdin.write_all(b"shutdown\n");
                            let _ = stdin.flush();
                        }
                        let _ = child.kill();
                        let _ = child.wait();
                    }
                    cleanup_routing(app, &state);
                }
                _ => {}
            }
        }
    }

    // Legacy log markers — only strong readiness signals (not CONNECT/handshake alone).
    if line.contains("[-] session failed:") {
        let msg = line
            .split("[-] session failed:")
            .nth(1)
            .map(|s| s.trim())
            .unwrap_or("Connection failed");
        let state = app.state::<AppState>();
        if !state.runtime.lock().status.eq_ignore_ascii_case("error") {
            emit_state(app, &state, "error", msg, None, None);
            state.generation.fetch_add(1, Ordering::SeqCst);
            state.connecting.store(false, Ordering::SeqCst);
            cleanup_routing(app, &state);
        }
    }
    if line.contains("socks5 listening on") || line.contains("socks5 server listening") || line.contains("http proxy listening") {
        socks_seen.store(true, Ordering::SeqCst);
    }
    if line.contains("data-plane verified") {
        tunnel_seen.store(true, Ordering::SeqCst);
    }
    // Handshake alone is NOT enough for TUN mode (WG handshake fires before WinTUN).
    if !want_tun && line.contains("handshake successful") {
        tunnel_seen.store(true, Ordering::SeqCst);
    }
    if line.contains("[tun] bridge active") || line.contains("TUN mode enabled") {
        tun_seen.store(true, Ordering::SeqCst);
        tunnel_seen.store(true, Ordering::SeqCst);
    }
    if let Some(endpoint) = parse_endpoint(line) {
        let state = app.state::<AppState>();
        let mut rt = state.runtime.lock();
        rt.endpoint = Some(endpoint);
        let snap = rt.clone();
        drop(rt);
        let _ = app.emit("session://state", snap);
    }

    // Proxy + tunnel always. TUN mode also requires tun_ready / bridge active.
    let ready = socks_seen.load(Ordering::SeqCst)
        && tunnel_seen.load(Ordering::SeqCst)
        && (!want_tun || tun_seen.load(Ordering::SeqCst));
    if ready {
        let state = app.state::<AppState>();
        mark_connected(app, &state, settings);
    }
}

fn emit_log(app: &AppHandle, line: String) {
    // Engine stderr lines come from env_logger with an uppercase level token
    // ("[ts LEVEL target] msg") — prefer that exact signal before falling back
    // to the fuzzy substring heuristics, which misclassified benign lines
    // containing the word "error" (e.g. "0 errors").
    let upper_error = line.contains(" ERROR ") || line.starts_with("ERROR ");
    let upper_warn = line.contains(" WARN ") || line.starts_with("WARN ");
    let level = if upper_error {
        "error"
    } else if upper_warn {
        "warn"
    } else {
        let lower = line.to_ascii_lowercase();
        if lower.contains("error") || lower.contains("failed") {
            "error"
        } else if lower.contains("warn") || lower.contains("[-]") {
            "warn"
        } else {
            "info"
        }
    };
    let _ = app.emit(
        "session://log",
        LogEvent {
            level: level.into(),
            message: line,
        },
    );
}

fn resolve_resource(app: &AppHandle, name: &str) -> Option<PathBuf> {
    app.path()
        .resolve(name, BaseDirectory::Resource)
        .ok()
        .filter(|p| p.is_file())
}

/// TUN runs elevated: only load regular files under the app install / portable root.
pub fn validate_trusted_binary(path: &PathBuf, label: &str) -> Result<(), CommandError> {
    let meta = fs::metadata(path).map_err(|e| format!("{label}: {e}"))?;
    if !meta.is_file() {
        return Err(format!("{label} is not a regular file").into());
    }
    if meta.len() == 0 {
        return Err(format!("{label} is empty").into());
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(format!("{label} must not be a reparse point/symlink").into());
        }
        // PE header check (MZ) — fail closed if unreadable or not PE.
        let mut hdr = [0u8; 2];
        let mut f = fs::File::open(path).map_err(|e| format!("{label}: cannot open: {e}"))?;
        use std::io::Read;
        f.read_exact(&mut hdr)
            .map_err(|e| format!("{label}: cannot read PE header: {e}"))?;
        if hdr != *b"MZ" {
            return Err(format!("{label} is not a Windows PE binary").into());
        }
    }
    let app_root = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()));
    let canon = path.canonicalize().unwrap_or_else(|_| path.clone());
    // M9 fix: the allowed roots are the exe's own directory and its PARENT
    // (packaged resource layouts put binaries under install-dir/resources).
    // The previous fallback accepted ANY path whose parent directory happened
    // to be named "resources" or "engine", letting arbitrary user-chosen
    // locations through the elevation-path trust check.
    let mut roots: Vec<PathBuf> = Vec::new();
    if let Some(root) = &app_root {
        roots.push(root.canonicalize().unwrap_or_else(|_| root.clone()));
        if let Some(parent) = root.parent() {
            roots.push(parent.canonicalize().unwrap_or_else(|_| parent.to_path_buf()));
        }
    }
    for root in &roots {
        if canon.starts_with(root) {
            return Ok(());
        }
    }
    Err(format!(
        "{label} rejected: must live under the app install directory (got {})",
        path.display()
    ).into())
}

/// Only allow safe host tokens into Windows ProxyOverride (no `;` injection).
fn sanitize_proxy_bypass_host(endpoint: &str) -> Option<String> {
    let host = endpoint
        .rsplit_once(':')
        .map(|(h, _)| h)
        .unwrap_or(endpoint)
        .trim_matches(['[', ']', ' ', '\t']);
    if host.is_empty() || host.len() > 253 {
        return None;
    }
    // IPv4 / hostname / simple IPv6 without zone or separators that break registry lists.
    let ok = host.chars().all(|c| {
        c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '_')
    }) && !host.contains(';')
        && !host.contains('<')
        && !host.contains('>');
    ok.then(|| host.to_string())
}

pub fn file_sha256_hex(path: &Path) -> Result<String, CommandError> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    let mut file = fs::File::open(path).map_err(|e| format!("cannot open {}: {e}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = file.read(&mut buf).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let res = hasher.finalize();
    let mut s = String::with_capacity(64);
    for b in res {
        use std::fmt::Write;
        let _ = write!(s, "{:02x}", b);
    }
    Ok(s)
}

include!(concat!(env!("OUT_DIR"), "/release_hashes.rs"));

/// Which witness this binary was built against, for logs and for support output:
/// the anchor's verbatim bytes, its own digest, the table derived from it, and
/// whether any entry is still the un-published placeholder.
pub fn engine_trust_anchor(
) -> (&'static [u8], &'static str, &'static [(&'static str, &'static str)], bool) {
    (
        ENGINE_TRUST_ANCHOR_BYTES,
        ENGINE_TRUST_ANCHOR_SHA256,
        EMBEDDED_RELEASE_HASHES,
        ENGINE_TRUST_ANCHOR_HAS_PLACEHOLDER,
    )
}

/// The all-zero digest `engine-trust.json` carries for an artifact whose witness
/// the release job has not published yet. It is unsatisfiable by construction, so
/// treating it as an ordinary mismatch would report a real file as tampered with.
const PLACEHOLDER_SHA256: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone)]
pub struct TrustedBinaryPolicy {
    /// Compiles *only* into a debug build.
    ///
    /// This used to be a plain `allow_unsigned_in_debug: bool` that
    /// `for_engine()` set to `true`, so the decision to skip Authenticode for
    /// the binary that receives the DPAPI master key lived in runtime data on
    /// every build, and only the extra `cfg!(debug_assertions)` at the use site
    /// kept a release build honest. There is now no field, and no code path, in
    /// a release binary that can decline a signature check.
    #[cfg(debug_assertions)]
    pub allow_unsigned_for_dev: bool,
    pub expected_publisher_cn: &'static str,
    pub embedded_hashes: &'static [(&'static str, &'static str)],
    pub enforce_hash_match: bool,
}

impl Default for TrustedBinaryPolicy {
    fn default() -> Self {
        Self::for_engine()
    }
}

impl TrustedBinaryPolicy {
    pub fn for_engine() -> Self {
        Self {
            #[cfg(debug_assertions)]
            allow_unsigned_for_dev: true,
            expected_publisher_cn: "deathline94",
            embedded_hashes: EMBEDDED_RELEASE_HASHES,
            enforce_hash_match: !cfg!(debug_assertions),
        }
    }

    pub fn for_wintun() -> Self {
        Self {
            #[cfg(debug_assertions)]
            allow_unsigned_for_dev: false,
            expected_publisher_cn: "WireGuard LLC",
            embedded_hashes: EMBEDDED_RELEASE_HASHES,
            enforce_hash_match: !cfg!(debug_assertions),
        }
    }
}

#[derive(Debug)]
pub enum BinaryTrustError {
    Validation(String),
    Authenticode(i32, String),
    PublisherMismatch { expected: String, found: String },
    HashMismatch { filename: String, expected: String, actual: String },
    MissingHash { filename: String },
    AnchorNotPublished { filename: String },
}

impl std::fmt::Display for BinaryTrustError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Validation(s) => write!(f, "Binary validation failed: {s}"),
            Self::Authenticode(code, msg) => {
                write!(f, "Authenticode verification failed (0x{code:08x}): {msg}")
            }
            Self::PublisherMismatch { expected, found } => {
                write!(f, "Publisher mismatch: expected '{expected}', found '{found}'")
            }
            Self::HashMismatch { filename, expected, actual } => {
                write!(
                    f,
                    "Hash mismatch for {filename}: expected {expected}, actual {actual}"
                )
            }
            Self::MissingHash { filename } => {
                write!(f, "Missing release hash in embedded policy for {filename}")
            }
            Self::AnchorNotPublished { filename } => write!(
                f,
                "No trust anchor published for {filename}: packaging/trust/engine-trust.json \
                 still carries its placeholder digest for this artifact, so nothing can be \
                 compared against. Record the signed build's sha256 there (see that file's \
                 $comment and packaging/trust/README.md); this is a release-pipeline gap, not a \
                 damaged install."
            ),
        }
    }
}

impl std::error::Error for BinaryTrustError {}

#[cfg(windows)]
pub fn verify_authenticode_signature(path: &Path, expected_cn: &str) -> Result<(), BinaryTrustError> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Security::WinTrust::{
        WinVerifyTrust, WINTRUST_DATA, WINTRUST_FILE_INFO, WTD_CACHE_ONLY_URL_RETRIEVAL,
        WTD_CHOICE_FILE, WTD_DISABLE_MD2_MD4, WTD_REVOCATION_CHECK_NONE, WTD_REVOKE_NONE,
        WTD_STATEACTION_IGNORE, WTD_UI_NONE,
    };

    let wide_path: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut file_info = WINTRUST_FILE_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: wide_path.as_ptr(),
        hFile: 0 as _,
        pgKnownSubject: std::ptr::null_mut(),
    };

    const WINTRUST_ACTION_GENERIC_VERIFY_V2: windows_sys::core::GUID = windows_sys::core::GUID {
        data1: 0x00aac56b,
        data2: 0xcd44,
        data3: 0x11d0,
        data4: [0x8c, 0xeb, 0x00, 0xc0, 0x4f, 0xc2, 0xaa, 0xe5],
    };

    let mut trust_data = WINTRUST_DATA {
        cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
        pPolicyCallbackData: std::ptr::null_mut(),
        pSIPClientData: std::ptr::null_mut(),
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: windows_sys::Win32::Security::WinTrust::WINTRUST_DATA_0 {
            pFile: &mut file_info,
        },
        // IGNORE, not CLOSE: `WTD_STATEACTION_CLOSE` only releases the cached
        // state, and releasing requires a *second* WinVerifyTrust call with the
        // same hWVTStateData — a single CLOSE call would leak it.
        dwStateAction: WTD_STATEACTION_IGNORE,
        hWVTStateData: 0 as _,
        pwszURLReference: std::ptr::null_mut(),
        // 0x80 is WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT, not ..._NONE, so the
        // value written here asked for a whole-chain CRL/OCSP walk on every
        // launch — which fails closed on an offline machine and, in CI, against
        // a just-issued certificate whose CRL is not published yet. Ask for no
        // revocation walk, but do refuse the broken legacy digests.
        dwProvFlags: WTD_REVOCATION_CHECK_NONE
            | WTD_DISABLE_MD2_MD4
            | WTD_CACHE_ONLY_URL_RETRIEVAL,
        dwUIContext: 0,
        pSignatureSettings: std::ptr::null_mut(),
    };

    let mut action_id = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    let status = unsafe {
        WinVerifyTrust(
            0 as _,
            &mut action_id,
            &mut trust_data as *mut _ as *mut std::ffi::c_void,
        )
    };

    if status != 0 {
        return Err(BinaryTrustError::Authenticode(
            status,
            format!("WinVerifyTrust returned error code: 0x{status:08x}"),
        ));
    }

    if !expected_cn.is_empty() {
        let ps_cmd = format!(
            "(Get-AuthenticodeSignature -LiteralPath '{}').SignerCertificate.Subject",
            path.to_string_lossy().replace('\'', "''")
        );
        let out = Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", &ps_cmd])
            .output()
            .map_err(|e| BinaryTrustError::Validation(format!("failed to query signer certificate: {e}")))?;
        
        if !out.status.success() {
            return Err(BinaryTrustError::Validation(format!(
                "failed to read signer certificate: {}",
                String::from_utf8_lossy(&out.stderr)
            )))
        }

        let subject = String::from_utf8_lossy(&out.stdout).trim().to_string();
        let expected_needle = format!("CN={expected_cn}");
        if !subject.contains(&expected_needle) && !subject.eq_ignore_ascii_case(expected_cn) {
            return Err(BinaryTrustError::PublisherMismatch {
                expected: expected_cn.to_string(),
                found: subject,
            });
        }
    }

    Ok(())
}

#[cfg(not(windows))]
pub fn verify_authenticode_signature(_path: &Path, _expected_cn: &str) -> Result<(), BinaryTrustError> {
    Ok(())
}

pub fn verify_elevated_binary(
    path: &Path,
    label: &str,
    policy: &TrustedBinaryPolicy,
) -> Result<(), BinaryTrustError> {
    // Which witness the running binary holds has to be recoverable from the logs
    // alone, otherwise a refusal is indistinguishable from an old build.
    static ANCHOR_LOGGED: std::sync::Once = std::sync::Once::new();
    let (_, anchor_sha, table, has_placeholder) = engine_trust_anchor();
    ANCHOR_LOGGED.call_once(|| {
        eprintln!(
            "[trust] engine-trust.json sha256={anchor_sha} entries={} placeholder_digest_present={has_placeholder}",
            table.len()
        );
    });

    let path_buf = path.to_path_buf();
    validate_trusted_binary(&path_buf, label)
        .map_err(|e| BinaryTrustError::Validation(e.message))?;

    let filename = path.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(label);

    let actual_hash = file_sha256_hex(path)
        .map_err(|e| BinaryTrustError::Validation(e.message))?;

    let mut found_hash = false;
    for &(expected_name, expected_hash) in policy.embedded_hashes {
        if expected_name.eq_ignore_ascii_case(filename) || expected_name.eq_ignore_ascii_case(label) {
            found_hash = true;
            if actual_hash.eq_ignore_ascii_case(expected_hash) {
                continue;
            }
            if expected_hash == PLACEHOLDER_SHA256 {
                // Nothing has been witnessed for this artifact yet, so this is a
                // pipeline gap rather than tampering. A debug build asserts
                // nothing about release provenance and may proceed; a release
                // build refuses, because "no comparison possible" is not a pass.
                if policy.enforce_hash_match {
                    return Err(BinaryTrustError::AnchorNotPublished {
                        filename: filename.to_string(),
                    });
                }
                continue;
            }
            return Err(BinaryTrustError::HashMismatch {
                filename: filename.to_string(),
                expected: expected_hash.to_string(),
                actual: actual_hash,
            });
        }
    }

    if policy.enforce_hash_match && !found_hash {
        return Err(BinaryTrustError::MissingHash {
            filename: filename.to_string(),
        });
    }

    #[cfg(windows)]
    {
        let auth_res = verify_authenticode_signature(path, policy.expected_publisher_cn);
        match auth_res {
            Ok(()) => {}
            Err(e) => {
                // Exactly one outcome exists in a release binary: refuse.
                #[cfg(debug_assertions)]
                if policy.allow_unsigned_for_dev {
                    eprintln!("[warn] debug build only, Authenticode check skipped: {e}");
                    return Ok(());
                }
                #[cfg(not(debug_assertions))]
                let _ = &e;
                return Err(e);
            }
        }
    }

    Ok(())
}

/// Verify the engine binary this process is about to spawn, in **every** mode.
///
/// The call used to live inside `if settings.routing_mode == "tun"`, so the
/// unelevated proxy/socks paths started a binary whose signature and digest
/// nobody had looked at: `engine_path` only proves "a PE under an allowed root",
/// which a dropped-in file satisfies. Wrapping it in one named function keeps a
/// mode from being able to opt out again by accident, and gives the invariant
/// gate a single token to count against the spawn sites.
fn verify_engine_or_refuse(path: &Path) -> Result<(), CommandError> {
    verify_elevated_binary(path, "aether.exe", &TrustedBinaryPolicy::for_engine())
        .map_err(CommandError::from)
}

/// Drop every `AETHER_*` variable this process inherited before spawning the
/// engine.
///
/// The child's environment used to be "ours plus the keys we set", which made
/// the whole `runtime_env` single-reader rule decorative: anything already in
/// the user's session — `AETHER_TUN`, `AETHER_CONFIG_KEY`, a kill-switch, a peer
/// override — reached the elevated process without the shell deciding it, and
/// `AETHER_CONFIG_KEY` in particular made the child skip the stdin handoff it was
/// promised. Enumerated rather than listed, so a new engine key cannot be
/// forgotten here.
fn scrub_ambient_engine_env(command: &mut Command) {
    for (key, _) in std::env::vars_os() {
        let name = key.to_string_lossy().into_owned();
        if name.to_ascii_uppercase().starts_with("AETHER_") {
            command.env_remove(name);
        }
    }
}

/// Write the engine's stdin preamble: the envelope key, and in TUN mode the one
/// path it is allowed to load the driver from.
///
/// A child process environment stays readable for the whole lifetime of that
/// process — crash collectors, profilers, monitoring agents and (on a debuggable
/// Android build) `adb` all see it — so passing the envelope key as
/// `AETHER_CONFIG_KEY` meant the key to every identity on disk sat in a
/// process-wide, long-lived, world-adjacent place. One line down the pipe this
/// parent already owns carries the same bytes with a far shorter exposure, and
/// the key is zeroized immediately after.
///
/// The driver path left the environment for the same reason and a sharper one:
/// `AETHER_WINTUN` was the elevated engine being told "load that DLL" by a value
/// any bystander able to influence the environment could set.
fn handoff_preamble(
    child: &mut Child,
    key: &str,
    wintun: Option<&Path>,
) -> Result<(), CommandError> {
    use std::io::Write as _;
    let Some(stdin) = child.stdin.as_mut() else {
        return Err(CommandError::new(
            "internal",
            "engine stdin is not piped; refusing to launch an engine that cannot receive its key",
        ));
    };
    let mut buf: Vec<u8> = Vec::with_capacity(key.len() + 64);
    buf.extend_from_slice(b"key ");
    buf.extend_from_slice(key.as_bytes());
    buf.push(b'\n');
    if let Some(path) = wintun {
        // Lossy-converted paths would name a file that does not exist, and the
        // engine would then refuse to start the tunnel with a confusing error.
        let text = path.to_str().ok_or_else(|| {
            CommandError::new(
                "handoff_failed",
                format!(
                    "wintun path {} is not valid UTF-8; install Aether under a plain path",
                    path.display()
                ),
            )
        })?;
        // Windows forbids control characters in file names, so a path cannot
        // forge a second preamble line.
        buf.extend_from_slice(b"dll wintun ");
        buf.extend_from_slice(text.as_bytes());
        buf.push(b'\n');
    }
    let written = stdin.write_all(&buf).and_then(|()| stdin.flush());
    zeroize::Zeroize::zeroize(&mut buf);
    match written {
        Ok(()) => Ok(()),
        Err(e) => Err(CommandError::new("handoff_failed", format!("handoff write: {e}"))),
    }
}

fn engine_path(app: &AppHandle, settings: &Settings) -> Result<PathBuf, CommandError> {
    // TUN: never honor custom overrides (elevated risk).
    // Non-TUN: custom paths allowed only after full trust checks.
    if settings.routing_mode != "tun" && !settings.engine_path.trim().is_empty() {
        let path = PathBuf::from(settings.engine_path.trim());
        if !path.exists() {
            return Err("Configured aether.exe was not found".into());
        }
        validate_trusted_binary(&path, "aether.exe")?;
        return Ok(path);
    }
    // No `AETHER_ENGINE` override: `settings.engine_path` above already lets a
    // user point at their own build, it is visible in the UI and persisted, and
    // it goes through the same `validate_trusted_binary` check. A second,
    // invisible env route to the same decision is how "which binary did the
    // shell actually launch" stops being answerable from the saved settings.
    if let Some(path) = resolve_resource(app, "aether.exe") {
        // Verified here, on every branch, rather than by each caller
        // remembering to: this function is the only way the shell learns which
        // binary to launch, and a returned path that skipped the checks turned
        // "we always validate the engine" into a claim about one call site.
        validate_trusted_binary(&path, "aether.exe")?;
        return Ok(path);
    }
    // Portable layout (Windows is case-insensitive: avoid "Aether.exe" vs "aether.exe")
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            for rel in [
                "engine\\aether.exe",
                "engine/aether.exe",
                "aether-engine.exe",
                "aether.exe",
            ] {
                let path = dir.join(rel);
                if path.exists() {
                    validate_trusted_binary(&path, "aether.exe")?;
                    return Ok(path);
                }
            }
        }
    }
    if settings.routing_mode == "tun" {
        return Err("aether.exe not found next to app; reinstall or use portable package".into());
    }
    let repo_build =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../aether/target/release/aether.exe");
    let Some(path) = repo_build.exists().then_some(repo_build) else {
        return Err("aether.exe not found. Build engine or choose it in Settings > Advanced.".into());
    };
    // The repository-build fallback is a development convenience. `validate_trusted_binary`
    // tolerates an unsigned local build only in a debug binary (see
    // `allow_unsigned_for_dev`), so in a release build this path cannot be used
    // to launch an engine nobody signed.
    validate_trusted_binary(&path, "aether.exe")?;
    Ok(path)
}

fn wintun_path(app: &AppHandle) -> Option<PathBuf> {
    if let Some(path) = resolve_resource(app, "wintun.dll") {
        return Some(path);
    }
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("wintun.dll")))
        .filter(|p| p.exists())
}

fn mark_connected(app: &AppHandle, state: &AppState, settings: &Settings) {
    if state.connected_once.swap(true, Ordering::SeqCst) {
        return;
    }
    let endpoint = state.runtime.lock().endpoint.clone();
    if settings.routing_mode == "system-proxy" {
        #[cfg(windows)]
        {
            let recovery_path = proxy_recovery_path(app).ok();
            match windows_proxy::enable(
                settings.http_port,
                endpoint.as_deref(),
                recovery_path.as_deref(),
            ) {
                Ok(snapshot) => {
                    *state.proxy_snapshot.lock() = Some(snapshot);
                    state.proxy_enabled.store(true, Ordering::SeqCst);
                }
                Err((error, snapshot)) => {
                    if let Some(snapshot) = snapshot {
                        *state.proxy_snapshot.lock() = Some(snapshot);
                        state.proxy_enabled.store(true, Ordering::SeqCst);
                    }
                    emit_log(app, format!("System proxy failed: {error}"));
                    // Stop engine so UI is not stuck with orphan child.
                    if let Some(mut child) = state.child.lock().take() {
                        state.generation.fetch_add(1, Ordering::SeqCst);
                        if let Some(mut stdin) = child.stdin.take() {
                            let _ = stdin.write_all(b"shutdown\n");
                            let _ = stdin.flush();
                        }
                        let _ = child.kill();
                        let _ = child.wait();
                    }
                    cleanup_routing(app, state);
                    emit_state(
                        app,
                        state,
                        "error",
                        "System proxy setup failed",
                        None,
                        endpoint,
                    );
                    return;
                }
            }
        }
    }
    let pid = state.runtime.lock().pid;
    let detail = match settings.routing_mode.as_str() {
        "tun" => "TUN active (full system)",
        "system-proxy" => "System proxy active",
        _ => "Proxy only active",
    };
    emit_state(app, state, "connected", detail, pid, endpoint);
}

fn stream_output<R: std::io::Read + Send + 'static>(
    app: AppHandle,
    reader: R,
    settings: Settings,
    socks_seen: Arc<AtomicBool>,
    tunnel_seen: Arc<AtomicBool>,
    tun_seen: Arc<AtomicBool>,
    generation: u64,
) {
    std::thread::spawn(move || {
        for line in BufReader::new(reader).lines().map_while(Result::ok) {
            let state = app.state::<AppState>();
            // Hold operation only for generation check + dispatch, not forever.
            {
                let _operation = state.operation.lock();
                if state.generation.load(Ordering::SeqCst) != generation {
                    break;
                }
                handle_engine_line(
                    &app,
                    &line,
                    &settings,
                    &socks_seen,
                    &tunnel_seen,
                    &tun_seen,
                );
            }
            emit_log(&app, line);
        }
    });
}

fn cleanup_routing(app: &AppHandle, state: &AppState) {
    #[cfg(windows)]
    if state.proxy_enabled.swap(false, Ordering::SeqCst) {
        let mut snapshot = state.proxy_snapshot.lock();
        if let Some(saved) = snapshot.take() {
            if let Err(error) = windows_proxy::restore(saved.clone()) {
                *snapshot = Some(saved);
                state.proxy_enabled.store(true, Ordering::SeqCst);
                eprintln!("system proxy restore failed: {error}");
            } else if let Ok(path) = proxy_recovery_path(app) {
                let _ = fs::remove_file(path);
            }
        }
    }
    state.connected_once.store(false, Ordering::SeqCst);
    // M8: drop the job object (closing its handle kills any surviving engine).
    #[cfg(windows)]
    {
        state.job.lock().take();
    }
}

fn watch_child(app: AppHandle) {
    std::thread::spawn(move || loop {
        std::thread::sleep(std::time::Duration::from_millis(500));
        let state = app.state::<AppState>();
        let _operation = state.operation.lock();
        let mut child_slot = state.child.lock();
        let Some(child) = child_slot.as_mut() else {
            continue;
        };
        match child.try_wait() {
            Ok(Some(status)) => {
                *child_slot = None;
                drop(child_slot);
                state.connecting.store(false, Ordering::SeqCst);
                state.generation.fetch_add(1, Ordering::SeqCst);
                let ever_connected = state.connected_once.load(Ordering::SeqCst);
                cleanup_routing(&app, &state);
                let already_error = state
                    .runtime
                    .lock()
                    .status
                    .eq_ignore_ascii_case("error");
                if already_error {
                    // Structured error event already set UI; keep it.
                    continue;
                }
                let (ui_status, detail) = if status.success() {
                    ("disconnected", "Engine stopped".to_string())
                } else if !ever_connected {
                    (
                        "error",
                        "Could not find a working gateway. Try HTTP/2 or another scan mode."
                            .to_string(),
                    )
                } else {
                    ("disconnected", format!("Engine exited ({status})"))
                };
                emit_state(&app, &state, ui_status, &detail, None, None);
            }
            Ok(None) => {}
            Err(_) => {
                *child_slot = None;
                drop(child_slot);
                state.connecting.store(false, Ordering::SeqCst);
                state.generation.fetch_add(1, Ordering::SeqCst);
                let ever_connected = state.connected_once.load(Ordering::SeqCst);
                cleanup_routing(&app, &state);
                let already_error = state
                    .runtime
                    .lock()
                    .status
                    .eq_ignore_ascii_case("error");
                if already_error {
                    continue;
                }
                if ever_connected {
                    emit_state(&app, &state, "disconnected", "Engine lost", None, None);
                } else {
                    emit_state(
                        &app,
                        &state,
                        "error",
                        "Engine lost before connect finished",
                        None,
                        None,
                    );
                }
            }
        }
    });
}

#[tauri::command]
fn get_settings(app: AppHandle) -> Settings {
    load_settings_file(&app)
}

#[tauri::command]
fn save_settings(app: AppHandle, settings: Settings) -> Result<(), CommandError> {
    validate_settings(&settings)?;
    save_settings_file(&app, &settings)?;
    #[cfg(windows)]
    autostart::set(settings.launch_at_login)?;
    Ok(())
}

#[tauri::command]
fn get_state(state: State<'_, AppState>) -> RuntimeState {
    state.runtime.lock().clone()
}

#[tauri::command]
fn is_admin() -> bool {
    #[cfg(windows)]
    {
        elevation::is_elevated()
    }
    #[cfg(not(windows))]
    {
        true
    }
}

#[tauri::command]
fn connect(app: AppHandle, state: State<'_, AppState>, settings: Settings) -> Result<(), CommandError> {
    let _operation = state.operation.lock();
    if state
        .connecting
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return Err("Aether is already running".into());
    }
    let result = (|| -> Result<(), CommandError> {
        // A scan and a tunnel must not run at once: stop any active scan first
        // (gracefully, persisting its best-so-far) before bringing up the tunnel.
        stop_scan_child(&state.scan_child);
        if state.child.lock().is_some() {
            return Err("Aether is already running".into());
        }
        validate_settings(&settings)?;
        save_settings_file(&app, &settings)?;
        #[cfg(windows)]
        autostart::set(settings.launch_at_login)?;

        if settings.routing_mode == "tun" {
            #[cfg(windows)]
            {
                // Prefer Admin session for TUN (Wintun + routes). No whole-GUI auto-relaunch.
                // Run Aether as Administrator once, or accept UAC when engine elevates via helper later.
                if !elevation::is_elevated() {
                    return Err(CommandError::new(
                        "permission_denied",
                        "Full-device TUN needs Administrator. Right-click Aether → Run as administrator, then Connect.",
                    ));
                }
                if wintun_path(&app).is_none() {
                    return Err(CommandError::new(
                        "not_found",
                        "wintun.dll not found. Reinstall Aether or place wintun.dll next to the app.",
                    ));
                }
            }
            #[cfg(not(windows))]
            {
                return Err("TUN mode is Windows-only".into());
            }
        }

        let executable = engine_path(&app, &settings)?;
        let dir = config_dir(&app)?;
        fs::create_dir_all(&dir).map_err(CommandError::from)?;
        restrict_directory_acl(&dir)?;

        // In TUN mode the driver is not optional, and neither is verifying it.
        // `if let Some(wintun) = wintun_path(&app)` skipped the whole check
        // precisely in the case that matters: the packaged DLL missing, silently
        // renamed, or shadowed by one the user dropped next to the exe.
        let mut wintun_for_handoff: Option<PathBuf> = None;
        if settings.routing_mode == "tun" {
            let wintun = wintun_path(&app).ok_or_else(|| {
                CommandError::new(
                    "not_found",
                    "wintun.dll is missing from the install directory; TUN cannot start and the \
                     driver will not be loaded from anywhere else",
                )
            })?;
            let wintun_policy = TrustedBinaryPolicy::for_wintun();
            verify_elevated_binary(&wintun, "wintun.dll", &wintun_policy)
                .map_err(CommandError::from)?;
            // Optional pin: set AETHER_WINTUN_SHA256 to require an exact file
            // hash. Read from the ambient environment on purpose, and note
            // that it can only ever *add* verification — leaving it unset
            // still requires a passing Authenticode chain, so there is no
            // value this key can take that weakens the check.
            #[allow(clippy::disallowed_methods)]
            if let Ok(expected) = std::env::var("AETHER_WINTUN_SHA256") {
                let expected = expected.trim().to_ascii_lowercase();
                if !expected.is_empty() {
                    let actual = file_sha256_hex(&wintun)?;
                    if actual != expected {
                        return Err(format!(
                            "wintun.dll hash mismatch (got {actual}, want {expected})"
                        )
                        .into());
                    }
                }
            }
            wintun_for_handoff = Some(wintun);
        }

        let mut dpapi_key = dpapi::get_or_create_dpapi_config_key(&dir)?;
        verify_engine_or_refuse(&executable)?;
        let mut command = Command::new(&executable);
        scrub_ambient_engine_env(&mut command);
        command
            .current_dir(executable.parent().unwrap_or(std::path::Path::new(".")))
            .env("AETHER_CONFIG_KEY_STDIN", "1")
            .env("AETHER_PROTOCOL", &settings.protocol)
            .env("AETHER_SCAN", &settings.scan_mode)
            .env("AETHER_IP", &settings.ip_version)
            .env("AETHER_NOIZE", &settings.noize)
            .env("AETHER_SOCKS", format!("127.0.0.1:{}", settings.socks_port))
            .env("AETHER_HTTP", format!("127.0.0.1:{}", settings.http_port))
            .env("AETHER_CONFIG", dir.join("aether.toml"))
            // TLS verification: intentionally NOT disabled here. The engine's SPKI
            // pinning (consts::MASQUE_PINS) is the tunnel's server authentication;
            // disabling it from the GUI would expose every user to MITM. Debug
            // builds can still opt out by setting the env var themselves.
            .env(
                "AETHER_MASQUE_HTTP2",
                if settings.transport == "h2" { "1" } else { "0" },
            )
            .env(
                "AETHER_QUIC_INITIAL_FRAG",
                if settings.quic_initial_frag {
                    settings.quic_initial_frag_size.clamp(16, 512).to_string()
                } else {
                    "0".to_string()
                },
            )
            .env(
                "AETHER_TUN",
                if settings.routing_mode == "tun" {
                    "1"
                } else {
                    "0"
                },
            )
            // Prefer auto MTU (engine probes 1400 vs 1280) unless user set AETHER_MTU outside.
            .env("AETHER_WG_NO_PROFILE_RETRY", "1")
            .env("AETHER_CONTROL_STDIN", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        // Forced peer from Scanner "Connect Direct".
        if !settings.peer.trim().is_empty() {
            command.env("AETHER_PEER", settings.peer.trim());
            command.env("AETHER_WG_PEER", settings.peer.trim());
        }

        if settings.noize.eq_ignore_ascii_case("custom") {
            command
                .env("AETHER_NOIZE_JC", settings.noize_jc.to_string())
                .env("AETHER_NOIZE_JMIN", settings.noize_jmin.to_string())
                .env("AETHER_NOIZE_JMAX", settings.noize_jmax.to_string())
                .env(
                    "AETHER_NOIZE_INTERVAL_MS",
                    settings.noize_interval_ms.to_string(),
                );
        }

        // The driver path goes on the control pipe below, never in the child's
        // environment: see `handoff_preamble`.

        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x08000000);
        }

        let mut child = command
            .spawn()
            .map_err(|e| {
                dpapi_key.zeroize();
                format!("Could not start aether.exe: {e}")
            })?;
        // The key travels on stdin, then is wiped: the child never holds it in
        // its environment and neither does this process for longer than a call.
        if let Err(e) = handoff_preamble(&mut child, &dpapi_key, wintun_for_handoff.as_deref()) {
            dpapi_key.zeroize();
            let _ = child.kill();
            let _ = child.wait();
            return Err(e);
        }
        dpapi_key.zeroize();
        let pid = child.id();
        // M8: put the engine into a kill-on-close job so it can never outlive us.
        #[cfg(windows)]
        match engine_job::Job::create().and_then(|j| {
            let assigned = j.assign_child(&child);
            if assigned.is_ok() {
                *state.job.lock() = Some(j);
            }
            assigned
        }) {
            Ok(()) => {}
            Err(error) => {
                eprintln!("engine job object unavailable ({error}); orphan protection disabled")
            }
        }
        let generation = state.generation.fetch_add(1, Ordering::SeqCst) + 1;
        let socks_seen = Arc::new(AtomicBool::new(false));
        let tunnel_seen = Arc::new(AtomicBool::new(false));
        let tun_seen = Arc::new(AtomicBool::new(false));
        state.connected_once.store(false, Ordering::SeqCst);

        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        *state.child.lock() = Some(child);
        emit_state(
            &app,
            &state,
            "connecting",
            if settings.routing_mode == "tun" {
                "Starting tunnel + full-system routing"
            } else {
                "Scanning reachable routes"
            },
            Some(pid),
            None,
        );
        if let Some(stdout) = stdout {
            stream_output(
                app.clone(),
                stdout,
                settings.clone(),
                socks_seen.clone(),
                tunnel_seen.clone(),
                tun_seen.clone(),
                generation,
            );
        }
        if let Some(stderr) = stderr {
            stream_output(
                app,
                stderr,
                settings,
                socks_seen,
                tunnel_seen,
                tun_seen,
                generation,
            );
        }
        Ok(())
    })();
    state.connecting.store(false, Ordering::SeqCst);
    result
}

#[tauri::command]
fn disconnect(app: AppHandle, state: State<'_, AppState>) -> Result<(), CommandError> {
    // M7 fix: hold the operation lock across the WHOLE teardown. The old code
    // released it while waiting on the child, letting a concurrent connect slip
    // in — after which cleanup_routing tore down the NEW session's system-proxy
    // state and clobbered its UI status with "disconnected". Holding is safe:
    // stream threads acquire the lock per-line only and observe the bumped
    // generation as soon as we release.
    let _operation = state.operation.lock();
    state.generation.fetch_add(1, Ordering::SeqCst);
    state.connecting.store(false, Ordering::SeqCst);
    let mut child = state.child.lock().take();
    if let Some(child) = child.as_mut() {
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(b"shutdown\n");
            let _ = stdin.flush();
        }
        // Fifteen seconds, and never silently. The engine uses this window to
        // close the tunnel, drop the routes it journaled and reset the adapter;
        // five was routinely too short on a slow link, so the shell killed it
        // mid-teardown and the machine kept routes to a dead adapter — with no
        // log line saying a kill happened.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        loop {
            match child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
                _ => {
                    eprintln!("[aether] engine outlived the 15s teardown grace; forcing exit (host state may need repair: run Aether with --repair-proxy, or reconnect once)");
                    let _ = child.kill();
                    let _ = child.wait();
                    break;
                }
            }
        }
    }
    cleanup_routing(&app, &state);
    emit_state(&app, &state, "disconnected", "Ready", None, None);
    Ok(())
}

#[tauri::command]
fn app_info() -> serde_json::Value {
    serde_json::json!({
        "name": "Aether Next",
        "version": env!("CARGO_PKG_VERSION"),
        "author": "deathline94",
        "engine": "deathline94/aether-next",
    })
}

#[tauri::command]
fn test_connection(settings: Settings) -> Result<String, CommandError> {
    validate_settings(&settings)?;
    let url = "https://www.cloudflare.com/cdn-cgi/trace";

    let (client, via_desc) = if settings.routing_mode == "tun" {
        let client = ureq::AgentBuilder::new()
            .timeout(std::time::Duration::from_secs(12))
            .build();
        (client, "TUN".to_string())
    } else {
        let proxy = format!("http://127.0.0.1:{}", settings.http_port);
        let client = ureq::AgentBuilder::new()
            .timeout(std::time::Duration::from_secs(12))
            .proxy(ureq::Proxy::new(&proxy).map_err(CommandError::from)?)
            .build();
        (client, proxy)
    };

    let body = client
        .get(url)
        .call()
        .map_err(|e| format!("connection test failed: {e}"))?
        .into_string()
        .map_err(CommandError::from)?;
    let ip = body
        .lines()
        .find_map(|l| l.strip_prefix("ip="))
        .unwrap_or("unknown");
    let loc = body
        .lines()
        .find_map(|l| l.strip_prefix("loc="))
        .unwrap_or("?");
    Ok(format!("OK via {via_desc} · ip={ip} loc={loc}"))
}

#[tauri::command]
fn scan(
    app: AppHandle,
    state: State<'_, AppState>,
    protocol: String,
    ip_version: String,
    concurrency: u32,
    timeout_ms: u32,
    noize: Option<String>,
) -> Result<(), CommandError> {
    // Serialize with connect/disconnect/stop_scan (QA-5) so two engine processes
    // can't spawn concurrently (double device registration + proxy-port contention).
    let _operation = state.operation.lock();
    // A tunnel and a scan must not run at once. The frontend disconnects first,
    // but guard here too in case that flow is bypassed.
    if state.child.lock().is_some() {
        return Err("Disconnect before starting a scan.".into());
    }
    // Clamp scan parameters defensively: the UI clamps too, but a replayed/direct
    // invoke could pass out-of-range values. 500 keeps even cheap-mode (WireGuard)
    // bursts sane; the engine additionally enforces its own expensive-mode ceiling.
    let concurrency = concurrency.clamp(1, 500);
    let timeout_ms = timeout_ms.clamp(3_000, 30_000);
    // Gracefully stop any existing scan first (persist its best-so-far).
    stop_scan_child(&state.scan_child);

    let settings = load_settings_file(&app);
    let executable = engine_path(&app, &settings)?;
    let dir = config_dir(&app)?;
    fs::create_dir_all(&dir).map_err(CommandError::from)?;
    restrict_directory_acl(&dir)?;

    let engine_protocol = match protocol.as_str() {
        "wireguard" => "wireguard",
        _ => "masque",
    };

    let mut dpapi_key = dpapi::get_or_create_dpapi_config_key(&dir)?;
    verify_engine_or_refuse(&executable)?;
    let mut command = Command::new(&executable);
    scrub_ambient_engine_env(&mut command);
    command
        .current_dir(executable.parent().unwrap_or(std::path::Path::new(".")))
        .env("AETHER_CONFIG_KEY_STDIN", "1")
        .env("AETHER_PROTOCOL", engine_protocol)
        .env("AETHER_SCAN", "balanced")
        .env("AETHER_SCAN_EXHAUSTIVE", "1")
        .env("AETHER_IP", &ip_version)
        .env("AETHER_NOIZE", noize.as_deref().unwrap_or("off"))
        .env("AETHER_CONFIG", dir.join("aether.toml"))
        .env("AETHER_SCAN_ONLY", "1")
        .env("AETHER_SCAN_CONCURRENCY", concurrency.to_string())
        .env("AETHER_SCAN_TIMEOUT_MS", timeout_ms.to_string())
        .env("AETHER_WG_NO_PROFILE_RETRY", "1")
        .env(
            "AETHER_MASQUE_HTTP2",
            if protocol == "masque-h2" { "1" } else { "0" },
        )
        .env(
            "AETHER_QUIC_INITIAL_FRAG",
            if settings.quic_initial_frag {
                settings.quic_initial_frag_size.clamp(16, 512).to_string()
            } else {
                "0".to_string()
            },
        )
        // Control channel so Stop can cooperatively cancel (persist best-so-far)
        // instead of SIGKILL mid cache-write.
        .env("AETHER_CONTROL_STDIN", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
    }

    let mut child = command
        .spawn()
        .map_err(|e| {
            dpapi_key.zeroize();
            format!("Could not start scan: {e}")
        })?;
    // A scan child never brings the tunnel up, so it gets the key line and no
    // driver line — the engine only waits for the second when AETHER_TUN is on.
    if let Err(e) = handoff_preamble(&mut child, &dpapi_key, None) {
        dpapi_key.zeroize();
        let _ = child.kill();
        let _ = child.wait();
        return Err(e);
    }
    dpapi_key.zeroize();

    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    *state.scan_child.lock() = Some(child);

    // Stream scan output on a SEPARATE thread per pipe. The engine writes
    // AETHER_EVENT progress to stdout and diagnostics to stderr; reading them
    // sequentially (stdout to EOF, then stderr) made a live scan show nothing until
    // Stop killed the process and stdout finally closed. One thread per stream
    // keeps both live.
    let terminal_sent = Arc::new(AtomicBool::new(false));
    let mut handles = Vec::new();
    if let Some(o) = stdout {
        handles.push(pump_scan_stream(app.clone(), Box::new(o), terminal_sent.clone()));
    }
    if let Some(e) = stderr {
        handles.push(pump_scan_stream(app.clone(), Box::new(e), terminal_sent.clone()));
    }
    let app_done = app.clone();
    std::thread::spawn(move || {
        for h in handles {
            let _ = h.join();
        }
        // Terminal scan_done only if the engine didn't already send one, so a crash
        // still unsticks the UI but a normal finish doesn't double-log.
        if !terminal_sent.load(Ordering::SeqCst) {
            let _ = app_done.emit("scan://event", serde_json::json!({
                "type": "scan_done",
                "addr": "",
                "rtt": "",
                "protocol": "",
            }));
        }
    });

    Ok(())
}

/// Read one scan output pipe on its own thread, forwarding AETHER_EVENT lines as
/// `scan://event` and every line to the activity log. Returns a join handle so the
/// caller can emit the terminal event only after all pipes drain.
fn pump_scan_stream(
    app: AppHandle,
    reader: Box<dyn std::io::Read + Send>,
    terminal_sent: Arc<AtomicBool>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        for line in BufReader::new(reader).lines().map_while(Result::ok) {
            if let Some(json) = line.split("AETHER_EVENT ").nth(1) {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(json.trim()) {
                    let ty = v.get("type").and_then(|t| t.as_str()).unwrap_or("");
                    match ty {
                        "scan_start" => {
                            let _ = app.emit("scan://event", serde_json::json!({
                                "type": "scan_start",
                                "mode": v.get("mode").and_then(|m| m.as_str()).unwrap_or(""),
                                "total": v.get("total").and_then(|t| t.as_u64()).unwrap_or(0),
                                "concurrency": v.get("concurrency").and_then(|c| c.as_u64()).unwrap_or(0),
                            }));
                        }
                        "scan_progress" => {
                            let _ = app.emit("scan://event", serde_json::json!({
                                "type": "scan_progress",
                                "scanned": v.get("scanned").and_then(|s| s.as_u64()).unwrap_or(0),
                                "total": v.get("total").and_then(|t| t.as_u64()).unwrap_or(0),
                                "working": v.get("working").and_then(|w| w.as_u64()).unwrap_or(0),
                            }));
                        }
                        "scan_hit" => {
                            let _ = app.emit("scan://event", serde_json::json!({
                                "type": "scan_hit",
                                "addr": v.get("addr").and_then(|a| a.as_str()).unwrap_or(""),
                                "rtt": v.get("rtt").and_then(|r| r.as_str()).unwrap_or(""),
                                "rttMs": v.get("rtt_ms").and_then(|r| r.as_f64()).unwrap_or(0.0),
                                "protocol": v.get("protocol").and_then(|p| p.as_str()).unwrap_or(""),
                            }));
                        }
                        "scan_done" => {
                            terminal_sent.store(true, Ordering::SeqCst);
                            let _ = app.emit("scan://event", v);
                        }
                        _ => {}
                    }
                }
            }
            emit_log(&app, line);
        }
    })
}

/// Gracefully stop the scan child: ask the engine to cancel (so it persists the
/// best endpoint found so far), wait briefly, then kill as a fallback. Does not
/// touch the `operation` lock, so callers already holding it won't deadlock.
fn stop_scan_child(scan_child: &Mutex<Option<Child>>) {
    let mut child = match scan_child.lock().take() {
        Some(c) => c,
        None => return,
    };
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(b"cancel\n");
        let _ = stdin.flush();
    }
    // A cancelled scan is mid-write to the endpoint cache more often than a
    // tunnel teardown is, and the whole point of `cancel` (rather than `kill`)
    // is that it finishes persisting best-so-far. Four seconds cut that short.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            _ => {
                eprintln!("[aether] scan child outlived the 15s cancel grace; forcing exit");
                let _ = child.kill();
                let _ = child.wait();
                break;
            }
        }
    }
}

#[tauri::command]
fn stop_scan(state: State<'_, AppState>) -> Result<(), CommandError> {
    // Serialize with connect/disconnect (QA-5) and cancel gracefully (QA-1).
    let _operation = state.operation.lock();
    stop_scan_child(&state.scan_child);
    Ok(())
}

#[cfg(windows)]
mod elevation {

    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    pub fn is_elevated() -> bool {
        unsafe {
            let mut token: HANDLE = std::ptr::null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                return false;
            }
            let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
            let mut size = 0u32;
            let ok = GetTokenInformation(
                token,
                TokenElevation,
                &mut elevation as *mut _ as *mut _,
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut size,
            );
            CloseHandle(token);
            ok != 0 && elevation.TokenIsElevated != 0
        }
    }
}

#[cfg(windows)]
mod autostart {
    use crate::CommandError;

    use std::env;
    use winreg::{enums::HKEY_CURRENT_USER, RegKey};

    const VALUE: &str = "Aether Next";

    pub fn set(enabled: bool) -> Result<(), CommandError> {
        let key = RegKey::predef(HKEY_CURRENT_USER)
            .open_subkey_with_flags(
                "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                winreg::enums::KEY_SET_VALUE | winreg::enums::KEY_QUERY_VALUE,
            )
            .map_err(CommandError::from)?;
        if enabled {
            let exe = env::current_exe().map_err(CommandError::from)?;
            let cmd = format!("\"{}\"", exe.display());
            key.set_value(VALUE, &cmd).map_err(CommandError::from)
        } else {
            let _ = key.delete_value(VALUE);
            Ok(())
        }
    }
}

#[cfg(windows)]
pub mod windows_proxy {
    use crate::CommandError;

    use serde::{Deserialize, Serialize};
    use std::io;
    use std::path::Path;
    use windows_sys::Win32::Networking::WinInet::{
        InternetSetOptionW, INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED,
    };
    use winreg::{enums::HKEY_CURRENT_USER, RegKey};

    #[derive(Clone, Serialize, Deserialize)]
    pub struct ProxySnapshot {
        pub enabled: u32,
        pub server: Option<String>,
        pub bypass: Option<String>,
    }

    fn key() -> io::Result<RegKey> {
        RegKey::predef(HKEY_CURRENT_USER).open_subkey_with_flags(
            "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
            winreg::enums::KEY_READ | winreg::enums::KEY_SET_VALUE,
        )
    }

    fn refresh() {
        unsafe {
            InternetSetOptionW(
                std::ptr::null_mut(),
                INTERNET_OPTION_SETTINGS_CHANGED,
                std::ptr::null_mut(),
                0,
            );
            InternetSetOptionW(
                std::ptr::null_mut(),
                INTERNET_OPTION_REFRESH,
                std::ptr::null_mut(),
                0,
            );
        }
    }

    pub fn enable(
        port: u16,
        endpoint: Option<&str>,
        recovery_path: Option<&Path>,
    ) -> Result<ProxySnapshot, (String, Option<ProxySnapshot>)> {
        let key = key().map_err(|e| (e.to_string(), None))?;
        let snapshot = ProxySnapshot {
            enabled: key.get_value("ProxyEnable").unwrap_or(0),
            server: key.get_value("ProxyServer").ok(),
            bypass: key.get_value("ProxyOverride").ok(),
        };
        if let Some(path) = recovery_path {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| (format!("proxy recovery directory: {e}"), None))?;
            }
            let json = serde_json::to_vec_pretty(&snapshot)
                .map_err(|e| (format!("proxy recovery encode: {e}"), None))?;
            let tmp = path.with_extension("json.tmp");
            std::fs::write(&tmp, json)
                .map_err(|e| (format!("proxy recovery write: {e}"), None))?;
            std::fs::rename(&tmp, path)
                .map_err(|e| (format!("proxy recovery commit: {e}"), None))?;
        }
        let result = (|| -> Result<(), CommandError> {
            key.set_value(
                "ProxyServer",
                &format!("http=127.0.0.1:{port};https=127.0.0.1:{port}"),
            )
            .map_err(CommandError::from)?;
            let mut bypass = String::from("localhost;127.*;<local>");
            if let Some(ep) = endpoint {
                if let Some(host) = super::sanitize_proxy_bypass_host(ep) {
                    bypass.push(';');
                    bypass.push_str(&host);
                }
            }
            key.set_value("ProxyOverride", &bypass)
                .map_err(CommandError::from)?;
            key.set_value("ProxyEnable", &1u32)
                .map_err(CommandError::from)?;
            Ok(())
        })();
        if let Err(error) = result {
            return match restore(snapshot.clone()) {
                Ok(()) => {
                    if let Some(path) = recovery_path {
                        let _ = std::fs::remove_file(path);
                    }
                    Err((error.message, None))
                }
                Err(rollback) => Err((
                    format!("{error}; rollback failed: {rollback}"),
                    Some(snapshot),
                )),
            };
        }
        refresh();
        Ok(snapshot)
    }

    pub fn verify_readback_values(
        snapshot: &ProxySnapshot,
        actual_enabled: u32,
        actual_server: Option<&str>,
        actual_bypass: Option<&str>,
    ) -> Result<(), CommandError> {
        if actual_enabled != snapshot.enabled {
            return Err(format!(
                "ProxyEnable read-back mismatch: expected {}, got {}",
                snapshot.enabled, actual_enabled
            ).into());
        }
        match (snapshot.server.as_deref(), actual_server) {
            (Some(expected), Some(actual)) if expected == actual => {}
            (None, None) => {}
            (Some(expected), actual) => {
                return Err(format!(
                    "ProxyServer read-back mismatch: expected Some({expected:?}), got {actual:?}"
                ).into());
            }
            (None, Some(actual)) => {
                return Err(format!(
                    "ProxyServer read-back mismatch: expected None, got Some({actual:?})"
                ).into());
            }
        }
        match (snapshot.bypass.as_deref(), actual_bypass) {
            (Some(expected), Some(actual)) if expected == actual => {}
            (None, None) => {}
            (Some(expected), actual) => {
                return Err(format!(
                    "ProxyOverride read-back mismatch: expected Some({expected:?}), got {actual:?}"
                ).into());
            }
            (None, Some(actual)) => {
                return Err(format!(
                    "ProxyOverride read-back mismatch: expected None, got Some({actual:?})"
                ).into());
            }
        }
        Ok(())
    }

    pub fn restore(snapshot: ProxySnapshot) -> Result<(), CommandError> {
        let key = key().map_err(CommandError::from)?;
        match snapshot.server.as_ref() {
            Some(value) => key
                .set_value("ProxyServer", value)
                .map_err(CommandError::from)?,
            None => match key.delete_value("ProxyServer") {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(format!("delete ProxyServer: {e}").into()),
            },
        }
        match snapshot.bypass.as_ref() {
            Some(value) => key
                .set_value("ProxyOverride", value)
                .map_err(CommandError::from)?,
            None => match key.delete_value("ProxyOverride") {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(format!("delete ProxyOverride: {e}").into()),
            },
        }
        key.set_value("ProxyEnable", &snapshot.enabled)
            .map_err(CommandError::from)?;

        // 3-tuple read-back verification: ProxyEnable, ProxyServer, ProxyOverride
        let current_enabled: u32 = key
            .get_value("ProxyEnable")
            .map_err(|e| format!("verify ProxyEnable: {e}"))?;
        let current_server = read_optional_reg_value(key.get_value("ProxyServer"), "ProxyServer")?;
        let current_bypass = read_optional_reg_value(key.get_value("ProxyOverride"), "ProxyOverride")?;

        verify_readback_values(
            &snapshot,
            current_enabled,
            current_server.as_deref(),
            current_bypass.as_deref(),
        )?;

        refresh();
        Ok(())
    }

    pub fn read_optional_reg_value(
        res: io::Result<String>,
        val_name: &str,
    ) -> Result<Option<String>, CommandError> {
        match res {
            Ok(v) => Ok(Some(v)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(format!("verify read {val_name}: {e}").into()),
        }
    }

    pub fn recover_internal<F: Fn(ProxySnapshot) -> Result<(), CommandError>>(
        path: &Path,
        restorer: F,
    ) -> Result<bool, CommandError> {
        if !path.exists() {
            return Ok(false);
        }
        let data = std::fs::read(path).map_err(CommandError::from)?;
        let snapshot: ProxySnapshot = serde_json::from_slice(&data).map_err(CommandError::from)?;
        restorer(snapshot)?;
        std::fs::remove_file(path).map_err(CommandError::from)?;
        Ok(true)
    }

    pub fn recover(path: &Path) -> Result<bool, CommandError> {
        recover_internal(path, restore)
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.show();
                let _ = window.set_focus();
                let _ = window.unminimize();
            }
        }))
        .manage(AppState::default())
        .setup(|app| {
            let dir = config_dir(app.handle())
                .map_err(|e| Box::new(std::io::Error::other(e)) as Box<dyn std::error::Error>)?;
            fs::create_dir_all(&dir)
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
            restrict_directory_acl(&dir)
                .map_err(|e| Box::new(std::io::Error::other(e)) as Box<dyn std::error::Error>)?;
            #[cfg(windows)]
            {
                let _ = dpapi::get_or_create_dpapi_config_key(&dir);
            }
            #[cfg(windows)]
            if let Ok(path) = proxy_recovery_path(app.handle()) {
                match windows_proxy::recover(&path) {
                    Ok(true) => emit_log(
                        app.handle(),
                        "Recovered Windows proxy after interrupted session".into(),
                    ),
                    Ok(false) => {}
                    Err(error) => emit_log(
                        app.handle(),
                        format!("Windows proxy recovery failed: {error}"),
                    ),
                }
            }
            if repair_proxy_requested() {
                // Everything that can be restored has been: the proxy journal
                // above and the route journal the engine replays at its own
                // startup. Exit without a tray, a window or an engine child, so
                // the command is usable as a repair and not only as a side
                // effect of opening the app.
                #[cfg(windows)]
                eprintln!("--repair-proxy: Windows proxy state restored (see messages above)");
                #[cfg(not(windows))]
                eprintln!("--repair-proxy: nothing to do; the system proxy integration is Windows-only");
                let _ = std::io::stderr().flush();
                std::process::exit(0);
            }
            watch_child(app.handle().clone());
            let settings = load_settings_file(app.handle());
            if settings.start_minimized {
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.hide();
                }
            }
            let show = MenuItem::with_id(app, "show", "Open Aether Next", true, None::<&str>)?;
            let connect_item = MenuItem::with_id(app, "connect", "Connect", true, None::<&str>)?;
            let disconnect_item =
                MenuItem::with_id(app, "disconnect", "Disconnect", true, None::<&str>)?;
            let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&show, &connect_item, &disconnect_item, &quit])?;
            // Prefer bundled PNG so tray is never a blank/default tile when window icon is missing.
            let tray_icon = tauri::image::Image::from_bytes(include_bytes!("../icons/128x128.png"))
                .or_else(|_| {
                    app.default_window_icon()
                        .cloned()
                        .ok_or_else(|| tauri::Error::AssetNotFound("window icon".into()))
                })
                .map_err(|e| {
                    Box::new(std::io::Error::other(format!("tray icon: {e}")))
                        as Box<dyn std::error::Error>
                })?;
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.set_icon(tray_icon.clone());
            }
            TrayIconBuilder::new()
                .icon(tray_icon)
                .tooltip("Aether Next")
                .menu(&menu)
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "show" => {
                        if let Some(window) = app.get_webview_window("main") {
                            let _ = window.show();
                            let _ = window.set_focus();
                        }
                    }
                    "connect" => {
                        let app = app.clone();
                        std::thread::spawn(move || {
                            let settings = load_settings_file(&app);
                            let state = app.state::<AppState>();
                            if let Err(e) = connect(app.clone(), state, settings) {
                                emit_log(&app, format!("tray connect: {e}"));
                            }
                        });
                    }
                    "disconnect" => {
                        let app = app.clone();
                        std::thread::spawn(move || {
                            let state = app.state::<AppState>();
                            let _ = disconnect(app.clone(), state);
                        });
                    }
                    "quit" => {
                        let app = app.clone();
                        std::thread::spawn(move || {
                            let state = app.state::<AppState>();
                            let _ = disconnect(app.clone(), state);
                            app.exit(0);
                        });
                    }
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    if matches!(
                        event,
                        TrayIconEvent::Click {
                            button: MouseButton::Left,
                            button_state: MouseButtonState::Up,
                            ..
                        }
                    ) {
                        if let Some(window) = tray.app_handle().get_webview_window("main") {
                            let _ = window.show();
                            let _ = window.set_focus();
                        }
                    }
                })
                .build(app)?;
            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                let _ = window.hide();
                api.prevent_close();
            }
        })
        .invoke_handler(tauri::generate_handler![
            get_settings,
            save_settings,
            get_state,
            is_admin,
            connect,
            disconnect,
            app_info,
            test_connection,
            scan,
            stop_scan
        ])
        .run(tauri::generate_context!())
        .expect("error while running Aether Next");
}
