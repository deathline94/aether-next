#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use parking_lot::Mutex;

/// Structured shell/IPC error.
///
/// Every shell helper used to return a bare message, so a caller could only
/// branch on prose (`msg.contains("not found")`) and the frontend received an
/// opaque rejection it had to read as text. `code` is the machine-readable half.
///
/// It serialises as `{code, message, field?}` — the contract in
/// `specs/015-full-audit-remediation/contracts/ipc-contract.md` (C-IPC-2). The
/// earlier shape was the message string, chosen so `String(e)` in the shipped
/// frontend kept working; that is what made the code unreachable, and a code no
/// caller can read is the same as no code. Both UIs now unwrap the object through
/// `lib/ipcError.ts`, which still accepts a bare string because the Android
/// bridge rejects with prose.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CommandError {
    pub code: &'static str,
    pub message: String,
    /// Which `Settings` field the command rejected, using the name the frontend
    /// state uses (`httpPort`, not `http_port`) so the form can attach the error
    /// to the input that caused it. `None` for everything that is not about a
    /// field.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<&'static str>,
}

impl CommandError {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            field: None,
        }
    }

    /// A rejected setting. `field` is the camelCase key of the `Settings` value
    /// that failed, which is the only way the UI can show it anywhere but in a
    /// log line.
    pub fn validation(field: &'static str, message: impl Into<String>) -> Self {
        Self {
            code: "validation",
            message: message.into(),
            field: Some(field),
        }
    }
}

impl std::fmt::Display for CommandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for CommandError {}

impl From<String> for CommandError {
    fn from(message: String) -> Self {
        Self {
            code: "internal",
            message,
            field: None,
        }
    }
}

impl From<&str> for CommandError {
    fn from(message: &str) -> Self {
        Self {
            code: "internal",
            message: message.to_string(),
            field: None,
        }
    }
}

impl From<serde_json::Error> for CommandError {
    fn from(e: serde_json::Error) -> Self {
        Self {
            code: "encode",
            message: e.to_string(),
            field: None,
        }
    }
}

impl From<tauri::Error> for CommandError {
    fn from(e: tauri::Error) -> Self {
        Self {
            code: "shell",
            message: e.to_string(),
            field: None,
        }
    }
}

impl From<ureq::Error> for CommandError {
    fn from(e: ureq::Error) -> Self {
        Self {
            code: "network",
            message: e.to_string(),
            field: None,
        }
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
        Self {
            code,
            message: e.to_string(),
            field: None,
        }
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
        Self {
            code,
            message: e.to_string(),
            field: None,
        }
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

/// Absolute path to a binary under `%SystemRoot%\\System32`.
///
/// `Command::new("icacls")` resolves through the standard Windows search order,
/// which tries the *application directory* first. The portable package ships the
/// GUI into a folder that `allowed_binary_roots` also trusts, so a dropped
/// `icacls.exe`/`powershell.exe` beside the exe runs with the shell's token: the
/// interactive user, and Administrator on the documented elevated TUN path.
/// System utilities are therefore always addressed by full path, and a missing
/// `%SystemRoot%` fails closed instead of falling back to the bare name.
#[cfg(windows)]
fn system32(program: &str) -> Result<PathBuf, CommandError> {
    let root = std::env::var_os("SystemRoot")
        .or_else(|| std::env::var_os("WINDIR"))
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .ok_or_else(|| {
            CommandError::new(
                "internal",
                format!("cannot locate %SystemRoot%\\System32\\{program}"),
            )
        })?;
    Ok(root.join("System32").join(program))
}

/// SDDL string (`S-1-5-21-...`) for the user SID of *this* process token.
///
/// Built from `GetTokenInformation(TokenUser)` rather than `ConvertSidToStringSidW`
/// so no ambient environment value takes part in an access decision.
#[cfg(windows)]
fn current_user_sid_string() -> Result<String, CommandError> {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{
        GetLengthSid, GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation, IsValidSid,
        TokenUser, PSID, SID, TOKEN_QUERY, TOKEN_USER,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return Err(CommandError::new("internal", "cannot open process token"));
        }
        // First call fails with ERROR_INSUFFICIENT_BUFFER and reports the size.
        let mut needed = 0u32;
        GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut needed);
        if needed < std::mem::size_of::<TOKEN_USER>() as u32 {
            CloseHandle(token);
            return Err(CommandError::new("internal", "cannot read token user SID"));
        }
        let mut buf = vec![0u8; needed as usize];
        let ok = GetTokenInformation(
            token,
            TokenUser,
            buf.as_mut_ptr() as *mut _,
            needed,
            &mut needed,
        );
        CloseHandle(token);
        if ok == 0 {
            return Err(CommandError::new("internal", "cannot read token user SID"));
        }
        let user: TOKEN_USER = std::ptr::read_unaligned(buf.as_ptr() as *const TOKEN_USER);
        let sid: PSID = user.User.Sid;
        if sid.is_null() || IsValidSid(sid) == 0 || GetLengthSid(sid) == 0 {
            return Err(CommandError::new("internal", "malformed token user SID"));
        }
        let sid_ref = &*(sid as *const SID);
        let count_ptr = GetSidSubAuthorityCount(sid);
        if sid_ref.Revision != 1 || count_ptr.is_null() {
            return Err(CommandError::new("internal", "malformed token user SID"));
        }
        let mut identifier_authority: u64 = 0;
        for byte in sid_ref.IdentifierAuthority.Value.iter() {
            identifier_authority = (identifier_authority << 8) | u64::from(*byte);
        }
        let mut out = format!("S-{}-{}", sid_ref.Revision, identifier_authority);
        for index in 0..u32::from(*count_ptr) {
            let sub = GetSidSubAuthority(sid, index);
            if sub.is_null() {
                return Err(CommandError::new("internal", "malformed token user SID"));
            }
            out.push('-');
            out.push_str(&(*sub).to_string());
        }
        Ok(out)
    }
}

#[cfg(windows)]
pub fn restrict_directory_acl(path: &Path) -> Result<(), CommandError> {
    // Fail closed. The previous `if let Ok(user)` skipped the whole ACL whenever
    // the principal was unavailable, so the file that gates every other secret
    // kept whatever the directory handed out.
    //
    // The principal comes from the token's user SID, never from `%USERNAME%`: on
    // the documented elevated path ("Run as administrator" with a different
    // admin credential) the env var names the *elevator's* account, so one
    // elevated run re-granted the secrets to the admin and locked the ordinary
    // user out of settings.json / config_key.dpapi / aether.toml - and made the
    // DPAPI master key undecryptable for the account that owns it.
    let sid = current_user_sid_string()?;
    let icacls = system32("icacls.exe")?;
    {
        let is_dir = path.is_dir();
        let scope = if is_dir { "(OI)(CI)" } else { "" };
        let user_perm = format!("*{sid}:{scope}F");
        let sys_perm = format!("SYSTEM:{scope}F");
        let output = Command::new(&icacls)
            .arg(path.as_os_str())
            // Grant only. `/inheritance:r` revoked every inherited ACE, which is
            // how an elevated run could delete the owning user's inherited
            // access; `/grant:r` replaces just the explicit ACE for each named
            // principal and leaves inheritance (and the owner's grant coming
            // through it) untouched.
            .arg("/grant:r")
            .arg(&user_perm)
            .arg("/grant:r")
            .arg(sys_perm)
            .output()
            .map_err(|e| {
                format!(
                    "failed to execute {} on {}: {e}",
                    icacls.display(),
                    path.display()
                )
            })?;
        if !output.status.success() {
            let err = String::from_utf8_lossy(&output.stderr);
            return Err(format!(
                "icacls failed to restrict permissions on {}: {}",
                path.display(),
                err.trim()
            )
            .into());
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
        CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
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
                        let slice = std::slice::from_raw_parts_mut(
                            out_blob.pbData,
                            out_blob.cbData as usize,
                        );
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
                return Err(format!(
                    "invalid DPAPI key envelope header in {}",
                    key_file.display()
                )
                .into());
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
                f.sync_all()
                    .map_err(|e| format!("cannot flush {}: {e}", tmp_file.display()))?;
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
                f.sync_all()
                    .map_err(|e| format!("cannot flush {}: {e}", tmp_file.display()))?;
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

        // The temp file's DACL travels with the rename, so this repeats a
        // restriction that is normally already in place — and repeating it while
        // *discarding* the result (`let _ =`) was the defect: where the directory
        // re-inherits over the file's own DACL, a failure here was silently the
        // difference between "this user can read the master key" and "everyone
        // can", against a comment that says fail closed. Report it, but leave the
        // file in place: deleting a DPAPI master key the user may already have
        // identities wrapped under is a worse loss than a loud failure.
        super::restrict_directory_acl(&key_file)?;

        let b64 = base64::engine::general_purpose::STANDARD.encode(raw_key);
        raw_key.zeroize();
        Ok(b64)
    }
}

/// A settings value drawn from a fixed vocabulary, with the wire format pinned.
///
/// Each of these used to be a `String` plus an allow-list in `validate_settings`,
/// which is the worst of both: the list could hold a typo (`"thorogh"`) as a legal
/// value, and it could disagree with what the UI offers — `ipVersion` accepted
/// `v4/v6/ipv4/dual…` but *not* `"both"`, the exact string the Scanner's
/// Dual-Stack option and the Settings row both send. The consequence was visible:
/// a legitimate choice was rejected on save and hard-broke the Connect button
/// while the identical label worked everywhere else.
///
/// Serialising always writes the canonical spelling, so the JSON on disk and in
/// the IPC payloads is byte-for-byte what the React app already produces — no
/// frontend change is needed. Deserialising accepts that spelling plus the legacy
/// aliases that meant the same thing, and a value the vocabulary cannot name
/// falls back to the variant `Settings::default()` would have produced rather
/// than turning a stale config into a load error (a *non-string* is still a type
/// error; `#[serde(default)]` is for absent keys, not for garbage).
macro_rules! wire_enum {
    (
        $(#[$meta:meta])*
        enum $name:ident {
            $($variant:ident = $wire:literal $(| $alias:literal)* $(,)?)*
        }
        default $default:ident
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum $name {
            $($variant),*
        }

        impl $name {
            /// The one spelling on the wire and in the child's environment.
            pub fn as_str(&self) -> &'static str {
                match self { $( $name::$variant => $wire, )* }
            }

            /// Canonical spelling plus the aliases that have always meant it.
            pub fn parse(raw: &str) -> Option<Self> {
                let value = raw.trim().to_ascii_lowercase();
                $(
                    if value == $wire $(|| value == $alias)* {
                        return Some($name::$variant);
                    }
                )*
                None
            }

            /// Every value the type can hold, for error prose.
            pub const ALL: &'static [$name] = &[$( $name::$variant ),*];
        }

        impl Default for $name {
            fn default() -> Self {
                $name::$default
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(self.as_str())
            }
        }

        impl serde::Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_str(self.as_str())
            }
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let raw = <String as serde::Deserialize>::deserialize(d)?;
                let value = Self::parse(&raw).unwrap_or_default();
                if Self::parse(&raw).is_none() && !raw.trim().is_empty() {
                    eprintln!(
                        "settings: {raw:?} is not a {} and was read as {:?}",
                        stringify!($name),
                        value,
                    );
                }
                Ok(value)
            }
        }
    };
}

wire_enum! {
    /// Tunnel protocol the engine dials. `warp` is legacy but a shipped config can
    /// hold it, so it stays representable rather than silently becoming `masque`.
    enum Protocol {
        Masque = "masque",
        Wireguard = "wireguard",
        Warp = "warp",
        Gool = "gool",
    }
    default Masque
}

wire_enum! {
    /// MASQUE inner transport. `auto` is the legacy "let the engine choose" value;
    /// it is not the same statement as `h3`, so it keeps its own variant.
    enum TransportKind {
        H3 = "h3",
        H2 = "h2",
        Auto = "auto",
    }
    default H2
}

wire_enum! {
    /// Probe velocity profile — "Probe Velocity Profile" in the Settings UI.
    ///
    /// The set is the engine's (`turbo/balanced/thorough/stealth/ironclad`), not
    /// the allow-list's, which also carried `fast`/`deep` as aliases, `auto` as a
    /// non-value and `"thorogh"` as a typo. Aliases below are the ones with a
    /// single established meaning; a misspelling is not an alias of anything.
    enum ScanMode {
        Turbo = "turbo" | "fast",
        Balanced = "balanced" | "auto",
        Thorough = "thorough" | "deep",
        Stealth = "stealth" | "quiet",
        Ironclad = "ironclad" | "verify",
    }
    default Balanced
}

wire_enum! {
    /// Address families to probe. `Dual` is the wire value `"both"` the UI has
    /// always sent — `"dual"` and `"all"` are the engine's aliases for it.
    enum IpVersion {
        Auto = "auto",
        V4 = "v4" | "4" | "ipv4",
        V6 = "v6" | "6" | "ipv6",
        Dual = "both" | "dual" | "all",
    }
    default V4
}

wire_enum! {
    /// How the OS is pointed at the engine.
    enum RoutingMode {
        ProxyOnly = "proxy-only" | "proxy" | "none",
        SystemProxy = "system-proxy" | "system",
        Tun = "tun" | "wintun",
    }
    default SystemProxy
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
// A config written before a field existed must load with that field at its
// default. Without this, one missing key failed the whole file: the shell reported
// a hydration error, the UI ran on defaults, and the first save overwrote the
// user's protocol, ports and obfuscation choices. Invalid values are still errors;
// this covers absent keys only.
#[serde(default)]
pub struct Settings {
    pub protocol: Protocol,
    pub transport: TransportKind,
    pub scan_mode: ScanMode,
    pub ip_version: IpVersion,
    pub noize: String,
    /// Custom obfuscation: junk packet count (when noize == custom).
    pub noize_jc: u32,
    /// Custom obfuscation: min junk size.
    pub noize_jmin: u32,
    /// Custom obfuscation: max junk size.
    pub noize_jmax: u32,
    /// Custom obfuscation: interval between junk packets (ms).
    pub noize_interval_ms: u32,
    pub routing_mode: RoutingMode,
    pub socks_port: u16,
    pub http_port: u16,
    pub start_minimized: bool,
    pub launch_at_login: bool,
    pub engine_path: String,
    /// Forced peer endpoint (set by Scanner "Connect Direct").
    #[serde(default)]
    pub peer: String,
    /// H3 anti-DPI: split the QUIC Initial ClientHello across two datagrams so
    /// on-path DPI can't read the SNI from the first Initial packet.
    #[serde(default)]
    pub quic_initial_frag: bool,
    /// H3 anti-DPI: bytes of ClientHello CRYPTO carried in the first Initial.
    #[serde(default = "default_quic_frag_size")]
    pub quic_initial_frag_size: u32,
}

fn default_quic_frag_size() -> u32 {
    96
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            protocol: Protocol::Masque,
            transport: TransportKind::H2,
            // Prefer balanced over turbo: better edge RTT → higher throughput.
            scan_mode: ScanMode::Balanced,
            ip_version: IpVersion::V4,
            noize: "off".into(),
            noize_jc: 5,
            noize_jmin: 50,
            noize_jmax: 128,
            noize_interval_ms: 0,
            routing_mode: RoutingMode::SystemProxy,
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
    /// RTT of the probe that proved the endpoint this session selected, in ms.
    /// `None` until something has actually been measured -- the UI renders that
    /// as "not measured" rather than 0 ms, which would read as an excellent link.
    handshake_rtt_ms: Option<u32>,
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
    /// What this session wrote to the registry, kept so a drift check can tell
    /// "someone else changed the proxy" from "we never set it".
    #[cfg(windows)]
    proxy_applied: Mutex<Option<windows_proxy::ProxySnapshot>>,
    connected_once: AtomicBool,
    connecting: AtomicBool,
    /// Set for the whole of a teardown's child wait. `disconnect` must not hold
    /// `operation` across that wait (the output pumps take it per line, so the
    /// pipes would stop being drained), which reopens the window the old comment
    /// called M7: a connect slipping in mid-teardown. This flag is what closes it
    /// again without the lock.
    tearing_down: AtomicBool,
    generation: AtomicU64,
    /// `(generation, when)` for the session currently in `connecting`. The
    /// watchdog in `watch_child` fires only while the generation still matches,
    /// so a session that reached any terminal state leaves the stamp inert.
    connect_since: Mutex<Option<(u64, std::time::Instant)>>,
    /// `(phase, when)` from the engine's last `heartbeat` event. The engine used
    /// to be silent for the whole multi-second endpoint hunt, which from the GUI
    /// side is indistinguishable from a hang; absence of pulses now says so.
    last_beat: Mutex<Option<(String, std::time::Instant)>>,
    /// Kept outside `RuntimeState` so the many `emit_state` callers cannot drop a
    /// measurement that arrived after they were written.
    handshake_rtt_ms: Mutex<Option<u32>>,
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
                handshake_rtt_ms: None,
            }),
            proxy_enabled: AtomicBool::new(false),
            #[cfg(windows)]
            proxy_snapshot: Mutex::new(None),
            #[cfg(windows)]
            proxy_applied: Mutex::new(None),
            connected_once: AtomicBool::new(false),
            connecting: AtomicBool::new(false),
            tearing_down: AtomicBool::new(false),
            generation: AtomicU64::new(0),
            connect_since: Mutex::new(None),
            last_beat: Mutex::new(None),
            handshake_rtt_ms: Mutex::new(None),
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

/// `--repair-proxy`: recovery entry point for a user whose system proxy still
/// points at an engine that died. The app restores the registry state and exits
/// instead of opening a window they would have to fight with. Reading argv is the
/// same operation on every platform, so this is deliberately not `cfg`-gated:
/// the call site in `setup` is not either, and gating it left the shell unable to
/// compile for Linux and macOS, where CI never builds it.
fn repair_proxy_requested() -> bool {
    std::env::args().any(|a| a == "--repair-proxy")
}

/// `--minimized`, the flag `autostart::set(true)` writes into the HKCU\Run value.
/// Without it the launch-at-login path only ever consulted `start_minimized` from
/// settings.json, so enabling autostart dropped a full window on the desktop at
/// every logon.
fn start_minimized_requested() -> bool {
    std::env::args().any(|a| a == "--minimized")
}

fn proxy_recovery_path(app: &AppHandle) -> Result<PathBuf, CommandError> {
    Ok(config_dir(app)?.join("proxy-recovery.json"))
}

/// Decode the contents of `settings.json`, distinguishing "absent" from
/// "damaged". Public so the corruption path is unit-testable without an app.
pub fn decode_settings_text(text: &str) -> Result<Settings, CommandError> {
    serde_json::from_str::<Settings>(text).map_err(|e| CommandError {
        code: "settings_corrupt",
        message: format!("settings.json is not readable ({e}); refusing to overwrite it"),
        field: Some("settings"),
    })
}

/// Read the persisted settings.
///
/// A malformed file used to be folded into `Settings::default()` here, and the
/// frontend's autosave (debounced at ~400 ms) then wrote those defaults back
/// over the user's real protocol / ports / obfuscation settings. Absent is a
/// first run and still yields defaults; *damaged* is now an error the UI can
/// show and, crucially, gate its persist effect on.
fn load_settings_file(app: &AppHandle) -> Result<Settings, CommandError> {
    let path = settings_path(app)?;
    match fs::read_to_string(&path) {
        Ok(text) => decode_settings_text(&text),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Settings::default()),
        Err(e) => Err(CommandError::new(
            "settings_unreadable",
            format!("cannot read {}: {e}", path.display()),
        )),
    }
}

/// For readers that only *launch* something and never write the file back: a
/// damaged settings.json must not disable the route sweep or the diagnostics
/// export, but the reason has to be in the log rather than silent.
fn load_settings_or_defaults(app: &AppHandle) -> Settings {
    load_settings_file(app).unwrap_or_else(|e| {
        eprintln!("settings unusable ({e}); continuing with defaults for this read");
        Settings::default()
    })
}

/// Write `bytes` to `path` by way of an exclusively-created, uniquely named
/// temporary file that is flushed before it is renamed into place.
///
/// The settings file and the proxy-recovery journal used to share a fixed
/// `*.json.tmp` name written with `fs::write` and no `sync_all`: two writers (an
/// autosave and a connect, or two shells over the same profile) interleaved into
/// one temp file, and a rename could publish bytes that were still in the cache
/// across a power loss — for `proxy-recovery.json` that is the only record of
/// what the machine's proxy was before Aether touched it. Same discipline as the
/// DPAPI envelope write. Public so the temp-file discipline is testable.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    let file_name = path
        .file_name()
        .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidInput))?
        .to_string_lossy()
        .into_owned();
    let tmp = path.with_file_name(format!(
        "{file_name}.{}.{}.tmp",
        std::process::id(),
        rand::random::<u32>()
    ));
    let inner = || -> std::io::Result<()> {
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            // Owner-only from the first byte: these files are written next to the
            // DPAPI key where `restrict_directory_acl` is a no-op.
            opts.mode(0o600);
        }
        let mut file = opts.open(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&tmp, path)?;
        Ok(())
    };
    let result = inner();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

fn save_settings_file(app: &AppHandle, settings: &Settings) -> Result<(), CommandError> {
    let path = settings_path(app)?;
    let parent = path.parent().ok_or("invalid config path")?;
    fs::create_dir_all(parent).map_err(CommandError::from)?;
    restrict_directory_acl(parent)?;
    let json = serde_json::to_vec_pretty(settings).map_err(CommandError::from)?;
    write_atomic(&path, &json).map_err(CommandError::from)
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
        handshake_rtt_ms: *state.handshake_rtt_ms.lock(),
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

/// The obfuscation profile names the engine is willing to run. Shared by
/// `validate_settings` (the Settings form) and the `scan` command: the scanner
/// used to take `noize` straight from the webview into `AETHER_NOIZE`, so a
/// profile could reach the engine's environment through a path that bypassed
/// every rule this list encodes.
pub const NOIZE_VOCABULARY: &[&str] = &[
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
];

/// One reading of `noize` for a child environment: absent means "off", anything
/// outside [`NOIZE_VOCABULARY`] is refused rather than forwarded.
fn validated_noize(noize: Option<&str>) -> Result<&'static str, CommandError> {
    let requested = noize.unwrap_or("off").trim();
    NOIZE_VOCABULARY
        .iter()
        .find(|o| o.eq_ignore_ascii_case(requested))
        .copied()
        .ok_or_else(|| {
            CommandError::validation(
                "noize",
                format!("noize must be one of: {}", NOIZE_VOCABULARY.join(", ")),
            )
        })
}

pub fn validate_settings(settings: &Settings) -> Result<(), CommandError> {
    for (field, name, port) in [
        ("httpPort", "HTTP", settings.http_port),
        ("socksPort", "SOCKS5", settings.socks_port),
    ] {
        if !(1024..=65535).contains(&port) {
            return Err(CommandError::validation(
                field,
                format!("{name} port must be 1024–65535 (got {port})"),
            ));
        }
    }
    if settings.http_port == settings.socks_port {
        return Err(CommandError::validation(
            "httpPort",
            "HTTP and SOCKS5 ports must differ",
        ));
    }
    // `protocol`, `transport`, `scanMode`, `ipVersion` and `routingMode` are not
    // checked here any more: they are `wire_enum!` types, so a value outside the
    // vocabulary cannot be built in the first place. That removes the drift this
    // list was papering over — `ipVersion` allowed `auto/4/6/v4/v6/ipv4/ipv6/dual`
    // but not `"both"`, which is the exact string the Scanner's Dual-Stack row and
    // the Settings select both send. A valid choice was refused on save and
    // hard-broke the Connect button while the same label worked everywhere else,
    // and `"thorogh"` sat in the list as a legal scan mode.
    //
    // The first argument is the `Settings` key in the name the frontend uses,
    // because that is what the form needs in order to mark the right input: a
    // rejected value otherwise has nowhere to go but the log, and the save
    // spinner never stops.
    let allow = |field: &'static str, val: &str, opts: &[&str]| -> Result<(), CommandError> {
        if opts.iter().any(|o| o.eq_ignore_ascii_case(val.trim())) {
            Ok(())
        } else {
            Err(CommandError::validation(
                field,
                format!("{field} must be one of: {}", opts.join(", ")),
            ))
        }
    };
    allow("noize", &settings.noize, NOIZE_VOCABULARY)?;
    if settings.noize.eq_ignore_ascii_case("custom") {
        if settings.noize_jmax < settings.noize_jmin {
            return Err(CommandError::validation(
                "noizeJmax",
                "custom obfuscation: max size must be >= min size",
            ));
        }
        // One message for three different inputs is a message nobody can act on,
        // so each bound reports the field it broke.
        if settings.noize_jc > 64 {
            return Err(CommandError::validation(
                "noizeJc",
                format!(
                    "custom obfuscation: junk packet count must be <= 64 (got {})",
                    settings.noize_jc
                ),
            ));
        }
        if settings.noize_jmax > 2048 {
            return Err(CommandError::validation(
                "noizeJmax",
                format!(
                    "custom obfuscation: max size must be <= 2048 (got {})",
                    settings.noize_jmax
                ),
            ));
        }
        if settings.noize_interval_ms > 5000 {
            return Err(CommandError::validation(
                "noizeIntervalMs",
                format!(
                    "custom obfuscation: interval must be <= 5000 ms (got {})",
                    settings.noize_interval_ms
                ),
            ));
        }
    }
    // `routingMode` is a `wire_enum!` type now, so the three values are the only
    // ones that can reach here.
    // A custom engine path is checked for existence here rather than at connect,
    // where the allow-list would refuse it and the user would be left with a
    // "binary is not trusted" error for a path they typed themselves. It used to
    // be validated nowhere: the settings form persists on a 400 ms debounce, so a
    // half-typed path reached the disk as the configured engine.
    if !settings.engine_path.trim().is_empty() && !Path::new(settings.engine_path.trim()).is_file()
    {
        return Err(CommandError::validation(
            "enginePath",
            format!(
                "engine path does not exist as a file: {}",
                settings.engine_path.trim()
            ),
        ));
    }
    Ok(())
}

/// Mirror of the engine's `session_event::SessionEvent`
/// (`aether/src/session_event.rs`), deserialised rather than probed field by
/// field.
///
/// The shell cannot depend on the engine crate -- that would drag `boring-sys`
/// into the GUI build -- so this is a copy, and the copy is what makes a new or
/// malformed variant visible: the old `Value` + `match ty` shape fell through to
/// `_ => {}`, which meant the engine adding an event was indistinguishable from
/// the shell ignoring it. An unparseable line is counted and reported instead.
/// Most fields are read by only one arm; the mirror declares the whole engine
/// shape on purpose, because the value of the type is that an unrecognised or
/// malformed payload cannot slip past unnoticed.
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[allow(dead_code)]
enum EngineEvent {
    IdentityReady {
        device_id: String,
        ipv4: String,
    },
    EndpointSelected {
        addr: String,
        protocol: String,
        #[serde(default)]
        rtt_ms: Option<f64>,
    },
    ProxyReady {
        socks: String,
        http: String,
    },
    TunnelReady {
        transport: String,
    },
    TunReady,
    Connected {
        detail: String,
    },
    Error {
        message: String,
    },
    Heartbeat {
        seq: u64,
        phase: String,
    },
    ScanStart {
        mode: String,
        total: usize,
        concurrency: usize,
    },
    ScanProgress {
        scanned: usize,
        total: usize,
        working: usize,
    },
    ScanHit {
        addr: String,
        rtt: String,
        rtt_ms: f64,
        protocol: String,
    },
    ScanDone {
        addr: String,
        rtt: String,
        protocol: String,
        #[serde(default)]
        best_rtt_ms: Option<f64>,
    },
}

/// Number of engine event lines that did not parse. Reported with the first
/// offending payload so a contract drift is noticed on the day it happens.
static MALFORMED_ENGINE_EVENTS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn note_malformed_event(app: &AppHandle, detail: String) {
    let n = MALFORMED_ENGINE_EVENTS.fetch_add(1, Ordering::Relaxed) + 1;
    // Loud once, then every 50th: the count is the point, not the volume.
    if n == 1 || n.is_multiple_of(50) {
        emit_log(
            app,
            format!("Ignored {n} malformed engine event(s); latest: {detail}"),
        );
    }
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
    let want_tun = settings.routing_mode == RoutingMode::Tun;
    if let Some(json) = line.split("AETHER_EVENT ").nth(1) {
        match serde_json::from_str::<EngineEvent>(json.trim()) {
            Ok(event) => match event {
                EngineEvent::EndpointSelected { addr, rtt_ms, .. } => {
                    let state = app.state::<AppState>();
                    if let Some(ms) = rtt_ms.map(|r| r.round().max(0.0) as u32) {
                        *state.handshake_rtt_ms.lock() = Some(ms);
                    }
                    let mut rt = state.runtime.lock();
                    rt.endpoint = Some(addr.to_string());
                    rt.handshake_rtt_ms = *state.handshake_rtt_ms.lock();
                    let snap = rt.clone();
                    drop(rt);
                    let _ = app.emit("session://state", snap);
                }
                EngineEvent::Heartbeat { phase, .. } => {
                    // Only the phase is kept: a pulse resets the stall timer.
                    let state = app.state::<AppState>();
                    *state.last_beat.lock() = Some((phase, std::time::Instant::now()));
                }
                EngineEvent::ProxyReady { .. } => {
                    socks_seen.store(true, Ordering::SeqCst);
                }
                EngineEvent::TunnelReady { .. } => {
                    tunnel_seen.store(true, Ordering::SeqCst);
                }
                EngineEvent::TunReady => {
                    tun_seen.store(true, Ordering::SeqCst);
                    // Full-system path: TUN up implies kernel bridge is usable.
                    tunnel_seen.store(true, Ordering::SeqCst);
                }
                EngineEvent::Connected { .. } => {
                    // Crypto + proxies only. Never treat as TUN-ready (false "connected"
                    // when WinTUN routes are still missing).
                    socks_seen.store(true, Ordering::SeqCst);
                    tunnel_seen.store(true, Ordering::SeqCst);
                }
                EngineEvent::Error { message } => {
                    let msg = message;
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
                EngineEvent::IdentityReady { .. } => {}
                // Scan traffic belongs to the scan child's own stream, which
                // parses it in `pump_scan_stream`.
                EngineEvent::ScanStart { .. }
                | EngineEvent::ScanProgress { .. }
                | EngineEvent::ScanHit { .. }
                | EngineEvent::ScanDone { .. } => {}
            },
            Err(e) => note_malformed_event(app, format!("{e}: {}", json.trim())),
        }
    }

    // Legacy log markers — only strong readiness signals (not CONNECT/handshake alone).
    //
    // A `[-] session failed:` line is *prose*: the engine writes it for a probe
    // that failed inside a session that is still healthy. Tearing the host down
    // here meant one transient line from a chatty scan dropped the job-object
    // handle and restored the system proxy under a live tunnel. Teardown belongs
    // to the structured `Error` event above and to `watch_child`'s exit path, both
    // of which know whether the session actually ended.
    if line.contains("[-] session failed:") {
        let msg = line
            .split("[-] session failed:")
            .nth(1)
            .map(|s| s.trim())
            .unwrap_or("Connection failed");
        let state = app.state::<AppState>();
        let status = state.runtime.lock().status.clone();
        if status.eq_ignore_ascii_case("connected") {
            // Keep the tunnel; say what was seen.
            emit_log(app, format!("engine reported a failed session ({msg})"));
        } else if !status.eq_ignore_ascii_case("error") {
            emit_state(app, &state, "error", msg, None, None);
        }
    }
    if line.contains("socks5 listening on")
        || line.contains("socks5 server listening")
        || line.contains("http proxy listening")
    {
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

/// The env_logger level token, when the line carries one.
///
/// Engine stderr lines come from env_logger as `[ts LEVEL target] msg`, so the
/// uppercase token is the only *authoritative* signal available; everything after
/// it is a guess about prose.
fn env_logger_level(line: &str) -> Option<&'static str> {
    if line.contains(" ERROR ")
        || line.starts_with("ERROR ")
        || line.contains(" FATAL ")
        || line.starts_with("FATAL ")
    {
        Some("error")
    } else if line.contains(" WARN ") || line.starts_with("WARN ") {
        Some("warn")
    } else {
        None
    }
}

/// Classify one engine line for the activity log. Public so the heuristics are
/// testable without a running engine.
///
/// The fallback used to ask whether the lowercased line *contained* "error", which
/// made a benign progress line ("0 errors so far", "error budget") arrive as an
/// error and turned the log into a wall of red on a healthy session. A prose line
/// now has to carry a failure *marker*, not the word.
pub fn log_level_for(line: &str) -> &'static str {
    if let Some(level) = env_logger_level(line) {
        return level;
    }
    let lower = line.to_ascii_lowercase();
    if lower.contains("error:")
        || lower.contains(": error")
        || lower.contains("errors occurred")
        || lower.contains("failed")
        || lower.contains("failure")
        || lower.contains("fatal")
        || lower.contains("panic")
        || lower.contains("cannot")
        || lower.contains("refused")
    {
        return "error";
    }
    if lower.contains("warn") || lower.contains("[-]") || lower.contains("retrying") {
        return "warn";
    }
    "info"
}

fn emit_log(app: &AppHandle, line: String) {
    let level = log_level_for(&line);
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
    // `symlink_metadata`, not `metadata`: `fs::metadata` *follows* reparse points,
    // so the `FILE_ATTRIBUTE_REPARSE_POINT` test below could only ever observe the
    // target's attributes. A link planted inside the install directory pointing at
    // any PE on the machine satisfied "regular file, not a reparse point".
    let meta = fs::symlink_metadata(path).map_err(|e| format!("{label}: {e}"))?;
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
    // The root test runs on the *canonical* path or not at all. Falling back to the
    // raw path on a failed canonicalize meant `…\Aether\..\..\evil\aether.exe` was
    // compared as a string against `…\Aether` and passed — a `..` walk out of the
    // trusted root, straight into the elevated TUN launch.
    let canon = path.canonicalize().map_err(|e| {
        CommandError::new(
            "validation",
            format!(
                "{label} rejected: its final path cannot be resolved ({e}), so it cannot be \
                 shown to live under a trusted root"
            ),
        )
    })?;
    let roots = allowed_binary_roots(app_root.as_deref());
    for root in &roots {
        if canon.starts_with(root) {
            return Ok(());
        }
    }
    Err(format!(
        "{label} rejected: must live under the app install directory (got {})",
        canon.display()
    )
    .into())
}

/// Only allow safe host tokens into Windows ProxyOverride (no `;` injection).
pub fn sanitize_proxy_bypass_host(endpoint: &str) -> Option<String> {
    let trimmed = endpoint.trim();
    let host = if let Some(rest) = trimmed.strip_prefix('[') {
        // Bracketed IPv6: `[::1]` or `[::1]:8080`. The port lives *outside* the
        // brackets, so the plain `rsplit_once(':')` below would have cut the
        // address itself in half.
        let (addr, suffix) = rest.split_once(']')?;
        let port_is_well_formed = suffix.is_empty()
            || (suffix.len() > 1
                && suffix.starts_with(':')
                && suffix[1..].bytes().all(|b| b.is_ascii_digit()));
        if !port_is_well_formed {
            return None;
        }
        addr
    } else {
        match trimmed.rsplit_once(':') {
            // `host:port` — but only when the head holds no colon of its own.
            // A bare, unbracketed IPv6 address (`2001:db8::1`, no port at all)
            // used to come back as `2001:db8:`, i.e. a wrong host written into
            // the system bypass list.
            Some((head, port))
                if !head.is_empty()
                    && !head.contains(':')
                    && !port.is_empty()
                    && port.bytes().all(|b| b.is_ascii_digit()) =>
            {
                head
            }
            _ => trimmed,
        }
    };
    let host = host.trim();
    if host.is_empty() || host.len() > 253 || host.ends_with(':') {
        return None;
    }
    // This character class *is* the filter. `;`, `<` and `>` — and every other
    // delimiter ProxyOverride could mis-parse — are not in it, so they need no
    // separate (and unreachable) `contains` checks beside it.
    let allowed = host
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '_'));
    allowed.then(|| host.to_string())
}

/// The only directories an engine binary may live in.
///
/// This used to be "the exe's directory and its parent", which for an installed
/// app is `C:\Program Files` — a root that includes every other vendor's folder —
/// and for the portable package is whatever directory the user extracted the zip
/// into, i.e. usually somewhere writable. The child launched from there is handed
/// the DPAPI master key, so "under the install directory, broadly" was not a
/// boundary worth the name. Named layout directories only, plus the repository
/// build path the dev fallback resolves, which is a fixed constant rather than a
/// place an attacker gets to write by being lucky.
pub fn allowed_binary_roots(exe_dir: Option<&Path>) -> Vec<PathBuf> {
    let mut roots: Vec<PathBuf> = Vec::new();
    if let Some(dir) = exe_dir {
        for candidate in [dir.to_path_buf(), dir.join("resources"), dir.join("engine")] {
            roots.push(candidate.canonicalize().unwrap_or(candidate));
        }
    }
    // `cargo run` / `cargo test` from the repository: the engine sits in the
    // workspace's release target directory, which is no relation to where the
    // shell binary happens to be.
    let repo_build = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../aether/target/release")
        .join(if cfg!(windows) {
            "aether.exe"
        } else {
            "aether"
        });
    roots.push(repo_build.canonicalize().unwrap_or(repo_build));
    roots
}

pub fn file_sha256_hex(path: &Path) -> Result<String, CommandError> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    let mut file =
        fs::File::open(path).map_err(|e| format!("cannot open {}: {e}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let res = hasher.finalize();
    let mut s = String::with_capacity(64);
    for b in res {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    Ok(s)
}

include!(concat!(env!("OUT_DIR"), "/release_hashes.rs"));

/// Which witness this binary was built against, for logs and for support output:
/// the anchor's verbatim bytes, its own digest, the table derived from it, and
/// whether any entry is still the un-published placeholder.
pub fn engine_trust_anchor() -> (
    &'static [u8],
    &'static str,
    &'static [(&'static str, &'static str)],
    bool,
) {
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
    PublisherMismatch {
        expected: String,
        found: String,
    },
    HashMismatch {
        filename: String,
        expected: String,
        actual: String,
    },
    MissingHash {
        filename: String,
    },
    AnchorNotPublished {
        filename: String,
    },
}

impl std::fmt::Display for BinaryTrustError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Validation(s) => write!(f, "Binary validation failed: {s}"),
            Self::Authenticode(code, msg) => {
                write!(f, "Authenticode verification failed (0x{code:08x}): {msg}")
            }
            Self::PublisherMismatch { expected, found } => {
                write!(
                    f,
                    "Publisher mismatch: expected '{expected}', found '{found}'"
                )
            }
            Self::HashMismatch {
                filename,
                expected,
                actual,
            } => {
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

/// The pinned signing-certificate digest the anchor holds for `filename`, or
/// `None` when the anchor carries no entry or only the all-zero placeholder.
pub fn embedded_cert_pin(filename: &str) -> Option<&'static str> {
    EMBEDDED_ISSUER_CERTS
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(filename))
        .map(|(_, digest)| *digest)
        .filter(|digest| *digest != PLACEHOLDER_SHA256)
}

/// Does this X.500 subject name `expected_cn` as a whole CN RDN value?
///
/// `subject.contains("CN=deathline94")` matched `CN=deathline94.example.com`, and
/// the looser `eq_ignore_ascii_case` fallback matched a subject with no `CN=` at
/// all — so any certificate whose common name merely *starts* with the expected
/// text passed "published by deathline94". Distinguished names are compared per
/// RDN instead: `CN=deathline94` matches, `CN=deathline94.example.com` and
/// `O=CN=deathline94` do not.
pub fn subject_names_common_name(subject: &str, expected_cn: &str) -> bool {
    let expected = expected_cn.trim();
    if expected.is_empty() {
        return false;
    }
    let bytes = subject.as_bytes();
    let mut start = 0usize;
    let mut quoted = false;
    let mut escaped = false;
    let mut matched = false;
    for (index, byte) in bytes.iter().enumerate() {
        if escaped {
            escaped = false;
            continue;
        }
        match byte {
            b'\\' => escaped = true,
            b'"' => quoted = !quoted,
            b',' | b';' if !quoted => {
                matched |= cn_rdn_matches(&subject[start..index], expected);
                start = index + 1;
            }
            _ => {}
        }
    }
    matched || cn_rdn_matches(&subject[start..], expected)
}

fn cn_rdn_matches(rdn: &str, expected: &str) -> bool {
    let Some((name, value)) = rdn.split_once('=') else {
        return false;
    };
    if !name.trim().eq_ignore_ascii_case("CN") {
        return false;
    }
    let value = value.trim();
    let value = value
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .unwrap_or(value);
    // Undo the `\,` / `\"` escaping a DN uses inside quoted values.
    let mut unescaped = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => match chars.next() {
                Some(next) => unescaped.push(next),
                None => unescaped.push(c),
            },
            other => unescaped.push(other),
        }
    }
    unescaped.trim().eq_ignore_ascii_case(expected)
}

#[cfg(windows)]
pub fn verify_authenticode_signature(
    path: &Path,
    expected_cn: &str,
    expected_cert_sha256: Option<&str>,
) -> Result<(), BinaryTrustError> {
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
        dwProvFlags: WTD_REVOCATION_CHECK_NONE | WTD_DISABLE_MD2_MD4 | WTD_CACHE_ONLY_URL_RETRIEVAL,
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

    if !expected_cn.is_empty() || expected_cert_sha256.is_some() {
        // Full path: `powershell.exe` resolved through the search order that puts
        // the application directory first.
        let shell = crate::system32("WindowsPowerShell\\v1.0\\powershell.exe")
            .map_err(|e| BinaryTrustError::Validation(e.message))?;
        let quoted = path.to_string_lossy().replace('\'', "''");
        // The leaf's own digest, sha256 over its DER — which is what the anchor's
        // `cert_sha256` field is defined as, and *not* the SHA-1 store thumbprint
        // `Get-AuthenticodeSignature` exposes as `Thumbprint`.
        let ps_cmd = format!(
            "$c = (Get-AuthenticodeSignature -LiteralPath '{quoted}').SignerCertificate; \
             if ($null -eq $c) {{ exit 3 }}; \
             $sha = [System.BitConverter]::ToString( \
             [System.Security.Cryptography.SHA256]::Create().ComputeHash($c.RawData) \
             ) -replace '-',''; Write-Output $sha; Write-Output $c.Subject"
        );
        let out = Command::new(&shell)
            .args(["-NoProfile", "-NonInteractive", "-Command", &ps_cmd])
            .output()
            .map_err(|e| {
                BinaryTrustError::Validation(format!("failed to query signer certificate: {e}"))
            })?;

        if !out.status.success() {
            return Err(BinaryTrustError::Validation(format!(
                "failed to read signer certificate: {}",
                String::from_utf8_lossy(&out.stderr)
            )));
        }

        let text = String::from_utf8_lossy(&out.stdout).replace("\r\n", "\n");
        let mut lines = text.trim().splitn(2, '\n');
        let found_hash = lines.next().unwrap_or("").trim().to_ascii_lowercase();
        let subject = lines.next().unwrap_or("").trim().to_string();

        // The certificate itself, not what it says it is called. A subject the
        // signer writes is free; the leaf digest is only obtainable from whoever
        // holds the private key that the release job recorded.
        if let Some(pinned) = expected_cert_sha256 {
            if found_hash != pinned.to_ascii_lowercase() {
                return Err(BinaryTrustError::PublisherMismatch {
                    expected: format!("{expected_cn} (leaf sha256 {pinned})"),
                    found: format!("{subject} (leaf sha256 {found_hash})"),
                });
            }
        }
        if !expected_cn.is_empty() && !subject_names_common_name(&subject, expected_cn) {
            return Err(BinaryTrustError::PublisherMismatch {
                expected: expected_cn.to_string(),
                found: subject,
            });
        }
    }

    Ok(())
}

#[cfg(not(windows))]
pub fn verify_authenticode_signature(
    _path: &Path,
    _expected_cn: &str,
    _expected_cert_sha256: Option<&str>,
) -> Result<(), BinaryTrustError> {
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
    // Hash and authenticate the *final* path. The two checks used to open whatever
    // name the caller passed while the root test resolved it separately, so the
    // bytes witnessed here and the file later launched were not guaranteed to be
    // the same object.
    let verified_path = path.canonicalize().map_err(|e| {
        BinaryTrustError::Validation(format!(
            "{}: cannot resolve a final path for verification ({e})",
            path.display()
        ))
    })?;

    let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or(label);

    let actual_hash =
        file_sha256_hex(&verified_path).map_err(|e| BinaryTrustError::Validation(e.message))?;

    let mut found_hash = false;
    for &(expected_name, expected_hash) in policy.embedded_hashes {
        if expected_name.eq_ignore_ascii_case(filename) || expected_name.eq_ignore_ascii_case(label)
        {
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
        // sha256 of the signing leaf, straight from the same anchor the file
        // digests come from. Absent (or the all-zero placeholder) means nothing is
        // pinned, which a release build may not treat as a pass for the same
        // reason it does not treat an absent file digest as one.
        let pinned = embedded_cert_pin(filename).or_else(|| embedded_cert_pin(label));
        if pinned.is_none() && policy.enforce_hash_match {
            return Err(BinaryTrustError::AnchorNotPublished {
                filename: filename.to_string(),
            });
        }
        let auth_res =
            verify_authenticode_signature(&verified_path, policy.expected_publisher_cn, pinned);
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
/// The call used to live inside `if settings.routing_mode == RoutingMode::Tun`, so the
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
        Err(e) => Err(CommandError::new(
            "handoff_failed",
            format!("handoff write: {e}"),
        )),
    }
}

fn engine_path(app: &AppHandle, settings: &Settings) -> Result<PathBuf, CommandError> {
    // TUN: never honor custom overrides (elevated risk).
    // Non-TUN: custom paths allowed only after full trust checks.
    if settings.routing_mode != RoutingMode::Tun && !settings.engine_path.trim().is_empty() {
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
    if settings.routing_mode == RoutingMode::Tun {
        return Err("aether.exe not found next to app; reinstall or use portable package".into());
    }
    let repo_build =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../aether/target/release/aether.exe");
    let Some(path) = repo_build.exists().then_some(repo_build) else {
        return Err(
            "aether.exe not found. Build engine or choose it in Settings > Advanced.".into(),
        );
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
    if settings.routing_mode == RoutingMode::SystemProxy {
        #[cfg(windows)]
        {
            let recovery_path = proxy_recovery_path(app).ok();
            match windows_proxy::enable(
                settings.http_port,
                endpoint.as_deref(),
                recovery_path.as_deref(),
            ) {
                Ok((snapshot, applied)) => {
                    *state.proxy_snapshot.lock() = Some(snapshot);
                    *state.proxy_applied.lock() = Some(applied);
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
    let detail = match settings.routing_mode {
        RoutingMode::Tun => "TUN active (full system)",
        RoutingMode::SystemProxy => "System proxy active",
        RoutingMode::ProxyOnly => "Proxy only active",
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
        let mut lines = BufReader::new(reader).lines();
        loop {
            let line = match lines.next() {
                Some(Ok(line)) => line,
                // Clean EOF: the engine closed this pipe, which is the normal end
                // of a stream.
                None => break,
                // A read error is *not* EOF. `.map_while(Result::ok)` used to end
                // the loop here with no message and no state change, so the UI kept
                // reporting a live session off a dead pipe: every later readiness,
                // error and heartbeat event — including the teardown ones — went
                // unread while the engine carried on running.
                Some(Err(e)) => {
                    emit_log(&app, format!("ERROR engine output pipe failed ({e})"));
                    let state = app.state::<AppState>();
                    let mut rt = state.runtime.lock();
                    rt.detail = format!("{} · engine log stream lost", rt.detail);
                    let snapshot = rt.clone();
                    drop(rt);
                    let _ = app.emit("session://state", snapshot);
                    break;
                }
            };
            let state = app.state::<AppState>();
            // Hold operation only for generation check + dispatch, not forever.
            {
                let _operation = state.operation.lock();
                if state.generation.load(Ordering::SeqCst) != generation {
                    break;
                }
                handle_engine_line(&app, &line, &settings, &socks_seen, &tunnel_seen, &tun_seen);
            }
            emit_log(&app, line);
        }
    });
}

/// Tear the host back down, and report what could not be undone.
///
/// The `()` return meant a failed system-proxy restore was an `eprintln!` and
/// nothing more: the UI went to "disconnected / Ready" while the machine was still
/// configured to use a port with nothing listening on it. That state is invisible
/// to the user until the browser stops working.
fn cleanup_routing(app: &AppHandle, state: &AppState) -> Vec<String> {
    let mut problems = Vec::new();
    #[cfg(windows)]
    if state.proxy_enabled.swap(false, Ordering::SeqCst) {
        let mut snapshot = state.proxy_snapshot.lock();
        if let Some(saved) = snapshot.take() {
            if let Err(error) = windows_proxy::restore(saved.clone()) {
                *snapshot = Some(saved);
                state.proxy_enabled.store(true, Ordering::SeqCst);
                problems.push(format!(
                    "system proxy restore failed ({error}); Windows is still routing through the \
                     tunnel's port - reconnect once or run Aether with --repair-proxy"
                ));
            } else if let Ok(path) = proxy_recovery_path(app) {
                let _ = fs::remove_file(path);
            }
        }
    }
    #[cfg(windows)]
    state.proxy_applied.lock().take();
    state.connected_once.store(false, Ordering::SeqCst);
    // M8: drop the job object (closing its handle kills any surviving engine).
    #[cfg(windows)]
    {
        state.job.lock().take();
    }
    problems
}

/// How often to check that the system proxy still says what this session set it to.
/// A third party that reverts it does so silently, and the failure mode is traffic
/// leaving the machine while the UI reads Connected.
#[cfg(windows)]
const PROXY_COHERENCE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);

/// How long a session may sit in `connecting` before the shell stops it.
///
/// The engine can fail to connect without ever exiting or emitting an error — a
/// black-holed edge, a probe that never returns — and then nothing else in this
/// process notices: `watch_child` reacted only to process exit, and a UI timer is
/// not a substitute because WebView2 throttles timers in a hidden (tray) window,
/// which is the normal state for this app. The Android UI already had exactly this
/// watchdog at the same interval; the desktop one belongs in the shell so it runs
/// whatever the window is doing.
pub const CONNECT_WATCHDOG_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(90);

/// The engine pulses at most this often (see `session_event::HEARTBEAT_INTERVAL`).
pub const HEARTBEAT_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

/// Three missed pulses is a stall. Two would fire on ordinary scheduling noise.
pub const HEARTBEAT_MISS_LIMIT: u32 = 3;

/// The stall window, as a pure function of the last pulse so it can be reasoned
/// about without a running engine.
///
/// `since_session_start` is what makes the "no pulse ever arrived" case
/// expressible. It used to have no clock to be judged against and its only caller
/// invoked this inside `if let Some(beat)`, so the branch could never run: an
/// engine that produced no event at all — killed before startup, or whose stdout
/// is not reaching us — looked identical to one that had not needed a pulse yet.
pub fn heartbeat_stall_action(
    last_beat: Option<(&str, std::time::Duration)>,
    armed: bool,
    miss_limit: u32,
    interval: std::time::Duration,
    since_session_start: Option<std::time::Duration>,
) -> Option<String> {
    if !armed {
        return None;
    }
    let (phase, elapsed) = match last_beat {
        Some((phase, elapsed)) => (phase, elapsed),
        None => {
            return match since_session_start {
                Some(age) if age >= interval * miss_limit => {
                    Some("no progress event received".to_string())
                }
                _ => None,
            }
        }
    };
    if elapsed >= interval * miss_limit {
        Some(format!(
            "{phase} ({} s since the last pulse)",
            elapsed.as_secs()
        ))
    } else {
        None
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum WatchdogAction {
    LeaveAlone,
    TimedOut,
}

/// The whole decision, as a function of the four facts that matter, so the cases
/// the old one-shot `Instant` could not express are testable: a stamp belongs to a
/// session that has since been replaced, and a session that reached any terminal
/// state must not be killed for it.
pub fn connect_watchdog_action(
    stamp: Option<(u64, std::time::Duration)>,
    current_generation: u64,
    status: &str,
    timeout: std::time::Duration,
) -> WatchdogAction {
    let Some((generation, elapsed)) = stamp else {
        return WatchdogAction::LeaveAlone;
    };
    if generation != current_generation {
        return WatchdogAction::LeaveAlone;
    }
    if !status.eq_ignore_ascii_case("connecting") {
        return WatchdogAction::LeaveAlone;
    }
    if elapsed >= timeout {
        return WatchdogAction::TimedOut;
    }
    WatchdogAction::LeaveAlone
}

fn watch_child(app: AppHandle) {
    #[cfg(windows)]
    let mut last_coherence = std::time::Instant::now();
    std::thread::spawn(move || loop {
        std::thread::sleep(std::time::Duration::from_millis(500));
        let state = app.state::<AppState>();
        let _operation = state.operation.lock();
        #[cfg(windows)]
        if last_coherence.elapsed() >= PROXY_COHERENCE_INTERVAL {
            last_coherence = std::time::Instant::now();
            if state.proxy_enabled.load(Ordering::SeqCst) {
                if let Some(want) = state.proxy_applied.lock().clone() {
                    match windows_proxy::read_current().and_then(|current| {
                        windows_proxy::verify_readback_values(&want, &current)?;
                        Ok(current)
                    }) {
                        Ok(_) => {}
                        // Something else wrote over our values. Re-asserting is the
                        // only honest response: leaving it means the user thinks
                        // their traffic is tunneled while it is going out raw.
                        Err(drift) => {
                            eprintln!("[proxy] {drift}; re-asserting");
                            emit_log(
                                &app,
                                format!(
                                    "The Windows proxy was changed outside Aether ({drift});                                      re-asserting it"
                                ),
                            );
                            if let Err(error) = windows_proxy::reassert(&want) {
                                eprintln!("[proxy] re-assert failed: {error}");
                                emit_log(
                                    &app,
                                    format!(
                                        "Could not re-assert the Windows proxy: {error}. Traffic may                                          be leaving unproxied - disconnect and reconnect to reset it."
                                    ),
                                );
                            }
                        }
                    }
                }
            }
        }
        // Heartbeat stall: a session whose engine stopped pulsing is wedged inside
        // one phase. During a connect this is a diagnostic the 90 s timeout then
        // enforces; once *connected* it is the only liveness signal this process
        // has, because a running-but-stopped-responding engine satisfies every
        // "does the process exist" check in the file. Warn once per gap by clearing
        // the stamp, so the next pulse re-arms it.
        {
            let status = state.runtime.lock().status.clone();
            let armed = state.connecting.load(Ordering::SeqCst)
                || status.eq_ignore_ascii_case("connecting")
                || status.eq_ignore_ascii_case("connected");
            let beat = state.last_beat.lock().take();
            let session_age = (*state.connect_since.lock()).map(|(_, started)| started.elapsed());
            let stalled = heartbeat_stall_action(
                beat.as_ref()
                    .map(|(phase, at)| (phase.as_str(), at.elapsed())),
                armed,
                HEARTBEAT_MISS_LIMIT,
                HEARTBEAT_INTERVAL,
                session_age,
            );
            match stalled {
                // Teardown only on evidence: a session that has pulsed before and
                // went silent. A *connected* session that has never pulsed at all
                // gets the same log line but is not stopped from here, because
                // "this engine build does not pulse while connected" would otherwise
                // read as a wedge and kill working tunnels.
                Some(detail) if status.eq_ignore_ascii_case("connected") && beat.is_some() => {
                    emit_log(
                        &app,
                        format!(
                            "Engine stopped reporting on a connected session: {detail}. Stopping \
                             it rather than leaving Windows routed through a tunnel nobody is \
                             serving"
                        ),
                    );
                    state.generation.fetch_add(1, Ordering::SeqCst);
                    state.connecting.store(false, Ordering::SeqCst);
                    *state.connect_since.lock() = None;
                    if let Some(mut child) = state.child.lock().take() {
                        if let Some(mut stdin) = child.stdin.take() {
                            let _ = stdin.write_all(b"shutdown\n");
                            let _ = stdin.flush();
                        }
                        let _ = child.kill();
                        let _ = child.wait();
                    }
                    let endpoint = state.runtime.lock().endpoint.clone();
                    let problems = cleanup_routing(&app, &state);
                    for problem in &problems {
                        eprintln!("[aether] {problem}");
                    }
                    let detail = if problems.is_empty() {
                        format!("Tunnel stopped: the engine stopped reporting ({detail})")
                    } else {
                        format!(
                            "Tunnel stopped: the engine stopped reporting ({detail}) · {}",
                            problems.join(" · ")
                        )
                    };
                    emit_state(&app, &state, "error", &detail, None, endpoint);
                }
                Some(detail) => {
                    emit_log(
                        &app,
                        format!("Engine stopped reporting while connecting: {detail}"),
                    );
                }
                // Not stalled: put the pulse back for the next tick.
                None => {
                    if let Some((phase, at)) = beat {
                        *state.last_beat.lock() = Some((phase, at));
                    }
                }
            }
        }
        if let Some((generation, started)) = *state.connect_since.lock() {
            let status = state.runtime.lock().status.clone();
            let action = connect_watchdog_action(
                Some((generation, started.elapsed())),
                state.generation.load(Ordering::SeqCst),
                &status,
                CONNECT_WATCHDOG_TIMEOUT,
            );
            if action == WatchdogAction::TimedOut {
                // Take the stamp before doing anything else: this loop runs every
                // 500 ms and a teardown that outlives one tick must not re-fire.
                *state.connect_since.lock() = None;
                let detail = "Connection timed out after 90 s: the engine reported no ready route.";
                emit_log(
                    &app,
                    format!("{detail} Stopping it so the next connect can start."),
                );
                state.generation.fetch_add(1, Ordering::SeqCst);
                state.connecting.store(false, Ordering::SeqCst);
                if let Some(mut child) = state.child.lock().take() {
                    if let Some(mut stdin) = child.stdin.take() {
                        use std::io::Write;
                        let _ = stdin.write_all(b"shutdown\n");
                        let _ = stdin.flush();
                    }
                    let _ = child.kill();
                    let _ = child.wait();
                }
                let endpoint = state.runtime.lock().endpoint.clone();
                let problems = cleanup_routing(&app, &state);
                let detail = if problems.is_empty() {
                    detail.to_string()
                } else {
                    for problem in &problems {
                        eprintln!("[aether] {problem}");
                    }
                    format!("{detail} · {}", problems.join(" · "))
                };
                emit_state(&app, &state, "error", &detail, None, endpoint);
                continue;
            }
        }
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
                let problems = cleanup_routing(&app, &state);
                let already_error = state.runtime.lock().status.eq_ignore_ascii_case("error");
                if already_error {
                    // Structured error event already set UI; keep it.
                    for problem in &problems {
                        eprintln!("[aether] {problem}");
                    }
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
                // What the teardown could not undo belongs in the status line, not
                // only in a log nobody opens.
                let detail = if problems.is_empty() {
                    detail
                } else {
                    for problem in &problems {
                        eprintln!("[aether] {problem}");
                    }
                    format!("{detail} · {}", problems.join(" · "))
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
                for problem in cleanup_routing(&app, &state) {
                    eprintln!("[aether] {problem}");
                }
                let already_error = state.runtime.lock().status.eq_ignore_ascii_case("error");
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

/// Run a command body that blocks on the filesystem, a child process or the
/// network on Tauri's blocking pool.
///
/// A non-`async` `#[tauri::command]` is resolved on the main (UI) thread, so the
/// icacls runs, DPAPI calls, multi-megabyte SHA-256s and the 15-second child
/// waits below froze the window mid-drag and made WebView2 miss its paint
/// callbacks. Only the boundary changes: the bodies stay synchronous, because
/// they park on locks and pipes rather than awaiting anything.
async fn command_blocking<T: Send + 'static>(
    name: &'static str,
    task: impl FnOnce() -> Result<T, CommandError> + Send + 'static,
) -> Result<T, CommandError> {
    tauri::async_runtime::spawn_blocking(task)
        .await
        .map_err(|e| CommandError::new("internal", format!("{name} task did not run: {e}")))
}

#[tauri::command]
fn get_settings(app: AppHandle) -> Result<Settings, CommandError> {
    // `Err` rather than `Settings::default()` on a damaged file: the frontend
    // autosaves whatever it was handed, so the silent default *was* the data
    // loss. A rejected promise is what lets the persist effect gate itself.
    load_settings_file(&app)
}

#[tauri::command]
async fn save_settings(app: AppHandle, settings: Settings) -> Result<(), CommandError> {
    command_blocking("save_settings", move || {
        save_settings_blocking(app, settings)
    })
    .await
}

/// `save_settings`'s body: it runs `icacls` on the config directory and writes the
/// registry Run key, both of which are child-process waits.
fn save_settings_blocking(app: AppHandle, settings: Settings) -> Result<(), CommandError> {
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
async fn connect(app: AppHandle, settings: Settings) -> Result<(), CommandError> {
    command_blocking("connect", move || connect_blocking(app, settings)).await
}

/// `connect`'s body: icacls, DPAPI, a multi-megabyte SHA-256, a signed-binary
/// PowerShell query and the engine spawn. Always runs off the UI thread — via
/// [`command_blocking`] for the IPC path, and on a dedicated thread for the tray
/// menu item.
fn connect_blocking(app: AppHandle, settings: Settings) -> Result<(), CommandError> {
    let state = app.state::<AppState>();
    let _operation = state.operation.lock();
    if state.tearing_down.load(Ordering::SeqCst) {
        // M7 (see `disconnect`): a connect that lands inside another session's
        // teardown window ends up having its system-proxy state torn down by that
        // teardown, and its UI status overwritten with "disconnected".
        return Err("Aether is still finishing the previous disconnect; try again".into());
    }
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

        if settings.routing_mode == RoutingMode::Tun {
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
        if settings.routing_mode == RoutingMode::Tun {
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
            .env("AETHER_PROTOCOL", settings.protocol.as_str())
            .env("AETHER_SCAN", settings.scan_mode.as_str())
            .env("AETHER_IP", settings.ip_version.as_str())
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
                if settings.transport == TransportKind::H2 {
                    "1"
                } else {
                    "0"
                },
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
                if settings.routing_mode == RoutingMode::Tun {
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

        // M8: the engine is meant to run inside a kill-on-close job so it can
        // never outlive us. Build the job *before* the spawn and refuse to launch
        // without it: `eprintln!` is not a user-visible failure in a
        // `windows_subsystem = "windows"` binary, and an engine that does outlive
        // the shell keeps ports 1819/1820 bound and the system-proxy registry
        // pointed at a tunnel nobody can close — the state every later launch
        // fails against.
        #[cfg(windows)]
        let job = engine_job::Job::create().map_err(|error| {
            CommandError::new(
                "job_unavailable",
                format!(
                    "Cannot start the engine: the kill-on-close job object could not be created \
                     ({error}); refusing to launch a process that could survive this window with \
                     the tunnel's ports and the Windows proxy still set"
                ),
            )
        })?;

        let mut child = command.spawn().map_err(|e| {
            dpapi_key.zeroize();
            format!("Could not start aether.exe: {e}")
        })?;
        #[cfg(windows)]
        if let Err(error) = job.assign_child(&child) {
            let _ = child.kill();
            let _ = child.wait();
            dpapi_key.zeroize();
            return Err(CommandError::new(
                "job_unavailable",
                format!(
                    "Cannot start the engine: the spawned process could not be placed in the \
                     kill-on-close job object ({error}); it has been terminated"
                ),
            ));
        }
        #[cfg(windows)]
        {
            *state.job.lock() = Some(job);
        }
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
        let generation = state.generation.fetch_add(1, Ordering::SeqCst) + 1;
        let socks_seen = Arc::new(AtomicBool::new(false));
        let tunnel_seen = Arc::new(AtomicBool::new(false));
        let tun_seen = Arc::new(AtomicBool::new(false));
        state.connected_once.store(false, Ordering::SeqCst);
        // A new session has measured nothing yet. Carrying the last run's
        // numbers over would be a fabricated stat wearing a real label.
        *state.handshake_rtt_ms.lock() = None;
        *state.last_beat.lock() = None;

        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        *state.child.lock() = Some(child);
        emit_state(
            &app,
            &state,
            "connecting",
            if settings.routing_mode == RoutingMode::Tun {
                "Starting tunnel + full-system routing"
            } else {
                "Scanning reachable routes"
            },
            Some(pid),
            None,
        );
        *state.connect_since.lock() = Some((generation, std::time::Instant::now()));
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
            // `app.clone()`, not `app`: `state` above borrows `app`, and the
            // `connecting` reset after this block still needs it.
            stream_output(
                app.clone(),
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
async fn disconnect(app: AppHandle) -> Result<(), CommandError> {
    command_blocking("disconnect", move || disconnect_blocking(app)).await
}

fn disconnect_blocking(app: AppHandle) -> Result<(), CommandError> {
    let state = app.state::<AppState>();
    let outcome = (|| -> Result<(), CommandError> {
        // Take the child and retire the generation under `operation`, then
        // RELEASE it before waiting. M7 asked for the lock to span the whole
        // teardown and it did — that was the bug: the output pumps acquire
        // `operation` for every single line (`stream_output`), so holding it
        // across the 15 s grace window meant nobody drained the pipes. A chatty
        // engine filled its stdout buffer, blocked writing, never reached its own
        // route-teardown path, and was force-killed at the end of the window —
        // exactly the outcome that leaves journaled routes installed and the
        // Windows proxy pointing at a dead port. The `tearing_down` gate is what
        // keeps a concurrent connect out of this window, not the lock.
        let mut child = {
            let _operation = state.operation.lock();
            state.generation.fetch_add(1, Ordering::SeqCst);
            state.connecting.store(false, Ordering::SeqCst);
            state.tearing_down.store(true, Ordering::SeqCst);
            state.child.lock().take()
        };
        let mut problems: Vec<String> = Vec::new();
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
                        eprintln!("[aether] engine outlived the 15s teardown grace; forcing exit");
                        problems.push(
                            "the engine had to be killed after the 15 s teardown grace; the routes it \
                             journaled may still be installed"
                                .to_string(),
                        );
                        let _ = child.kill();
                        let _ = child.wait();
                        break;
                    }
                }
            }
        }
        // `child` is dropped here, closing its handles; the job object is dropped
        // by `cleanup_routing`, which is what kills anything still inside it.
        problems.extend(cleanup_routing(&app, &state));

        if problems.is_empty() {
            emit_state(&app, &state, "disconnected", "Ready", None, None);
            return Ok(());
        }
        // Partial failure is reported as partial failure. The tunnel *is* down, so the
        // status says so, but "Ready" would claim the host was put back together when
        // the teardown path knows it was not.
        let detail = problems.join(" · ");
        eprintln!("[aether] disconnect incomplete: {detail}");
        emit_state(&app, &state, "disconnected", &detail, None, None);
        Err(CommandError::new("disconnect_incomplete", detail))
    })();
    {
        // Under `operation`, so a connect either sees the gate and refuses, or
        // starts after every byte of host state has been put back.
        let _operation = state.operation.lock();
        state.tearing_down.store(false, Ordering::SeqCst);
    }
    outcome
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

/// Sweep routes a previous crash left behind, at GUI startup rather than only
/// when someone opens TUN mode. Abandoned-route recovery used to be reachable
/// exclusively from the TUN bring-up path, so a session that died in proxy mode
/// left the machine pointed at a tunnel that no longer existed until the user
/// happened to enable TUN again. The engine owns the journal and the deletion
/// rules; the shell only launches it — verified, with the inherited environment
/// scrubbed — and does not wait for it.
#[cfg(windows)]
fn spawn_route_repair(app: &AppHandle) {
    let settings = load_settings_or_defaults(app);
    let Ok(executable) = engine_path(app, &settings) else {
        return; // No resolvable engine yet; connect will report the real reason.
    };
    if verify_engine_or_refuse(&executable).is_err() {
        return;
    }
    let mut command = Command::new(&executable);
    scrub_ambient_engine_env(&mut command);
    command
        .arg("--repair-routes")
        .current_dir(executable.parent().unwrap_or(Path::new(".")))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if let Err(e) = command.spawn() {
        emit_log(app, format!("Could not start the route repair: {e}"));
    }
}

/// Export what the engine actually resolved, for a bug report that can be
/// checked. Read-only: it runs `aether --diagnostics`, which never opens a
/// tunnel and never needs the config key, so no preamble and no key line go to
/// the child. The binary is still verified first — a diagnostics run executes
/// code just like a session does.
/// How long `aether --diagnostics` may take before the shell gives up on it.
/// The child writes a small JSON document and exits; anything past this is a
/// hang, and `Command::output()` (what this replaced) waits forever on one.
const DIAGNOSTICS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

#[tauri::command]
async fn diagnostics(app: AppHandle) -> Result<serde_json::Value, CommandError> {
    command_blocking("diagnostics", move || diagnostics_blocking(app)).await
}

fn diagnostics_blocking(app: AppHandle) -> Result<serde_json::Value, CommandError> {
    let state = app.state::<AppState>();
    if state.child.lock().is_some() || state.scan_child.lock().is_some() {
        return Err(CommandError::new(
            "busy",
            "Stop the running session or scan before exporting diagnostics.",
        ));
    }
    let settings = load_settings_or_defaults(&app);
    let executable = engine_path(&app, &settings)?;
    verify_engine_or_refuse(&executable)?;

    let mut command = Command::new(&executable);
    scrub_ambient_engine_env(&mut command);
    command
        .arg("--diagnostics")
        .current_dir(executable.parent().unwrap_or(Path::new(".")))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|e| CommandError::new("spawn_failed", format!("Could not run the engine: {e}")))?;
    // Read both pipes on their own threads so a child that fills one of them
    // cannot deadlock against the wait below, and give the wait a deadline: an
    // engine that wedges inside `--diagnostics` used to hold this command — and,
    // because it was synchronous, the UI thread — open indefinitely.
    let stdout_handle = child.stdout.take();
    let stderr_handle = child.stderr.take();
    let stdout_thread = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        if let Some(mut handle) = stdout_handle {
            let _ = std::io::Read::read_to_end(&mut handle, &mut bytes);
        }
        bytes
    });
    let stderr_thread = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        if let Some(mut handle) = stderr_handle {
            let _ = std::io::Read::read_to_end(&mut handle, &mut bytes);
        }
        bytes
    });
    let deadline = std::time::Instant::now() + DIAGNOSTICS_TIMEOUT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            other => {
                let _ = child.kill();
                let _ = child.wait();
                let detail = match other {
                    Err(e) => format!("its exit status could not be read ({e})"),
                    _ => format!("it did not exit within {} s", DIAGNOSTICS_TIMEOUT.as_secs()),
                };
                return Err(CommandError::new(
                    "timeout",
                    format!("Diagnostics were terminated: {detail}; the engine process was killed"),
                ));
            }
        }
    };
    // The process is gone, so both write ends are closed and these joins cannot
    // block on a live child.
    let stdout = stdout_thread.join().unwrap_or_default();
    let stderr = stderr_thread.join().unwrap_or_default();
    if !status.success() {
        let err = String::from_utf8_lossy(&stderr);
        return Err(CommandError::new(
            "engine_failed",
            format!(
                "Diagnostics exited {status} — {}",
                err.lines().last().unwrap_or("").trim()
            ),
        ));
    }
    let text = String::from_utf8_lossy(&stdout);
    let value: serde_json::Value = serde_json::from_str(text.trim()).map_err(|e| {
        CommandError::new(
            "bad_output",
            format!("Engine diagnostics were not JSON: {e}"),
        )
    })?;
    Ok(value)
}

#[tauri::command]
async fn test_connection(settings: Settings) -> Result<String, CommandError> {
    command_blocking("test_connection", move || {
        test_connection_blocking(settings)
    })
    .await
}

/// The probe itself. `ureq`'s agent is synchronous and its timeout is 12 s, so
/// this has to run off the UI thread.
fn test_connection_blocking(settings: Settings) -> Result<String, CommandError> {
    validate_settings(&settings)?;
    let url = "https://www.cloudflare.com/cdn-cgi/trace";

    let (client, via_desc) = if settings.routing_mode == RoutingMode::Tun {
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
// Tauri derives the JS-callable signature from these parameters, so grouping the
// scan inputs into one struct would change the wire contract the frontend calls
// with. The count is the cost of that; the values are validated in `scan_blocking`.
fn scan(
    app: AppHandle,
    run_id: String,
    protocol: String,
    ip_version: IpVersion,
    concurrency: u32,
    timeout_ms: u32,
    noize: Option<String>,
) -> Result<(), CommandError> {
    command_blocking("scan", move || {
        scan_blocking(
            app,
            run_id,
            protocol,
            ip_version,
            concurrency,
            timeout_ms,
            noize,
        )
    })
    .await
}

/// `scan`'s body: it takes the operation lock, stops the running scan (up to the
/// cancel grace window), runs `icacls`, unwraps the DPAPI key and hashes the
/// engine, so it cannot run on the UI thread.
#[allow(clippy::too_many_arguments)] // seven, all of them the frontend's own call shape
fn scan_blocking(
    app: AppHandle,
    run_id: String,
    protocol: String,
    ip_version: IpVersion,
    concurrency: u32,
    timeout_ms: u32,
    noize: Option<String>,
) -> Result<(), CommandError> {
    let state = app.state::<AppState>();
    // Before the lock and before the running scan is stopped: a parameter this
    // command refuses must not be able to take down the scan already in flight.
    let noize = validated_noize(noize.as_deref())?;
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

    let settings = load_settings_file(&app)?;
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
        // T161: the profile the user picked, not a hardcoded one. This used to
        // read `"balanced"` whatever the Settings row said, so "Probe Velocity
        // Profile" changed the banner (the engine echoes its own mode back in
        // `scan_start`) and nothing else — the scan ran at the same rate either
        // way. Same channel as every other setting here: the child's environment,
        // which `engine_config::from_env` reads through `runtime_env`.
        .env("AETHER_SCAN", settings.scan_mode.as_str())
        .env("AETHER_SCAN_EXHAUSTIVE", "1")
        .env("AETHER_IP", ip_version.as_str())
        .env("AETHER_NOIZE", noize)
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

    let mut child = command.spawn().map_err(|e| {
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
    let scan_pid = child.id();
    *state.scan_child.lock() = Some(child);

    // Stream scan output on a SEPARATE thread per pipe. The engine writes
    // AETHER_EVENT progress to stdout and diagnostics to stderr; reading them
    // sequentially (stdout to EOF, then stderr) made a live scan show nothing until
    // Stop killed the process and stdout finally closed. One thread per stream
    // keeps both live.
    let terminal_sent = Arc::new(AtomicBool::new(false));
    let hits = Arc::new(AtomicU64::new(0));
    let mut handles = Vec::new();
    if let Some(o) = stdout {
        handles.push(pump_scan_stream(
            app.clone(),
            run_id.clone(),
            Box::new(o),
            terminal_sent.clone(),
            hits.clone(),
        ));
    }
    if let Some(e) = stderr {
        handles.push(pump_scan_stream(
            app.clone(),
            run_id.clone(),
            Box::new(e),
            terminal_sent.clone(),
            hits.clone(),
        ));
    }
    let app_done = app.clone();
    std::thread::spawn(move || {
        for h in handles {
            let _ = h.join();
        }
        // Reap the process. Both pipes closed, so the scan is over; until now the
        // only things that ever cleared `scan_child` were `stop_scan` and the next
        // `connect`, so a scan that finished on its own left the slot occupied for
        // the rest of the program's life and `diagnostics` answered "Stop the
        // running session or scan first" forever.
        //
        // `try_wait` only, and only for *this* run's pid: a scan that is still
        // shutting down must not block this thread, and a newer scan must never be
        // cleared by an older run's pump.
        {
            let state = app_done.state::<AppState>();
            let mut slot = state.scan_child.lock();
            if let Some(child) = slot.as_mut() {
                if child.id() == scan_pid {
                    match child.try_wait() {
                        Ok(Some(_)) | Err(_) => *slot = None,
                        // Still running: leave it for `stop_scan`.
                        Ok(None) => {}
                    }
                }
            }
        }
        // Terminal scan_done only if the engine didn't already send one, so a crash
        // still unsticks the UI but a normal finish doesn't double-log.
        if let Some(event) = scan_terminal_event(
            terminal_sent.load(Ordering::SeqCst),
            hits.load(Ordering::SeqCst),
        ) {
            emit_scan_event(&app_done, &run_id, event);
        }
    });

    Ok(())
}

/// The synthetic terminal event for a scan whose process ended without saying so.
///
/// This used to be a `scan_done` with empty `addr`/`rtt`, which the UI read as
/// "finished, nothing found": a scan that had already surfaced a dozen working
/// endpoints was reported as having found none, and on the desktop a `scan_done`
/// also ends the run — so the one message that could not be trusted was the one
/// that decided the outcome. `None` means the engine already reported its own
/// terminal event and nothing should be invented here.
pub fn scan_terminal_event(terminal_sent: bool, hits: u64) -> Option<serde_json::Value> {
    if terminal_sent {
        return None;
    }
    let message = if hits == 0 {
        "the scan process ended without reporting a result, and no working endpoint had been found"
            .to_string()
    } else {
        format!(
            "the scan process ended without reporting a result; {hits} working endpoint(s) were \
             already found and are kept"
        )
    };
    Some(serde_json::json!({ "type": "scan_failed", "message": message }))
}

/// Read one scan output pipe on its own thread, forwarding AETHER_EVENT lines as
/// `scan://event` and every line to the activity log. Returns a join handle so the
/// caller can emit the terminal event only after all pipes drain.
/// Every scan event is stamped with the run that produced it. A stop/start
/// pair can leave the previous run's terminal event in flight, and without an
/// id the UI has no way to tell a stale "found nothing" from a live scan's
/// progress — the one message that decides the outcome.
fn emit_scan_event(app: &AppHandle, run_id: &str, event: serde_json::Value) {
    let mut event = event;
    if let Some(obj) = event.as_object_mut() {
        obj.insert(
            "runId".to_string(),
            serde_json::Value::String(run_id.to_string()),
        );
    }
    let _ = app.emit("scan://event", event);
}

fn pump_scan_stream(
    app: AppHandle,
    run_id: String,
    reader: Box<dyn std::io::Read + Send>,
    terminal_sent: Arc<AtomicBool>,
    hits: Arc<AtomicU64>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        for line in BufReader::new(reader).lines().map_while(Result::ok) {
            if let Some(json) = line.split("AETHER_EVENT ").nth(1) {
                match serde_json::from_str::<EngineEvent>(json.trim()) {
                    Err(e) => note_malformed_event(&app, format!("{e}: {}", json.trim())),
                    Ok(v) => {
                        match v {
                            EngineEvent::ScanStart {
                                mode,
                                total,
                                concurrency,
                            } => {
                                emit_scan_event(
                                    &app,
                                    &run_id,
                                    serde_json::json!({
                                        "type": "scan_start",
                                        "mode": mode,
                                        "total": total,
                                        "concurrency": concurrency,
                                    }),
                                );
                            }
                            EngineEvent::ScanProgress {
                                scanned,
                                total,
                                working,
                            } => {
                                emit_scan_event(
                                    &app,
                                    &run_id,
                                    serde_json::json!({
                                        "type": "scan_progress",
                                        "scanned": scanned,
                                        "total": total,
                                        "working": working,
                                    }),
                                );
                            }
                            EngineEvent::ScanHit {
                                addr,
                                rtt,
                                rtt_ms,
                                protocol,
                            } => {
                                hits.fetch_add(1, Ordering::SeqCst);
                                emit_scan_event(
                                    &app,
                                    &run_id,
                                    serde_json::json!({
                                        "type": "scan_hit",
                                        "addr": addr,
                                        "rtt": rtt,
                                        "rttMs": rtt_ms,
                                        "protocol": protocol,
                                    }),
                                );
                            }
                            EngineEvent::ScanDone {
                                addr,
                                rtt,
                                protocol,
                                best_rtt_ms,
                            } => {
                                terminal_sent.store(true, Ordering::SeqCst);
                                // Re-keyed rather than forwarded raw like the other arms used to be
                                // done to them: the engine's `best_rtt_ms` is snake_case while every
                                // other field on this channel is camelCase, and an empty `rtt` used
                                // to reach the UI as `best: 1.1.1.1:443 ()` — a pair of brackets
                                // around nothing, which reads as a measurement of zero. Absent stays
                                // absent (`null`), never a fabricated 0.
                                emit_scan_event(
                                    &app,
                                    &run_id,
                                    serde_json::json!({
                                        "type": "scan_done",
                                        "addr": addr,
                                        "rtt": rtt,
                                        "protocol": protocol,
                                        "bestRttMs": best_rtt_ms,
                                    }),
                                );
                            }
                            // Session-level events on a scan child are not this
                            // stream's business; the scan process does not emit them.
                            EngineEvent::IdentityReady { .. }
                            | EngineEvent::EndpointSelected { .. }
                            | EngineEvent::ProxyReady { .. }
                            | EngineEvent::TunnelReady { .. }
                            | EngineEvent::TunReady
                            | EngineEvent::Connected { .. }
                            | EngineEvent::Error { .. }
                            | EngineEvent::Heartbeat { .. } => {}
                        }
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
async fn stop_scan(app: AppHandle) -> Result<(), CommandError> {
    command_blocking("stop_scan", move || stop_scan_blocking(app)).await
}

/// `stop_scan`'s body. `stop_scan_child` busy-waits up to the full cancel grace
/// window, so this must not run on the UI thread.
fn stop_scan_blocking(app: AppHandle) -> Result<(), CommandError> {
    let state = app.state::<AppState>();
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
            // `--minimized`: the setting's own name promises a start that stays in
            // the tray, and `setup` only ever consulted settings.json — which the
            // shell being started *by* this key also has, but a launch-at-logon
            // with no window is what "Launch at login" has always meant here.
            let cmd = format!("\"{}\" --minimized", exe.display());
            key.set_value(VALUE, &cmd).map_err(CommandError::from)
        } else {
            // A failed delete used to be discarded and `Ok` returned, so the
            // "Launch at login" toggle could display *off* while HKCU\Run still
            // started the app at every logon. An absent value is the state that was
            // asked for; anything else is a write that did not happen.
            match key.delete_value(VALUE) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(CommandError::new(
                    "autostart",
                    format!("could not remove the `{VALUE}` Run entry: {e}"),
                )),
            }
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

    #[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
    pub struct ProxySnapshot {
        pub enabled: u32,
        pub server: Option<String>,
        pub bypass: Option<String>,
        /// The PAC URL, which WinINet honours *ahead* of `ProxyServer`. It was not
        /// part of the snapshot at all, so enabling Aether on a machine with a
        /// corporate PAC left the PAC in charge — traffic went direct while the UI
        /// reported the proxy as active — and disconnecting deleted a `ProxyServer`
        /// that had been ours for the whole session.
        ///
        /// `#[serde(default)]`: a recovery file written by an older build has no
        /// such field, and a missing optional field must not fatal the read that is
        /// trying to undo the proxy.
        #[serde(default)]
        pub auto_config_url: Option<String>,
    }

    /// `ProxyEnable` absent is a real state ("this profile never enabled a proxy"),
    /// so it maps to 0. Any *other* read failure must propagate: `unwrap_or(0)`
    /// turned a transient registry error into "the user's proxy was off", which the
    /// restore path then honoured by switching a live proxy off permanently.
    fn read_enable(key: &RegKey) -> Result<u32, CommandError> {
        match key.get_value::<u32, _>("ProxyEnable") {
            Ok(v) => Ok(v),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(0),
            Err(e) => Err(format!("read ProxyEnable: {e}").into()),
        }
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

    /// The four registry values that say "Aether owns the proxy right now".
    ///
    /// One definition, used by the writer, by the 30 s coherence check and by any
    /// later re-assert. Having the expectation computed in two places is how a
    /// checker ends up validating a string the writer never wrote.
    pub fn applied_expectation(port: u16, endpoint: Option<&str>) -> ProxySnapshot {
        let mut bypass = String::from("localhost;127.*;<local>");
        if let Some(ep) = endpoint {
            if let Some(host) = super::sanitize_proxy_bypass_host(ep) {
                bypass.push(';');
                bypass.push_str(&host);
            }
        }
        ProxySnapshot {
            enabled: 1,
            server: Some(format!("http=127.0.0.1:{port};https=127.0.0.1:{port}")),
            bypass: Some(bypass),
            // We deleted it on purpose; it must stay deleted while we own the proxy.
            auto_config_url: None,
        }
    }

    /// Read the proxy state as it is right now. Every read is hard-fail: a snapshot
    /// that silently lost a value is a snapshot that will delete that value on
    /// restore.
    fn read_snapshot(key: &RegKey) -> Result<ProxySnapshot, CommandError> {
        Ok(ProxySnapshot {
            enabled: read_enable(key)?,
            server: read_optional_reg_value(key.get_value("ProxyServer"), "ProxyServer")?,
            bypass: read_optional_reg_value(key.get_value("ProxyOverride"), "ProxyOverride")?,
            auto_config_url: read_optional_reg_value(
                key.get_value("AutoConfigURL"),
                "AutoConfigURL",
            )?,
        })
    }

    /// What the registry says now, for the coherence check and for reports.
    pub fn read_current() -> Result<ProxySnapshot, CommandError> {
        read_snapshot(&key()?)
    }

    /// Write `want` over the current values and confirm it stuck. Used when a third
    /// party (another VPN client, a login script, GPO) has changed the proxy out
    /// from under a session that still claims to own it.
    pub fn reassert(want: &ProxySnapshot) -> Result<(), CommandError> {
        let key = key()?;
        let server = want.server.clone().unwrap_or_default();
        let bypass = want.bypass.clone().unwrap_or_default();
        key.set_value("ProxyServer", &server)
            .map_err(CommandError::from)?;
        key.set_value("ProxyOverride", &bypass)
            .map_err(CommandError::from)?;
        match want.auto_config_url.as_ref() {
            Some(v) => key
                .set_value("AutoConfigURL", v)
                .map_err(CommandError::from)?,
            None => match key.delete_value("AutoConfigURL") {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(format!("delete AutoConfigURL: {e}").into()),
            },
        }
        key.set_value("ProxyEnable", &want.enabled)
            .map_err(CommandError::from)?;
        let actual = read_snapshot(&key)?;
        verify_readback_values(want, &actual)?;
        refresh();
        Ok(())
    }

    pub fn enable(
        port: u16,
        endpoint: Option<&str>,
        recovery_path: Option<&Path>,
    ) -> Result<(ProxySnapshot, ProxySnapshot), (String, Option<ProxySnapshot>)> {
        let key = key().map_err(|e| (e.to_string(), None))?;
        let snapshot = read_snapshot(&key).map_err(|e| (e.message, None))?;
        // Registry mirror first: from this moment on, a deleted recovery file is
        // an inconvenience rather than an unrecoverable loss.
        write_mirror(&snapshot);
        if let Some(path) = recovery_path {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| (format!("proxy recovery directory: {e}"), None))?;
            }
            let json = serde_json::to_vec_pretty(&snapshot)
                .map_err(|e| (format!("proxy recovery encode: {e}"), None))?;
            // Exclusively-created temp + fsync before the rename: this file is the
            // only record of what the proxy was before Aether touched it, and a
            // fixed `proxy-recovery.json.tmp` name let a second writer (or a
            // reconnect while the first session was still bringing the proxy up)
            // interleave into it.
            crate::write_atomic(path, &json)
                .map_err(|e| (format!("proxy recovery write/commit: {e}"), None))?;
        }
        let applied = applied_expectation(port, endpoint);
        let result = (|| -> Result<(), CommandError> {
            let server = applied.server.clone().unwrap_or_default();
            let bypass = applied.bypass.clone().unwrap_or_default();
            key.set_value("ProxyServer", &server)
                .map_err(CommandError::from)?;
            key.set_value("ProxyOverride", &bypass)
                .map_err(CommandError::from)?;
            // Take the PAC out of the way while our proxy is active, but only
            // because it has been snapshotted: `restore` puts it back.
            match key.delete_value("AutoConfigURL") {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(format!("delete AutoConfigURL: {e}").into()),
            }
            key.set_value("ProxyEnable", &1u32)
                .map_err(CommandError::from)?;
            Ok(())
        })();
        if let Err(error) = result {
            clear_mirror();
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
        // The caller keeps the *applied* values so it can tell, later, whether
        // something else changed the proxy underneath it.
        Ok((snapshot, applied))
    }

    /// Compare what the registry says now against what was intended, in full.
    ///
    /// Takes two snapshots rather than three loose parameters so that adding a
    /// field to `ProxySnapshot` cannot leave the comparison checking one value
    /// fewer than the writer wrote — which is how `AutoConfigURL` came to be
    /// restored, cleared and verified by nobody at the same time.
    pub fn verify_readback_values(
        expected: &ProxySnapshot,
        actual: &ProxySnapshot,
    ) -> Result<(), CommandError> {
        if actual.enabled != expected.enabled {
            return Err(format!(
                "ProxyEnable read-back mismatch: expected {}, got {}",
                expected.enabled, actual.enabled
            )
            .into());
        }
        for (name, want, got) in [
            ("ProxyServer", &expected.server, &actual.server),
            ("ProxyOverride", &expected.bypass, &actual.bypass),
            (
                "AutoConfigURL",
                &expected.auto_config_url,
                &actual.auto_config_url,
            ),
        ] {
            if want != got {
                return Err(format!(
                    "{name} read-back mismatch: expected {:?}, got {:?}",
                    want.as_deref(),
                    got.as_deref()
                )
                .into());
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
        match snapshot.auto_config_url.as_ref() {
            Some(value) => key
                .set_value("AutoConfigURL", value)
                .map_err(CommandError::from)?,
            None => match key.delete_value("AutoConfigURL") {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(format!("delete AutoConfigURL: {e}").into()),
            },
        }
        key.set_value("ProxyEnable", &snapshot.enabled)
            .map_err(CommandError::from)?;

        // Read every value back before deciding the restore worked.
        let actual = ProxySnapshot {
            enabled: read_enable(&key)?,
            server: read_optional_reg_value(key.get_value("ProxyServer"), "ProxyServer")?,
            bypass: read_optional_reg_value(key.get_value("ProxyOverride"), "ProxyOverride")?,
            auto_config_url: read_optional_reg_value(
                key.get_value("AutoConfigURL"),
                "AutoConfigURL",
            )?,
        };

        verify_readback_values(&snapshot, &actual)?;
        // Only now: the mirror is what a later start restores *from*, and clearing
        // it before the values are back would lose the only remaining record.
        clear_mirror();

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

    /// What this session's proxy journal looks like in `HKCU`, next to the
    /// recovery *file*.
    ///
    /// The file is the primary record and the registry is the copy, because an
    /// antivirus real-time scan is known to quarantine a JSON file a process just
    /// wrote while leaving the process running. When that happens the *only* sign
    /// that Windows is still pointed at a port is the setting itself, and the next
    /// launch finds nothing to recover from: the user's browser keeps failing with
    /// no Aether running and no record of why.
    #[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
    pub struct JournalMirror {
        pub creator_pid: u32,
        pub written_unix: u64,
        pub snapshot: ProxySnapshot,
    }

    const JOURNAL_SUBKEY: &str = "Software\\AetherNext";
    const JOURNAL_VALUE: &str = "ProxyJournal";

    fn write_mirror(snapshot: &ProxySnapshot) {
        let mirror = JournalMirror {
            creator_pid: std::process::id(),
            written_unix: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            snapshot: snapshot.clone(),
        };
        let json = match serde_json::to_string(&mirror) {
            Ok(j) => j,
            Err(e) => {
                eprintln!("[proxy] cannot encode the registry journal mirror: {e}");
                return;
            }
        };
        match RegKey::predef(HKEY_CURRENT_USER)
            .create_subkey(JOURNAL_SUBKEY)
            .map(|(k, _)| k)
        {
            Ok(key) => {
                if let Err(e) = key.set_value::<String, _>(JOURNAL_VALUE, &json) {
                    eprintln!("[proxy] cannot write the registry journal mirror: {e}");
                }
            }
            Err(e) => eprintln!("[proxy] cannot open {JOURNAL_SUBKEY} for the journal mirror: {e}"),
        }
    }

    fn read_mirror() -> Option<JournalMirror> {
        let key = RegKey::predef(HKEY_CURRENT_USER)
            .open_subkey(JOURNAL_SUBKEY)
            .ok()?;
        let raw: String = key.get_value(JOURNAL_VALUE).ok()?;
        match serde_json::from_str(&raw) {
            Ok(m) => Some(m),
            Err(e) => {
                // Unparseable is not "restore with defaults": a mirror nobody can
                // read says nothing about what the previous session changed.
                eprintln!("[proxy] registry journal mirror is unreadable ({e}); clearing it");
                clear_mirror();
                None
            }
        }
    }

    fn clear_mirror() {
        if let Ok(key) = RegKey::predef(HKEY_CURRENT_USER).open_subkey(JOURNAL_SUBKEY) {
            let _ = key.delete_value(JOURNAL_VALUE);
        }
    }

    /// Whether a leftover mirror justifies restoring the proxy on this start.
    ///
    /// Kept free of I/O so the decision — and the case it exists for, "the file is
    /// gone, the session that made the change is dead" — is testable on any machine.
    pub fn decide_sweep(
        mirror: Option<&JournalMirror>,
        recovery_file_present: bool,
        holder_alive: bool,
    ) -> Sweep {
        if mirror.is_none() {
            // No mirror at all: the recovery file, if any, was already consumed by
            // the caller, and a proxy change with no record anywhere is a different
            // bug than the one this sweep exists for.
            return Sweep::Nothing;
        }
        if recovery_file_present {
            return Sweep::Nothing;
        }
        if holder_alive {
            // Another session owns the proxy right now. Restoring would take the
            // machine off a tunnel that is demonstrably up.
            return Sweep::Nothing;
        }
        Sweep::RestoreFromMirror
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Sweep {
        Nothing,
        /// The recovery file is gone, the mirror says a session changed the proxy,
        /// and the process that did it is no longer alive.
        RestoreFromMirror,
    }

    /// Is the pid recorded in the mirror still running? Only ever used to decide
    /// whether to *leave the proxy alone*, so an unknown answer means "alive".
    fn holder_alive(pid: u32) -> bool {
        if pid == 0 || pid == std::process::id() {
            return true;
        }
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::Threading::{
            GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
        };
        // ` STILL_ACTIVE` is the exit code a running process reports; windows-sys
        // does not export the constant, and a magic 259 with no name is unreadable.
        const STILL_ACTIVE: u32 = 259;
        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if handle.is_null() {
                // Access denied means the process exists and is someone else's.
                return std::io::Error::last_os_error().raw_os_error() == Some(5);
            }
            let mut code = 0u32;
            let ok = GetExitCodeProcess(handle, &mut code);
            CloseHandle(handle);
            ok != 0 && code == STILL_ACTIVE
        }
    }

    /// Startup orphan sweep: restore from the mirror when the file was lost.
    pub fn sweep_orphan() -> Option<ProxySnapshot> {
        let mirror = read_mirror()?;
        match decide_sweep(Some(&mirror), false, holder_alive(mirror.creator_pid)) {
            Sweep::RestoreFromMirror => {
                eprintln!(
                    "[proxy] recovery file missing but HKCU\\{JOURNAL_SUBKEY} still records a change \
                     by dead pid {}; restoring the proxy from the mirror",
                    mirror.creator_pid
                );
                Some(mirror.snapshot)
            }
            Sweep::Nothing => None,
        }
    }

    /// Consume a recovery file: restore, and only then unlink. A restore that
    /// reports failure leaves the file in place, so the next start tries again.
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
    // Read argv *before any plugin is registered*. `--repair-proxy` is the entry
    // point for a machine whose Windows proxy still points at an engine that died,
    // and the single-instance plugin — registered ahead of `setup` — used to catch
    // the invocation first, merely focus the tray app's window and exit, so the
    // repair below was never reached by exactly the user who needs it. That flag
    // now runs a real second instance instead.
    let repair_only = repair_proxy_requested();
    let mut builder = tauri::Builder::default().plugin(tauri_plugin_opener::init());
    if !repair_only {
        builder = builder.plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.show();
                let _ = window.set_focus();
                let _ = window.unminimize();
            }
        }));
    }
    builder
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
                spawn_route_repair(app.handle());
            }
            #[cfg(windows)]
            {
                let mut recovered = false;
                if let Ok(path) = proxy_recovery_path(app.handle()) {
                    match windows_proxy::recover(&path) {
                        Ok(true) => {
                            recovered = true;
                            emit_log(
                                app.handle(),
                                "Recovered Windows proxy after interrupted session".into(),
                            );
                        }
                        Ok(false) => {}
                        Err(error) => emit_log(
                            app.handle(),
                            format!("Windows proxy recovery failed: {error}"),
                        ),
                    }
                }
                if !recovered {
                    // The file was gone but HKCU still said a session had changed the
                    // proxy, and the process that did it is dead. Restore from the
                    // mirror; `restore` clears it once the values read back.
                    if let Some(snapshot) = windows_proxy::sweep_orphan() {
                        match windows_proxy::restore(snapshot) {
                            Ok(()) => emit_log(
                                app.handle(),
                                "Restored the Windows proxy from the registry journal: the recovery                                  file was missing and the session that set it had ended"
                                    .into(),
                            ),
                            Err(error) => emit_log(
                                app.handle(),
                                format!("Registry-journal proxy restore failed: {error}"),
                            ),
                        }
                    }
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
            let settings = load_settings_or_defaults(app.handle());
            if settings.start_minimized || start_minimized_requested() {
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
                            let settings = load_settings_or_defaults(&app);
                            // The blocking body, not the `async` command: this is
                            // already off the UI thread and cannot await.
                            if let Err(e) = connect_blocking(app.clone(), settings) {
                                emit_log(&app, format!("tray connect: {e}"));
                            }
                        });
                    }
                    "disconnect" => {
                        let app = app.clone();
                        std::thread::spawn(move || {
                            let _ = disconnect_blocking(app);
                        });
                    }
                    "quit" => {
                        let app = app.clone();
                        std::thread::spawn(move || {
                            let _ = disconnect_blocking(app.clone());
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
            diagnostics,
            scan,
            stop_scan
        ])
        .run(tauri::generate_context!())
        .expect("error while running Aether Next");
}
