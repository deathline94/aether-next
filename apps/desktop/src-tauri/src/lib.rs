#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{BufRead, BufReader, Write},
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
};
use tauri::{
    menu::{Menu, MenuItem},
    path::BaseDirectory,
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    AppHandle, Emitter, Manager, State,
};

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
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            protocol: "masque".into(),
            transport: "h2".into(),
            // Prefer balanced over turbo: better edge RTT → higher throughput.
            scan_mode: "balanced".into(),
            ip_version: "v4".into(),
            noize: "medium".into(),
            noize_jc: 4,
            noize_jmin: 48,
            noize_jmax: 190,
            noize_interval_ms: 4,
            routing_mode: "system-proxy".into(),
            socks_port: 1819,
            http_port: 1820,
            start_minimized: false,
            launch_at_login: false,
            engine_path: String::new(),
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
    runtime: Mutex<RuntimeState>,
    proxy_enabled: AtomicBool,
    #[cfg(windows)]
    proxy_snapshot: Mutex<Option<windows_proxy::ProxySnapshot>>,
    connected_once: AtomicBool,
    connecting: AtomicBool,
    generation: AtomicU64,
    operation: Mutex<()>,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            child: Mutex::new(None),
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
        }
    }
}

fn config_dir(app: &AppHandle) -> Result<PathBuf, String> {
    app.path().app_config_dir().map_err(|e| e.to_string())
}

fn settings_path(app: &AppHandle) -> Result<PathBuf, String> {
    Ok(config_dir(app)?.join("settings.json"))
}

#[cfg(windows)]
fn proxy_recovery_path(app: &AppHandle) -> Result<PathBuf, String> {
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

fn save_settings_file(app: &AppHandle, settings: &Settings) -> Result<(), String> {
    let path = settings_path(app)?;
    fs::create_dir_all(path.parent().ok_or("invalid config path")?).map_err(|e| e.to_string())?;
    let json = serde_json::to_string_pretty(settings).map_err(|e| e.to_string())?;
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, json).map_err(|e| e.to_string())?;
    fs::rename(&tmp, &path).map_err(|e| e.to_string())
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
    *state.runtime.lock().unwrap() = value.clone();
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

fn validate_settings(settings: &Settings) -> Result<(), String> {
    for (name, port) in [
        ("HTTP", settings.http_port),
        ("SOCKS5", settings.socks_port),
    ] {
        if !(1024..=65535).contains(&port) {
            return Err(format!("{name} port must be 1024–65535 (got {port})"));
        }
    }
    if settings.http_port == settings.socks_port {
        return Err("HTTP and SOCKS5 ports must differ".into());
    }
    let allow = |field: &str, val: &str, opts: &[&str]| {
        if opts.iter().any(|o| o.eq_ignore_ascii_case(val.trim())) {
            Ok(())
        } else {
            Err(format!("{field} must be one of: {}", opts.join(", ")))
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
        &["fast", "balanced", "deep", "turbo", "auto"],
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
                        let mut rt = state.runtime.lock().unwrap();
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
                    let endpoint = state.runtime.lock().unwrap().endpoint.clone();
                    
                    // 1) Paint the banner.
                    emit_state(app, &state, "error", &msg, None, endpoint);

                    // 2) Tear the session down so the next Connect is allowed WITHOUT
                    //    dismissing the banner. watch_child's `already_error` guard keeps
                    //    the error banner visible when the child finally exits.
                    state.generation.fetch_add(1, Ordering::SeqCst);
                    state.connecting.store(false, Ordering::SeqCst);
                    let child = state.child.lock().unwrap().take();
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
    if line.contains("socks5 server listening") || line.contains("http proxy listening") {
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
        let mut rt = state.runtime.lock().unwrap();
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
    let lower = line.to_ascii_lowercase();
    let level = if lower.contains("error") || lower.contains("failed") {
        "error"
    } else if lower.contains("warn") || lower.contains("[-]") {
        "warn"
    } else {
        "info"
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
fn validate_trusted_binary(path: &PathBuf, label: &str) -> Result<(), String> {
    let meta = fs::metadata(path).map_err(|e| format!("{label}: {e}"))?;
    if !meta.is_file() {
        return Err(format!("{label} is not a regular file"));
    }
    if meta.len() == 0 {
        return Err(format!("{label} is empty"));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(format!("{label} must not be a reparse point/symlink"));
        }
        // PE header check (MZ) — fail closed if unreadable or not PE.
        let mut hdr = [0u8; 2];
        let mut f = fs::File::open(path).map_err(|e| format!("{label}: cannot open: {e}"))?;
        use std::io::Read;
        f.read_exact(&mut hdr)
            .map_err(|e| format!("{label}: cannot read PE header: {e}"))?;
        if hdr != *b"MZ" {
            return Err(format!("{label} is not a Windows PE binary"));
        }
    }
    let app_root = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()));
    let canon = path.canonicalize().unwrap_or_else(|_| path.clone());
    if let Some(root) = app_root {
        let root = root.canonicalize().unwrap_or(root);
        if canon.starts_with(&root) {
            return Ok(());
        }
    }
    // Packaged Tauri resources often live under a sibling resources/ directory.
    if let Some(parent) = path.parent() {
        let name = parent.file_name().and_then(|s| s.to_str()).unwrap_or("");
        if name.eq_ignore_ascii_case("resources") || name.eq_ignore_ascii_case("engine") {
            return Ok(());
        }
    }
    Err(format!(
        "{label} rejected: must live under the app install directory (got {})",
        path.display()
    ))
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

fn file_sha256_hex(path: &PathBuf) -> Result<String, String> {
    #[cfg(windows)]
    {
        let out = Command::new("certutil")
            .args(["-hashfile", &path.to_string_lossy(), "SHA256"])
            .output()
            .map_err(|e| e.to_string())?;
        let text = String::from_utf8_lossy(&out.stdout);
        for line in text.lines() {
            let t = line.trim().replace(' ', "").to_ascii_lowercase();
            if t.len() == 64 && t.chars().all(|c| c.is_ascii_hexdigit()) {
                return Ok(t);
            }
        }
        Err("could not parse certutil SHA256 output".into())
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        Err("hash check unsupported on this platform".into())
    }
}

fn engine_path(app: &AppHandle, settings: &Settings) -> Result<PathBuf, String> {
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
    if settings.routing_mode != "tun" {
        if let Ok(path) = std::env::var("AETHER_ENGINE") {
            let path = PathBuf::from(path);
            if path.exists() {
                validate_trusted_binary(&path, "aether.exe")?;
                return Ok(path);
            }
        }
    }
    if let Some(path) = resolve_resource(app, "aether.exe") {
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
    repo_build
        .exists()
        .then_some(repo_build)
        .ok_or("aether.exe not found. Build engine or choose it in Settings > Advanced.".into())
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
    let endpoint = state.runtime.lock().unwrap().endpoint.clone();
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
                    *state.proxy_snapshot.lock().unwrap() = Some(snapshot);
                    state.proxy_enabled.store(true, Ordering::SeqCst);
                }
                Err((error, snapshot)) => {
                    if let Some(snapshot) = snapshot {
                        *state.proxy_snapshot.lock().unwrap() = Some(snapshot);
                        state.proxy_enabled.store(true, Ordering::SeqCst);
                    }
                    emit_log(app, format!("System proxy failed: {error}"));
                    // Stop engine so UI is not stuck with orphan child.
                    if let Some(mut child) = state.child.lock().unwrap().take() {
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
    let pid = state.runtime.lock().unwrap().pid;
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
                let _operation = state.operation.lock().unwrap();
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
        let mut snapshot = state.proxy_snapshot.lock().unwrap();
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
}

fn watch_child(app: AppHandle) {
    std::thread::spawn(move || loop {
        std::thread::sleep(std::time::Duration::from_millis(500));
        let state = app.state::<AppState>();
        let _operation = state.operation.lock().unwrap();
        let mut child_slot = state.child.lock().unwrap();
        let Some(child) = child_slot.as_mut() else {
            continue;
        };
        match child.try_wait() {
            Ok(Some(status)) => {
                *child_slot = None;
                drop(child_slot);
                state.connecting.store(false, Ordering::SeqCst);
                state.generation.fetch_add(1, Ordering::SeqCst);
                cleanup_routing(&app, &state);
                let already_error = state
                    .runtime
                    .lock()
                    .unwrap()
                    .status
                    .eq_ignore_ascii_case("error");
                if already_error {
                    // Structured error event already set UI; keep it.
                    continue;
                }
                let ever_connected = state.connected_once.load(Ordering::SeqCst);
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
                cleanup_routing(&app, &state);
                let already_error = state
                    .runtime
                    .lock()
                    .unwrap()
                    .status
                    .eq_ignore_ascii_case("error");
                if already_error {
                    continue;
                }
                let ever_connected = state.connected_once.load(Ordering::SeqCst);
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
fn save_settings(app: AppHandle, settings: Settings) -> Result<(), String> {
    validate_settings(&settings)?;
    save_settings_file(&app, &settings)?;
    #[cfg(windows)]
    autostart::set(settings.launch_at_login)?;
    Ok(())
}

#[tauri::command]
fn get_state(state: State<'_, AppState>) -> RuntimeState {
    state.runtime.lock().unwrap().clone()
}

#[tauri::command]
fn is_admin() -> bool {
    #[cfg(windows)]
    {
        return elevation::is_elevated();
    }
    #[cfg(not(windows))]
    {
        true
    }
}

#[tauri::command]
fn connect(app: AppHandle, state: State<'_, AppState>, settings: Settings) -> Result<(), String> {
    let _operation = state.operation.lock().unwrap();
    if state
        .connecting
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return Err("Aether is already running".into());
    }
    let result = (|| -> Result<(), String> {
        if state.child.lock().unwrap().is_some() {
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
                    return Err(
                        "Full-device TUN needs Administrator. Right-click Aether → Run as administrator, then Connect."
                            .into(),
                    );
                }
                if wintun_path(&app).is_none() {
                    return Err(
                        "wintun.dll not found. Reinstall Aether or place wintun.dll next to the app."
                            .into(),
                    );
                }
            }
            #[cfg(not(windows))]
            {
                return Err("TUN mode is Windows-only".into());
            }
        }

        let executable = engine_path(&app, &settings)?;
        let dir = config_dir(&app)?;
        fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        if settings.routing_mode == "tun" {
            validate_trusted_binary(&executable, "aether.exe")?;
            if let Some(wintun) = wintun_path(&app) {
                validate_trusted_binary(&wintun, "wintun.dll")?;
                // Optional pin: set AETHER_WINTUN_SHA256 to require exact file hash.
                if let Ok(expected) = std::env::var("AETHER_WINTUN_SHA256") {
                    let expected = expected.trim().to_ascii_lowercase();
                    if !expected.is_empty() {
                        let actual = file_sha256_hex(&wintun)?;
                        if actual != expected {
                            return Err(format!(
                                "wintun.dll hash mismatch (got {actual}, want {expected})"
                            ));
                        }
                    }
                }
            }
        }

        let mut command = Command::new(&executable);
        command
            .current_dir(executable.parent().unwrap_or(std::path::Path::new(".")))
            .env("AETHER_PROTOCOL", &settings.protocol)
            .env("AETHER_SCAN", &settings.scan_mode)
            .env("AETHER_IP", &settings.ip_version)
            .env("AETHER_NOIZE", &settings.noize)
            .env("AETHER_SOCKS", format!("127.0.0.1:{}", settings.socks_port))
            .env("AETHER_HTTP", format!("127.0.0.1:{}", settings.http_port))
            .env("AETHER_CONFIG", dir.join("aether.toml"))
            .env(
                "AETHER_MASQUE_HTTP2",
                if settings.transport == "h2" { "1" } else { "0" },
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

        if let Some(wintun) = wintun_path(&app) {
            // Only pass Wintun path we already validated for TUN; never env override.
            command.env("AETHER_WINTUN", wintun);
        }

        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x08000000);
        }

        let mut child = command
            .spawn()
            .map_err(|e| format!("Could not start aether.exe: {e}"))?;
        let pid = child.id();
        let generation = state.generation.fetch_add(1, Ordering::SeqCst) + 1;
        let socks_seen = Arc::new(AtomicBool::new(false));
        let tunnel_seen = Arc::new(AtomicBool::new(false));
        let tun_seen = Arc::new(AtomicBool::new(false));
        state.connected_once.store(false, Ordering::SeqCst);

        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        *state.child.lock().unwrap() = Some(child);
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
fn disconnect(app: AppHandle, state: State<'_, AppState>) -> Result<(), String> {
    // Invalidate readers first under lock, then wait outside lock so stdout can drain.
    let mut child = {
        let _operation = state.operation.lock().unwrap();
        state.generation.fetch_add(1, Ordering::SeqCst);
        state.connecting.store(false, Ordering::SeqCst);
        state.child.lock().unwrap().take()
    };
    if let Some(child) = child.as_mut() {
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(b"shutdown\n");
            let _ = stdin.flush();
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            match child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
                Ok(None) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    break;
                }
                Err(_) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    break;
                }
            }
        }
    }
    let _operation = state.operation.lock().unwrap();
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
fn test_connection(settings: Settings) -> Result<String, String> {
    validate_settings(&settings)?;
    let proxy = format!("http://127.0.0.1:{}", settings.http_port);
    let url = "https://www.cloudflare.com/cdn-cgi/trace";
    let client = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(12))
        .proxy(ureq::Proxy::new(&proxy).map_err(|e| e.to_string())?)
        .build();
    let body = client
        .get(url)
        .call()
        .map_err(|e| format!("proxy test failed: {e}"))?
        .into_string()
        .map_err(|e| e.to_string())?;
    let ip = body
        .lines()
        .find_map(|l| l.strip_prefix("ip="))
        .unwrap_or("unknown");
    let loc = body
        .lines()
        .find_map(|l| l.strip_prefix("loc="))
        .unwrap_or("?");
    Ok(format!("OK via {proxy} · ip={ip} loc={loc}"))
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
    use std::env;
    use winreg::{enums::HKEY_CURRENT_USER, RegKey};

    const VALUE: &str = "Aether Next";

    pub fn set(enabled: bool) -> Result<(), String> {
        let key = RegKey::predef(HKEY_CURRENT_USER)
            .open_subkey_with_flags(
                "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                winreg::enums::KEY_SET_VALUE | winreg::enums::KEY_QUERY_VALUE,
            )
            .map_err(|e| e.to_string())?;
        if enabled {
            let exe = env::current_exe().map_err(|e| e.to_string())?;
            let cmd = format!("\"{}\"", exe.display());
            key.set_value(VALUE, &cmd).map_err(|e| e.to_string())
        } else {
            let _ = key.delete_value(VALUE);
            Ok(())
        }
    }
}

#[cfg(windows)]
mod windows_proxy {
    use serde::{Deserialize, Serialize};
    use std::io;
    use std::path::Path;
    use windows_sys::Win32::Networking::WinInet::{
        InternetSetOptionW, INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED,
    };
    use winreg::{enums::HKEY_CURRENT_USER, RegKey};

    #[derive(Clone, Serialize, Deserialize)]
    pub struct ProxySnapshot {
        enabled: u32,
        server: Option<String>,
        bypass: Option<String>,
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
        let result = (|| -> Result<(), String> {
            key.set_value(
                "ProxyServer",
                &format!("http=127.0.0.1:{port};https=127.0.0.1:{port}"),
            )
            .map_err(|e| e.to_string())?;
            let mut bypass = String::from("localhost;127.*;<local>");
            if let Some(ep) = endpoint {
                if let Some(host) = super::sanitize_proxy_bypass_host(ep) {
                    bypass.push(';');
                    bypass.push_str(&host);
                }
            }
            key.set_value("ProxyOverride", &bypass)
                .map_err(|e| e.to_string())?;
            key.set_value("ProxyEnable", &1u32)
                .map_err(|e| e.to_string())?;
            Ok(())
        })();
        if let Err(error) = result {
            return match restore(snapshot.clone()) {
                Ok(()) => {
                    if let Some(path) = recovery_path {
                        let _ = std::fs::remove_file(path);
                    }
                    Err((error, None))
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

    pub fn restore(snapshot: ProxySnapshot) -> Result<(), String> {
        let key = key().map_err(|e| e.to_string())?;
        match snapshot.server {
            Some(value) => key
                .set_value("ProxyServer", &value)
                .map_err(|e| e.to_string())?,
            None => {
                let _ = key.delete_value("ProxyServer");
            }
        }
        match snapshot.bypass {
            Some(value) => key
                .set_value("ProxyOverride", &value)
                .map_err(|e| e.to_string())?,
            None => {
                let _ = key.delete_value("ProxyOverride");
            }
        }
        key.set_value("ProxyEnable", &snapshot.enabled)
            .map_err(|e| e.to_string())?;
        refresh();
        Ok(())
    }

    pub fn recover(path: &Path) -> Result<bool, String> {
        if !path.exists() {
            return Ok(false);
        }
        let data = std::fs::read(path).map_err(|e| e.to_string())?;
        let snapshot: ProxySnapshot = serde_json::from_slice(&data).map_err(|e| e.to_string())?;
        restore(snapshot)?;
        std::fs::remove_file(path).map_err(|e| e.to_string())?;
        Ok(true)
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
            test_connection
        ])
        .run(tauri::generate_context!())
        .expect("error while running Aether Next");
}
