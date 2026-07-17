#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{BufRead, BufReader},
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
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
            noize: "firewall".into(),
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
        }
    }
}

fn config_dir(app: &AppHandle) -> Result<PathBuf, String> {
    app.path().app_config_dir().map_err(|e| e.to_string())
}

fn settings_path(app: &AppHandle) -> Result<PathBuf, String> {
    Ok(config_dir(app)?.join("settings.json"))
}

fn load_settings_file(app: &AppHandle) -> Settings {
    settings_path(app)
        .ok()
        .and_then(|path| fs::read_to_string(path).ok())
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_default()
}

fn save_settings_file(app: &AppHandle, settings: &Settings) -> Result<(), String> {
    let path = settings_path(app)?;
    fs::create_dir_all(path.parent().ok_or("invalid config path")?).map_err(|e| e.to_string())?;
    let json = serde_json::to_string_pretty(settings).map_err(|e| e.to_string())?;
    fs::write(path, json).map_err(|e| e.to_string())
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
    for (name, port) in [("HTTP", settings.http_port), ("SOCKS5", settings.socks_port)] {
        if port < 1024 {
            return Err(format!("{name} port must be 1024–65535 (got {port})"));
        }
    }
    if settings.http_port == settings.socks_port {
        return Err("HTTP and SOCKS5 ports must differ".into());
    }
    Ok(())
}

/// Prefer structured `AETHER_EVENT {...}` lines; fall back to log markers.
fn handle_engine_line(
    app: &AppHandle,
    line: &str,
    settings: &Settings,
    socks_seen: &AtomicBool,
    tunnel_seen: &AtomicBool,
) {
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
                "tunnel_ready" | "tun_ready" => {
                    tunnel_seen.store(true, Ordering::SeqCst);
                }
                "connected" => {
                    socks_seen.store(true, Ordering::SeqCst);
                    tunnel_seen.store(true, Ordering::SeqCst);
                }
                "error" => {
                    if let Some(msg) = v.get("message").and_then(|m| m.as_str()) {
                        emit_log(app, format!("engine error: {msg}"));
                    }
                }
                _ => {}
            }
        }
    }

    // Legacy log markers (engine without events / partial paths)
    if line.contains("socks5 server listening") || line.contains("http proxy listening") {
        socks_seen.store(true, Ordering::SeqCst);
    }
    if line.contains("connect-ip status: 200")
        || line.contains("handshake successful")
        || line.contains("[tun] bridge active")
        || line.contains("quic handshake established")
    {
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

    let ready = if settings.protocol == "masque" {
        socks_seen.load(Ordering::SeqCst) && tunnel_seen.load(Ordering::SeqCst)
    } else {
        socks_seen.load(Ordering::SeqCst) || tunnel_seen.load(Ordering::SeqCst)
    };
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
        .filter(|p| p.exists())
}

fn engine_path(app: &AppHandle, settings: &Settings) -> Result<PathBuf, String> {
    if !settings.engine_path.trim().is_empty() {
        let path = PathBuf::from(settings.engine_path.trim());
        return path
            .exists()
            .then_some(path)
            .ok_or("Configured aether.exe was not found".into());
    }
    if let Ok(path) = std::env::var("AETHER_ENGINE") {
        let path = PathBuf::from(path);
        if path.exists() {
            return Ok(path);
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
    let repo_build = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../aether/target/release/aether.exe");
    repo_build.exists().then_some(repo_build).ok_or(
        "aether.exe not found. Build engine or choose it in Settings > Advanced.".into(),
    )
}

fn wintun_path(app: &AppHandle) -> Option<PathBuf> {
    if let Ok(path) = std::env::var("AETHER_WINTUN") {
        let path = PathBuf::from(path);
        if path.exists() {
            return Some(path);
        }
    }
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
        match windows_proxy::enable(settings.http_port, endpoint.as_deref()) {
            Ok(snapshot) => *state.proxy_snapshot.lock().unwrap() = Some(snapshot),
            Err(error) => emit_log(app, format!("System proxy failed: {error}")),
        }
        state.proxy_enabled.store(true, Ordering::SeqCst);
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
) {
    std::thread::spawn(move || {
        for line in BufReader::new(reader).lines().map_while(Result::ok) {
            handle_engine_line(&app, &line, &settings, &socks_seen, &tunnel_seen);
            emit_log(&app, line);
        }
    });
}

fn cleanup_routing(state: &AppState) {
    #[cfg(windows)]
    if state.proxy_enabled.swap(false, Ordering::SeqCst) {
        if let Some(snapshot) = state.proxy_snapshot.lock().unwrap().take() {
            let _ = windows_proxy::restore(snapshot);
        }
    }
    state.connected_once.store(false, Ordering::SeqCst);
}

fn watch_child(app: AppHandle) {
    std::thread::spawn(move || loop {
        std::thread::sleep(std::time::Duration::from_millis(500));
        let state = app.state::<AppState>();
        let mut child_slot = state.child.lock().unwrap();
        let Some(child) = child_slot.as_mut() else {
            continue;
        };
        match child.try_wait() {
            Ok(Some(status)) => {
                *child_slot = None;
                drop(child_slot);
                cleanup_routing(&state);
                let detail = if status.success() {
                    "Engine stopped".into()
                } else {
                    format!("Engine exited ({status})")
                };
                emit_state(&app, &state, "disconnected", &detail, None, None);
            }
            Ok(None) => {}
            Err(_) => {
                *child_slot = None;
                drop(child_slot);
                cleanup_routing(&state);
                emit_state(&app, &state, "disconnected", "Engine lost", None, None);
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
            if !elevation::is_elevated() {
                elevation::relaunch_elevated()?;
                app.exit(0);
                return Ok(());
            }
            if wintun_path(&app).is_none() {
                return Err("wintun.dll not found. Reinstall Aether or place wintun.dll next to the app.".into());
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
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    if let Some(wintun) = wintun_path(&app) {
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
    let socks_seen = Arc::new(AtomicBool::new(false));
    let tunnel_seen = Arc::new(AtomicBool::new(false));
    state.connected_once.store(false, Ordering::SeqCst);

    if let Some(stdout) = child.stdout.take() {
        stream_output(
            app.clone(),
            stdout,
            settings.clone(),
            socks_seen.clone(),
            tunnel_seen.clone(),
        );
    }
    if let Some(stderr) = child.stderr.take() {
        stream_output(app.clone(), stderr, settings, socks_seen, tunnel_seen);
    }
    *state.child.lock().unwrap() = Some(child);
    emit_state(
        &app,
        &state,
        "connecting",
        "Scanning reachable routes",
        Some(pid),
        None,
    );
    Ok(())
}

#[tauri::command]
fn disconnect(app: AppHandle, state: State<'_, AppState>) -> Result<(), String> {
    if let Some(mut child) = state.child.lock().unwrap().take() {
        child.kill().map_err(|e| e.to_string())?;
        let _ = child.wait();
    }
    cleanup_routing(&state);
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
    use std::env;
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    use windows_sys::Win32::UI::Shell::ShellExecuteW;
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

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

    fn wide(s: &str) -> Vec<u16> {
        OsStr::new(s).encode_wide().chain(Some(0)).collect()
    }

    pub fn relaunch_elevated() -> Result<(), String> {
        let exe = env::current_exe().map_err(|e| e.to_string())?;
        let exe_w = wide(&exe.to_string_lossy());
        let op = wide("runas");
        let ret = unsafe {
            ShellExecuteW(
                std::ptr::null_mut(),
                op.as_ptr(),
                exe_w.as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                SW_SHOWNORMAL,
            )
        } as isize;
        if ret <= 32 {
            return Err(format!("UAC elevation failed (code {ret}). Run Aether as Administrator for TUN."));
        }
        Ok(())
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
    use std::io;
    use windows_sys::Win32::Networking::WinInet::{
        InternetSetOptionW, INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED,
    };
    use winreg::{enums::HKEY_CURRENT_USER, RegKey};

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

    pub fn enable(port: u16, endpoint: Option<&str>) -> Result<ProxySnapshot, String> {
        let key = key().map_err(|e| e.to_string())?;
        let snapshot = ProxySnapshot {
            enabled: key.get_value("ProxyEnable").unwrap_or(0),
            server: key.get_value("ProxyServer").ok(),
            bypass: key.get_value("ProxyOverride").ok(),
        };
        key.set_value(
            "ProxyServer",
            &format!("http=127.0.0.1:{port};https=127.0.0.1:{port}"),
        )
        .map_err(|e| e.to_string())?;
        let mut bypass = String::from("localhost;127.*;<local>");
        if let Some(ep) = endpoint {
            let host = ep.rsplit_once(':').map(|(h, _)| h).unwrap_or(ep);
            if !host.is_empty() {
                bypass.push(';');
                bypass.push_str(host.trim_matches(['[', ']']));
            }
        }
        key.set_value("ProxyOverride", &bypass)
            .map_err(|e| e.to_string())?;
        key.set_value("ProxyEnable", &1u32).map_err(|e| e.to_string())?;
        refresh();
        Ok(snapshot)
    }

    pub fn restore(snapshot: ProxySnapshot) -> Result<(), String> {
        let key = key().map_err(|e| e.to_string())?;
        key.set_value("ProxyEnable", &snapshot.enabled)
            .map_err(|e| e.to_string())?;
        match snapshot.server {
            Some(value) => key.set_value("ProxyServer", &value).map_err(|e| e.to_string())?,
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
        refresh();
        Ok(())
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
            TrayIconBuilder::new()
                .icon(app.default_window_icon().unwrap().clone())
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
                        let settings = load_settings_file(app);
                        let state = app.state::<AppState>();
                        if let Err(e) = connect(app.clone(), state, settings) {
                            emit_log(app, format!("tray connect: {e}"));
                        }
                    }
                    "disconnect" => {
                        let state = app.state::<AppState>();
                        let _ = disconnect(app.clone(), state);
                    }
                    "quit" => {
                        let state = app.state::<AppState>();
                        let _ = disconnect(app.clone(), state);
                        app.exit(0);
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
