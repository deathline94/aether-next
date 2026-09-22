//! Aether desktop shell.
//!
//! The shell owns four things and nothing else: the IPC surface the webview calls,
//! the engine child process and the host state attached to it (system proxy, route
//! journal, job object), the trust decision about which binary may be executed, and
//! the tray/startup/exit path. Each lives in its own module; this file is the
//! command boundary and the composition root, and it deliberately holds no logic —
//! `generate_handler!` below *is* the IPC contract, so it has to stay readable as
//! one (`ipc-command-parity` in `scripts/verify-invariants.mjs` parses it here).

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod acl;
#[cfg(windows)]
mod autostart;
pub mod dpapi;
#[cfg(windows)]
mod elevation;
mod engine;
#[cfg(windows)]
mod engine_job;
mod error;
mod events;
mod probes;
mod proxy;
mod scan;
mod settings;
mod startup;
mod state;
mod supervision;
pub(crate) mod tray;
mod trust;

pub use acl::restrict_directory_acl;
pub use error::CommandError;
pub use events::log_level_for;
pub use proxy::sanitize_proxy_bypass_host;
#[cfg(windows)]
pub use proxy::windows_proxy;
pub use scan::scan_terminal_event;
pub use settings::{
    decode_settings_text, validate_settings, write_atomic, IpVersion, Protocol, RoutingMode,
    ScanMode, Settings, TransportKind, NOIZE_VOCABULARY,
};
pub use supervision::{
    connect_watchdog_action, engine_exit_outcome, heartbeat_stall_action, EngineExit,
    WatchdogAction, CONNECT_WATCHDOG_TIMEOUT, HEARTBEAT_INTERVAL, HEARTBEAT_MISS_LIMIT,
};
pub use trust::{
    allowed_binary_roots, embedded_cert_pin, engine_trust_anchor, file_sha256_hex,
    subject_names_common_name, validate_trusted_binary, verify_authenticode_signature,
    verify_elevated_binary, BinaryTrustError, TrustedBinaryPolicy, EMBEDDED_RELEASE_HASHES,
};

use crate::state::{note_webview_ready, AppState, RuntimeState};
use tauri::{AppHandle, Manager, State};

/* ------------------------------------------------------------- the boundary */

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
    // `?` unwraps the *join* handle only: a panic inside the blocking task becomes
    // `internal`, while the task's own Err reaches the caller unchanged.
    tauri::async_runtime::spawn_blocking(task)
        .await
        .map_err(|e| CommandError::new("internal", format!("{name} task did not run: {e}")))?
}

#[tauri::command]
fn get_settings(app: AppHandle) -> Result<Settings, CommandError> {
    // One of the four boot commands the page issues *after* it has awaited its
    // `listen()` calls, which is what makes it the readiness signal for the log
    // lines `setup` emitted too early to be seen.
    note_webview_ready(&app);
    settings::load_settings_file(&app)
}

#[tauri::command]
async fn save_settings(app: AppHandle, settings: Settings) -> Result<(), CommandError> {
    command_blocking("save_settings", move || {
        settings::save_settings_blocking(app, settings)
    })
    .await
}

#[tauri::command]
fn get_state(app: AppHandle, state: State<'_, AppState>) -> RuntimeState {
    note_webview_ready(&app);
    state.runtime.lock().clone()
}

#[tauri::command]
fn is_admin(app: AppHandle) -> bool {
    note_webview_ready(&app);
    #[cfg(windows)]
    {
        elevation::is_elevated()
    }
    // Off Windows the answer is permissive on purpose, and it is not a claim about
    // privileges: the only thing the UI gates on it is the Windows TUN path, which
    // `connect` refuses outright on every other platform (`engine_path` never even
    // resolves a driver), so a truthful `false` here would only mislabel the
    // Settings row. The key story is the same shape — `dpapi::service()` reports
    // `KeyService::None` and every path that needs a wrapped key fails with
    // `key_service_unavailable` rather than writing one unwrapped.
    #[cfg(not(windows))]
    {
        true
    }
}

#[tauri::command]
async fn connect(app: AppHandle, settings: Settings) -> Result<(), CommandError> {
    command_blocking("connect", move || {
        // The payload came from the window, and that is worth recording: the tray
        // path can only read `settings.json`, so the two drivers of one engine have
        // to be tellable apart afterwards.
        supervision::connect_blocking(app, settings, "window", "the window's form")
    })
    .await
}

#[tauri::command]
async fn disconnect(app: AppHandle) -> Result<(), CommandError> {
    command_blocking("disconnect", move || supervision::disconnect_blocking(app)).await
}

#[tauri::command]
fn app_info(app: AppHandle) -> serde_json::Value {
    note_webview_ready(&app);
    serde_json::json!({
        "name": "Aether Next",
        "version": env!("CARGO_PKG_VERSION"),
        "author": "deathline94",
        "engine": "deathline94/aether-next",
    })
}

#[tauri::command]
async fn test_connection(settings: Settings) -> Result<String, CommandError> {
    command_blocking("test_connection", move || {
        probes::test_connection_blocking(settings)
    })
    .await
}

#[tauri::command]
async fn diagnostics(app: AppHandle) -> Result<serde_json::Value, CommandError> {
    command_blocking("diagnostics", move || probes::diagnostics_blocking(app)).await
}

#[tauri::command]
// Tauri derives the JS-callable signature from these parameters, so grouping the
// scan inputs into one struct would change the wire contract the frontend calls
// with. `state` is resolved inside the body instead, which also keeps the
// argument count under clippy's threshold.
async fn scan(
    app: AppHandle,
    run_id: String,
    protocol: String,
    ip_version: IpVersion,
    concurrency: u32,
    timeout_ms: u32,
    noize: Option<String>,
) -> Result<(), CommandError> {
    command_blocking("scan", move || {
        scan::scan_blocking(
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

#[tauri::command]
async fn stop_scan(app: AppHandle) -> Result<(), CommandError> {
    command_blocking("stop_scan", move || scan::stop_scan_blocking(app)).await
}

/* ------------------------------------------------------------ composition */

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // Read argv *before any plugin is registered*. `--repair-proxy` is the entry
    // point for a machine whose Windows proxy still points at an engine that died,
    // and the single-instance plugin — registered ahead of `setup` — used to catch
    // the invocation first, merely focus the tray app's window and exit, so the
    // repair below was never reached by exactly the user who needs it. That flag
    // now runs a real second instance instead.
    let repair_only = settings::repair_proxy_requested();
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
    // `build` + `run`, not `Builder::run`: the latter is the same thing with the
    // event-loop callback thrown away, and the exit teardown needs that callback.
    let app = builder
        .manage(AppState::default())
        .setup(tray::setup)
        .on_window_event(tray::on_window_event)
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
        .build(tauri::generate_context!());
    match app {
        Ok(app) => app.run(tray::on_run_event),
        // This used to be `.expect("error while running Aether Next")`, i.e. a
        // panic in a binary that has no console: a failed tray-icon load or a DPI
        // mismatch produced a double click that did nothing, with no diagnostic
        // anywhere. Report through the channels that still exist at this point —
        // the startup log, stderr, and a message box — then leave non-zero.
        Err(error) => startup::report_and_exit("Aether Next failed to start", &error.to_string()),
    }
}
