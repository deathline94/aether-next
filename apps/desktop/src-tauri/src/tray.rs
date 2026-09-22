//! Tray and run composition: the startup work that has to happen before a window
//! can be trusted to exist, the menu that drives the engine without a webview, and
//! the one exit path every driver shares.

use crate::settings::{
    config_dir, describe_settings, load_settings_file, settings_age, start_minimized_requested,
    Settings,
};
use crate::state::{emit_log, AppState};
use crate::supervision::{connect_blocking, disconnect_blocking, spawn_route_repair};
use std::sync::atomic::Ordering;
use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Manager, RunEvent, Window, WindowEvent};

#[cfg(windows)]
use crate::dpapi;
#[cfg(windows)]
use crate::proxy::windows_proxy;

/// Everything that must be true before the window is shown.
///
/// Returning `Err` here is a fatal startup failure: `run()` reports it through
/// [`crate::startup`], because a `windows_subsystem = "windows"` build has no
/// console for a panic to reach.
pub(crate) fn setup(app: &mut tauri::App) -> Result<(), Box<dyn std::error::Error>> {
    let dir = config_dir(app.handle())
        .map_err(|e| Box::new(std::io::Error::other(e)) as Box<dyn std::error::Error>)?;
    std::fs::create_dir_all(&dir).map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
    crate::acl::restrict_directory_acl(&dir)
        .map_err(|e| Box::new(std::io::Error::other(e)) as Box<dyn std::error::Error>)?;
    // The activity-log lines below are emitted before the webview has subscribed
    // (see `state::emit_log`), and this is the record of them if the webview never
    // comes up at all.
    crate::startup::note(&format!(
        "startup: configuration directory {}",
        dir.display()
    ));
    #[cfg(windows)]
    {
        let _ = dpapi::get_or_create_dpapi_config_key(&dir);
        spawn_route_repair(app.handle());
    }
    #[cfg(windows)]
    {
        let mut recovered = false;
        if let Ok(path) = crate::settings::proxy_recovery_path(app.handle()) {
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
            // proxy, and the process that did it is dead. Restore from the mirror;
            // `restore` clears it once the values read back.
            if let Some(snapshot) = windows_proxy::sweep_orphan() {
                match windows_proxy::restore(snapshot) {
                    Ok(()) => emit_log(
                        app.handle(),
                        "Restored the Windows proxy from the registry journal: the recovery \
                         file was missing and the session that set it had ended"
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
    if crate::settings::repair_proxy_requested() {
        // Everything that can be restored has been: the proxy journal above and
        // the route journal the engine replays at its own startup. Exit without a
        // tray, a window or an engine child, so the command is usable as a repair
        // and not only as a side effect of opening the app.
        crate::startup::note(if cfg!(windows) {
            "--repair-proxy: Windows proxy state restored (see the lines above)"
        } else {
            "--repair-proxy: nothing to do; the system proxy integration is Windows-only"
        });
        std::process::exit(0);
    }
    crate::supervision::watch_child(app.handle().clone());
    let settings = crate::settings::load_settings_or_defaults(app.handle());
    if settings.start_minimized || start_minimized_requested() {
        if let Some(window) = app.get_webview_window("main") {
            let _ = window.hide();
        }
    }
    let show = MenuItem::with_id(app, "show", "Open Aether Next", true, None::<&str>)?;
    let connect_item = MenuItem::with_id(app, "connect", "Connect", true, None::<&str>)?;
    let disconnect_item = MenuItem::with_id(app, "disconnect", "Disconnect", true, None::<&str>)?;
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
            Box::new(std::io::Error::other(format!("tray icon: {e}"))) as Box<dyn std::error::Error>
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
            "connect" => tray_connect(app),
            "disconnect" => tray_disconnect(app),
            "quit" => tray_quit(app),
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
}

/// The tray's Connect, using the only settings a tray click can reach.
///
/// A tray menu item cannot carry the webview's form state, so it reads
/// `settings.json` — which is up to the frontend's 400 ms debounce behind the form,
/// and indefinitely behind whenever a save was rejected. `busy` is a frontend
/// concept too; the shell's own answer is `connect_blocking`'s "already running".
/// Both disagreements are named in the log *before* the action runs, so a session
/// started from the tray can be attributed to the settings it really used rather
/// than to whatever the window happens to be showing.
fn tray_connect(app: &AppHandle) {
    let app = app.clone();
    std::thread::spawn(move || {
        let on_disk = match load_settings_file(&app) {
            Ok(settings) => {
                emit_log(
                    &app,
                    format!(
                        "Tray Connect: starting the engine with the settings saved on disk ({}), \
                         last written {} — anything not yet saved in the window's form is not \
                         part of them.",
                        describe_settings(&settings),
                        settings_age(&app),
                    ),
                );
                settings
            }
            Err(error) => {
                emit_log(
                    &app,
                    format!(
                        "Tray Connect: settings.json is unusable ({error}), so the built-in \
                         defaults are being used instead ({}) — open the window and check them \
                         before trusting this session",
                        describe_settings(&Settings::default()),
                    ),
                );
                Settings::default()
            }
        };
        warn_if_disk_disagrees_with_session(&app, &on_disk, "Tray Connect");
        // The blocking body, not the `async` command: this is already off the UI
        // thread and cannot await.
        if let Err(error) = connect_blocking(app.clone(), on_disk, "tray", "settings.json") {
            emit_log(
                &app,
                format!(
                    "Tray Connect did not start a session: {error} — the window's own busy state \
                     is not consulted for a tray action, so check whether a session is already \
                     running"
                ),
            );
        }
    });
}

/// The tray's Disconnect: what it stops is the *running session*, not the form.
fn tray_disconnect(app: &AppHandle) {
    let app = app.clone();
    std::thread::spawn(move || {
        // Cloned out of the lock in one expression: nothing from here on may be
        // holding it while it calls back into the supervisor.
        let origin = app
            .state::<AppState>()
            .session_origin
            .lock()
            .as_ref()
            .map(|origin| {
                (
                    origin.source,
                    origin.provenance,
                    origin.settings.clone(),
                    origin.started.elapsed(),
                )
            });
        match origin {
            Some((source, provenance, settings, age)) => {
                emit_log(
                    &app,
                    format!(
                        "Tray Disconnect: stopping the session started {} ago by {source} from \
                         {provenance} ({}) — this affects the running engine only, whatever the \
                         window's form holds",
                        format_duration(age),
                        describe_settings(&settings),
                    ),
                );
                if let Ok(on_disk) = load_settings_file(&app) {
                    warn_if_disk_disagrees_with_session(&app, &on_disk, "Tray Disconnect");
                }
            }
            None => emit_log(
                &app,
                "Tray Disconnect: no session of this process is recorded; running the teardown \
                 anyway so any leftover Windows proxy or route journal state is put back"
                    .into(),
            ),
        }
        if let Err(error) = disconnect_blocking(app.clone()) {
            emit_log(&app, format!("Tray Disconnect reported a problem: {error}"));
        }
    });
}

/// Tray Quit: ask the runtime to exit and let the shared teardown in
/// [`on_run_event`] do the work, so quitting from the tray and quitting any other
/// way are one code path rather than two that can drift.
fn tray_quit(app: &AppHandle) {
    emit_log(app, "Tray Quit: requesting shutdown".into());
    app.exit(0);
}

/// Say out loud when the settings on disk are not the ones in force.
fn warn_if_disk_disagrees_with_session(app: &AppHandle, on_disk: &Settings, who: &str) {
    let running = app
        .state::<AppState>()
        .session_origin
        .lock()
        .as_ref()
        .map(|origin| origin.settings.clone());
    let Some(running) = running else { return };
    let differences = crate::settings::settings_differences(&running, on_disk);
    if differences.is_empty() {
        return;
    }
    emit_log(
        app,
        format!(
            "{who}: settings.json and the running session disagree on {} — the session is using \
             ({}) while the file now says ({}). The tray acts on the file.",
            differences.join(", "),
            describe_settings(&running),
            describe_settings(on_disk),
        ),
    );
}

/// Hide-to-tray, unless an exit was already asked for.
///
/// Closing the window has always meant "keep running in the tray" here, and that is
/// the documented behaviour; what it used to swallow unconditionally was the close
/// *after* Quit, which is the difference between a tray app that exits and one that
/// has to be killed.
pub(crate) fn on_window_event(window: &Window, event: &WindowEvent) {
    if let WindowEvent::CloseRequested { api, .. } = event {
        let exiting = window
            .app_handle()
            .state::<AppState>()
            .exiting
            .load(Ordering::SeqCst);
        if exiting {
            // Not prevented: the window is closing because the app is leaving, and
            // the teardown runs in `RunEvent::ExitRequested`.
            return;
        }
        let _ = window.hide();
        api.prevent_close();
    }
}

/// The exit path every driver shares: tray Quit, `AppHandle::exit`, and a close
/// that was allowed through all land here, and all get the same cleanup.
///
/// `prevent_exit` + a worker rather than an inline teardown because the child wait
/// is up to the 15 s grace window, and parking the event loop that long leaves a
/// painted, unresponsive window on screen the whole time. The process still cannot
/// leave before the cleanup has run: the worker's own `exit` re-enters this
/// handler, where the guard has already been taken.
pub(crate) fn on_run_event(app: &AppHandle, event: RunEvent) {
    match event {
        RunEvent::ExitRequested { code, api, .. } => {
            let state = app.state::<AppState>();
            if state.exiting.swap(true, Ordering::SeqCst) {
                return;
            }
            api.prevent_exit();
            let app = app.clone();
            std::thread::spawn(move || {
                emit_log(
                    &app,
                    format!(
                        "Exiting{}: stopping the session and putting the host back",
                        match code {
                            Some(code) => format!(" (code {code})"),
                            None => String::new(),
                        }
                    ),
                );
                crate::startup::note("exit requested: running the teardown");
                if let Err(error) = disconnect_blocking(app.clone()) {
                    emit_log(
                        &app,
                        format!("the exit teardown reported a problem: {error}"),
                    );
                    crate::startup::note(&format!("exit teardown reported a problem: {error}"));
                }
                crate::startup::note("exit teardown complete");
                app.exit(code.unwrap_or(0));
            });
        }
        RunEvent::Exit => {
            // Nothing may outlive the process even if the teardown above could not
            // run: dropping the job handle here kills whatever is still inside it.
            #[cfg(windows)]
            app.state::<AppState>().job.lock().take();
            #[cfg(not(windows))]
            let _ = app;
        }
        _ => {}
    }
}

/// A duration the way a log line should read it.
fn format_duration(elapsed: std::time::Duration) -> String {
    let secs = elapsed.as_secs();
    if secs < 60 {
        format!("{secs} s")
    } else if secs < 3600 {
        format!("{} m {} s", secs / 60, secs % 60)
    } else {
        format!("{} h", secs / 3600)
    }
}
