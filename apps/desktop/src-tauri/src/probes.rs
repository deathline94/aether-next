//! Read-only engine probes the shell supervises: `--diagnostics` for a bug
//! report a checker can verify, and the pre-tunnel connectivity test. Both run a
//! child or a network call, so neither belongs on the UI thread.
use crate::engine::{engine_path, scrub_ambient_engine_env};
use crate::error::CommandError;
use crate::settings::{load_settings_or_defaults, validate_settings, RoutingMode, Settings};
use crate::state::AppState;
use crate::trust::verify_engine_or_refuse;
use std::path::Path;
use std::process::{Command, Stdio};
use tauri::{AppHandle, Manager};

/// Export what the engine actually resolved, for a bug report that can be
/// checked. Read-only: it runs `aether --diagnostics`, which never opens a
/// tunnel and never needs the config key, so no preamble and no key line go to
/// the child. The binary is still verified first — a diagnostics run executes
/// code just like a session does.
/// How long `aether --diagnostics` may take before the shell gives up on it.
/// The child writes a small JSON document and exits; anything past this is a
/// hang, and `Command::output()` (what this replaced) waits forever on one.
const DIAGNOSTICS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

pub(crate) fn diagnostics_blocking(app: AppHandle) -> Result<serde_json::Value, CommandError> {
    let state = app.state::<AppState>();
    if state.child.lock().is_some() || state.scan_child.lock().is_some() {
        return Err(CommandError::new(
            "busy",
            "Stop the running session or scan before exporting diagnostics.",
        ));
    }
    let settings = load_settings_or_defaults(&app);
    let executable = engine_path(&app, &settings)?;
    let engine_guard = verify_engine_or_refuse(&executable)?;

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
    drop(engine_guard);
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

/// The probe itself. `ureq`'s agent is synchronous and its timeout is 12 s, so
/// this has to run off the UI thread.
pub(crate) fn test_connection_blocking(settings: Settings) -> Result<String, CommandError> {
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
