//! Session supervision: bring the engine up with its key over the control pipe,
//! keep the host-side routing attached to it, watch it, and tear the host back
//! down. The watchdogs live here because a hidden (tray) window throttles UI
//! timers, which is this app's normal state.
use crate::acl::restrict_directory_acl;
use crate::dpapi;
use crate::engine::{engine_path, handoff_preamble, scrub_ambient_engine_env, wintun_path};
use crate::error::CommandError;
use crate::events::handle_engine_line;
use crate::scan::stop_scan_child;
use crate::settings::{
    config_dir, load_settings_or_defaults, proxy_recovery_path, save_settings_file,
    validate_settings, RoutingMode, Settings, TransportKind,
};
use crate::state::{emit_log, emit_state, AppState, SessionOrigin};
use crate::trust::{
    file_sha256_hex, verify_elevated_binary, verify_engine_or_refuse, TrustedBinaryPolicy,
};
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tauri::{AppHandle, Emitter, Manager};
use zeroize::Zeroize;

#[cfg(windows)]
use crate::autostart;
#[cfg(windows)]
use crate::elevation;
#[cfg(windows)]
use crate::engine_job;
#[cfg(windows)]
use crate::proxy::windows_proxy;

fn shutdown_with_grace(child: &mut std::process::Child, grace: std::time::Duration) {
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(b"shutdown\n");
        let _ = stdin.flush();
    }
    let deadline = std::time::Instant::now() + grace;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return,
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(25));
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return;
            }
        }
    }
}

pub(crate) fn mark_connected(app: &AppHandle, state: &AppState, settings: &Settings) {
    if state.connected_once.swap(true, Ordering::SeqCst) {
        return;
    }
    *state.connect_since.lock() = None;
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
                    state.generation.fetch_add(1, Ordering::SeqCst);
                    state.connecting.store(false, Ordering::SeqCst);
                    *state.session_origin.lock() = None;
                    *state.last_beat.lock() = None;
                    if let Some(mut child) = state.child.lock().take() {
                        shutdown_with_grace(&mut child, std::time::Duration::from_secs(2));
                    }
                    let problems = cleanup_routing(app, state);
                    for problem in &problems {
                        crate::startup::note(&format!("[aether] {problem}"));
                    }
                    let detail = if problems.is_empty() {
                        "System proxy setup failed".to_string()
                    } else {
                        format!("System proxy setup failed · {}", problems.join(" · "))
                    };
                    emit_state(app, state, "error", &detail, None, endpoint);
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
pub(crate) fn cleanup_routing(app: &AppHandle, state: &AppState) -> Vec<String> {
    let mut problems = Vec::new();
    #[cfg(windows)]
    if state.proxy_enabled.swap(false, Ordering::SeqCst) {
        let mut snapshot = state.proxy_snapshot.lock();
        if let Some(saved) = snapshot.take() {
            let applied = state.proxy_applied.lock().clone();
            match windows_proxy::restore_if_ours(applied.as_ref(), saved.clone()) {
                Ok(true) => {
                    if let Ok(path) = proxy_recovery_path(app) {
                        let _ = fs::remove_file(path);
                    }
                }
                // The live registry is no longer what this session wrote, so the
                // values to put back are the user's, not the snapshot's. The
                // journal describes a proxy that is gone; closing it keeps every
                // later start from restoring it over the newer values.
                Ok(false) => {
                    if let Ok(path) = proxy_recovery_path(app) {
                        let _ = fs::remove_file(path);
                    }
                    emit_log(
                        app,
                        "The Windows proxy was left as it is: it changed outside Aether while \
                         this session was up, and restoring the pre-session values would have \
                         overwritten that change"
                            .into(),
                    );
                }
                Err(error) => {
                    *snapshot = Some(saved);
                    state.proxy_enabled.store(true, Ordering::SeqCst);
                    problems.push(format!(
                        "system proxy restore failed ({error}); Windows is still routing through the \
                         tunnel's port - reconnect once or run Aether with --repair-proxy"
                    ));
                }
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
        // Every caller reaches this after the child was killed or reaped. Only
        // now may an updater replace the driver bytes that were authenticated
        // before launch; the engine could have loaded them at any earlier point.
        state.wintun_guard.lock().take();
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

/// What the child reap turned up on one tick.
///
/// The status is reduced to its code here, because that is the only part of it
/// this process can act on — and because keeping an `ExitStatus` alive across the
/// teardown would mean carrying a handle whose meaning the platform does not
/// guarantee past the wait.
enum Reaped {
    /// Exited 0: a session that was asked to stop and did.
    Clean,
    /// Exited non-zero. `None` is a status with no code (a signal).
    Failed(Option<i32>),
    /// The exit status could not be read at all.
    Lost(String),
}

/// What the supervisor decided the liveness signals mean.
///
/// Deciding and acting are kept apart on purpose. `watch_child` used to take
/// `state.operation` at the top of every 500 ms iteration and hold it across the
/// registry coherence check, both watchdogs and the child reap — and
/// `stream_output` takes that same lock for *every line it reads*. A tick's
/// `RegGetValueW`/`RegSetValueW` traffic therefore queued every engine line behind
/// it: readiness, heartbeat, and the structured `error` event that ends a session.
enum Liveness {
    /// A session that had been reporting and went silent while connected.
    StopConnected(String),
    /// Something looks stalled, but stopping is not warranted from here.
    Report(String),
}

/// The engine's exit, translated into what the UI should say.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineExit {
    /// The `status` the banner renders: `error` or `disconnected`.
    pub status: &'static str,
    /// The sentence, including the exit code and whether retrying is the answer.
    pub detail: String,
}

/// What an engine exit code means.
///
/// `aether/src/cli.rs` separates the two failure kinds deliberately: **4** is a
/// retryable failure (this pass found no working endpoint; an edge black-holed a
/// probe) and **1** is fatal (an identity, configuration or transport problem that a
/// second attempt cannot fix). Both used to land here as an undifferentiated
/// non-zero, and the shell then invented one sentence for every case — "Could not
/// find a working gateway. Try HTTP/2 or another scan mode." — which was worth
/// following after exit 4 and a wasted reconnect after exit 1.
///
/// `None` means there was no code to read (a child taken down by a signal, or a
/// status the platform would not give). That stays undifferentiated, and says so:
/// guessing "transient" here would be the fabricated diagnosis this file keeps
/// removing everywhere else.
pub fn engine_exit_outcome(code: Option<i32>, ever_connected: bool) -> EngineExit {
    match code {
        Some(4) if ever_connected => EngineExit {
            status: "disconnected",
            detail: "Engine stopped after a transient failure (exit 4) — reconnecting may work."
                .to_string(),
        },
        Some(4) => EngineExit {
            status: "error",
            detail: "Transient failure: the engine found no working route this time (exit 4), \
                     and called it retryable — try Connect again, or change the transport or \
                     scan mode."
                .to_string(),
        },
        Some(1) if ever_connected => EngineExit {
            status: "disconnected",
            detail: "Engine exited on a fatal failure (exit 1); retrying will not change it."
                .to_string(),
        },
        Some(1) => EngineExit {
            status: "error",
            detail: "Fatal failure: the engine refused the session (exit 1). Reconnecting cannot \
                     fix this — check the protocol, ports and identity in Settings."
                .to_string(),
        },
        Some(code) => EngineExit {
            status: if ever_connected {
                "disconnected"
            } else {
                "error"
            },
            detail: if ever_connected {
                format!("Engine exited (status {code})")
            } else {
                format!("The engine stopped unexpectedly (exit {code}); the log has its last line")
            },
        },
        None => EngineExit {
            status: if ever_connected {
                "disconnected"
            } else {
                "error"
            },
            detail: if ever_connected {
                "Engine exited without reporting a status".to_string()
            } else {
                "The engine stopped before reporting a working route and gave no exit status; \
                 whether a retry would help is not known"
                    .to_string()
            },
        },
    }
}

/// The Windows proxy coherence check for one tick.
///
/// Deliberately takes no lifecycle lock: it reads and (when it has to) writes the
/// registry, which is exactly the I/O that used to sit in front of the output
/// pumps. What it must not do is write *after* a teardown decided the session is
/// over, so ownership is re-checked immediately before the re-assert.
#[cfg(windows)]
fn check_proxy_coherence(app: &AppHandle, state: &AppState) {
    let owned =
        || state.proxy_enabled.load(Ordering::SeqCst) && !state.tearing_down.load(Ordering::SeqCst);
    if !owned() {
        return;
    }
    let Some(want) = state.proxy_applied.lock().clone() else {
        return;
    };
    match windows_proxy::read_current().and_then(|current| {
        windows_proxy::verify_readback_values(&want, &current)?;
        Ok(current)
    }) {
        Ok(_) => {
            // The read-back above is a complete check of the values Aether writes
            // and an incomplete check of the route traffic takes: Windows consults
            // a connection's own `DefaultConnectionSettings` ahead of the per-user
            // values, so a machine with a per-connection proxy can satisfy every
            // read while that connection's traffic goes elsewhere. Detecting it is
            // cheap; owning it (writing the blob back) is still T048b.
            static REPORTED: std::sync::atomic::AtomicBool =
                std::sync::atomic::AtomicBool::new(false);
            let telling = || !REPORTED.swap(true, std::sync::atomic::Ordering::SeqCst);
            match windows_proxy::per_connection_conflicts() {
                Ok(conflicts) if conflicts.is_empty() => {}
                Ok(conflicts) => {
                    let listed = conflicts
                        .iter()
                        .map(|c| format!("{} → {}", c.connection, c.effective))
                        .collect::<Vec<_>>()
                        .join(", ");
                    eprintln!("[proxy] a per-connection proxy outranks the system proxy: {listed}");
                    if telling() {
                        emit_log(
                            app,
                            format!(
                                "A per-connection proxy setting on this machine ({listed}) takes \
                                 precedence over the system proxy Aether sets, so traffic on that \
                                 connection may not be routed through it. Full-device (tun) mode \
                                 does not depend on the system proxy."
                            ),
                        );
                    }
                }
                Err(why) => {
                    eprintln!("[proxy] per-connection proxy settings cannot be checked: {why}");
                    if telling() {
                        emit_log(
                            app,
                            format!(
                                "Aether cannot read this machine's per-connection proxy settings \
                                 ({why}), so it cannot promise that every connection follows the \
                                 proxy it set. Full-device (tun) mode does not depend on them."
                            ),
                        );
                    }
                }
            }
        }
        // Something else wrote over our values. Re-asserting is the only honest
        // response: leaving it means the user thinks their traffic is tunneled
        // while it is going out raw.
        Err(drift) => {
            let _operation = state.operation.lock();
            if !owned() {
                return;
            }
            eprintln!("[proxy] {drift}; re-asserting");
            emit_log(
                app,
                format!("The Windows proxy was changed outside Aether ({drift}); re-asserting it"),
            );
            if let Err(error) = windows_proxy::reassert(&want) {
                eprintln!("[proxy] re-assert failed: {error}");
                emit_log(
                    app,
                    format!(
                        "Could not re-assert the Windows proxy: {error}. Traffic may be leaving \
                         unproxied - disconnect and reconnect to reset it."
                    ),
                );
            }
        }
    }
}

/// What the engine's heartbeat pulses say about the session, right now.
fn check_liveness(
    state: &AppState,
    woke_from_sleep: bool,
    stall_reported: &AtomicBool,
) -> Option<Liveness> {
    let status = state.runtime.lock().status.clone();
    let armed = state.connecting.load(Ordering::SeqCst)
        || status.eq_ignore_ascii_case("connecting")
        || status.eq_ignore_ascii_case("connected");
    if !armed {
        stall_reported.store(false, Ordering::SeqCst);
        return None;
    }
    if woke_from_sleep {
        // After OS suspend/resume, grant one heartbeat window from now rather than
        // immediately killing a session whose monotonic clock jumped while asleep.
        let now = std::time::Instant::now();
        let mut beat = state.last_beat.lock();
        if let Some((_, at)) = beat.as_mut() {
            *at = now;
        }
        stall_reported.store(false, Ordering::SeqCst);
        return None;
    }
    let beat = state.last_beat.lock().clone();
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
        Some(detail) if status.eq_ignore_ascii_case("connected") && beat.is_some() => {
            Some(Liveness::StopConnected(detail))
        }
        Some(detail) => {
            if !stall_reported.swap(true, Ordering::SeqCst) {
                Some(Liveness::Report(detail))
            } else {
                None
            }
        }
        None => {
            stall_reported.store(false, Ordering::SeqCst);
            None
        }
    }
}

/// Has the connect watchdog expired for the session that is currently stamped?
///
/// The stamp is taken as the decision is made: this loop runs every 500 ms and a
/// teardown that outlives one tick must not re-fire.
fn connect_watchdog_expired(state: &AppState, session: u64) -> bool {
    let Some((generation, started)) = *state.connect_since.lock() else {
        return false;
    };
    if generation != session {
        // The stamp is from a session this tick has already stopped reasoning
        // about; whatever replaced it has its own clock running.
        return false;
    }
    let status = state.runtime.lock().status.clone();
    let action = connect_watchdog_action(
        Some((generation, started.elapsed())),
        state.generation.load(Ordering::SeqCst),
        &status,
        CONNECT_WATCHDOG_TIMEOUT,
    );
    if action != WatchdogAction::TimedOut {
        return false;
    }
    // Drop only the stamp this decision was taken from: a connect that landed in
    // the meantime owns the field now, and clearing its watchdog would leave a
    // wedged session nothing else in the process will ever stop.
    let mut stamp = state.connect_since.lock();
    if matches!(*stamp, Some((g, _)) if g == generation) {
        *stamp = None;
    }
    true
}

/// Stop a session the supervisor decided is not recoverable, and say why.
///
/// `operation` is held only for the claim — retire the generation, drop the stamps,
/// take the child — and released before the wait, for the reason `disconnect`
/// documents: the output pumps take that lock per line, so holding it across the
/// kill makes the pipes stop draining and the engine stop noticing anything.
fn stop_stalled_session(app: &AppHandle, state: &AppState, reason: &str, session: u64) {
    let child = {
        let _operation = state.operation.lock();
        if state.generation.load(Ordering::SeqCst) != session
            || state.tearing_down.load(Ordering::SeqCst)
        {
            return;
        }
        state.generation.fetch_add(1, Ordering::SeqCst);
        state.connecting.store(false, Ordering::SeqCst);
        state.tearing_down.store(true, Ordering::SeqCst);
        *state.connect_since.lock() = None;
        *state.session_origin.lock() = None;
        *state.last_beat.lock() = None;
        state.child.lock().take()
    };
    if let Some(mut child) = child {
        shutdown_with_grace(&mut child, std::time::Duration::from_secs(2));
    }
    let endpoint = state.runtime.lock().endpoint.clone();
    let problems = cleanup_routing(app, state);
    for problem in &problems {
        crate::startup::note(&format!("[aether] {problem}"));
    }
    let detail = if problems.is_empty() {
        reason.to_string()
    } else {
        format!("{reason} · {}", problems.join(" · "))
    };
    emit_state(app, state, "error", &detail, None, endpoint);
    {
        let _operation = state.operation.lock();
        state.tearing_down.store(false, Ordering::SeqCst);
    }
}

pub(crate) fn watch_child(app: AppHandle) {
    #[cfg(windows)]
    let mut last_coherence = std::time::Instant::now();
    let stall_reported = AtomicBool::new(false);
    let mut last_tick = std::time::Instant::now();
    std::thread::spawn(move || loop {
        std::thread::sleep(std::time::Duration::from_millis(500));
        let tick_gap = last_tick.elapsed();
        last_tick = std::time::Instant::now();
        let woke_from_sleep = tick_gap > std::time::Duration::from_secs(5);
        let state = app.state::<AppState>();
        let session = state.generation.load(Ordering::SeqCst);

        #[cfg(windows)]
        if last_coherence.elapsed() >= PROXY_COHERENCE_INTERVAL {
            last_coherence = std::time::Instant::now();
            check_proxy_coherence(&app, &state);
        }

        match check_liveness(&state, woke_from_sleep, &stall_reported) {
            Some(Liveness::StopConnected(detail)) => {
                emit_log(
                    &app,
                    format!(
                        "Engine stopped reporting on a connected session: {detail}. Stopping it \
                         rather than leaving Windows routed through a tunnel nobody is serving"
                    ),
                );
                stop_stalled_session(
                    &app,
                    &state,
                    &format!("Tunnel stopped: the engine stopped reporting ({detail})"),
                    session,
                );
            }
            Some(Liveness::Report(detail)) => {
                emit_log(
                    &app,
                    format!("Engine stopped reporting while connecting: {detail}"),
                );
            }
            None => {}
        }

        if connect_watchdog_expired(&state, session) {
            let detail = "Connection timed out after 90 s: the engine reported no ready route.";
            emit_log(
                &app,
                format!("{detail} Stopping it so the next connect can start."),
            );
            stop_stalled_session(&app, &state, detail, session);
        }

        let (reaped, uncertain_child) = {
            let mut child_slot = state.child.lock();
            match child_slot.as_mut() {
                None => continue,
                Some(child) => match child.try_wait() {
                    Ok(Some(status)) => {
                        *child_slot = None;
                        if status.success() {
                            (Reaped::Clean, None)
                        } else {
                            (Reaped::Failed(status.code()), None)
                        }
                    }
                    Ok(None) => continue,
                    Err(error) => (Reaped::Lost(error.to_string()), child_slot.take()),
                },
            }
        };
        if let Some(mut child) = uncertain_child {
            let _ = child.kill();
            let _ = child.wait();
        }
        let ever_connected = {
            let _operation = state.operation.lock();
            if state.generation.load(Ordering::SeqCst) != session
                || state.tearing_down.load(Ordering::SeqCst)
            {
                continue;
            }
            state.connecting.store(false, Ordering::SeqCst);
            state.generation.fetch_add(1, Ordering::SeqCst);
            *state.connect_since.lock() = None;
            *state.session_origin.lock() = None;
            *state.last_beat.lock() = None;
            state.connected_once.load(Ordering::SeqCst)
        };
        let problems = cleanup_routing(&app, &state);
        if state.runtime.lock().status.eq_ignore_ascii_case("error") {
            for problem in &problems {
                crate::startup::note(&format!("[aether] {problem}"));
            }
            continue;
        }
        let outcome = match reaped {
            Reaped::Clean => EngineExit {
                status: "disconnected",
                detail: "Engine stopped".to_string(),
            },
            // The engine's own taxonomy: 4 is "this pass failed, another may not",
            // 1 is "the configuration cannot work", and both used to be one message.
            Reaped::Failed(code) => {
                let outcome = engine_exit_outcome(code, ever_connected);
                emit_log(&app, format!("engine exit: {}", outcome.detail));
                outcome
            }
            Reaped::Lost(error) => EngineExit {
                status: if ever_connected {
                    "disconnected"
                } else {
                    "error"
                },
                detail: if ever_connected {
                    format!("Engine lost ({error})")
                } else {
                    format!("Engine lost before connect finished ({error})")
                },
            },
        };
        // What the teardown could not undo belongs in the status line, not only in
        // a log nobody opens.
        let detail = if problems.is_empty() {
            outcome.detail
        } else {
            for problem in &problems {
                crate::startup::note(&format!("[aether] {problem}"));
            }
            format!("{} · {}", outcome.detail, problems.join(" · "))
        };
        emit_state(&app, &state, outcome.status, &detail, None, None);
    });
}

/// Whether a connect may replace `settings.json` with the settings it was given.
///
/// The window's form and a tray read that succeeded are the user's configuration
/// and replace the file as they always have. A tray read that failed fills the gap
/// with `Settings::default()` only so a session can start; those built-in defaults
/// must never become the file the user opens next, or the corrupt file they could
/// have repaired is gone.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum PersistSettings {
    Yes,
    No,
}

/// `connect`'s body: icacls, DPAPI, a multi-megabyte SHA-256, a signed-binary
/// PowerShell query and the engine spawn. Always runs off the UI thread — via
/// [`crate::command_blocking`] for the IPC path, and on a dedicated thread for the
/// tray menu item.
///
/// `source`/`provenance` are recorded with the settings that were used, because
/// there are two drivers of one engine: the window sends its form state, the tray
/// can only read `settings.json`, and `busy` lives in the frontend. A session that
/// cannot be attributed to the configuration it started with cannot be diagnosed.
pub(crate) fn connect_blocking(
    app: AppHandle,
    settings: Settings,
    source: &'static str,
    provenance: &'static str,
    persist: PersistSettings,
) -> Result<(), CommandError> {
    let state = app.state::<AppState>();
    let _operation = state.operation.lock();
    if state.exiting.load(Ordering::SeqCst) {
        return Err("Aether is shutting down.".into());
    }
    if state.tearing_down.load(Ordering::SeqCst) {
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
        stop_scan_child(&state.scan_child);
        if state.child.lock().is_some() {
            return Err("Aether is already running".into());
        }
        validate_settings(&settings)?;
        if persist == PersistSettings::Yes {
            save_settings_file(&app, &settings)?;
            #[cfg(windows)]
            autostart::set(settings.launch_at_login)?;
        }

        if settings.routing_mode == RoutingMode::Tun {
            #[cfg(windows)]
            {
                if !elevation::is_elevated() {
                    return Err(CommandError::new(
                        "permission_denied",
                        "Full-device TUN needs Administrator. Quit Aether Next from the system tray, then right-click → Run as administrator.",
                    ));
                }
                if wintun_path(&app).is_none() {
                    return Err(CommandError::new(
                        "not_found",
                        "wintun.dll not found. Reinstall Aether Next or place wintun.dll next to the app.",
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

        let mut wintun_for_handoff: Option<PathBuf> = None;
        #[cfg(windows)]
        let mut wintun_guard: Option<fs::File> = None;
        if settings.routing_mode == RoutingMode::Tun {
            let wintun = wintun_path(&app).ok_or_else(|| {
                CommandError::new(
                    "not_found",
                    "wintun.dll is missing from the install directory; TUN cannot start and the \
                     driver will not be loaded from anywhere else",
                )
            })?;
            let wintun_policy = TrustedBinaryPolicy::for_wintun();
            let verified_driver = verify_elevated_binary(&wintun, "wintun.dll", &wintun_policy)
                .map_err(CommandError::from)?;
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
            wintun_for_handoff = Some(wintun.canonicalize().unwrap_or(wintun));
            #[cfg(windows)]
            {
                wintun_guard = Some(verified_driver);
            }
        }

        let mut dpapi_key = dpapi::get_or_create_dpapi_config_key(&dir)?;
        let canonical_exe = executable.canonicalize().unwrap_or(executable);
        let engine_guard = verify_engine_or_refuse(&canonical_exe)?;
        let mut command = Command::new(&canonical_exe);
        scrub_ambient_engine_env(&mut command);
        command
            .current_dir(canonical_exe.parent().unwrap_or(std::path::Path::new(".")))
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
            .env("AETHER_MASQUE_H2_FRAGMENT", "0")
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
        drop(engine_guard);
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
        // What is now running, and who asked for it. Every later teardown —
        // `disconnect`, the tray, an exit — reports against this rather than
        // against whatever the form holds at that moment.
        *state.session_origin.lock() = Some(SessionOrigin {
            source,
            provenance,
            settings: settings.clone(),
            started: std::time::Instant::now(),
        });

        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        #[cfg(windows)]
        {
            // The supervisor may reap a fast-failing child as soon as it sees
            // the slot. Publish its driver guard first, so that cleanup cannot
            // run between child publication and guard publication.
            *state.wintun_guard.lock() = wintun_guard;
        }
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

pub(crate) fn disconnect_blocking(app: AppHandle) -> Result<(), CommandError> {
    let state = app.state::<AppState>();
    let mut child = {
        let _operation = state.operation.lock();
        if state.tearing_down.swap(true, Ordering::SeqCst) {
            // A disconnect is already running; do not drop its Job handle or clear
            // `tearing_down` underneath its 15s route-teardown grace window.
            drop(_operation);
            while state.tearing_down.load(Ordering::SeqCst) {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            return Ok(());
        }
        state.generation.fetch_add(1, Ordering::SeqCst);
        state.connecting.store(false, Ordering::SeqCst);
        *state.connect_since.lock() = None;
        *state.last_beat.lock() = None;
        *state.session_origin.lock() = None;
        state.child.lock().take()
    };
    let outcome = (|| -> Result<(), CommandError> {
        let mut problems: Vec<String> = Vec::new();
        if let Some(child) = child.as_mut() {
            if let Some(mut stdin) = child.stdin.take() {
                let _ = stdin.write_all(b"shutdown\n");
                let _ = stdin.flush();
            }
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
        problems.extend(cleanup_routing(&app, &state));

        if problems.is_empty() {
            emit_state(&app, &state, "disconnected", "Ready", None, None);
            return Ok(());
        }
        let detail = problems.join(" · ");
        eprintln!("[aether] disconnect incomplete: {detail}");
        emit_state(&app, &state, "disconnected", &detail, None, None);
        Err(CommandError::new("disconnect_incomplete", detail))
    })();
    {
        let _operation = state.operation.lock();
        state.tearing_down.store(false, Ordering::SeqCst);
    }
    outcome
}

#[cfg(windows)]
pub(crate) fn spawn_route_repair(app: &AppHandle) {
    let settings = load_settings_or_defaults(app);
    let Ok(executable) = engine_path(app, &settings) else {
        return;
    };
    let canonical_exe = executable.canonicalize().unwrap_or(executable);
    let Ok(engine_guard) = verify_engine_or_refuse(&canonical_exe) else {
        return;
    };
    let Ok(job) = engine_job::Job::create() else {
        return;
    };
    let mut command = Command::new(&canonical_exe);
    scrub_ambient_engine_env(&mut command);
    command
        .arg("--repair-routes")
        .current_dir(canonical_exe.parent().unwrap_or(Path::new(".")))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
    }
    match command.spawn() {
        Ok(mut child) => {
            drop(engine_guard);
            let _ = job.assign_child(&child);
            std::thread::spawn(move || {
                let _job = job;
                let _ = child.wait();
            });
        }
        Err(e) => {
            drop(engine_guard);
            emit_log(app, format!("Could not start the route repair: {e}"));
        }
    }
}
