//! The engine-event mirror and its dispatch.
//!
//! One place decides what a line from the engine means for the UI: the structured
//! `AETHER_EVENT` payload for every state the shell acts on, the log level for
//! the activity stream, and prose only where the wording *is* the payload (a
//! failed probe reported inside a session that is still alive).
use crate::settings::{RoutingMode, Settings};
use crate::state::{emit_log, emit_state, AppState};
use crate::supervision::{cleanup_routing, mark_connected};
use serde::Deserialize;
use std::sync::atomic::{AtomicBool, Ordering};
use tauri::{AppHandle, Emitter, Manager};

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
pub(crate) enum EngineEvent {
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

pub(crate) fn note_malformed_event(app: &AppHandle, detail: String) {
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
pub(crate) fn handle_engine_line(
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
    //
    // The guard below used to keep one exception: while not connected it wrote the
    // prose straight into runtime state as `error`. That is the same claim the
    // structured path already makes - so a failed probe during a scan, whose
    // session state is "connecting" or "disconnected", put an error on the UI for
    // something that was never a tunnel attempt. Now it is always a log line, and
    // the state answer comes only from events that know the outcome.
    if let Some(msg) = line
        .split("[-] session failed:")
        .nth(1)
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        emit_log(app, format!("engine reported a failed session ({msg})"));
    }
    // Readiness has exactly one source: the structured `ProxyReady`,
    // `TunnelReady` and `TunReady` events handled above, which the engine emits
    // on every path that reaches those states. Below this line used to sit a
    // second, parallel answer — `socks5 listening on`, `data-plane verified`,
    // `handshake successful`, `[tun] bridge active`, and four English phrases that
    // mined the endpoint out of a log line — and it was load-bearing only because
    // it agreed by luck. A reword on the engine's side did not fail anything: it
    // left the endpoint out of the UI, or a tunnel marked ready before its
    // data-plane existed, with no error on either side of the boundary. Prose is
    // still read for one thing only, above: the banner for a failed probe inside
    // a live session, where the wording is the payload.

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
    } else if line.contains(" INFO ")
        || line.starts_with("INFO ")
        || line.contains(" DEBUG ")
        || line.starts_with("DEBUG ")
        || line.contains(" TRACE ")
        || line.starts_with("TRACE ")
    {
        Some("info")
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
