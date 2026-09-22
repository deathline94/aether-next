//! The scan child: a second engine process in `--scan-only` shape, its own
//! output pump that turns `AETHER_EVENT` lines into `scan://event`, and the
//! cooperative cancel that lets it persist its best-so-far.
use crate::acl::restrict_directory_acl;
use crate::dpapi;
use crate::engine::{engine_path, handoff_preamble, scrub_ambient_engine_env};
use crate::error::CommandError;
use crate::events::{note_malformed_event, EngineEvent};
use crate::settings::{config_dir, load_settings_file, validated_noize, IpVersion};
use crate::state::{emit_log, AppState};
use crate::trust::verify_engine_or_refuse;
use parking_lot::Mutex;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tauri::{AppHandle, Emitter, Manager};
use zeroize::Zeroize;

/// `scan`'s body: it takes the operation lock, stops the running scan (up to the
/// cancel grace window), runs `icacls`, unwraps the DPAPI key and hashes the
/// engine, so it cannot run on the UI thread.
#[allow(clippy::too_many_arguments)] // seven, all of them the frontend's own call shape
pub(crate) fn scan_blocking(
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
    let stream_failed = Arc::new(AtomicBool::new(false));
    let mut handles = Vec::new();
    if let Some(o) = stdout {
        handles.push(pump_scan_stream(
            app.clone(),
            run_id.clone(),
            Box::new(o),
            terminal_sent.clone(),
            hits.clone(),
            stream_failed.clone(),
        ));
    }
    if let Some(e) = stderr {
        handles.push(pump_scan_stream(
            app.clone(),
            run_id.clone(),
            Box::new(e),
            terminal_sent.clone(),
            hits.clone(),
            stream_failed.clone(),
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
            stream_failed.load(Ordering::SeqCst),
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
pub fn scan_terminal_event(
    terminal_sent: bool,
    hits: u64,
    output_stream_failed: bool,
) -> Option<serde_json::Value> {
    if terminal_sent {
        return None;
    }
    let message = if output_stream_failed {
        // Named separately because the remedy is different: the shell stopped
        // reading this run's output, so nothing about the engine's own result is
        // known, and "the process ended without reporting a result" would send a
        // reader to the engine log for a fault in this process.
        let kept = if hits == 0 {
            "no working endpoint had been found".to_string()
        } else {
            format!("{hits} working endpoint(s) were already found and are kept")
        };
        format!("the scan's output stream failed in the shell while the run was active; {kept}")
    } else if hits == 0 {
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
pub(crate) fn emit_scan_event(app: &AppHandle, run_id: &str, event: serde_json::Value) {
    let mut event = event;
    if let Some(obj) = event.as_object_mut() {
        obj.insert(
            "runId".to_string(),
            serde_json::Value::String(run_id.to_string()),
        );
    }
    let _ = app.emit("scan://event", event);
}

/// One step of reading a scan output pipe.
enum ScanLine {
    Line(String),
    /// The stream is over: either the child closed it, or reading it failed.
    End,
}

/// Read the next line, separating "the child closed this pipe" from "the read
/// failed".
///
/// `.map_while(Result::ok)` — what this replaced — treated the two as the same
/// event with no message and no state change, so a scan whose pipe broke
/// mid-flight simply stopped forwarding events while the UI kept the run open and
/// was eventually told "the scan process ended without reporting a result". That
/// sentence blames the engine for a failure in this process, which is why the
/// distinction is recorded in `stream_failed` as well as in the log.
fn scan_line(
    app: &AppHandle,
    lines: &mut std::io::Lines<BufReader<Box<dyn std::io::Read + Send>>>,
    stream_failed: &AtomicBool,
) -> ScanLine {
    match lines.next() {
        Some(Ok(line)) => ScanLine::Line(line),
        // Clean EOF: the scan child closed the pipe, which is the normal end of a
        // stream and needs no announcement — the terminal event covers it.
        None => ScanLine::End,
        Some(Err(error)) => {
            stream_failed.store(true, Ordering::SeqCst);
            emit_log(app, format!("ERROR scan output pipe failed ({error})"));
            ScanLine::End
        }
    }
}

fn pump_scan_stream(
    app: AppHandle,
    run_id: String,
    reader: Box<dyn std::io::Read + Send>,
    terminal_sent: Arc<AtomicBool>,
    hits: Arc<AtomicU64>,
    stream_failed: Arc<AtomicBool>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let mut lines = BufReader::new(reader).lines();
        while let ScanLine::Line(line) = scan_line(&app, &mut lines, &stream_failed) {
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
pub(crate) fn stop_scan_child(scan_child: &Mutex<Option<Child>>) {
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

/// `stop_scan`'s body. `stop_scan_child` busy-waits up to the full cancel grace
/// window, so this must not run on the UI thread.
pub(crate) fn stop_scan_blocking(app: AppHandle) -> Result<(), CommandError> {
    let state = app.state::<AppState>();
    // Serialize with connect/disconnect (QA-5) and cancel gracefully (QA-1).
    let _operation = state.operation.lock();
    stop_scan_child(&state.scan_child);
    Ok(())
}
