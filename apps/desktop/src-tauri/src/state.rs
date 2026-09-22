//! Process-wide session state, and the two channels the webview listens to.
//!
//! `AppState` is what every command, the tray and the three background threads
//! (`watch_child`, the engine output pumps, the scan pumps) share. Its fields are
//! `pub(crate)` rather than private because the supervision, scan and event paths
//! all have to take the same locks, and a per-field accessor layer would only hide
//! *which* lock a caller is holding — the one question every deadlock report needs.

use crate::settings::Settings;
use parking_lot::Mutex;
use serde::Serialize;
use std::process::Child;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use tauri::{AppHandle, Emitter, Manager};

#[cfg(windows)]
use crate::engine_job;
#[cfg(windows)]
use crate::proxy::windows_proxy;

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RuntimeState {
    pub(crate) status: String,
    pub(crate) detail: String,
    pub(crate) pid: Option<u32>,
    pub(crate) endpoint: Option<String>,
    /// RTT of the probe that proved the endpoint this session selected, in ms.
    /// `None` until something has actually been measured -- the UI renders that
    /// as "not measured" rather than 0 ms, which would read as an excellent link.
    pub(crate) handshake_rtt_ms: Option<u32>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LogEvent {
    pub(crate) level: String,
    pub(crate) message: String,
}

/// Which settings a live session was started from, and who asked for it.
///
/// The tray menu and the webview are two independent drivers of the same engine:
/// the tray can only read `settings.json`, while the form holds edits for up to
/// the 400 ms debounce (and indefinitely while a save is failing). Recording the
/// origin makes the two agreeable *in the log* — see [`crate::supervision`]'s tray
/// path — instead of leaving a session whose configuration nobody can name.
pub(crate) struct SessionOrigin {
    /// `"window"` for the IPC command, `"tray"` for the tray menu.
    pub(crate) source: &'static str,
    /// Where those settings came from: the on-disk file, or the caller's payload.
    pub(crate) provenance: &'static str,
    pub(crate) settings: Settings,
    pub(crate) started: std::time::Instant,
}

pub(crate) struct AppState {
    pub(crate) child: Mutex<Option<Child>>,
    pub(crate) scan_child: Mutex<Option<Child>>,
    pub(crate) runtime: Mutex<RuntimeState>,
    pub(crate) proxy_enabled: AtomicBool,
    #[cfg(windows)]
    pub(crate) proxy_snapshot: Mutex<Option<windows_proxy::ProxySnapshot>>,
    /// What this session wrote to the registry, kept so a drift check can tell
    /// "someone else changed the proxy" from "we never set it".
    #[cfg(windows)]
    pub(crate) proxy_applied: Mutex<Option<windows_proxy::ProxySnapshot>>,
    pub(crate) connected_once: AtomicBool,
    pub(crate) connecting: AtomicBool,
    /// Set for the whole of a teardown's child wait. `disconnect` must not hold
    /// `operation` across that wait (the output pumps take it per line, so the
    /// pipes would stop being drained), which reopens the window the old comment
    /// called M7: a connect slipping in mid-teardown. This flag is what closes it
    /// again without the lock.
    pub(crate) tearing_down: AtomicBool,
    pub(crate) generation: AtomicU64,
    /// `(generation, when)` for the session currently in `connecting`. The
    /// watchdog in `watch_child` fires only while the generation still matches,
    /// so a session that reached any terminal state leaves the stamp inert.
    pub(crate) connect_since: Mutex<Option<(u64, std::time::Instant)>>,
    /// `(phase, when)` from the engine's last `heartbeat` event. The engine used
    /// to be silent for the whole multi-second endpoint hunt, which from the GUI
    /// side is indistinguishable from a hang; absence of pulses now says so.
    pub(crate) last_beat: Mutex<Option<(String, std::time::Instant)>>,
    /// Kept outside `RuntimeState` so the many `emit_state` callers cannot drop a
    /// measurement that arrived after they were written.
    pub(crate) handshake_rtt_ms: Mutex<Option<u32>>,
    pub(crate) operation: Mutex<()>,
    #[cfg(windows)]
    pub(crate) job: Mutex<Option<engine_job::Job>>,
    /// The settings and driver behind the running session, for the tray path and
    /// for any later "what was I running?" question.
    pub(crate) session_origin: Mutex<Option<SessionOrigin>>,
    /// `session://log` lines emitted before the webview subscribed.
    pub(crate) pending_logs: Mutex<Vec<LogEvent>>,
    /// Flipped by the first boot command, which can only reach the shell once the
    /// page has registered its listeners.
    pub(crate) log_ready: AtomicBool,
    /// Set when an exit has been asked for, so `CloseRequested` stops swallowing
    /// the close and the teardown in [`crate::tray`] runs exactly once.
    pub(crate) exiting: AtomicBool,
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
            session_origin: Mutex::new(None),
            pending_logs: Mutex::new(Vec::new()),
            log_ready: AtomicBool::new(false),
            exiting: AtomicBool::new(false),
        }
    }
}

pub(crate) fn emit_state(
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

/// How many pre-subscribe log lines are held.
///
/// Bounded because the buffer is written by the same path a chatty engine drives;
/// dropping the oldest is better than an unbounded queue in a tray-resident
/// process, and the lines that matter at startup are the first ones.
const PENDING_LOG_LIMIT: usize = 256;

/// Send one line to the activity log.
///
/// `setup()` reports proxy recovery, route repair and the corrupted-settings
/// outcome before the webview has called `listen("session://log")` — the listener
/// is registered by a React effect that runs after the page boots — so those lines
/// used to be emitted into nothing. The messages a user needs when the app
/// "appears to do nothing" on start were precisely the ones nobody could see.
/// Lines emitted before [`note_webview_ready`] are buffered and flushed in order
/// when the first boot command lands; [`crate::startup`] mirrors them to a log
/// file, which is the channel that survives a webview that never came up at all.
pub(crate) fn emit_log(app: &AppHandle, line: String) {
    let event = LogEvent {
        level: crate::events::log_level_for(&line).into(),
        message: line,
    };
    let state = app.state::<AppState>();
    if !state.log_ready.load(Ordering::SeqCst) {
        let mut pending = state.pending_logs.lock();
        // Re-check under the lock: `note_webview_ready` holds this same lock across
        // its flush, so either this line joins the buffer before it drains or it
        // goes out directly after it — the order the UI sees is the order emitted.
        if !state.log_ready.load(Ordering::SeqCst) {
            crate::startup::note(&event.message);
            pending.push(event);
            if pending.len() > PENDING_LOG_LIMIT {
                pending.remove(0);
            }
            return;
        }
    }
    let _ = app.emit("session://log", event);
}

/// The page is up and its listeners are registered: deliver what was buffered.
///
/// Called from the boot commands the frontend issues *after* it has awaited
/// `listen("session://state")` and `listen("session://log")` (see
/// `apps/desktop/src/hooks/useRuntime.ts`), which is the only readiness signal the
/// shell gets without changing the IPC contract. Idempotent and cheap: once the
/// flag is set every later line goes straight out.
pub(crate) fn note_webview_ready(app: &AppHandle) {
    let state = app.state::<AppState>();
    // The guard is held across the flush, not just across the swap: `emit_log`
    // re-checks readiness under this same lock, so a line emitted while the page is
    // being caught up cannot overtake the older ones behind it. No listener in this
    // process subscribes to `session://log`, so nothing reachable from `emit` can
    // re-enter this lock. Calling it twice is a no-op — the buffer is empty.
    let mut pending = state.pending_logs.lock();
    state.log_ready.store(true, Ordering::SeqCst);
    let buffered = std::mem::take(&mut *pending);
    for event in buffered {
        let _ = app.emit("session://log", event);
    }
}
