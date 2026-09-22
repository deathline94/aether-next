use serde::Serialize;

/// Structured events for GUI/CLI consumers. Printed as one JSON line:
/// `AETHER_EVENT {...}`
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SessionEvent {
    IdentityReady {
        device_id: String,
        ipv4: String,
    },
    EndpointSelected {
        addr: String,
        protocol: String,
        /// RTT of the probe that proved this endpoint, in milliseconds.
        /// `None` when the peer was forced from config or reused from the
        /// quick-reconnect cache without a fresh measurement — the UI shows
        /// "not measured", never 0 ms.
        rtt_ms: Option<f64>,
    },
    ProxyReady {
        socks: String,
        http: String,
    },
    TunnelReady {
        transport: String,
    },
    #[allow(dead_code)]
    TunReady,
    Connected {
        detail: String,
    },
    Error {
        message: String,
    },
    /// Liveness pulse, emitted while the session is **making progress**.
    ///
    /// It used to be a free-running timer on its own task, which meant a session
    /// parked forever on a hung await kept pulsing exactly as brightly as one that
    /// was working. Absence of pulses now means the session loop has not advanced,
    /// which is the only thing the pulse was ever supposed to say.
    Heartbeat {
        seq: u64,
        phase: &'static str,
    },
    // ─── Scan-only mode events ──────────────────────────────────────────────
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
        /// Measured RTT of the endpoint this scan settled on, in milliseconds.
        /// `None` when the peer was forced from config and nothing was probed —
        /// never a zero, which the UI would render as a real 0 ms.
        best_rtt_ms: Option<f64>,
    },
}

pub fn emit(event: SessionEvent) {
    // Any event other than the pulse is the session doing something, so it is
    // progress. `Heartbeat` is excluded because it is emitted *from* the pulse
    // loop: marking progress there would keep a wedged session pulsing forever,
    // which is the exact bug this rule removes.
    if !matches!(event, SessionEvent::Heartbeat { .. }) {
        mark_progress();
    }
    match serde_json::to_string(&event) {
        Ok(json) => {
            // Write structured events to STDOUT (one line, flushed immediately) rather
            // than the stderr logger. GUI consumers read stdout for live progress; the
            // desktop scan reader drains stdout first, so events on stderr only surfaced
            // after the process exited (scanner looked frozen until Stop). stdout is a
            // LineWriter behind a pipe, so an explicit flush guarantees each event ships
            // the instant it is emitted.
            use std::io::Write;
            let out = std::io::stdout();
            let mut lock = out.lock();
            let _ = writeln!(lock, "AETHER_EVENT {json}");
            let _ = lock.flush();
        }
        Err(e) => {
            // An event that cannot be serialised never reaches the GUI, so the
            // consumer's "did anything happen?" answer would be "nothing". Count
            // it instead of dropping it silently.
            let n = crate::counters::bump(&crate::counters::MALFORMED_EVENTS);
            log::error!("[-] could not serialise a session event (count {n}): {e}");
        }
    }
}

/// Emitted at most this often. Below the shell's 15 s stall threshold so three
/// consecutive misses is unambiguous rather than a scheduling hiccup.
pub const HEARTBEAT_INTERVAL: std::time::Duration =
    std::time::Duration::from_secs(5);

/// Coarse session progress, reported with every heartbeat.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Starting,
    Identity,
    SelectingEndpoint,
    Handshake,
    Tunnel,
    Scan,
}

impl Phase {
    pub fn label(self) -> &'static str {
        match self {
            Phase::Starting => "starting",
            Phase::Identity => "identity",
            Phase::SelectingEndpoint => "selecting_endpoint",
            Phase::Handshake => "handshake",
            Phase::Tunnel => "tunnel",
            Phase::Scan => "scan",
        }
    }

    fn from_index(v: u8) -> Self {
        match v {
            1 => Phase::Identity,
            2 => Phase::SelectingEndpoint,
            3 => Phase::Handshake,
            4 => Phase::Tunnel,
            5 => Phase::Scan,
            _ => Phase::Starting,
        }
    }
}

static PHASE: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

pub fn set_phase(phase: Phase) {
    PHASE.store(phase as u8, std::sync::atomic::Ordering::Relaxed);
    mark_progress();
}

pub fn current_phase() -> Phase {
    Phase::from_index(PHASE.load(std::sync::atomic::Ordering::Relaxed))
}

/// Monotonic count of things the session has *done*. Not a clock: the pulse asks
/// "has anything happened since the last one", and a counter answers that without
/// depending on wall-clock direction.
static PROGRESS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Record that the session made a forward step. Call it at every point that can
/// legitimately take a while and is, in fact, progressing — a phase change, an
/// event, a tunnel supervision pass. Long-running awaits that do *not* call it are
/// exactly what the pulse is supposed to notice.
pub fn mark_progress() {
    PROGRESS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}

/// The current progress stamp.
pub fn progress_stamp() -> u64 {
    PROGRESS.load(std::sync::atomic::Ordering::Relaxed)
}

/// Decides whether one heartbeat tick earns a pulse.
///
/// Split out from the task so "a stalled loop stops pulsing" is testable without
/// a runtime and without a fake session.
#[derive(Debug, Default)]
pub struct PulseGate {
    seen: u64,
    seq: u64,
}

impl PulseGate {
    /// `Some(seq)` when `stamp` moved since the last tick, `None` when it did not.
    pub fn tick(&mut self, stamp: u64) -> Option<u64> {
        if stamp == self.seen {
            return None;
        }
        self.seen = stamp;
        self.seq += 1;
        Some(self.seq)
    }
}

/// Owns the heartbeat task and stops it when dropped, so a session that returns
/// or unwinds cannot keep pulsing.
pub struct Heartbeat(tokio::task::JoinHandle<()>);

impl Drop for Heartbeat {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Pulses actually emitted, so the wiring between the gate and the task is
/// observable. Without this the gate has a unit test and the loop it guards does
/// not, which is how a "fixed" pulse can stay unfixed.
static PULSES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

#[cfg(test)]
pub fn pulse_count() -> u64 {
    PULSES.load(std::sync::atomic::Ordering::Relaxed)
}

/// Start the phase heartbeat. The first tick fires immediately, so a consumer
/// sees proof of life at startup instead of after five silent seconds.
pub fn start_heartbeat() -> Heartbeat {
    start_heartbeat_in(HEARTBEAT_INTERVAL)
}

fn start_heartbeat_in(interval: std::time::Duration) -> Heartbeat {
    Heartbeat(tokio::spawn(async move {
        let mut tick = tokio::time::interval(interval);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut gate = PulseGate::default();
        // Starting the session is itself a step, so the first tick pulses.
        mark_progress();
        loop {
            tick.tick().await;
            if let Some(seq) = gate.tick(progress_stamp()) {
                PULSES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                emit(SessionEvent::Heartbeat {
                    seq,
                    phase: current_phase().label(),
                });
            }
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::{mark_progress, progress_stamp, Phase, PulseGate, HEARTBEAT_INTERVAL};

    /// The progress stamp is process-global, so the tests that reason about it
    /// cannot run concurrently with each other.
    static PROGRESS_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

    #[test]
    fn every_phase_has_a_stable_label() {
        let _g = PROGRESS_LOCK.lock();
        let labels = [
            Phase::Starting,
            Phase::Identity,
            Phase::SelectingEndpoint,
            Phase::Handshake,
            Phase::Tunnel,
            Phase::Scan,
        ]
        .iter()
        .map(|p| p.label())
        .collect::<Vec<_>>();
        let mut unique = labels.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), labels.len(), "phase labels must be distinct");
        // Round-trips through the atomic encoding the heartbeat task reads.
        for p in [Phase::Starting, Phase::Scan, Phase::Handshake, Phase::Tunnel] {
            super::set_phase(p);
            assert_eq!(super::current_phase(), p);
        }
    }

    #[test]
    fn heartbeat_interval_is_under_the_shell_stall_window() {
        // The shell declares a stall after 3 misses; that only leaves a window
        // worth acting on if three pulses genuinely fit inside it.
        assert!(HEARTBEAT_INTERVAL * 3 < std::time::Duration::from_secs(30));
    }

    /// The gate is what makes the pulse mean something: a tick that saw no
    /// progress must not pulse.
    #[test]
    fn the_pulse_gate_only_moves_with_progress() {
        let mut gate = PulseGate::default();
        assert_eq!(gate.tick(1), Some(1));
        assert_eq!(gate.tick(1), None, "an idle tick must not pulse");
        assert_eq!(gate.tick(1), None);
        assert_eq!(gate.tick(2), Some(2));
        assert_eq!(gate.tick(5), Some(3), "any advance counts, not only +1");
        assert_eq!(gate.tick(5), None);
    }

    /// The finding this pins: the heartbeat used to be a free-running timer on an
    /// independent task, so a session parked on a hung await kept pulsing and the
    /// shell saw a live session forever. A loop that stops marking progress must
    /// stop the pulse, and marking again must restart it.
    #[tokio::test]
    async fn a_stalled_loop_stops_pulsing() {
        use std::time::Duration;
        let _g = PROGRESS_LOCK.lock();

        let _hb = super::start_heartbeat_in(Duration::from_millis(10));
        // The startup mark is a step, so the very first tick pulses.
        tokio::time::sleep(Duration::from_millis(80)).await;
        let after_start = pulse_count();
        assert!(
            after_start >= 1,
            "the first pulse never arrived: {after_start}"
        );

        // Nothing progresses for many intervals.
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(
            pulse_count(),
            after_start,
            "a session that did nothing still pulsed"
        );

        mark_progress();
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert!(
            pulse_count() > after_start,
            "progress did not resume the pulse"
        );
    }

    /// A phase transition is progress, and the consumer must never be told a
    /// session is alive by the pulse it is itself emitting.
    #[test]
    fn setting_a_phase_counts_as_progress_and_a_pulse_does_not() {
        let _g = PROGRESS_LOCK.lock();
        let before = progress_stamp();
        super::set_phase(Phase::Tunnel);
        assert_eq!(progress_stamp(), before + 1);
        super::emit(super::SessionEvent::Heartbeat {
            seq: 1,
            phase: "tunnel",
        });
        assert_eq!(
            progress_stamp(),
            before + 1,
            "the pulse must not manufacture its own progress"
        );
        super::emit(super::SessionEvent::TunnelReady {
            transport: "test".into(),
        });
        assert_eq!(progress_stamp(), before + 2, "a real event is progress");
    }
}
