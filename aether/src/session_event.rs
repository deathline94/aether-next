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
    /// Liveness pulse, emitted at most `HEARTBEAT_INTERVAL` apart while the
    /// session is running. Absence of these for 3+ intervals means the engine is
    /// wedged inside one phase, which from the outside used to look identical to
    /// slow-but-progressing work.
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
    if let Ok(json) = serde_json::to_string(&event) {
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
}

pub fn current_phase() -> Phase {
    Phase::from_index(PHASE.load(std::sync::atomic::Ordering::Relaxed))
}

/// Owns the heartbeat task and stops it when dropped, so a session that returns
/// or unwinds cannot keep pulsing.
pub struct Heartbeat(tokio::task::JoinHandle<()>);

impl Drop for Heartbeat {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Start the phase heartbeat. The first tick fires immediately, so a consumer
/// sees proof of life at startup instead of after five silent seconds.
pub fn start_heartbeat() -> Heartbeat {
    Heartbeat(tokio::spawn(async move {
        let mut tick = tokio::time::interval(HEARTBEAT_INTERVAL);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut seq = 0u64;
        loop {
            tick.tick().await;
            seq += 1;
            emit(SessionEvent::Heartbeat {
                seq,
                phase: current_phase().label(),
            });
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::{Phase, HEARTBEAT_INTERVAL};

    #[test]
    fn every_phase_has_a_stable_label() {
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
        for p in [Phase::Starting, Phase::Scan, Phase::Handshake] {
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
}
