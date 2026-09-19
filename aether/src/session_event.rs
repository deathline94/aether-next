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
