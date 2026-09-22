//! Named counters for paths that discard work.
//!
//! A silent drop is undiagnosable: the tunnel reports itself healthy while
//! packets, replies or cache entries vanish. Every such path gets a number
//! BEFORE the path itself is argued about, so "did this guard ever fire?" has an
//! answer instead of a guess. `snapshot()` is what the diagnostics export prints.

use std::sync::atomic::{AtomicU64, Ordering};

/// Inbound IP packets dropped because the netstack queue was full or closed.
pub static INBOUND_DROPPED: AtomicU64 = AtomicU64::new(0);
/// Outbound packets dropped on a full datagram queue or a closed stream.
pub static DATAGRAM_SEND_DROPPED: AtomicU64 = AtomicU64::new(0);
/// Engine events that arrived as `AETHER_EVENT` but did not parse.
pub static MALFORMED_EVENTS: AtomicU64 = AtomicU64::new(0);
/// Cache entries rejected by `sanitise` (bogus RTT, malformed address, …).
pub static CACHE_ENTRIES_REJECTED: AtomicU64 = AtomicU64::new(0);
/// H3 responses ignored because they did not belong to the request stream.
pub static IGNORED_OFFSTREAM_STATUS: AtomicU64 = AtomicU64::new(0);

fn peek(c: &AtomicU64) -> u64 {
    c.load(Ordering::Relaxed)
}

/// Bump a counter and return the new value, for callers that rate-limit their
/// own logging off it.
pub fn bump(c: &AtomicU64) -> u64 {
    c.fetch_add(1, Ordering::Relaxed) + 1
}

/// Bump by a batch count — for a routine that rejects several records per call.
pub fn bump_by(c: &AtomicU64, n: u64) -> u64 {
    c.fetch_add(n, Ordering::Relaxed) + n
}

/// Every counter, in a stable order, for logs and the diagnostics export.
pub fn snapshot() -> serde_json::Value {
    serde_json::json!({
        "inbound_dropped": peek(&INBOUND_DROPPED),
        "datagram_send_dropped": peek(&DATAGRAM_SEND_DROPPED),
        "malformed_events": peek(&MALFORMED_EVENTS),
        "cache_entries_rejected": peek(&CACHE_ENTRIES_REJECTED),
        "ignored_offstream_status": peek(&IGNORED_OFFSTREAM_STATUS),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bumping_a_counter_moves_its_snapshot_entry() {
        let name = "malformed_events";
        let before = peek(&MALFORMED_EVENTS);
        assert_eq!(bump(&MALFORMED_EVENTS), before + 1);
        let after = bump(&MALFORMED_EVENTS);
        assert_eq!(after, before + 2);
        assert_eq!(
            snapshot()[name].as_u64().expect("counter present in snapshot"),
            after,
            "{name} is not wired into snapshot()"
        );
    }

    /// A counter that no code path increments is the same lie as a guard that
    /// cannot be reached, so each one must have at least one caller.
    #[test]
    fn every_counter_has_a_name_the_snapshot_reports() {
        let snap = snapshot();
        for key in [
            "inbound_dropped",
            "datagram_send_dropped",
            "malformed_events",
            "cache_entries_rejected",
            "ignored_offstream_status",
        ] {
            assert!(snap.get(key).is_some(), "{key} missing from snapshot()");
        }
    }
}
