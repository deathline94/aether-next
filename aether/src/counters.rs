//! Named counters for paths that discard work.
//!
//! A silent drop is undiagnosable: the tunnel reports itself healthy while
//! packets, replies or cache entries vanish. Every such path gets a number
//! BEFORE the path itself is argued about, so "did this guard ever fire?" has an
//! answer instead of a guess. `snapshot()` is what the diagnostics export prints.
//!
//! The counter, its snapshot key and the exported table all come from the one
//! `counters!` invocation below. Declaring a counter anywhere else is a compile
//! error, and forgetting its key is a failing test — a list of names repeated
//! under the `json!` macro can never disagree with it, so it can never fail
//! either.

use std::sync::atomic::{AtomicU64, Ordering};

macro_rules! counters {
    ($( #[doc = $doc:literal] $name:ident => $key:literal, )*) => {
        $(
            #[doc = $doc]
            pub static $name: AtomicU64 = AtomicU64::new(0);
        )*

        /// Every counter, in a stable order, for logs and the diagnostics export.
        pub fn snapshot() -> serde_json::Value {
            serde_json::json!({
                $( $key: peek(&$name), )*
            })
        }

        /// `(snapshot key, counter)` for every counter that exists.
        pub const ALL: &[(&'static str, &'static AtomicU64)] = &[
            $( ( $key, &$name ), )*
        ];
    };
}

counters! {
    /// Inbound IP packets dropped because the netstack queue was full or closed.
    INBOUND_DROPPED => "inbound_dropped",
    /// Outbound packets dropped on a full datagram queue or a closed stream.
    DATAGRAM_SEND_DROPPED => "datagram_send_dropped",
    /// UDP datagrams the stack refused to send. Nothing above retransmits UDP, so
    /// a refusal here is a loss the application will never hear about otherwise.
    UDP_EGRESS_DROPPED => "udp_egress_dropped",
    /// Engine events that arrived as `AETHER_EVENT` but did not parse.
    MALFORMED_EVENTS => "malformed_events",
    /// Cache entries rejected by `sanitise` (bogus RTT, malformed address, …).
    CACHE_ENTRIES_REJECTED => "cache_entries_rejected",
    /// H3 responses ignored because they did not belong to the request stream.
    IGNORED_OFFSTREAM_STATUS => "ignored_offstream_status",
    /// Scan Stop requests dropped because no scan was running to receive them.
    STALE_SCAN_CANCELS => "stale_scan_cancels",
    /// Hot-subnet drill-down waves abandoned by cancellation or the scan deadline
    /// before they finished their neighbour list.
    DRILL_DOWN_WAVES_ABANDONED => "drill_down_waves_abandoned",
}

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
            snapshot()[name]
                .as_u64()
                .expect("counter present in snapshot"),
            after,
            "{name} is not wired into snapshot()"
        );
    }

    /// A counter that no code path increments is the same lie as a guard that
    /// cannot be reached, so each one must have at least one caller.
    #[test]
    fn every_counter_has_a_name_the_snapshot_reports() {
        let snap = snapshot();
        assert!(!ALL.is_empty(), "no counter is declared at all");
        for (key, counter) in ALL {
            assert_eq!(
                snap.get(*key).and_then(|v| v.as_u64()),
                Some(peek(*counter)),
                "{key} is declared but snapshot() does not report it"
            );
        }
        // The table has to be complete in the other direction too: a key in the
        // export that no counter owns is a number nobody can move.
        assert_eq!(
            snap.as_object().map(|m| m.len()),
            Some(ALL.len()),
            "snapshot() and the counter table disagree on how many counters exist"
        );
    }

    /// The point of `ALL` being a `(key, &AtomicU64)` pair rather than a list of
    /// names: bumping through the table has to be visible in the export.
    #[test]
    fn a_counter_reached_through_the_table_is_reported() {
        let (key, counter) = *ALL
            .iter()
            .find(|(k, _)| *k == "cache_entries_rejected")
            .expect("cache_entries_rejected is in the table");
        let before = peek(counter);
        assert_eq!(bump(counter), before + 1);
        assert_eq!(snapshot()[key].as_u64(), Some(before + 1));
    }
}
