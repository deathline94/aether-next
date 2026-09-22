//! The 90 s connect watchdog's decision, in isolation.
//!
//! `watch_child` used to react only to the engine process exiting. An engine that
//! hangs mid-connect — black-holed edge, probe that never returns — exits for
//! nothing, emits no error, and leaves the UI on "connecting" with the Settings tab
//! locked and the only remedy a manual disconnect. The watchdog has to be in the
//! shell rather than the page because WebView2 throttles timers in a window hidden
//! to the tray, which is how this app normally runs.

// The test exe needs the shell's embedded application manifest to start on Windows.
#[cfg(windows)]
#[link(name = "resource", kind = "static")]
extern "C" {}

use aether_desktop_lib::{
    connect_watchdog_action, heartbeat_stall_action, WatchdogAction, CONNECT_WATCHDOG_TIMEOUT,
    HEARTBEAT_INTERVAL, HEARTBEAT_MISS_LIMIT,
};
use std::time::Duration;

const TIMEOUT: Duration = CONNECT_WATCHDOG_TIMEOUT;
const INTERVAL: Duration = HEARTBEAT_INTERVAL;
const MISS_LIMIT: u32 = HEARTBEAT_MISS_LIMIT;

fn under() -> Duration {
    TIMEOUT - Duration::from_millis(1)
}

#[test]
fn nothing_fires_without_a_session_underway() {
    assert_eq!(
        connect_watchdog_action(None, 7, "connecting", TIMEOUT),
        WatchdogAction::LeaveAlone,
        "no stamp means no session was started"
    );
}

#[test]
fn a_stamp_belongs_to_the_session_that_made_it() {
    // Generation moves on when a session ends, is replaced, or errors out. A
    // watchdog that ignored it would kill whatever session is running now because
    // an earlier one timed out.
    assert_eq!(
        connect_watchdog_action(Some((3, TIMEOUT * 2)), 4, "connecting", TIMEOUT),
        WatchdogAction::LeaveAlone
    );
}

#[test]
fn a_session_that_already_ended_is_left_alone_even_if_its_stamp_is_overdue() {
    for status in ["connected", "error", "disconnected"] {
        assert_eq!(
            connect_watchdog_action(Some((4, TIMEOUT * 2)), 4, status, TIMEOUT),
            WatchdogAction::LeaveAlone,
            "the terminal state is the reason the stamp is still there"
        );
    }
}

#[test]
fn only_a_connect_that_outstays_the_budget_is_a_timeout() {
    assert_eq!(
        connect_watchdog_action(Some((4, under())), 4, "connecting", TIMEOUT),
        WatchdogAction::LeaveAlone
    );
    assert_eq!(
        connect_watchdog_action(Some((4, TIMEOUT)), 4, "connecting", TIMEOUT),
        WatchdogAction::TimedOut,
        "the budget is inclusive: a 90 s connect is already not going to make it"
    );
    assert_eq!(
        connect_watchdog_action(
            Some((4, TIMEOUT + Duration::from_secs(1))),
            4,
            "connecting",
            TIMEOUT
        ),
        WatchdogAction::TimedOut
    );
}

/// The status is produced by `emit_state`, which writes the lowercase strings — but
/// this comparison is against a value that has been through JSON, and a case-sensitive
/// `==` here would silently disable the watchdog rather than mis-fire it.
#[test]
fn the_connecting_check_does_not_care_about_case() {
    assert_eq!(
        connect_watchdog_action(Some((4, TIMEOUT)), 4, "Connecting", TIMEOUT),
        WatchdogAction::TimedOut
    );
}

/// The "no pulse has ever arrived" branch.
///
/// It existed in the source but could not run: its only caller invoked
/// `heartbeat_stall_action` inside `if let Some(beat) = ...`, so the `None` case
/// was structurally excluded, and an engine that produced *no* event at all — the
/// worst case, not the ordinary one — looked identical to a healthy session.
#[test]
fn a_session_that_has_never_pulsed_becomes_a_stall_on_a_clock() {
    assert_eq!(
        heartbeat_stall_action(
            None,
            true,
            MISS_LIMIT,
            INTERVAL,
            Some(INTERVAL * (MISS_LIMIT + 1))
        ),
        Some("no progress event received".to_string())
    );
    // Inside the budget there is nothing to conclude yet...
    assert_eq!(
        heartbeat_stall_action(
            None,
            true,
            MISS_LIMIT,
            INTERVAL,
            Some(Duration::from_secs(1))
        ),
        None
    );
    // ...and with no session age at all the function must not invent one.
    assert_eq!(
        heartbeat_stall_action(None, true, MISS_LIMIT, INTERVAL, None),
        None
    );
    // Not armed: never a stall, whatever the clocks say.
    assert_eq!(
        heartbeat_stall_action(
            None,
            false,
            MISS_LIMIT,
            INTERVAL,
            Some(INTERVAL * (MISS_LIMIT + 5))
        ),
        None
    );
}

#[test]
fn a_recent_pulse_wins_over_the_age_of_the_session() {
    assert_eq!(
        heartbeat_stall_action(
            Some(("probing", INTERVAL * (MISS_LIMIT - 1))),
            true,
            MISS_LIMIT,
            INTERVAL,
            Some(INTERVAL * 100)
        ),
        None
    );
    assert_eq!(
        heartbeat_stall_action(
            Some(("tuning", INTERVAL * (MISS_LIMIT + 1))),
            true,
            MISS_LIMIT,
            INTERVAL,
            None
        ),
        Some("tuning (20 s since the last pulse)".to_string())
    );
}
