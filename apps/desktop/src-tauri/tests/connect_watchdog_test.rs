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
    connect_watchdog_action, WatchdogAction, CONNECT_WATCHDOG_TIMEOUT,
};
use std::time::Duration;

const TIMEOUT: Duration = CONNECT_WATCHDOG_TIMEOUT;

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
        connect_watchdog_action(Some((4, TIMEOUT + Duration::from_secs(1))), 4, "connecting", TIMEOUT),
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
