//! What the shell says when a scan's process ends without saying anything.

// The test exe needs the shell's embedded application manifest to start on Windows.
#[cfg(windows)]
#[link(name = "resource", kind = "static")]
extern "C" {}

use aether_desktop_lib::scan_terminal_event;

#[test]
fn a_scan_that_reported_its_own_ending_gets_no_invented_one() {
    assert_eq!(
        scan_terminal_event(true, 3),
        None,
        "the engine said scan_done; a second terminal event is a double report"
    );
}

/// The defect: the synthetic event used to be `scan_done` with empty fields, which
/// the UI read as "finished, nothing found" — reporting a scan that had already
/// found a dozen endpoints as having found none.
#[test]
fn an_abandoned_scan_is_reported_as_a_failure_not_an_empty_success() {
    let event = scan_terminal_event(false, 12).expect("the UI needs a terminal event");
    assert_eq!(event["type"], "scan_failed", "got {event}");
    let message = event["message"].as_str().expect("message is a string");
    assert!(
        message.contains("12"),
        "the count already found has to survive: {message}"
    );
    assert!(
        !message.contains("no working endpoint"),
        "twelve were found; the message must not say none: {message}"
    );
}

#[test]
fn an_abandoned_scan_that_found_nothing_says_so() {
    let event = scan_terminal_event(false, 0).expect("the UI needs a terminal event");
    assert_eq!(event["type"], "scan_failed");
    assert!(
        event["message"]
            .as_str()
            .unwrap_or_default()
            .contains("no working endpoint"),
        "got {event}"
    );
}
