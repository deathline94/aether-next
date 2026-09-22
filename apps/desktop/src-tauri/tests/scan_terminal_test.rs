//! What the shell says when a scan's process ends without saying anything.

// The test exe needs the shell's embedded application manifest to start on Windows.
#[cfg(windows)]
#[link(name = "resource", kind = "static")]
extern "C" {}

use aether_desktop_lib::scan_terminal_event;

#[test]
fn a_scan_that_reported_its_own_ending_gets_no_invented_one() {
    assert_eq!(
        scan_terminal_event(true, 3, false),
        None,
        "the engine said scan_done; a second terminal event is a double report"
    );
}

/// The defect: the synthetic event used to be `scan_done` with empty fields, which
/// the UI read as "finished, nothing found" — reporting a scan that had already
/// found a dozen endpoints as having found none.
#[test]
fn an_abandoned_scan_is_reported_as_a_failure_not_an_empty_success() {
    let event = scan_terminal_event(false, 12, false).expect("the UI needs a terminal event");
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
    let event = scan_terminal_event(false, 0, false).expect("the UI needs a terminal event");
    assert_eq!(event["type"], "scan_failed");
    assert!(
        event["message"]
            .as_str()
            .unwrap_or_default()
            .contains("no working endpoint"),
        "got {event}"
    );
}

/// A pipe this process failed to read is not an engine that had nothing to say.
///
/// The pump used to swallow the read error and leave the run reporting "the scan
/// process ended without reporting a result", which sends a reader to the engine log
/// for a fault in the shell.
#[test]
fn a_broken_output_stream_is_blamed_on_the_shell() {
    let event = scan_terminal_event(false, 7, true).expect("the UI needs a terminal event");
    assert_eq!(event["type"], "scan_failed");
    let message = event["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("output stream failed in the shell"),
        "the fault has to name its own side: {message}"
    );
    assert!(message.contains('7'), "the count survives: {message}");
    assert!(
        !message.contains("process ended"),
        "the process may still be running: {message}"
    );

    let empty = scan_terminal_event(false, 0, true).expect("the UI needs a terminal event");
    let empty = empty["message"].as_str().unwrap_or_default();
    assert!(
        empty.contains("output stream failed in the shell"),
        "got {empty}"
    );
    assert!(empty.contains("no working endpoint"), "got {empty}");
}

/// The activity log's level, decided without a running engine.
///
/// The prose fallback asked whether the lowercased line *contained* "error", so a
/// progress line reading "0 errors" arrived as an error and a healthy session's
/// log went red.
#[test]
fn a_benign_mention_of_errors_is_not_an_error_line() {
    assert_eq!(
        aether_desktop_lib::log_level_for("probed 12 endpoints, 0 errors"),
        "info"
    );
    assert_eq!(
        aether_desktop_lib::log_level_for("error budget still intact"),
        "info"
    );
}

#[test]
fn a_real_failure_still_classifies_as_error() {
    assert_eq!(
        aether_desktop_lib::log_level_for("[07:11:02 ERROR aether::session] handshake error: rst"),
        "error"
    );
    assert_eq!(
        aether_desktop_lib::log_level_for("engine error: connection refused"),
        "error"
    );
    assert_eq!(
        aether_desktop_lib::log_level_for("cannot bind 127.0.0.1:1820"),
        "error"
    );
}

#[test]
fn the_env_logger_token_beats_the_prose_heuristics() {
    assert_eq!(
        aether_desktop_lib::log_level_for("[07:11:02  WARN aether] retry after failed probe"),
        "warn"
    );
    assert_eq!(
        aether_desktop_lib::log_level_for("[-] degraded path"),
        "warn"
    );
    assert_eq!(
        aether_desktop_lib::log_level_for("data-plane verified"),
        "info"
    );
}
