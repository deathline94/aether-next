//! What the shell says when the engine's process ends.
//!
//! `aether/src/cli.rs` exits **4** for a failure it calls retryable and **1** for a
//! fatal one, and both used to arrive here as "non-zero" with one invented sentence
//! for every case. The mapping is a pure function so the two branches can be
//! asserted without an engine, a network, or a machine that can lose one.

// The test exe needs the shell's embedded application manifest to start on Windows.
#[cfg(windows)]
#[link(name = "resource", kind = "static")]
extern "C" {}

use aether_desktop_lib::{engine_exit_outcome, EngineExit};

#[test]
fn a_clean_exit_is_reported_as_a_stop_not_a_failure() {
    // The supervisor short-circuits `status.success()` itself; 0 through the mapper
    // anyway has to agree with it rather than contradict the banner.
    let exit = engine_exit_outcome(Some(0), true);
    assert_eq!(exit.status, "disconnected");
}

#[test]
fn exit_four_is_a_transient_failure_a_retry_can_answer() {
    let exit = engine_exit_outcome(Some(4), false);
    assert_eq!(
        exit,
        EngineExit {
            status: "error",
            detail: "Transient failure: the engine found no working route this time (exit 4), \
                     and called it retryable — try Connect again, or change the transport or \
                     scan mode."
                .to_string(),
        },
        "the retryable case has to say so, and say what to retry"
    );
    assert!(
        exit.detail.to_lowercase().contains("retry"),
        "the word the user acts on: {}",
        exit.detail
    );
}

#[test]
fn exit_one_is_fatal_and_does_not_advice_a_retry() {
    let exit = engine_exit_outcome(Some(1), false);
    assert_eq!(exit.status, "error");
    assert!(exit.detail.contains("Fatal failure"), "got {}", exit.detail);
    assert!(
        exit.detail.contains("Reconnecting cannot fix this"),
        "the sentence must close off the retry path: {}",
        exit.detail
    );
    assert!(
        !exit.detail.to_lowercase().contains("try connect"),
        "a fatal failure must not read like a transient one: {}",
        exit.detail
    );
}

#[test]
fn the_two_codes_do_not_collapse_into_one_sentence() {
    // The defect this replaces: one message for both, so the advice was wrong half
    // the time and the user could not tell whether reconnecting was worth it.
    assert_ne!(
        engine_exit_outcome(Some(4), false).detail,
        engine_exit_outcome(Some(1), false).detail
    );
}

#[test]
fn a_failure_after_a_connected_session_is_a_stop_either_way() {
    // The tunnel was up and came down; the banner says disconnected, but the reason
    // still distinguishes the two codes.
    for (code, needle) in [(4, "transient"), (1, "fatal")] {
        let exit = engine_exit_outcome(Some(code), true);
        assert_eq!(exit.status, "disconnected", "exit {code}");
        assert!(
            exit.detail.to_lowercase().contains(needle),
            "exit {code}: {}",
            exit.detail
        );
    }
}

#[test]
fn an_unrecognised_code_is_not_invented_into_either_kind() {
    // A code the engine does not emit today (an older binary, a runtime abort) must
    // not be reported as either a transient or a fatal verdict.
    let exit = engine_exit_outcome(Some(101), false);
    assert_eq!(exit.status, "error");
    assert!(
        exit.detail.contains("101"),
        "the code belongs in the text: {}",
        exit.detail
    );
    assert!(
        !exit.detail.contains("retry"),
        "no claim either way: {}",
        exit.detail
    );
}

#[test]
fn a_status_with_no_code_says_that_instead_of_guessing() {
    let exit = engine_exit_outcome(None, false);
    assert_eq!(exit.status, "error");
    assert!(
        exit.detail.contains("no exit status"),
        "got {}",
        exit.detail
    );
    assert!(
        exit.detail.contains("is not known"),
        "an unknown stays an unknown: {}",
        exit.detail
    );
    assert!(
        !exit.detail.contains("try Connect"),
        "and must not be turned into advice: {}",
        exit.detail
    );
}
