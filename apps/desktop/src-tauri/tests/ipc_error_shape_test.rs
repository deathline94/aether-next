//! The machine-readable half of a shell error has to survive the wire.

// The test exe needs the shell's embedded application manifest to start on
// Windows at all — without it the process dies with STATUS_ENTRYPOINT_NOT_FOUND
// before a single test runs. Every test binary in this crate links it.
#[cfg(windows)]
#[link(name = "resource", kind = "static")]
extern "C" {}

use aether_desktop_lib::{validate_settings, CommandError, Settings};
use serde_json::Value;

fn to_json(err: &CommandError) -> Value {
    serde_json::to_value(err).expect("CommandError is serialisable")
}

fn settings_with(break_it: impl Fn(&mut Settings)) -> Settings {
    let mut settings = Settings::default();
    break_it(&mut settings);
    settings
}

type Breaker = fn(&mut Settings);

/// `disconnect_incomplete`, `anchor_not_published` and `key_service_unavailable`
/// exist so a UI can branch on them. While `CommandError` serialised as
/// `self.message` alone, none of them reached the frontend: the only thing to
/// branch on was prose, which is the defect BC-20 was written to prevent.
#[test]
fn a_serialised_error_carries_its_code_beside_its_message() {
    let err = CommandError::new(
        "disconnect_incomplete",
        "system proxy could not be restored",
    );
    let json = to_json(&err);
    assert_eq!(json["code"], "disconnect_incomplete", "got {json}");
    assert_eq!(json["message"], "system proxy could not be restored");
    assert!(
        json.get("field").is_none(),
        "an error about no particular field must not invent one: {json}"
    );
}

/// A validation failure is the case where the field name is load-bearing: the
/// Settings form shows "Synchronizing changes…" until a save succeeds, so a
/// rejected port has to be attached to the port input or the spinner is forever.
#[test]
fn a_rejected_setting_names_the_field_that_failed() {
    let err = validate_settings(&settings_with(|s| s.http_port = s.socks_port))
        .expect_err("equal ports must be refused");
    assert_eq!(err.code, "validation", "got {err:?}");
    assert_eq!(
        err.field,
        Some("httpPort"),
        "the field has to be the name the frontend state uses, not the Rust one"
    );

    let err = validate_settings(&settings_with(|s| s.noize = "volcano".into()))
        .expect_err("an unknown obfuscation profile must be refused");
    assert_eq!(err.code, "validation");
    assert_eq!(err.field, Some("noize"));
}

/// Every error the shell can produce about a field has to name it: a `None`
/// here would leave that branch of the form with the eternal spinner.
///
/// `protocol`, `transport`, `scanMode`, `ipVersion` and `routingMode` used to be
/// in this list. They cannot be broken by construction any more — those values
/// are `wire_enum!` types now, so a `Settings` holding `"teleport"` does not
/// exist — which is the stronger version of the check: the rejection the form had
/// to display is unreachable. Their wire contract is covered instead by
/// `settings_compat_test.rs`.
#[test]
fn every_validation_failure_names_a_field() {
    let cases: Vec<(&str, Breaker)> = vec![
        ("httpPort", |s| s.http_port = 80),
        ("socksPort", |s| s.socks_port = 1),
        ("httpPort", |s| s.http_port = s.socks_port),
        ("noize", |s| s.noize = "volcano".into()),
        ("enginePath", |s| {
            s.engine_path = "C:\\definitely-not-here\\aether.exe".into()
        }),
        ("noizeJmax", |s| {
            s.noize = "custom".into();
            s.noize_jmin = 3000;
            s.noize_jmax = 4000;
        }),
        ("noizeJc", |s| {
            s.noize = "custom".into();
            s.noize_jc = 4000;
        }),
        ("noizeIntervalMs", |s| {
            s.noize = "custom".into();
            s.noize_interval_ms = 9000;
        }),
    ];
    for (field, break_it) in cases {
        let err = match validate_settings(&settings_with(break_it)) {
            Ok(()) => panic!("{field} was accepted; the case does not test anything"),
            Err(err) => err,
        };
        assert_eq!(err.code, "validation", "for {field}: {err:?}");
        assert_eq!(err.field, Some(field), "for {field}: {err:?}");
        assert!(
            !err.message.is_empty(),
            "an error with no prose is unshowable"
        );
    }
}

/// Logs, `emit_log` strings and the tests above all format errors as prose.
/// Only the wire shape changes.
#[test]
fn the_display_form_stays_the_message() {
    let err = CommandError::new("not_found", "wintun.dll is missing");
    assert_eq!(format!("{err}"), "wintun.dll is missing");
}

/// Existence, not trust: the path a user typed is refused only because nothing is
/// there. Whether a file that *is* there may be executed is the allow-list and the
/// anchor's business, and this check must not pretend to decide it.
#[test]
fn a_custom_engine_path_must_exist_and_may_be_blank() {
    let dir = std::env::temp_dir().join(format!("aether-engine-path-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");
    let file = dir.join("aether.exe");
    std::fs::write(&file, b"MZ placeholder, not executed by this test").expect("write");

    let existing = settings_with(|s| s.engine_path = file.to_string_lossy().into_owned());
    validate_settings(&existing).expect("a path that exists is a legitimate choice");

    let blank = settings_with(|s| s.engine_path = "   ".into());
    validate_settings(&blank).expect("blank means the default location, not a bad path");

    let missing =
        settings_with(|s| s.engine_path = dir.join("nowhere.exe").to_string_lossy().into_owned());
    let err = validate_settings(&missing).expect_err("a half-typed path must not be saved");
    assert_eq!(err.code, "validation");
    assert_eq!(err.field, Some("enginePath"));

    let dir_as_target = settings_with(|s| s.engine_path = dir.to_string_lossy().into_owned());
    validate_settings(&dir_as_target)
        .expect_err("an engine is a file; a directory is not one, and `is_file` is the check");

    let _ = std::fs::remove_dir_all(&dir);
}
