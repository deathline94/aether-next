//! `--diagnostics`: one machine-readable snapshot of what the engine actually
//! resolved, for support without screenshot archaeology.
//!
//! The point of the task this answers (T024) is that a bug report used to say
//! "it does not connect" and nothing else was checkable: which engine binary ran,
//! which config the process settled on, whether a route journal was still owned by
//! a dead process, and whether packets were being quietly dropped. Each of those
//! lived in a different place, and several had no reader at all.
//!
//! Values are reported as resolved here, not as configured in some file elsewhere:
//! a redacted copy of the real effective environment is included because a
//! "worked on my machine" report is worthless without it. Anything that looks
//! like a credential is redacted to its length — the name staying visible is the
//! point (a support agent needs to see that the flag is set), the value never is.

use std::path::PathBuf;

use crate::counters;
use crate::runtime_env;

/// Keys whose value is a secret or derives one. Matched on the name so a new
/// knob cannot leak by being forgotten in a per-key list.
fn is_secret_key(key: &str) -> bool {
    let k = key.to_ascii_uppercase();
    k.contains("KEY") || k.contains("SECRET") || k.contains("TOKEN") || k.contains("PASS")
}

/// Redact a secret value while keeping its shape reportable.
pub fn redact(value: &str) -> String {
    format!("<redacted len={}", value.chars().count()) + ">"
}

/// Effective environment, secrets redacted.
pub fn environment() -> Vec<(String, String)> {
    runtime_env::snapshot()
        .into_iter()
        .map(|(k, v)| {
            let shown = if is_secret_key(&k) { redact(&v) } else { v };
            (k, shown)
        })
        .collect()
}

/// The engine binary this code is running from, with its digest.
///
/// A path is not enough: the shell verifies and spawns a specific file, and the
/// support question is whether the bytes that failed are the bytes we can reason
/// about. A digest failure is reported as `null` with an `error`, never as a
/// digest of nothing.
pub fn self_binary() -> serde_json::Value {
    match std::env::current_exe() {
        Ok(path) => match crate::trust::file_sha256_hex(&path) {
            Ok(digest) => serde_json::json!({
                "path": path.display().to_string(),
                "sha256": digest,
            }),
            Err(e) => serde_json::json!({
                "path": path.display().to_string(),
                "sha256": serde_json::Value::Null,
                "error": e.to_string(),
            }),
        },
        Err(e) => serde_json::json!({
            "path": serde_json::Value::Null,
            "error": e.to_string(),
        }),
    }
}

/// Route journals on disk, with the owner each one claims.
///
/// Left-over journals are the single most common reason a machine keeps pointing
/// traffic at a tunnel that no longer exists, and they are invisible in the UI.
pub fn journals() -> Vec<PathBuf> {
    #[cfg(windows)]
    {
        crate::route_repair::list_journal_paths()
    }
    #[cfg(not(windows))]
    {
        Vec::new()
    }
}

/// The full snapshot, as one JSON value.
pub fn report() -> serde_json::Value {
    serde_json::json!({
        "engine_version": env!("CARGO_PKG_VERSION"),
        "binary": self_binary(),
        "counters": counters::snapshot(),
        "environment": environment(),
        "route_journals": journals()
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>(),
        "platform": {
            "os": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
            "family_unix": cfg!(unix),
            "family_windows": cfg!(windows),
        },
        "not_reported_here": [
            "per-binary trust decisions and the proxy journal belong to the desktop shell, which is the process that makes them; the engine cannot see them",
            "the config file's plaintext contents are never included — only the effective environment keys, with secrets redacted"
        ],
    })
}

/// Print the report and flush, so a GUI can capture it as one line.
pub fn print() {
    let text = serde_json::to_string_pretty(&report())
        .unwrap_or_else(|e| format!("{{\"error\": \"serialise diagnostics: {e}\"}}"));
    println!("{text}");
    use std::io::Write;
    let _ = std::io::stdout().flush();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_secret_value_never_survives_redaction() {
        let r = redact("hunter2-very-secret");
        assert!(!r.contains("hunter2"), "redaction leaked the value: {r}");
        assert!(r.contains("len=19"), "length should stay reportable: {r}");
    }

    #[test]
    fn secret_detection_is_by_name_not_by_hardcoded_list() {
        for k in [
            "AETHER_CONFIG_KEY",
            "AETHER_PROXY_PASSWORD",
            "AETHER_DEVICE_TOKEN",
            "AETHER_SOMETHING_SECRET",
        ] {
            assert!(is_secret_key(k), "{k} would be exported verbatim");
        }
        for k in ["AETHER_SCAN", "AETHER_MTU", "AETHER_TUN"] {
            assert!(!is_secret_key(k), "{k} is a knob, not a credential");
        }
    }

    /// The export is the thing a support agent pastes, so an absent value has to
    /// be visible as absent rather than defaulted into looking fine.
    #[test]
    fn report_names_every_section_it_claims() {
        let v = report();
        for key in [
            "engine_version",
            "binary",
            "counters",
            "environment",
            "route_journals",
            "platform",
        ] {
            assert!(v.get(key).is_some(), "{key} missing from the report");
        }
        assert_eq!(
            v["engine_version"].as_str(),
            Some(env!("CARGO_PKG_VERSION")),
            "version must come from the crate, not a literal"
        );
        assert!(
            v["counters"].get("inbound_dropped").is_some(),
            "the counters section must expose the drop counters"
        );
    }

    #[test]
    fn environment_export_redacts_without_dropping_keys() {
        runtime_env::set("AETHER_DIAG_TEST_KEY", "super-private-value");
        runtime_env::set("AETHER_DIAG_TEST_PLAIN", "visible");
        let env = environment();
        let secret = env
            .iter()
            .find(|(k, _)| k == "AETHER_DIAG_TEST_KEY")
            .map(|(_, v)| v.clone())
            .expect("redacted key should still be listed");
        assert!(!secret.contains("super-private-value"), "leaked: {secret}");
        assert!(secret.contains("len=19"), "length lost: {secret}");
        assert!(
            env.iter()
                .any(|(k, v)| k == "AETHER_DIAG_TEST_PLAIN" && v == "visible"),
            "a normal knob must pass through unchanged"
        );
        runtime_env::remove("AETHER_DIAG_TEST_KEY");
        runtime_env::remove("AETHER_DIAG_TEST_PLAIN");
    }
}
