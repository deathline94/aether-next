#[cfg(windows)]
#[link(name = "resource", kind = "static")]
extern "C" {}

use aether_desktop_lib::{
    file_sha256_hex, verify_elevated_binary,
    BinaryTrustError, TrustedBinaryPolicy,
};
use std::fs;

#[test]
fn test_elevation_trust_rejects_non_pe() {
    let temp_dir = std::env::temp_dir().join(format!("aether_test_non_pe_{}", std::process::id()));
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).expect("create temp dir");

    let fake_bin = temp_dir.join("fake_aether.exe");
    fs::write(&fake_bin, b"THIS IS NOT A PE FILE").expect("write fake bin");

    let policy = TrustedBinaryPolicy {
        #[cfg(debug_assertions)]
        allow_unsigned_for_dev: true,
        expected_publisher_cn: "deathline94",
        embedded_hashes: &[],
        enforce_hash_match: false,
    };

    let res = verify_elevated_binary(&fake_bin, "aether.exe", &policy);
    assert!(res.is_err(), "Non-PE file must be rejected");
    if let Err(e) = res {
        assert!(
            matches!(e, BinaryTrustError::Validation(_)),
            "Expected Validation error for non-PE binary, got {e:?}"
        );
    }

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_elevation_trust_rejects_hash_mismatch() {
    let current_exe = std::env::current_exe().expect("current exe");
    let actual_hash = file_sha256_hex(&current_exe).expect("calculate hash");
    let filename_owned = current_exe.file_name().unwrap().to_str().unwrap().to_string();
    let filename: &'static str = Box::leak(filename_owned.into_boxed_str());

    // A digest that is wrong *and published*. All-zeros would be the
    // un-published-placeholder case, which is a different refusal handled by
    // `placeholder_anchor_refuses_instead_of_matching_nothing`.
    let wrong_hash = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";
    let hashes: &'static [(&'static str, &'static str)] = Box::leak(vec![(filename, wrong_hash)].into_boxed_slice());
    let policy = TrustedBinaryPolicy {
        #[cfg(debug_assertions)]
        allow_unsigned_for_dev: true,
        expected_publisher_cn: "deathline94",
        embedded_hashes: hashes,
        enforce_hash_match: false,
    };

    let res = verify_elevated_binary(&current_exe, filename, &policy);
    assert!(res.is_err(), "Mismatched hash must be rejected");
    match res {
        Err(BinaryTrustError::HashMismatch { expected, actual, .. }) => {
            assert_eq!(expected, wrong_hash);
            assert_eq!(actual, actual_hash);
        }
        other => panic!("Expected HashMismatch, got {other:?}"),
    }
}

#[cfg(windows)]
#[test]
fn test_elevation_trust_rejects_unsigned_when_enforced() {
    let current_exe = std::env::current_exe().expect("current exe");
    let policy = TrustedBinaryPolicy {
        #[cfg(debug_assertions)]
        allow_unsigned_for_dev: false,
        expected_publisher_cn: "deathline94",
        embedded_hashes: &[],
        enforce_hash_match: false,
    };

    let filename = current_exe.file_name().unwrap().to_str().unwrap();
    let res = verify_elevated_binary(&current_exe, filename, &policy);
    assert!(
        res.is_err(),
        "an unsigned binary must be refused when the policy does not allow the debug skip",
    );
    match res {
        Err(BinaryTrustError::Authenticode(code, msg)) => {
            println!("Correctly caught Authenticode error: 0x{code:08x} ({msg})");
        }
        other => panic!("Expected Authenticode error, got {other:?}"),
    }
}

#[test]
fn test_elevation_trust_distinct_policies() {
    let engine_policy = TrustedBinaryPolicy::for_engine();
    assert_eq!(engine_policy.expected_publisher_cn, "deathline94");

    let wintun_policy = TrustedBinaryPolicy::for_wintun();
    assert_eq!(wintun_policy.expected_publisher_cn, "WireGuard LLC");
    assert_ne!(
        engine_policy.expected_publisher_cn, wintun_policy.expected_publisher_cn,
        "the engine and the driver must not share one publisher expectation",
    );

    // The developer escape hatch compiles only into a debug build; a release
    // binary has no such field, so it has no code path that can decline
    // Authenticode. This block is the regression test for that.
    #[cfg(debug_assertions)]
    {
        assert!(engine_policy.allow_unsigned_for_dev);
        assert!(!wintun_policy.allow_unsigned_for_dev);
    }
}

/// The defect this guards: `build.rs` used to hash `resources/aether.exe` — the
/// very file it then shipped — so the runtime comparison could only ever succeed,
/// and on a clean checkout (`resources/*.exe` is gitignored) it emitted no entry
/// at all and the "missing digest is an error" branch was unreachable. Both
/// directions of that check were unable to fail.
#[test]
fn embedded_hashes_are_sourced_from_the_reviewed_anchor_not_from_the_artifact() {
    let anchor_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../packaging/trust/engine-trust.json");
    let text = fs::read_to_string(&anchor_path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", anchor_path.display()));
    let doc: serde_json::Value = text.parse().expect("anchor must be valid JSON");
    let files = doc["files"].as_array().expect("anchor needs a files[] array");

    assert!(
        !files.is_empty(),
        "anchor carries no entries, so nothing is being checked"
    );

    for entry in files {
        let name = entry["name"].as_str().expect("entry name");
        let want = entry["file_sha256"].as_str().expect("entry digest");
        let found = aether_desktop_lib::EMBEDDED_RELEASE_HASHES
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .unwrap_or_else(|| {
                panic!("{name} has an anchor entry but no embedded digest — an absent \
                        entry must not be allowed to mean \"nothing to check\"")
            });
        assert_eq!(
            found.1,
            want,
            "embedded digest for {name} does not come from the anchor"
        );
    }
}

#[test]
fn anchor_covers_every_artifact_the_shell_checks_with_a_well_formed_digest() {
    for name in ["aether.exe", "wintun.dll"] {
        let entry = aether_desktop_lib::EMBEDDED_RELEASE_HASHES
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .unwrap_or_else(|| panic!("no embedded digest for {name}"));
        assert_eq!(entry.1.len(), 64, "{name} digest is not 64 hex chars");
        assert!(
            entry.1.bytes().all(|b| b.is_ascii_hexdigit()),
            "{name} digest is not hex: {}",
            entry.1
        );
    }
}

/// The anchor travels *as bytes*, so a running shell can be asked which witness
/// it holds. This also catches a stale build: editing `engine-trust.json`
/// without recompiling leaves the embedded copy behind.
#[test]
fn embedded_anchor_bytes_are_the_committed_file_itself() {
    let (bytes, sha, _, _) = aether_desktop_lib::engine_trust_anchor();
    let anchor_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../packaging/trust/engine-trust.json");
    let on_disk = fs::read(&anchor_path).expect("anchor readable");
    assert_eq!(
        bytes, on_disk,
        "embedded anchor differs from the committed one — rebuild before trusting it"
    );
    assert_eq!(
        sha,
        file_sha256_hex(&anchor_path).expect("hash"),
        "embedded anchor digest is not the digest of the embedded bytes"
    );
}

/// Provenance alone is not truth: the anchor's `wintun.dll` entry was a
/// hand-written digest that had never been compared with the tracked binary, and
/// it disagreed. `packaging/wintun.dll` is committed, so its own entry is
/// checkable at test time — which is the only way that class of error fails loud.
#[test]
fn anchor_digests_match_the_committed_artifacts_they_describe() {
    let dll = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../packaging/wintun.dll");
    let measured = file_sha256_hex(&dll).expect("packaging/wintun.dll is committed and readable");
    let (_, _, table, _) = aether_desktop_lib::engine_trust_anchor();
    let claimed = table
        .iter()
        .find(|(n, _)| *n == "wintun.dll")
        .map(|(_, d)| *d)
        .expect("anchor entry for wintun.dll");
    assert_eq!(
        claimed,
        measured.as_str(),
        "the anchor describes a different wintun.dll than the one shipped; a wrong witness \
         refuses a good file and, once corrected by whoever hit it, accepts a bad one"
    );
}

/// An all-zero digest is what the committed placeholder carries before the
/// release job publishes a witness. It must never be *satisfiable*: whatever is
/// on disk cannot hash to it, and the refusal has to say so rather than look
/// like a corrupt install.
#[test]
fn placeholder_anchor_refuses_instead_of_matching_nothing() {
    let current_exe = std::env::current_exe().expect("current exe");
    let filename_owned = current_exe
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let filename: &'static str = Box::leak(filename_owned.into_boxed_str());
    let zeros: &'static str = "0000000000000000000000000000000000000000000000000000000000000000";
    let hashes: &'static [(&'static str, &'static str)] =
        Box::leak(vec![(filename, zeros)].into_boxed_slice());

    let policy = TrustedBinaryPolicy {
        #[cfg(debug_assertions)]
        allow_unsigned_for_dev: true,
        expected_publisher_cn: "deathline94",
        embedded_hashes: hashes,
        enforce_hash_match: true,
    };

    let err = verify_elevated_binary(&current_exe, "test-binary", &policy)
        .expect_err("a placeholder digest must never be accepted");
    let code = aether_desktop_lib::CommandError::from(err).code;
    assert_eq!(
        code, "anchor_not_published",
        "must name the pipeline step that is missing, not look like tampering"
    );
}

#[test]
fn test_elevation_trust_rejects_missing_hash_when_enforced() {
    let current_exe = std::env::current_exe().expect("current exe");
    let filename_owned = current_exe.file_name().unwrap().to_str().unwrap().to_string();
    let filename: &'static str = Box::leak(filename_owned.clone().into_boxed_str());

    let policy = TrustedBinaryPolicy {
        #[cfg(debug_assertions)]
        allow_unsigned_for_dev: true,
        expected_publisher_cn: "deathline94",
        embedded_hashes: &[], // empty table -> hash is missing
        enforce_hash_match: true,
    };

    let res = verify_elevated_binary(&current_exe, filename, &policy);
    assert!(res.is_err(), "Missing hash must be rejected when enforce_hash_match=true");
    match res {
        Err(BinaryTrustError::MissingHash { filename: missing }) => {
            assert_eq!(missing, filename_owned);
        }
        other => panic!("Expected MissingHash, got {other:?}"),
    }
}

#[test]
fn test_elevation_trust_allows_missing_hash_when_not_enforced() {
    let current_exe = std::env::current_exe().expect("current exe");
    let filename_owned = current_exe.file_name().unwrap().to_str().unwrap().to_string();
    let filename: &'static str = Box::leak(filename_owned.into_boxed_str());

    let policy = TrustedBinaryPolicy {
        #[cfg(debug_assertions)]
        allow_unsigned_for_dev: true,
        expected_publisher_cn: "deathline94",
        embedded_hashes: &[],
        enforce_hash_match: false,
    };

    let res = verify_elevated_binary(&current_exe, filename, &policy);
    assert!(res.is_ok(), "Missing hash must be allowed when enforce_hash_match=false in debug: {res:?}");
}

/// The old root set was "the exe's directory **and its parent**". For an
/// installed app that parent is `C:\Program Files`; for the portable package it is
/// whatever folder the user unpacked the zip into. A child launched from there is
/// handed the DPAPI master key, so the set has to be named layout directories, not
/// a directory that happens to contain one.
#[test]
fn trusted_binary_roots_are_the_named_layout_directories_only() {
    let base = std::env::temp_dir().join(format!("aether_roots_{}", std::process::id()));
    let app = base.join("Aether Next");
    for dir in [&app, &app.join("resources"), &app.join("engine"), &base.join("OtherVendor")] {
        fs::create_dir_all(dir).expect("create dir");
    }

    let roots = aether_desktop_lib::allowed_binary_roots(Some(&app));
    assert!(
        roots.iter().any(|r| r == &app.canonicalize().unwrap()),
        "the exe's own directory must be a root"
    );
    assert!(roots.iter().any(|r| r == &app.join("resources").canonicalize().unwrap()));
    assert!(roots.iter().any(|r| r == &app.join("engine").canonicalize().unwrap()));
    assert!(
        !roots.iter().any(|r| r == &base.canonicalize().unwrap()),
        "the parent directory must not be a root: it is Program Files, or the user's extraction \
         folder, or Temp"
    );

    // The property that matters: a sibling install is outside every root, and the
    // containing directory itself would have admitted it.
    let sibling = app.join("..").join("OtherVendor").join("aether.exe");
    let resolved = sibling.canonicalize().unwrap_or_else(|_| {
        base.join("OtherVendor").join("aether.exe")
    });
    assert!(
        !roots.iter().any(|r| resolved.starts_with(r)),
        "a binary in a sibling directory was accepted by the root list"
    );
    let _ = fs::remove_dir_all(&base);
}
