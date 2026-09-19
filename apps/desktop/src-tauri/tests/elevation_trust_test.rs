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
        allow_unsigned_in_debug: true,
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

    let wrong_hash = "0000000000000000000000000000000000000000000000000000000000000000";
    let hashes: &'static [(&'static str, &'static str)] = Box::leak(vec![(filename, wrong_hash)].into_boxed_slice());
    let policy = TrustedBinaryPolicy {
        allow_unsigned_in_debug: true,
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
        allow_unsigned_in_debug: false,
        expected_publisher_cn: "deathline94",
        embedded_hashes: &[],
        enforce_hash_match: false,
    };

    let filename = current_exe.file_name().unwrap().to_str().unwrap();
    let res = verify_elevated_binary(&current_exe, filename, &policy);
    assert!(res.is_err(), "Unsigned test binary must be rejected when allow_unsigned_in_debug=false");
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
    assert!(engine_policy.allow_unsigned_in_debug);

    let wintun_policy = TrustedBinaryPolicy::for_wintun();
    assert_eq!(wintun_policy.expected_publisher_cn, "WireGuard LLC");
    assert!(!wintun_policy.allow_unsigned_in_debug);
}

#[test]
fn test_elevation_trust_rejects_missing_hash_when_enforced() {
    let current_exe = std::env::current_exe().expect("current exe");
    let filename_owned = current_exe.file_name().unwrap().to_str().unwrap().to_string();
    let filename: &'static str = Box::leak(filename_owned.clone().into_boxed_str());

    let policy = TrustedBinaryPolicy {
        allow_unsigned_in_debug: true,
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
        allow_unsigned_in_debug: true,
        expected_publisher_cn: "deathline94",
        embedded_hashes: &[],
        enforce_hash_match: false,
    };

    let res = verify_elevated_binary(&current_exe, filename, &policy);
    assert!(res.is_ok(), "Missing hash must be allowed when enforce_hash_match=false in debug: {res:?}");
}
