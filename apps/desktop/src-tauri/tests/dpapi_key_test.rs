#[cfg(windows)]
#[link(name = "resource", kind = "static")]
extern "C" {}

use aether_desktop_lib::dpapi::{encrypt_with, service, KeyService};

/// The bug this replaces was invisible *because* of how the tests were written:
/// `encrypt`/`decrypt` were the identity function off Windows, and every test
/// that checked them was `#[cfg(windows)]`, so the platform that stored the
/// master key in plaintext had nothing asserting on it.
///
/// This test is not cfg-gated. Whatever the platform's answer is, the pair must
/// not be able to agree that an unwrapped key counts as protected.
#[test]
fn an_unavailable_key_service_refuses_rather_than_echoing_the_plaintext() {
    let key = [0x5au8; 32];
    if service() == KeyService::None {
        let err = encrypt_with(&key, KeyService::None)
            .expect_err("no OS secret store must be a refusal, not a pass-through");
        assert!(
            err.message.contains("never written unwrapped"),
            "the error has to name the missing backend: {err:?}"
        );
    } else {
        let wrapped = encrypt_with(&key, service()).expect("a real service wraps the key");
        assert_ne!(&wrapped[..], &key[..], "the key went to disk as plaintext");
        let back = aether_desktop_lib::dpapi::decrypt_with(&wrapped, service())
            .expect("unwrap succeeds");
        assert_eq!(&back[..], &key[..]);
        // Asking the unavailable service explicitly must still refuse, even on
        // the platform where production never selects it.
        assert!(encrypt_with(&key, KeyService::None).is_err());
    }
}

#[cfg(windows)]
#[test]
fn test_dpapi_roundtrip() {
    let plain = b"aether-super-secret-identity-token-roundtrip-test-payload";
    let enc = aether_desktop_lib::dpapi::encrypt(plain).expect("DPAPI encrypt should succeed");
    assert_ne!(enc, plain);
    let dec = aether_desktop_lib::dpapi::decrypt(&enc).expect("DPAPI decrypt should succeed");
    assert_eq!(dec, plain);
}

#[cfg(windows)]
#[test]
fn test_dpapi_get_or_create_key() {
    use std::fs;
    let temp_dir = std::env::temp_dir().join(format!("aether_test_dpapi_{}", std::process::id()));
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).expect("create temp dir");

    // 1. First call creates the key file
    let key1 = aether_desktop_lib::dpapi::get_or_create_dpapi_config_key(&temp_dir)
        .expect("create dpapi key");
    assert!(!key1.is_empty());
    assert!(temp_dir.join("config_key.dpapi").exists());

    // 2. Second call loads the existing key file and returns the same key
    let key2 = aether_desktop_lib::dpapi::get_or_create_dpapi_config_key(&temp_dir)
        .expect("load existing dpapi key");
    assert_eq!(key1, key2);

    // 3. Decoding base64 should yield exactly 32 bytes
    use base64::Engine;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(&key1)
        .expect("valid base64");
    assert_eq!(raw.len(), 32);

    // Clean up
    let _ = fs::remove_dir_all(&temp_dir);
}

#[cfg(windows)]
#[test]
fn test_dpapi_tampered_envelope() {
    use std::fs;
    let temp_dir = std::env::temp_dir().join(format!("aether_test_dpapi_tamper_{}", std::process::id()));
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).expect("create temp dir");

    // Invalid magic header
    let key_file = temp_dir.join("config_key.dpapi");
    fs::write(&key_file, b"BAD0corrupted_payload").expect("write bad key");
    let res = aether_desktop_lib::dpapi::get_or_create_dpapi_config_key(&temp_dir);
    assert!(res.is_err(), "tampered header must be rejected");

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_zeroize_cleanup() {
    use zeroize::Zeroize;
    let mut secret = vec![0x42u8; 32];
    assert!(secret.iter().all(|&b| b == 0x42));
    secret.zeroize();
    assert!(secret.iter().all(|&b| b == 0));
}
