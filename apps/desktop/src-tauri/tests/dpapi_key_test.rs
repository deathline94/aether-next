#[cfg(windows)]
#[link(name = "resource", kind = "static")]
extern "C" {}

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
