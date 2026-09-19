use aether::account::Identity;
use aether::config::{load, save, write_private_file};
use std::fs;

fn dummy_identity() -> Identity {
    Identity {
        device_id: "test_dev".into(),
        access_token: "test_token".into(),
        cert_pem: vec![],
        key_pem: vec![],
        ipv4: "172.16.0.2".into(),
        ipv6: "2606:4700:110:8751:19d6:4fd1:d894:21dc".into(),
        wg_private_key: [2u8; 32],
        wg_peer_public_key: [3u8; 32],
        client_id: [1u8; 3],
        masque_endpoint: None,
    }
}

#[test]
fn test_atomic_write_and_overwrite() {
    let temp_dir = std::env::temp_dir().join(format!("aether_test_atomic_{}", std::process::id()));
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).expect("create temp dir");

    let file_path = temp_dir.join("secret.bin").to_string_lossy().to_string();

    // 1. Initial write
    write_private_file(&file_path, b"initial secret payload").expect("initial write");
    let content1 = fs::read_to_string(&file_path).expect("read initial");
    assert_eq!(content1, "initial secret payload");

    // 2. Overwrite atomically
    write_private_file(&file_path, b"updated secret payload").expect("overwrite");
    let content2 = fs::read_to_string(&file_path).expect("read updated");
    assert_eq!(content2, "updated secret payload");

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_config_recovery_from_backup() {
    let temp_dir = std::env::temp_dir().join(format!("aether_test_bak_{}", std::process::id()));
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).expect("create temp dir");

    let config_path = temp_dir.join("aether.toml").to_string_lossy().to_string();
    let bak_path = format!("{config_path}.bak");

    // Save identity directly to .bak
    let ident = dummy_identity();
    save(&bak_path, &ident).expect("save to bak");
    assert!(!std::path::Path::new(&config_path).exists());
    assert!(std::path::Path::new(&bak_path).exists());

    // Load should recover from backup
    let loaded = load(&config_path).expect("load with recovery").expect("identity exists");
    assert_eq!(loaded.device_id, "test_dev");
    assert!(std::path::Path::new(&config_path).exists(), "Primary file should be restored");

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_plaintext_migration_to_encrypted() {
    let temp_dir = std::env::temp_dir().join(format!("aether_test_mig_{}", std::process::id()));
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).expect("create temp dir");

    let config_path = temp_dir.join("aether.toml").to_string_lossy().to_string();

    // 1. Write legacy plaintext identity (without AETHERCFG1 header)
    let ident = dummy_identity();
    std::env::remove_var("AETHER_CONFIG_KEY");
    save(&config_path, &ident).expect("save plaintext");

    let raw = fs::read(&config_path).expect("read raw");
    assert!(!raw.starts_with(b"AETHERCFG1\n"), "Must be legacy plaintext");

    // 2. Set AETHER_CONFIG_KEY and load
    use base64::Engine;
    let test_key = [42u8; 32];
    let key_b64 = base64::engine::general_purpose::STANDARD.encode(&test_key);
    std::env::set_var("AETHER_CONFIG_KEY", &key_b64);

    let loaded = load(&config_path).expect("load with migration").expect("identity exists");
    assert_eq!(loaded.device_id, "test_dev");

    // 3. File should now be encrypted with magic header!
    let migrated_raw = fs::read(&config_path).expect("read migrated");
    assert!(migrated_raw.starts_with(b"AETHERCFG1\n"), "Must be migrated to encrypted format");

    std::env::remove_var("AETHER_CONFIG_KEY");
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_plaintext_migration_fails_fatally_when_save_fails() {
    let temp_dir = std::env::temp_dir().join(format!("aether_test_mig_fail_{}", std::process::id()));
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).expect("create temp dir");

    let config_path = temp_dir.join("aether.toml").to_string_lossy().to_string();

    // 1. Write legacy plaintext identity (without AETHERCFG1 header)
    let ident = dummy_identity();
    std::env::remove_var("AETHER_CONFIG_KEY");
    save(&config_path, &ident).expect("save plaintext");

    // Make config_path read-only so subsequent atomic save fails
    let mut perms = fs::metadata(&config_path).expect("meta").permissions();
    perms.set_readonly(true);
    fs::set_permissions(&config_path, perms).expect("set readonly");

    // 2. Set AETHER_CONFIG_KEY and load
    use base64::Engine;
    let test_key = [42u8; 32];
    let key_b64 = base64::engine::general_purpose::STANDARD.encode(&test_key);
    std::env::set_var("AETHER_CONFIG_KEY", &key_b64);

    let res = load(&config_path);
    assert!(res.is_err(), "Migration must fail fatally if saving encrypted config fails");

    // Cleanup permissions before deleting temp dir
    let mut perms_clean = fs::metadata(&config_path).expect("meta").permissions();
    perms_clean.set_readonly(false);
    let _ = fs::set_permissions(&config_path, perms_clean);
    std::env::remove_var("AETHER_CONFIG_KEY");
    let _ = fs::remove_dir_all(&temp_dir);
}
