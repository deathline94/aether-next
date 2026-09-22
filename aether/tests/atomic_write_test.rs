use aether::account::Identity;
use aether::config::{load, save, write_private_file};
use aether::runtime_env;
use base64::Engine;
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

/// A pre-envelope config, exactly as an upgraded install leaves it behind.
fn write_legacy_plaintext(path: &str) {
    let b64 = base64::engine::general_purpose::STANDARD;
    fs::write(
        path,
        format!(
            "device_id = \"test_dev\"\naccess_token = \"test_token\"\nipv4 = \"172.16.0.2\"\nipv6 = \"2606:4700:110:8751:19d6:4fd1:d894:21dc\"\nwg_private_key = \"{}\"\nwg_peer_public_key = \"{}\"\n",
            b64.encode([2u8; 32]),
            b64.encode([3u8; 32]),
        ),
    )
    .expect("write legacy plaintext");
}

fn set_key() {
    let key_b64 = base64::engine::general_purpose::STANDARD.encode([42u8; 32]);
    runtime_env::set("AETHER_CONFIG_KEY", &key_b64);
}

static TEST_MUTEX: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

fn temp(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("aether_test_{tag}_{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

#[test]
fn test_atomic_write_and_overwrite() {
    let _guard = TEST_MUTEX.lock();
    let dir = temp("atomic");
    let file_path = dir.join("secret.bin").to_string_lossy().to_string();

    write_private_file(&file_path, b"initial secret payload").expect("initial write");
    assert_eq!(fs::read_to_string(&file_path).unwrap(), "initial secret payload");

    write_private_file(&file_path, b"updated secret payload").expect("overwrite");
    assert_eq!(fs::read_to_string(&file_path).unwrap(), "updated secret payload");

    // Every temp file must have been consumed, and the name must be unique
    // enough that two writers in one process cannot collide on it.
    let leftovers: Vec<String> = fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| n.ends_with(".tmp"))
        .collect();
    assert!(leftovers.is_empty(), "temp files left behind: {leftovers:?}");

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_unauthenticated_backup_is_never_restored() {
    let _guard = TEST_MUTEX.lock();
    let dir = temp("bak");
    let config_path = dir.join("aether.toml").to_string_lossy().to_string();
    let bak_path = format!("{config_path}.bak");
    set_key();

    // A config that exists only at the backup name is *not* a config. Restoring
    // it was the bug: whichever process could write `<path>.bak` chose the
    // identity the tunnel authenticated with.
    save(&bak_path, &dummy_identity()).expect("save to bak");
    match load(&config_path) {
        Ok(None) => {}
        Ok(Some(id)) => panic!("load adopted a backup identity: {}", id.device_id),
        Err(e) => panic!("load must report no config, not fail: {e}"),
    }
    assert!(!std::path::Path::new(&bak_path).exists(), "the stray backup must be moved");
    assert!(
        std::path::Path::new(&format!("{config_path}.quarantined")).exists(),
        "and preserved for inspection rather than deleted"
    );

    runtime_env::remove("AETHER_CONFIG_KEY");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_plaintext_migration_to_encrypted() {
    let _guard = TEST_MUTEX.lock();
    let dir = temp("mig");
    let config_path = dir.join("aether.toml").to_string_lossy().to_string();

    runtime_env::remove("AETHER_CONFIG_KEY");
    write_legacy_plaintext(&config_path);
    let raw = fs::read(&config_path).expect("read raw");
    assert!(!raw.starts_with(b"AETHERCFG"), "Must be legacy plaintext");

    set_key();
    let loaded = match load(&config_path) {
        Ok(Some(id)) => id,
        Ok(None) => panic!("expected an identity after migration"),
        Err(e) => panic!("load with migration: {e}"),
    };
    assert_eq!(loaded.device_id, "test_dev");

    let migrated_raw = fs::read(&config_path).expect("read migrated");
    assert!(
        migrated_raw.starts_with(b"AETHERCFG2\n"),
        "Must be migrated to the v2 envelope"
    );

    runtime_env::remove("AETHER_CONFIG_KEY");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_plaintext_migration_fails_fatally_when_save_fails() {
    let _guard = TEST_MUTEX.lock();
    let dir = temp("mig_fail");
    let config_path = dir.join("aether.toml").to_string_lossy().to_string();

    runtime_env::remove("AETHER_CONFIG_KEY");
    write_legacy_plaintext(&config_path);

    // Make the config unwritable so the migration re-save fails.
    let mut perms = fs::metadata(&config_path).expect("meta").permissions();
    perms.set_readonly(true);
    fs::set_permissions(&config_path, perms).expect("set readonly");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut dir_perms = fs::metadata(&dir).expect("meta dir").permissions();
        dir_perms.set_mode(0o555);
        fs::set_permissions(&dir, dir_perms).expect("set dir readonly");
    }

    set_key();
    assert!(load(&config_path).is_err(), "Migration must fail fatally if the re-save fails");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut dir_perms = fs::metadata(&dir).expect("meta dir").permissions();
        dir_perms.set_mode(0o755);
        let _ = fs::set_permissions(&dir, dir_perms);
    }
    let mut perms_clean = fs::metadata(&config_path).expect("meta").permissions();
    #[allow(clippy::permissions_set_readonly_false)]
    perms_clean.set_readonly(false);
    let _ = fs::set_permissions(&config_path, perms_clean);
    runtime_env::remove("AETHER_CONFIG_KEY");
    let _ = fs::remove_dir_all(&dir);
}

#[cfg(all(windows, feature = "test-hooks"))]
#[test]
fn test_write_private_file_fails_closed_on_acl_failure() {
    let _guard = TEST_MUTEX.lock();
    let dir = temp("acl_fail");
    let file_path = dir.join("secret.bin").to_string_lossy().to_string();

    aether::config::ACL_FAIL_FOR_TEST.store(true, std::sync::atomic::Ordering::SeqCst);
    let res = write_private_file(&file_path, b"super secret data");
    aether::config::ACL_FAIL_FOR_TEST.store(false, std::sync::atomic::Ordering::SeqCst);

    assert!(res.is_err(), "write_private_file must fail when ACL restriction fails");
    assert!(!std::path::Path::new(&file_path).exists(), "target secret file must not be created");
    let leftovers: Vec<String> = fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| n.ends_with(".tmp"))
        .collect();
    assert!(leftovers.is_empty(), "the temp file must be removed on failure: {leftovers:?}");

    let _ = fs::remove_dir_all(&dir);
}
