use aether::cache::{provision_lock, ProvisionGuard};
use std::time::Duration;

#[test]
fn test_provision_lock_mutual_exclusion_and_release() {
    let temp_dir = std::env::temp_dir().join(format!("aether_test_prov_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&temp_dir);
    std::fs::create_dir_all(&temp_dir).expect("create temp dir");

    let config_path = temp_dir.join("aether.toml").to_string_lossy().to_string();

    // 1. Acquire primary lock
    let guard1 = provision_lock(&config_path).expect("guard1 acquisition should succeed");

    // 2. Second attempt with short wait must fail (non-failing-open)
    let lock_file = aether::cache::cache_path(&config_path).into_os_string();
    let mut lock_path = lock_file;
    lock_path.push(".provision.lock");
    let lock_buf = std::path::PathBuf::from(lock_path);

    let res = ProvisionGuard::try_acquire(&lock_buf, Duration::from_millis(150));
    assert!(res.is_err(), "Concurrent lock acquisition must fail and not fail open");

    // 3. Drop primary lock
    drop(guard1);

    // 4. Now second attempt must succeed
    let guard2 = ProvisionGuard::try_acquire(&lock_buf, Duration::from_millis(500));
    assert!(guard2.is_ok(), "Lock acquisition after drop must succeed");

    drop(guard2);
    let _ = std::fs::remove_dir_all(&temp_dir);
}
