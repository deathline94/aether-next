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
    let err_msg = res.err().unwrap().to_string();
    assert!(
        err_msg.contains(&format!("held by pid={} (alive=true)", std::process::id())),
        "Timeout error must report owner pid and alive liveness: {err_msg}"
    );

    // 3. Drop primary lock
    drop(guard1);

    // Lock file MUST be retained permanently to prevent unlinked-inode races
    assert!(lock_buf.exists(), "Lock file must NOT be deleted on drop");

    // 4. Now second attempt must succeed
    let guard2 = ProvisionGuard::try_acquire(&lock_buf, Duration::from_millis(500));
    assert!(guard2.is_ok(), "Lock acquisition after drop must succeed");

    drop(guard2);
    assert!(lock_buf.exists(), "Lock file must remain after guard2 drop");
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_multi_contender_provision_lock_sequential_exclusion() {
    use std::sync::{Arc, Barrier};

    let temp_dir = std::env::temp_dir().join(format!("aether_test_prov_multi_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&temp_dir);
    std::fs::create_dir_all(&temp_dir).expect("create temp dir");

    let config_path = temp_dir.join("aether.toml").to_string_lossy().to_string();
    let mut lock_file = aether::cache::cache_path(&config_path).into_os_string();
    lock_file.push(".provision.lock");
    let lock_buf = std::path::PathBuf::from(lock_file);

    let contenders = 3;
    let barrier = Arc::new(Barrier::new(contenders));
    let success_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    let mut handles = Vec::new();
    for _ in 0..contenders {
        let b = Arc::clone(&barrier);
        let sc = Arc::clone(&success_count);
        let p = lock_buf.clone();
        handles.push(std::thread::spawn(move || {
            b.wait();
            // Retry acquiring for up to 3 seconds
            let start = std::time::Instant::now();
            while start.elapsed() < Duration::from_secs(3) {
                if let Ok(guard) = ProvisionGuard::try_acquire(&p, Duration::from_millis(50)) {
                    sc.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    std::thread::sleep(Duration::from_millis(100));
                    drop(guard);
                    return;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            panic!("Contender failed to acquire lock within timeout");
        }));
    }

    for h in handles {
        h.join().expect("thread join");
    }

    assert_eq!(
        success_count.load(std::sync::atomic::Ordering::SeqCst),
        contenders,
        "All contenders must sequentially acquire and release the lock"
    );
    assert!(lock_buf.exists(), "Lock file must exist after all contenders drop");

    let _ = std::fs::remove_dir_all(&temp_dir);
}
