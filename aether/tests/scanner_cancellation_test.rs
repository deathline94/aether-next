#![allow(clippy::uninlined_format_args)]

use aether::prober::{hunt_best, request_scan_cancel, IpScan, ProbeConfig, ProbeResult, ScanMode, VerifyFn};
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

static TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[tokio::test]
async fn test_scanner_cancellation_aborts_pending_futures() {
    let _guard = TEST_LOCK.lock().await;
    let mut config = ProbeConfig::for_test();
    let temp_dir = std::env::temp_dir().join(format!("aether_scan_cancel_1_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&temp_dir);
    config.config_path = temp_dir.join("aether.toml").to_string_lossy().to_string();
    let ports = vec![443];

    // Verification future that sleeps for 10 seconds to simulate in-flight probes
    let verify: Box<VerifyFn<'static>> = Box::new(|ip: IpAddr, port: u16, _timeout: Duration, _ironclad: bool| {
        Box::pin(async move {
            tokio::time::sleep(Duration::from_secs(10)).await;
            Some(ProbeResult {
                ip,
                port,
                rtt: Duration::from_millis(50),
            })
        })
    });

    // Spawn a concurrent task that triggers scan cancellation after 20ms
    tokio::spawn(async {
        tokio::time::sleep(Duration::from_millis(20)).await;
        request_scan_cancel();
    });

    let start = Instant::now();
    let result = hunt_best(&config, &ports, IpScan::V4, ScanMode::Turbo, &*verify).await;
    let elapsed = start.elapsed();

    // Cancellation must break out promptly (< 250ms), far faster than the 10s pending futures
    assert!(
        elapsed < Duration::from_millis(250),
        "hunt_best took {elapsed:?} to abort, expected < 250ms"
    );
    // Since no probe finished, result is NoCleanEndpoint
    assert!(result.is_err(), "Expected error when cancelled before any probe succeeded");
}

#[tokio::test]
async fn test_scanner_cancellation_preserves_best_hit() {
    let _guard = TEST_LOCK.lock().await;
    let mut config = ProbeConfig::for_test();
    let temp_dir = std::env::temp_dir().join(format!("aether_scan_cancel_2_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&temp_dir);
    config.config_path = temp_dir.join("aether.toml").to_string_lossy().to_string();
    let ports = vec![443];
    let counter = Arc::new(AtomicUsize::new(0));

    let verify_counter = counter.clone();
    let verify: Box<VerifyFn<'static>> = Box::new(move |ip: IpAddr, port: u16, _timeout: Duration, _ironclad: bool| {
        let cnt = verify_counter.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            if cnt == 0 {
                // First probe succeeds fast
                Some(ProbeResult {
                    ip,
                    port,
                    rtt: Duration::from_millis(15),
                })
            } else {
                // Subsequent probes hang
                tokio::time::sleep(Duration::from_secs(10)).await;
                Some(ProbeResult {
                    ip,
                    port,
                    rtt: Duration::from_millis(50),
                })
            }
        })
    });

    tokio::spawn(async {
        // Wait for first hit to land then cancel
        tokio::time::sleep(Duration::from_millis(30)).await;
        request_scan_cancel();
    });

    let start = Instant::now();
    let result = hunt_best(&config, &ports, IpScan::V4, ScanMode::Balanced, &*verify).await;
    let elapsed = start.elapsed();

    assert!(
        elapsed < Duration::from_millis(300),
        "hunt_best took {elapsed:?} to abort, expected < 300ms"
    );
    assert!(result.is_ok(), "Expected Ok(best) when cancelled after a probe succeeded");
    let pr = result.unwrap();
    assert_eq!(pr.rtt, Duration::from_millis(15));
}

#[tokio::test]
async fn test_scanner_pre_hunt_cancellation() {
    let _guard = TEST_LOCK.lock().await;
    let mut config = ProbeConfig::for_test();
    let temp_dir = std::env::temp_dir().join(format!("aether_scan_cancel_pre_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&temp_dir);
    config.config_path = temp_dir.join("aether.toml").to_string_lossy().to_string();
    let ports = vec![443];

    let probe_called = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let probe_called_clone = probe_called.clone();
    let verify: Box<VerifyFn<'static>> = Box::new(move |ip: IpAddr, port: u16, _timeout: Duration, _ironclad: bool| {
        probe_called_clone.store(true, Ordering::SeqCst);
        Box::pin(async move {
            Some(ProbeResult {
                ip,
                port,
                rtt: Duration::from_millis(15),
            })
        })
    });

    // Request cancel BEFORE hunt_best is invoked
    request_scan_cancel();

    let start = Instant::now();
    let result = hunt_best(&config, &ports, IpScan::V4, ScanMode::Balanced, &*verify).await;
    let elapsed = start.elapsed();

    assert!(result.is_err(), "Expected error when cancelled prior to hunt_best");
    assert!(!probe_called.load(Ordering::SeqCst), "Verify probe should not have been called");
    assert!(elapsed < Duration::from_millis(100), "Pre-cancelled hunt must abort immediately (< 100ms), took {elapsed:?}");
}
