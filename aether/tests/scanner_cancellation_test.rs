#![allow(clippy::uninlined_format_args)]

use aether::cache::Measurement;
use aether::prober::{
    hunt_best, register_scan_session, request_scan_cancel, scan_cancelled_for, IpScan, ProbeConfig,
    ProbeResult, ScanMode, ScanRunGuard, ScanTally, VerifyFn,
};
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

static TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Fresh temp dir + config for one scan, so a test never reads another's cache.
fn scratch_config(tag: &str) -> ProbeConfig {
    let mut config = ProbeConfig::for_test();
    let temp_dir =
        std::env::temp_dir().join(format!("aether_scan_cancel_{tag}_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&temp_dir);
    config.config_path = temp_dir.join("aether.toml").to_string_lossy().to_string();
    config
}

#[tokio::test]
async fn test_scanner_cancellation_aborts_pending_futures() {
    let _guard = TEST_LOCK.lock().await;
    let mut config = ProbeConfig::for_test();
    let temp_dir =
        std::env::temp_dir().join(format!("aether_scan_cancel_1_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&temp_dir);
    config.config_path = temp_dir.join("aether.toml").to_string_lossy().to_string();
    let ports = vec![443];

    // Verification future that sleeps for 10 seconds to simulate in-flight probes
    let verify: Box<VerifyFn<'static>> = Box::new(
        |ip: IpAddr, port: u16, _timeout: Duration, _ironclad: bool| {
            Box::pin(async move {
                tokio::time::sleep(Duration::from_secs(10)).await;
                Some(ProbeResult {
                    ip,
                    port,
                    rtt: Duration::from_millis(50),
                })
            })
        },
    );

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
    assert!(
        result.is_err(),
        "Expected error when cancelled before any probe succeeded"
    );
}

#[tokio::test]
async fn test_scanner_cancellation_preserves_best_hit() {
    let _guard = TEST_LOCK.lock().await;
    let mut config = ProbeConfig::for_test();
    let temp_dir =
        std::env::temp_dir().join(format!("aether_scan_cancel_2_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&temp_dir);
    config.config_path = temp_dir.join("aether.toml").to_string_lossy().to_string();
    let ports = vec![443];
    let counter = Arc::new(AtomicUsize::new(0));

    let verify_counter = counter.clone();
    let verify: Box<VerifyFn<'static>> = Box::new(
        move |ip: IpAddr, port: u16, _timeout: Duration, _ironclad: bool| {
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
        },
    );

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
    assert!(
        result.is_ok(),
        "Expected Ok(best) when cancelled after a probe succeeded"
    );
    let pr = result.unwrap();
    assert_eq!(pr.rtt, Duration::from_millis(15));
}

#[tokio::test]
async fn test_scanner_pre_hunt_cancellation() {
    let _guard = TEST_LOCK.lock().await;
    let config = scratch_config("pre");
    let ports = vec![443];

    let probe_called = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let probe_called_clone = probe_called.clone();
    let verify: Box<VerifyFn<'static>> = Box::new(
        move |ip: IpAddr, port: u16, _timeout: Duration, _ironclad: bool| {
            probe_called_clone.store(true, Ordering::SeqCst);
            Box::pin(async move {
                Some(ProbeResult {
                    ip,
                    port,
                    rtt: Duration::from_millis(15),
                })
            })
        },
    );

    // Press "Stop" with NO scan running, then "Connect".
    request_scan_cancel();

    let result = hunt_best(&config, &ports, IpScan::V4, ScanMode::Turbo, &*verify).await;

    // The Stop belonged to no scan: `register_scan_session` used to store it, hand
    // `Err(NoCleanEndpoint)` to the next Connect and swallow the Stop entirely — so
    // the first Connect after every idle Stop failed with a "no working gateway"
    // message that described a scan that had never run.
    assert!(
        probe_called.load(Ordering::SeqCst),
        "a Stop raised before the scan started must not cancel that scan"
    );
    assert!(
        result.is_ok(),
        "stale cancellation poisoned the scan: {result:?}"
    );
    let _ = std::fs::remove_dir_all(
        std::env::temp_dir().join(format!("aether_scan_cancel_pre_{}", std::process::id())),
    );
}

#[tokio::test]
async fn test_two_live_scans_are_both_cancellable() {
    let _guard = TEST_LOCK.lock().await;

    let (gen1, token1) = register_scan_session().expect("first registration");
    let run1 = ScanRunGuard(gen1);
    let (gen2, token2) = register_scan_session().expect("second registration");
    let run2 = ScanRunGuard(gen2);
    assert_ne!(gen1, gen2, "each scan gets its own generation");
    assert!(!token1.is_cancelled() && !token2.is_cancelled());

    request_scan_cancel();

    // `SCAN_REGISTRY` held exactly one `Option<CancellationToken>`, so the second
    // registration overwrote the first: Stop reached only the newest scan and the
    // older one probed on at double the intended concurrency with no way to halt it.
    assert!(token1.is_cancelled(), "Stop must reach the older live scan");
    assert!(
        token2.is_cancelled(),
        "Stop must reach the newest live scan"
    );
    assert!(
        scan_cancelled_for(gen1),
        "the older scan must observe its own cancellation"
    );
    assert!(
        scan_cancelled_for(gen2),
        "the newest scan must observe its own cancellation"
    );

    drop(run1);
    drop(run2);
}

#[tokio::test]
async fn test_retired_scans_token_does_not_leak_into_a_newer_scan() {
    let _guard = TEST_LOCK.lock().await;

    let (gen1, token1) = register_scan_session().expect("first registration");
    let run1 = ScanRunGuard(gen1);
    let (gen2, token2) = register_scan_session().expect("second registration");
    let run2 = ScanRunGuard(gen2);

    // Scan 1 finishes while scan 2 is still probing. The guard compared its own
    // generation against the NEWEST one and did nothing on mismatch, so scan 1's
    // token stayed in the registry — uncancelled, unreachable, and still "live" as
    // far as any later Stop was concerned.
    drop(run1);
    assert!(
        token1.is_cancelled(),
        "a finished scan must have its own token cancelled"
    );
    assert!(!token2.is_cancelled(), "the still-live scan keeps running");
    assert!(
        !scan_cancelled_for(gen2),
        "retiring an older scan must not cancel a newer one"
    );

    // A Stop now reaches the one scan that is actually live, and the scan the test
    // started afterwards is unaffected.
    request_scan_cancel();
    assert!(
        token2.is_cancelled(),
        "Stop must reach the remaining live scan"
    );
    drop(run2);

    let (gen3, token3) = register_scan_session().expect("third registration");
    let run3 = ScanRunGuard(gen3);
    assert!(!token3.is_cancelled());
    assert!(
        !scan_cancelled_for(gen3),
        "a Stop from a previous generation must not carry over"
    );
    drop(run3);
}

#[tokio::test]
async fn test_cancel_during_a_scan_still_stops_that_scan() {
    let _guard = TEST_LOCK.lock().await;
    let config = scratch_config("midflight");
    let ports = vec![443];

    let verify: Box<VerifyFn<'static>> = Box::new(
        |ip: IpAddr, port: u16, _timeout: Duration, _ironclad: bool| {
            Box::pin(async move {
                tokio::time::sleep(Duration::from_secs(10)).await;
                Some(ProbeResult {
                    ip,
                    port,
                    rtt: Duration::from_millis(50),
                })
            })
        },
    );

    tokio::spawn(async {
        tokio::time::sleep(Duration::from_millis(20)).await;
        request_scan_cancel();
    });

    let start = Instant::now();
    let result = hunt_best(&config, &ports, IpScan::V4, ScanMode::Balanced, &*verify).await;

    // Dropping the stale-stop inheritance must not weaken a real Stop.
    assert!(
        start.elapsed() < Duration::from_millis(400),
        "a Stop raised while the scan is registered must abort it, took {:?}",
        start.elapsed()
    );
    assert!(
        result.is_err(),
        "nothing was probed successfully, so the scan must not report Ok"
    );
    let _ = std::fs::remove_dir_all(std::env::temp_dir().join(format!(
        "aether_scan_cancel_midflight_{}",
        std::process::id()
    )));
}

// ── Finding 3: progress accounting is a pure function, so test it as one ──────

#[test]
fn drill_down_probes_never_inflate_the_sweep_counter() {
    let mut tally = ScanTally::new(10);
    for _ in 0..10 {
        tally.candidate_done();
    }
    // A hot /24 wave examines ~40 neighbours the sweep never queued.
    tally.drill_down_done(40);

    // The old code did `scanned += 1 + drill_examined`, so the number the UI was
    // shown blew past the total announced by `ScanStart`...
    assert_eq!(
        tally.reported(),
        10,
        "reported work must never exceed the queued total"
    );
    // ...and the `scanned == total_candidates` completion line could then never
    // match, so the scan that had finished all its work never said so.
    assert!(
        tally.is_complete(),
        "completion must fire once the sweep is done"
    );
    assert!(
        tally.should_report(),
        "the final tick must still emit a progress event"
    );
    // The extra work is not hidden, it is just counted apart.
    assert_eq!(
        tally.drill_probes(),
        40,
        "drill-down probes are reported separately"
    );
    assert_eq!(tally.probes_sent(), 50, "total probe work is still visible");
}

#[test]
fn a_partial_sweep_is_not_complete_and_reports_every_fiftieth() {
    let mut tally = ScanTally::new(200);
    for _ in 0..49 {
        tally.candidate_done();
    }
    assert!(!tally.is_complete());
    assert!(!tally.should_report(), "no event between the ticks");
    tally.candidate_done();
    assert!(tally.should_report(), "every 50th candidate emits");
    assert_eq!(tally.reported(), 50);
    tally.drill_down_done(400);
    assert_eq!(
        tally.reported(),
        50,
        "drill-downs do not move the sweep counter"
    );
    assert_eq!(tally.drill_probes(), 400);
}

#[tokio::test]
async fn test_scanner_cancellation_barrier_with_populated_cache() {
    let _guard = TEST_LOCK.lock().await;
    let mut config = ProbeConfig::for_test();
    let temp_dir =
        std::env::temp_dir().join(format!("aether_scan_cancel_barrier_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&temp_dir);
    config.config_path = temp_dir.join("aether.toml").to_string_lossy().to_string();

    // Populate cache with multiple endpoints so Tier-0 cache race is triggered
    let ep1 = "192.0.2.1:443".parse::<std::net::SocketAddr>().unwrap();
    let ep2 = "192.0.2.2:443".parse::<std::net::SocketAddr>().unwrap();
    // `write_with_rtt` takes the measurement kind the RTT came from; the call site
    // predated that parameter and no longer compiled.
    config.cache_kind.write_with_rtt(
        &config.config_path,
        vec![(ep1, 10), (ep2, 20)],
        Measurement::HandshakeProbe,
    );

    let ports = vec![443];

    // Verification probe that simulates a long running probe (5s)
    let entered = Arc::new(tokio::sync::Notify::new());
    let entered_probe = entered.clone();
    let verify: Box<VerifyFn<'static>> = Box::new(
        move |ip: IpAddr, port: u16, _timeout: Duration, _ironclad: bool| {
            let entered = entered_probe.clone();
            Box::pin(async move {
                entered.notify_one();
                tokio::time::sleep(Duration::from_secs(5)).await;
                Some(ProbeResult {
                    ip,
                    port,
                    rtt: Duration::from_millis(50),
                })
            })
        },
    );

    let hunt = hunt_best(&config, &ports, IpScan::V4, ScanMode::Balanced, &*verify);
    tokio::pin!(hunt);
    tokio::select! {
        _ = entered.notified() => {}
        result = &mut hunt => panic!("scan completed before cancellation: {result:?}"),
    }
    let start = Instant::now();
    request_scan_cancel();
    let result = hunt.await;
    let elapsed = start.elapsed();

    assert!(result.is_err(), "Expected cancellation error");
    assert!(
        elapsed < Duration::from_millis(250),
        "Cancellation with populated cache must abort immediately (< 250ms), took {elapsed:?}"
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}
