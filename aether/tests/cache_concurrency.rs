//! T083 — two processes writing the learned-endpoint cache at once.
//!
//! The lock in `cache.rs` is allowed to *skip* an update when it cannot take the
//! lock in time (the cache is learned state, and losing one write is cheaper than
//! writing over another process's whole document). What it is not allowed to do is
//! lose one silently, or let a read-modify-write land on a stale snapshot.
//!
//! So this does not assert "10 000 updates, none lost" — the design would reject
//! that. It asserts the property that survives the skip rule: every update a
//! process was told it applied is present afterwards, and one process's write never
//! erases another's. That second part is what a missing or advisory-but-ignored lock
//! breaks first, because each writer rewrites the entire document.
//!
//! Runs the real thing across two OS processes: an in-process thread pair would
//! share the same `File` descriptors and prove nothing about `fs2`'s advisory lock.

use std::io::Read;
use std::net::SocketAddr;
use std::process::{Command, Stdio};

// Deliberately not `AETHER_*`: that prefix belongs to the engine's own single-reader
// config store, and a test-harness channel must not be able to look like it.
const CHILD_ENV: &str = "CACHE_TEST_CHILD_SPEC";
const WRITES: usize = 120;

fn slot_address(slot: usize) -> SocketAddr {
    // Documentation prefix 198.51.100.0/24: never a real edge, and `sanitise`
    // keeps it because it is a plausible unicast address.
    format!("198.51.100.{}:443", 20 + slot).parse().unwrap()
}

fn child_body(slot: usize, base: &str) -> usize {
    let addr = slot_address(slot);
    let mut applied = 0usize;
    for _ in 0..WRITES {
        if aether::cache::record_success(base, addr, true) == aether::cache::Mutation::Applied {
            applied += 1;
        }
    }
    applied
}

#[test]
fn two_processes_updating_the_cache_lose_no_applied_update() {
    // A test binary reading its own harness variable is not app configuration.
    #[allow(clippy::disallowed_methods)]
    let spawned_as_child = std::env::var(CHILD_ENV).ok();
    if let Some(spec) = spawned_as_child {
        let (slot, base) = spec.split_once('|').expect("CHILD_ENV is `slot|base`");
        let applied = child_body(slot.parse().expect("slot number"), base);
        println!("APPLIED {applied}");
        std::io::Write::flush(&mut std::io::stdout()).ok();
        std::process::exit(0);
    }

    let dir = std::env::temp_dir().join(format!("aether_cache_two_proc_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");
    let base = dir.join("aether.toml").to_string_lossy().to_string();

    let exe = std::env::current_exe().expect("test binary");
    let mut children = Vec::new();
    for slot in 0..2usize {
        let child = Command::new(&exe)
            .arg("--exact")
            .arg("two_processes_updating_the_cache_lose_no_applied_update")
            .arg("--nocapture")
            .env(CHILD_ENV, format!("{slot}|{base}"))
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn the contending writer");
        children.push(child);
    }

    let mut applied = Vec::new();
    for (slot, mut child) in children.into_iter().enumerate() {
        let mut out = String::new();
        if let Some(mut stdout) = child.stdout.take() {
            let _ = stdout.read_to_string(&mut out);
        }
        let status = child.wait().expect("wait for the child");
        assert!(status.success(), "writer {slot} exited with {status}");
        let count = out
            .lines()
            .find_map(|l| l.strip_prefix("APPLIED "))
            .and_then(|v| v.trim().parse::<usize>().ok())
            .unwrap_or_else(|| panic!("writer {slot} reported no applied count; stdout was {out:?}"));
        applied.push(count);
    }

    // Both must have made progress: zero applied means they starved each other,
    // and the assertion below would pass trivially on two empty histories.
    for (slot, count) in applied.iter().enumerate() {
        assert!(
            *count > WRITES / 4,
            "writer {slot} applied only {count} of {WRITES} updates — the lock is starving writers, not sequencing them"
        );
    }

    let cache = aether::cache::load_endpoints(&base);
    assert_eq!(cache.version, 2, "a document written under contention must still be versioned");
    for (slot, count) in applied.iter().enumerate() {
        let addr = slot_address(slot);
        let entry = cache
            .masque
            .iter()
            .find(|e| e.addr == addr)
            .unwrap_or_else(|| panic!("writer {slot}'s endpoint {addr} vanished from the cache"));
        assert_eq!(
            entry.successes as usize, *count,
            "writer {slot} reported {count} applied updates but the cache holds {} — a \
             read-modify-write landed on a stale snapshot and erased the other writer's work",
            entry.successes
        );
    }

    let _ = std::fs::remove_dir_all(&dir);
}
