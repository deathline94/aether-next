//! Process-wide runtime configuration store (S3 fix).
//!
//! Historically the engine round-tripped resolved settings through
//! `std::env::set_var`, but mutating the process environment after the async
//! runtime has spawned worker threads is a data race (and is `unsafe` as of the
//! 2024 edition). This module is a thread-safe, in-process replacement:
//! writers call [`set`], readers call [`var`], and any key not set here
//! transparently falls back to the real process environment, so values injected
//! by a parent GUI process or the shell keep working unchanged.

use std::collections::HashMap;
use std::sync::{OnceLock, RwLock};

fn store() -> &'static RwLock<HashMap<String, String>> {
    static STORE: OnceLock<RwLock<HashMap<String, String>>> = OnceLock::new();
    STORE.get_or_init(|| RwLock::new(HashMap::new()))
}

/// Set (or overwrite) a runtime config value. Safe to call from any thread.
pub fn set(key: &str, val: &str) {
    if let Ok(mut map) = store().write() {
        map.insert(key.to_string(), val.to_string());
    }
}

/// Read a runtime config value, falling back to the real process environment
/// when the key has not been set in-process.
pub fn var(key: &str) -> Option<String> {
    if let Ok(map) = store().read() {
        if let Some(v) = map.get(key) {
            return Some(v.clone());
        }
    }
    std::env::var(key).ok()
}

// ─── Typed convenience accessors ────────────────────────────────────────────

/// Read a boolean flag ("1", "true", "yes", "on").
pub fn flag(key: &str) -> bool {
    match var(key) {
        Some(v) => {
            let v = v.trim().to_lowercase();
            v == "1" || v == "true" || v == "yes" || v == "on"
        }
        None => false,
    }
}

/// Read a usize value.
pub fn usize(key: &str) -> Option<usize> {
    var(key).and_then(|v| v.trim().parse().ok())
}

/// Read a u16 value.
pub fn u16(key: &str) -> Option<u16> {
    var(key).and_then(|v| v.trim().parse().ok())
}
