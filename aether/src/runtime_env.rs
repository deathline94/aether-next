//! Process-wide runtime configuration store — the **only** reader of `AETHER_*`.
//!
//! ## Why this module owns the rule
//!
//! The engine historically round-tripped settings through `std::env::set_var`,
//! which is a data race once the async runtime has workers (and `unsafe` in the
//! 2024 edition). The replacement shipped half-migrated: this store was written
//! by some call sites while the *readers* stayed on `std::env::var`. That is not
//! a style problem — it disabled a security control and created a latent
//! process-wide switch at the same time:
//!
//! * `h3_probe.rs` set `the former ambient TLS kill-switch` **here**;
//! * `tls.rs` and `masque_h2.rs` read it from the **real environment**.
//!
//! So the fingerprint probe's advertised "verify nothing, read SETTINGS from any
//! edge" mode never took effect, while the same key remained reachable from any
//! local process that could set an environment variable.
//!
//! ## Contract
//!
//! * The process environment is snapshotted **once**, on first access, for
//!   `AETHER_`-prefixed keys only. Values injected by the parent GUI/shell before
//!   spawn therefore keep working; values appearing afterwards cannot silently
//!   win over an in-process write.
//! * [`var`] never falls through to the live environment.
//! * [`set`] / [`remove`] are the only mutation paths, both poison-safe: a write
//!   is never silently dropped (the previous `if let Ok(..)` discarded it, after
//!   which readers saw a *different* setting).
//! * [`flag`] is truthiness, not presence. `AETHER_X=0` means **false**
//!   (see `wireguard.rs`, where presence-only inverted a data-plane check).
//! * A numeric value that fails to parse is reported, not silently defaulted.

use std::collections::HashMap;
use std::sync::{OnceLock, RwLock};

const PREFIX: &str = "AETHER_";

#[derive(Default)]
struct Store {
    map: RwLock<HashMap<String, String>>,
}

fn store() -> &'static Store {
    static STORE: OnceLock<Store> = OnceLock::new();
    STORE.get_or_init(|| {
        let mut seeded = HashMap::new();
        // Snapshot once, before any worker thread exists. Everything after this
        // point flows through set()/remove().
        for (k, v) in std::env::vars_os() {
            let (k, v) = (k.to_string_lossy().into_owned(), v.to_string_lossy().into_owned());
            if k.starts_with(PREFIX) {
                seeded.insert(k, v);
            }
        }
        log::debug!(
            "[config] runtime store seeded with {} {PREFIX}* value(s) from the process environment",
            seeded.len()
        );
        Store {
            map: RwLock::new(seeded),
        }
    })
}

/// Poison-safe read access. A panic elsewhere must not make configuration
/// unreadable or, worse, drop a write on the floor.
fn with_map<R>(f: impl FnOnce(&HashMap<String, String>) -> R) -> R {
    let guard = match store().map.read() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    f(&guard)
}

/// Set (or overwrite) a runtime config value. Safe to call from any thread.
pub fn set(key: &str, val: &str) {
    let mut guard = match store().map.write() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    guard.insert(key.to_string(), val.to_string());
}

/// Clear a runtime config value.
///
/// The store previously had no removal path at all, which meant a diagnostic
/// that turned verification off could only ever be *shadowed*, never undone —
/// leaving a sticky switch for the remaining life of the process.
pub fn remove(key: &str) {
    let mut guard = match store().map.write() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    guard.remove(key);
}

/// Read a config value. Never consults the live process environment.
pub fn var(key: &str) -> Option<String> {
    with_map(|m| m.get(key).cloned())
}

/// Immutable copy of the current configuration, for diagnostics export.
pub fn snapshot() -> Vec<(String, String)> {
    let mut v = with_map(|m| m.iter().map(|(k, val)| (k.clone(), val.clone())).collect::<Vec<_>>());
    v.sort();
    v
}

/// Truthiness, shared by every boolean knob.
///
/// Presence alone is deliberately **not** truthy: `AETHER_X=0`, `=false`,
/// `=off` and `=` all mean false.
pub fn truthy(raw: &str) -> bool {
    matches!(raw.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on")
}

/// Read a boolean flag (default false).
pub fn flag(key: &str) -> bool {
    var(key).is_some_and(|v| truthy(&v))
}

/// Read a string with a default.
pub fn str_or(key: &str, default: &str) -> String {
    match var(key) {
        Some(v) if !v.trim().is_empty() => v,
        _ => default.to_string(),
    }
}

/// Read a number, reporting a malformed value instead of silently reverting to
/// the default. `AETHER_QUIC_MAX_UDP_PAYLOAD=abc` must not look like a
/// successfully-configured 1350.
pub fn usize_or(key: &str, default: usize) -> usize {
    match usize(key) {
        Some(v) => v,
        None => default,
    }
}

/// Read an optional number. `None` means absent, empty, or unparseable — the
/// last case is logged so a typo cannot masquerade as "not configured".
pub fn usize(key: &str) -> Option<usize> {
    let raw = var(key)?;
    let t = raw.trim();
    if t.is_empty() {
        return None;
    }
    match t.parse::<usize>() {
        Ok(n) => Some(n),
        Err(e) => {
            log::warn!("[config] {key}={t:?} is not a number ({e}); ignoring the value");
            None
        }
    }
}

/// Read a bounded number, clamping with a visible warning.
pub fn usize_bounded(key: &str, default: usize, min: usize, max: usize) -> usize {
    let v = usize_or(key, default);
    if v < min || v > max {
        log::warn!("[config] {key}={v} out of range {min}..={max}; clamping");
        v.clamp(min, max)
    } else {
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truthiness_is_not_presence() {
        for bad in ["0", "false", "no", "off", "", "  ", "FALSE", "No"] {
            assert!(!truthy(bad), "{bad:?} must not mean true");
        }
        for good in ["1", "true", "TRUE", "yes", "on", " on "] {
            assert!(truthy(good), "{good:?} must mean true");
        }
    }

    #[test]
    fn set_then_var_then_remove() {
        set("AETHER_SELFTEST_KEY", "1");
        assert_eq!(var("AETHER_SELFTEST_KEY").as_deref(), Some("1"));
        assert!(flag("AETHER_SELFTEST_KEY"));
        remove("AETHER_SELFTEST_KEY");
        assert_eq!(var("AETHER_SELFTEST_KEY"), None);
        assert!(!flag("AETHER_SELFTEST_KEY"));
    }

    #[test]
    fn a_zero_valued_flag_is_false() {
        // The inverted-knob bug: presence-only semantics made `=0` disable a
        // safety check rather than keep it on.
        set("AETHER_SELFTEST_FLAG", "0");
        assert!(!flag("AETHER_SELFTEST_FLAG"));
        remove("AETHER_SELFTEST_FLAG");
    }

    #[test]
    fn unparseable_number_falls_back_to_default() {
        set("AETHER_SELFTEST_NUM", "abc");
        assert_eq!(usize_or("AETHER_SELFTEST_NUM", 1350), 1350);
        set("AETHER_SELFTEST_NUM", " 1400 ");
        assert_eq!(usize_or("AETHER_SELFTEST_NUM", 1350), 1400);
        remove("AETHER_SELFTEST_NUM");
    }

    #[test]
    fn bounds_are_clamped_not_trusted() {
        set("AETHER_SELFTEST_B", "99999");
        assert_eq!(usize_bounded("AETHER_SELFTEST_B", 10, 1, 100), 100);
        remove("AETHER_SELFTEST_B");
    }

    #[test]
    fn live_process_env_cannot_win_after_seeding() {
        let key = "AETHER_SELFTEST_RACE";
        set(key, "in-process");
        // Even if something mutates the real environment behind our back, the
        // store is authoritative — this is what makes the single-reader rule
        // observable rather than aspirational.
        std::env::set_var(key, "ambient");
        assert_eq!(var(key).as_deref(), Some("in-process"));
        std::env::remove_var(key);
        remove(key);
    }
}
