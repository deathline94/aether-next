//! Persist recent working edges so the next connect can try warm paths first.
//!
//! File format (one endpoint per line, best first):
//! ```text
//! 162.159.198.1:443 42
//! 162.159.192.1:443 80
//! ```
//! Optional second field is RTT in milliseconds (for ranking).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

const MAX_ENTRIES: usize = 12;

pub fn cache_path(kind: &str) -> PathBuf {
    if let Ok(base) = std::env::var("AETHER_CONFIG") {
        let p = PathBuf::from(base);
        let stem = p
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("aether");
        let parent = p.parent().unwrap_or_else(|| std::path::Path::new("."));
        return parent.join(format!("{stem}-{kind}-lastconn.txt"));
    }
    PathBuf::from(format!("aether-{kind}-lastconn.txt"))
}

/// Load ranked warm endpoints (best / most recent first). Empty if missing.
pub fn load_ranked(kind: &str) -> Vec<SocketAddr> {
    let path = cache_path(kind);
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let addr_s = line.split_whitespace().next().unwrap_or("");
        if let Ok(a) = addr_s.parse::<SocketAddr>() {
            if seen.insert(a) {
                out.push(a);
            }
        }
        if out.len() >= MAX_ENTRIES {
            break;
        }
    }
    if !out.is_empty() {
        log::info!(
            "[+] warm endpoint cache ({kind}): {} address(es), prefer {}",
            out.len(),
            out[0]
        );
    }
    out
}

/// Back-compat single-endpoint load (first ranked entry).
pub fn load(kind: &str) -> Option<SocketAddr> {
    load_ranked(kind).into_iter().next()
}

/// Save a single winner (promotes to front of ranked list).
pub fn save(kind: &str, addr: SocketAddr) {
    save_ranked(kind, &[(addr, Duration::from_millis(0))]);
}

/// Merge successful probes into the ranked cache (lowest RTT first, cap size).
pub fn save_ranked(kind: &str, hits: &[(SocketAddr, Duration)]) {
    if hits.is_empty() {
        return;
    }
    let mut merged: Vec<(SocketAddr, u64)> = Vec::new();
    let mut seen = std::collections::HashSet::new();

    // New hits first (already roughly best-first from caller when sorted).
    let mut sorted: Vec<(SocketAddr, Duration)> = hits.to_vec();
    sorted.sort_by_key(|(_, rtt)| *rtt);
    for (addr, rtt) in sorted {
        if seen.insert(addr) {
            merged.push((addr, rtt.as_millis() as u64));
        }
    }
    // Keep older cache entries that were not re-probed this session.
    for old in load_ranked(kind) {
        if seen.insert(old) {
            merged.push((old, u64::MAX / 2));
        }
        if merged.len() >= MAX_ENTRIES {
            break;
        }
    }
    merged.truncate(MAX_ENTRIES);

    let path = cache_path(kind);
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let body: String = merged
        .iter()
        .map(|(a, ms)| {
            if *ms == 0 || *ms >= u64::MAX / 4 {
                format!("{a}\n")
            } else {
                format!("{a} {ms}\n")
            }
        })
        .collect();
    if let Err(e) = std::fs::write(&path, body) {
        log::debug!("endpoint cache write {path:?}: {e}");
    } else {
        log::debug!(
            "[+] saved warm endpoint cache ({kind}): {} address(es)",
            merged.len()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn ranked_roundtrip() {
        let dir = std::env::temp_dir().join(format!("aether-cache-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let conf = dir.join("aether.toml");
        std::env::set_var("AETHER_CONFIG", conf.to_str().unwrap());
        let a = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 443);
        let b = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)), 443);
        save_ranked(
            "testkind",
            &[
                (b, Duration::from_millis(20)),
                (a, Duration::from_millis(5)),
            ],
        );
        let ranked = load_ranked("testkind");
        assert_eq!(ranked.first().copied(), Some(a));
        assert!(ranked.contains(&b));
        let _ = std::fs::remove_dir_all(&dir);
        std::env::remove_var("AETHER_CONFIG");
    }
}
