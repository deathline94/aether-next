use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use serde::{Serialize, Deserialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// Maximum cached endpoints per protocol.
const MAX_CACHED: usize = 10;

/// Endpoints older than this (in seconds) are automatically pruned on load.
const STALE_THRESHOLD_SECS: u64 = 24 * 60 * 60; // 24 hours

#[derive(Serialize, Deserialize, Default)]
pub struct EndpointsCache {
    pub masque: Vec<CachedEndpoint>,
    pub wireguard: Vec<CachedEndpoint>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct CachedEndpoint {
    pub addr: SocketAddr,
    pub timestamp: u64,
    /// Round-trip time in milliseconds (0 means unknown / legacy entry).
    #[serde(default)]
    pub rtt_ms: u32,
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

/// Remove endpoints older than `STALE_THRESHOLD_SECS`.
fn decay_stale(endpoints: &mut Vec<CachedEndpoint>) {
    let now = now_secs();
    endpoints.retain(|e| now.saturating_sub(e.timestamp) < STALE_THRESHOLD_SECS);
}

pub fn load_endpoints(base_config: &str) -> EndpointsCache {
    let path = cache_path(base_config);
    let mut cache = if let Ok(data) = std::fs::read_to_string(&path) {
        serde_json::from_str(&data).unwrap_or_default()
    } else {
        EndpointsCache::default()
    };
    // Auto-prune stale entries on every load
    decay_stale(&mut cache.masque);
    decay_stale(&mut cache.wireguard);
    cache
}

pub fn save_endpoints(base_config: &str, cache: &EndpointsCache) {
    let path = cache_path(base_config);
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(data) = serde_json::to_string_pretty(cache) {
        let _ = std::fs::write(path, data);
    }
}

pub fn add_to_masque(base_config: &str, endpoints: Vec<SocketAddr>) {
    add_to_masque_with_rtt(base_config, endpoints.into_iter().map(|a| (a, 0)).collect());
}

pub fn add_to_masque_with_rtt(base_config: &str, endpoints: Vec<(SocketAddr, u32)>) {
    let mut cache = load_endpoints(base_config);
    let now = now_secs();

    for (addr, rtt_ms) in endpoints.into_iter().rev() {
        cache.masque.retain(|e| e.addr != addr);
        cache.masque.insert(0, CachedEndpoint { addr, timestamp: now, rtt_ms });
    }
    cache.masque.truncate(MAX_CACHED);
    save_endpoints(base_config, &cache);
}

pub fn get_masque(base_config: &str) -> Vec<SocketAddr> {
    load_endpoints(base_config).masque.into_iter().map(|e| e.addr).collect()
}

/// Returns cached masque endpoints sorted by RTT (lowest first).
/// Each entry is (addr, rtt_ms). Entries with rtt_ms == 0 are sorted last.
pub fn get_masque_sorted(base_config: &str) -> Vec<(SocketAddr, u32)> {
    let mut eps: Vec<_> = load_endpoints(base_config)
        .masque
        .into_iter()
        .map(|e| (e.addr, e.rtt_ms))
        .collect();
    eps.sort_by_key(|&(_, rtt)| if rtt == 0 { u32::MAX } else { rtt });
    eps
}

pub fn add_to_wireguard(base_config: &str, endpoints: Vec<SocketAddr>) {
    add_to_wireguard_with_rtt(base_config, endpoints.into_iter().map(|a| (a, 0)).collect());
}

pub fn add_to_wireguard_with_rtt(base_config: &str, endpoints: Vec<(SocketAddr, u32)>) {
    let mut cache = load_endpoints(base_config);
    let now = now_secs();

    for (addr, rtt_ms) in endpoints.into_iter().rev() {
        cache.wireguard.retain(|e| e.addr != addr);
        cache.wireguard.insert(0, CachedEndpoint { addr, timestamp: now, rtt_ms });
    }
    cache.wireguard.truncate(MAX_CACHED);
    save_endpoints(base_config, &cache);
}

pub fn get_wireguard(base_config: &str) -> Vec<SocketAddr> {
    load_endpoints(base_config).wireguard.into_iter().map(|e| e.addr).collect()
}

/// Returns cached wireguard endpoints sorted by RTT (lowest first).
pub fn get_wireguard_sorted(base_config: &str) -> Vec<(SocketAddr, u32)> {
    let mut eps: Vec<_> = load_endpoints(base_config)
        .wireguard
        .into_iter()
        .map(|e| (e.addr, e.rtt_ms))
        .collect();
    eps.sort_by_key(|&(_, rtt)| if rtt == 0 { u32::MAX } else { rtt });
    eps
}

fn cache_path(base_config: &str) -> PathBuf {
    let base = Path::new(base_config);
    if base.is_dir() {
        base.join("aether-endpoints.json")
    } else if let Some(parent) = base.parent() {
        if parent.as_os_str().is_empty() {
            PathBuf::from("aether-endpoints.json")
        } else {
            parent.join("aether-endpoints.json")
        }
    } else {
        PathBuf::from("aether-endpoints.json")
    }
}
