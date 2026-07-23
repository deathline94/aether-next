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
    // #7: Trust scoring — track success/failure history per endpoint.
    /// Number of successful connections through this endpoint.
    #[serde(default)]
    pub successes: u32,
    /// Number of failed connection attempts.
    #[serde(default)]
    pub failures: u32,
}

impl CachedEndpoint {
    /// Trust score: weighted combination of success rate and RTT.
    /// Higher is better. Range: 0.0 .. ~100.0
    pub fn trust_score(&self) -> f64 {
        let total = self.successes + self.failures;
        if total == 0 {
            // No history — neutral score based on RTT only.
            return if self.rtt_ms > 0 {
                50.0 - (self.rtt_ms as f64 * 0.1).min(40.0)
            } else {
                30.0
            };
        }
        let rate = self.successes as f64 / total as f64;
        let rtt_penalty = if self.rtt_ms > 0 { (self.rtt_ms as f64 * 0.05).min(20.0) } else { 10.0 };
        // Recency bonus: newer entries get up to +10.
        let age_secs = now_secs().saturating_sub(self.timestamp);
        let recency = if age_secs < 3600 { 10.0 } else if age_secs < 86400 { 5.0 } else { 0.0 };
        (rate * 70.0) - rtt_penalty + recency
    }
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

/// Returns cached masque endpoints sorted by trust score (highest first).
/// Each entry is (addr, rtt_ms). Combines RTT + success rate + recency.
pub fn get_masque_sorted(base_config: &str) -> Vec<(SocketAddr, u32)> {
    let mut eps: Vec<CachedEndpoint> = load_endpoints(base_config).masque;
    eps.sort_by(|a, b| b.trust_score().partial_cmp(&a.trust_score()).unwrap_or(std::cmp::Ordering::Equal));
    eps.into_iter().map(|e| (e.addr, e.rtt_ms)).collect()
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

/// Returns cached wireguard endpoints sorted by trust score (highest first).
pub fn get_wireguard_sorted(base_config: &str) -> Vec<(SocketAddr, u32)> {
    let mut eps: Vec<CachedEndpoint> = load_endpoints(base_config).wireguard;
    eps.sort_by(|a, b| b.trust_score().partial_cmp(&a.trust_score()).unwrap_or(std::cmp::Ordering::Equal));
    eps.into_iter().map(|e| (e.addr, e.rtt_ms)).collect()
}

/// #7: Record a successful connection to an endpoint (increments trust).
pub fn record_success(base_config: &str, addr: SocketAddr, is_masque: bool) {
    let mut cache = load_endpoints(base_config);
    let list = if is_masque { &mut cache.masque } else { &mut cache.wireguard };
    if let Some(ep) = list.iter_mut().find(|e| e.addr == addr) {
        ep.successes += 1;
        ep.timestamp = now_secs();
    }
    save_endpoints(base_config, &cache);
}

/// #7: Record a failed connection attempt (decrements trust).
pub fn record_failure(base_config: &str, addr: SocketAddr, is_masque: bool) {
    let mut cache = load_endpoints(base_config);
    let list = if is_masque { &mut cache.masque } else { &mut cache.wireguard };
    if let Some(ep) = list.iter_mut().find(|e| e.addr == addr) {
        ep.failures += 1;
    }
    save_endpoints(base_config, &cache);
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
