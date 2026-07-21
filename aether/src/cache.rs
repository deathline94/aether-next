use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use serde::{Serialize, Deserialize};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Serialize, Deserialize, Default)]
pub struct EndpointsCache {
    pub masque: Vec<CachedEndpoint>,
    pub wireguard: Vec<CachedEndpoint>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct CachedEndpoint {
    pub addr: SocketAddr,
    pub timestamp: u64,
}

pub fn load_endpoints(base_config: &str) -> EndpointsCache {
    let path = cache_path(base_config);
    if let Ok(data) = std::fs::read_to_string(&path) {
        if let Ok(cache) = serde_json::from_str(&data) {
            return cache;
        }
    }
    EndpointsCache::default()
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
    let mut cache = load_endpoints(base_config);
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    
    for addr in endpoints.into_iter().rev() {
        cache.masque.retain(|e| e.addr != addr);
        cache.masque.insert(0, CachedEndpoint { addr, timestamp: now });
    }
    cache.masque.truncate(5); // Keep top 5
    save_endpoints(base_config, &cache);
}

pub fn get_masque(base_config: &str) -> Vec<SocketAddr> {
    load_endpoints(base_config).masque.into_iter().map(|e| e.addr).collect()
}

pub fn add_to_wireguard(base_config: &str, endpoints: Vec<SocketAddr>) {
    let mut cache = load_endpoints(base_config);
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    
    for addr in endpoints.into_iter().rev() {
        cache.wireguard.retain(|e| e.addr != addr);
        cache.wireguard.insert(0, CachedEndpoint { addr, timestamp: now });
    }
    cache.wireguard.truncate(5); // Keep top 5
    save_endpoints(base_config, &cache);
}

pub fn get_wireguard(base_config: &str) -> Vec<SocketAddr> {
    load_endpoints(base_config).wireguard.into_iter().map(|e| e.addr).collect()
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
