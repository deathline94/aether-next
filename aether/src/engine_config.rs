use std::net::SocketAddr;

use crate::error::{AetherError, Result};

/// Typed runtime options. Single place for env defaults + validation.
#[derive(Debug, Clone)]
pub struct EngineConfig {
    pub protocol: String,
    pub scan: String,
    pub ip: String,
    pub noize: String,
    pub socks: SocketAddr,
    pub http: SocketAddr,
    pub config_path: String,
    pub masque_http2: bool,
    pub tun: bool,
    pub peer: Option<SocketAddr>,
    pub wg_peer: Option<SocketAddr>,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            protocol: "masque".into(),
            scan: "balanced".into(),
            ip: "v4".into(),
            noize: "firewall".into(),
            socks: "127.0.0.1:1819".parse().unwrap(),
            http: "127.0.0.1:1820".parse().unwrap(),
            config_path: "aether.toml".into(),
            masque_http2: false,
            tun: false,
            peer: None,
            wg_peer: None,
        }
    }
}

impl EngineConfig {
    pub fn from_env() -> Result<Self> {
        let mut cfg = Self::default();
        if let Ok(v) = std::env::var("AETHER_PROTOCOL") {
            if !v.trim().is_empty() {
                cfg.protocol = v.trim().to_lowercase();
            }
        }
        if let Ok(v) = std::env::var("AETHER_SCAN") {
            if !v.trim().is_empty() {
                cfg.scan = v.trim().to_lowercase();
            }
        }
        if let Ok(v) = std::env::var("AETHER_IP") {
            if !v.trim().is_empty() {
                cfg.ip = v.trim().to_lowercase();
            }
        }
        if let Ok(v) = std::env::var("AETHER_NOIZE") {
            if !v.trim().is_empty() {
                cfg.noize = v.trim().to_lowercase();
            }
        }
        if let Ok(v) = std::env::var("AETHER_CONFIG") {
            if !v.trim().is_empty() {
                cfg.config_path = v;
            }
        }
        cfg.socks = parse_listen("AETHER_SOCKS", "127.0.0.1:1819")?;
        cfg.http = parse_listen("AETHER_HTTP", "127.0.0.1:1820")?;
        if cfg.socks.port() == cfg.http.port() {
            return Err(AetherError::Other(
                "AETHER_SOCKS and AETHER_HTTP ports must differ".into(),
            ));
        }
        cfg.masque_http2 = env_truthy("AETHER_MASQUE_HTTP2");
        cfg.tun = env_truthy("AETHER_TUN");
        cfg.peer = env_addr("AETHER_PEER")?;
        cfg.wg_peer = env_addr("AETHER_WG_PEER")?.or(cfg.peer);
        Ok(cfg)
    }

    pub fn has_forced_peer(&self) -> bool {
        self.peer.is_some() || self.wg_peer.is_some()
    }
}

fn env_truthy(name: &str) -> bool {
    match std::env::var(name) {
        Ok(v) => {
            let v = v.trim().to_lowercase();
            v == "1" || v == "true" || v == "yes" || v == "on" || v == "h2"
        }
        Err(_) => false,
    }
}

fn env_addr(name: &str) -> Result<Option<SocketAddr>> {
    match std::env::var(name) {
        Ok(v) if !v.trim().is_empty() => {
            let addr: SocketAddr = v
                .trim()
                .parse()
                .map_err(|_| AetherError::Other(format!("bad {name} address {v}")))?;
            Ok(Some(addr))
        }
        _ => Ok(None),
    }
}

fn parse_listen(var: &str, default: &str) -> Result<SocketAddr> {
    let raw = std::env::var(var).unwrap_or_else(|_| default.to_string());
    let addr: SocketAddr = raw
        .parse()
        .map_err(|_| AetherError::Other(format!("bad {var} address {raw}")))?;
    if addr.port() < 1024 {
        return Err(AetherError::Other(format!(
            "{var} port must be >= 1024 (got {})",
            addr.port()
        )));
    }
    Ok(addr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_ports_valid() {
        let c = EngineConfig::default();
        assert_ne!(c.socks.port(), c.http.port());
        assert!(c.socks.port() >= 1024);
    }
}
