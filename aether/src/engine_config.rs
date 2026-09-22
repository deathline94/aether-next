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
        // First thing, before any code touches the config file: the parent hands
        // over the envelope key on stdin rather than in the environment.
        crate::keyhandoff::receive_if_requested()?;
        let mut cfg = Self::default();
        if let Some(v) = crate::runtime_env::var("AETHER_PROTOCOL") {
            if !v.trim().is_empty() {
                cfg.protocol = v.trim().to_lowercase();
            }
        }
        if let Some(v) = crate::runtime_env::var("AETHER_SCAN") {
            if !v.trim().is_empty() {
                cfg.scan = v.trim().to_lowercase();
            }
        }
        if let Some(v) = crate::runtime_env::var("AETHER_IP") {
            if !v.trim().is_empty() {
                cfg.ip = v.trim().to_lowercase();
            }
        }
        if let Some(v) = crate::runtime_env::var("AETHER_NOIZE") {
            if !v.trim().is_empty() {
                cfg.noize = v.trim().to_lowercase();
            }
        }
        if let Some(v) = crate::runtime_env::var("AETHER_CONFIG") {
            if !v.trim().is_empty() {
                cfg.config_path = v;
            }
        }
        cfg.socks = parse_listen("AETHER_SOCKS", "127.0.0.1:1819")?;
        cfg.http = parse_listen("AETHER_HTTP", "127.0.0.1:1820")?;
        if !env_truthy("AETHER_ALLOW_REMOTE_PROXY")
            && (!cfg.socks.ip().is_loopback() || !cfg.http.ip().is_loopback())
        {
            return Err(AetherError::Config(
                "proxy listeners must use loopback unless AETHER_ALLOW_REMOTE_PROXY=1".into(),
            ));
        }
        if cfg.socks.port() == cfg.http.port() {
            return Err(AetherError::Config(
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

/// A boolean knob. Delegates to the one truth table in the process
/// (`runtime_env::truthy`), so every boolean answers the same question the same
/// way.
///
/// The list used to carry `"h2"` as well — a *transport* token accepted as a
/// *truth* value by the helper that also decides `AETHER_TUN`. Neither the desktop
/// nor the Android runner ever writes `h2` (both write `1`/`0`), so it could only
/// arrive from a hand-set or copied-out environment, and `AETHER_TUN=h2` then
/// raised a Wintun adapter and rewrote host routes. Value vocabularies do not get
/// to overlap like that.
fn env_truthy(name: &str) -> bool {
    match crate::runtime_env::var(name) {
        Some(v) => crate::runtime_env::truthy(&v),
        None => false,
    }
}

fn env_addr(name: &str) -> Result<Option<SocketAddr>> {
    match crate::runtime_env::var(name) {
        Some(v) if !v.trim().is_empty() => {
            let addr: SocketAddr = v
                .trim()
                .parse()
                .map_err(|_| AetherError::Config(format!("bad {name} address {v}")))?;
            Ok(Some(addr))
        }
        _ => Ok(None),
    }
}

fn parse_listen(var: &str, default: &str) -> Result<SocketAddr> {
    let raw = crate::runtime_env::var(var).unwrap_or_else(|| default.to_string());
    let addr: SocketAddr = raw
        .parse()
        .map_err(|_| AetherError::Config(format!("bad {var} address {raw}")))?;
    if addr.port() < 1024 {
        return Err(AetherError::Config(format!(
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

    /// `AETHER_TUN` and `AETHER_MASQUE_HTTP2` are answered by the same helper, and
    /// that helper used to treat the transport token `h2` as "true" — so a value
    /// copied from one knob enabled the other, including the one that raises a
    /// network adapter and rewrites host routes.
    #[test]
    fn boolean_knobs_accept_only_truth_values() {
        const KEY: &str = "AETHER_SELFTEST_BOOL";
        for not_true in [
            "h2", "h3", "wg", "masque", "0", "false", "no", "off", "", "  ", "maybe",
        ] {
            crate::runtime_env::set(KEY, not_true);
            assert!(
                !env_truthy(KEY),
                "{not_true:?} must not enable a boolean knob"
            );
        }
        for is_true in ["1", "true", "TRUE", "yes", "on", " on "] {
            crate::runtime_env::set(KEY, is_true);
            assert!(env_truthy(KEY), "{is_true:?} should be true");
        }
        crate::runtime_env::remove(KEY);
        assert!(!env_truthy(KEY), "absent is false");
    }
}
