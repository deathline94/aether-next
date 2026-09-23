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
            config_path: default_config_path(),
            masque_http2: false,
            tun: false,
            peer: None,
            wg_peer: None,
        }
    }
}

/// Where the identity file lives when nothing says otherwise: a per-user
/// directory, which is the kind of place both shells already keep it — Tauri's
/// `app_data_dir` (`scan.rs`, `supervision.rs`) and Android's private `filesDir`
/// (`EngineRunner.kt`) each hand over an absolute path, and the engine's own CLI
/// default gets its folder under the same kind of root.
///
/// The default used to be `"aether.toml"`, resolved against whatever the working
/// directory happened to be. Started from a desktop shortcut the engine then read
/// and wrote its DPAPI envelope and endpoint cache in `C:\Windows\System32` or
/// wherever the launcher left it: usually an unexplained permission error, and in
/// a shared writable directory — a world-writable `Public` folder, a repo checked
/// out by two accounts — somebody else's `aether.toml` standing in as this user's
/// identity. A config path is a security input, so it does not get to depend on
/// where the process was born.
pub fn default_config_path() -> String {
    #[cfg(windows)]
    let root = std::env::var_os("APPDATA")
        .or_else(|| std::env::var_os("LOCALAPPDATA"))
        .map(std::path::PathBuf::from);
    #[cfg(not(windows))]
    let root = std::env::var_os("XDG_CONFIG_HOME")
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| std::path::PathBuf::from(h).join(".config")));
    // `temp_dir` is the last resort and is still absolute, unlike a bare relative
    // name: Android's process has neither `HOME` nor `APPDATA`, and its own
    // private temp directory is where a file it must not share belongs.
    let fallback = std::env::temp_dir().join("aether").join("aether.toml");
    let path = root
        .map(|r| r.join("aether").join("aether.toml"))
        // A relative `$APPDATA`/`$HOME` — spec-invalid, but it happens in a
        // container — would hand the answer back to the working directory.
        .filter(|p| p.is_absolute())
        .unwrap_or(fallback);
    path.to_string_lossy().into_owned()
}

/// Absolute paths only, for the reason above: a relative `AETHER_CONFIG` is
/// resolved against the CWD, which is precisely the failure the default exists to
/// remove. Both shells pass absolute app-data paths, so this rejects nothing that
/// the product does today.
fn absolute_config_path(name: &str, raw: &str) -> Result<String> {
    if std::path::Path::new(raw).is_absolute() {
        return Ok(raw.to_string());
    }
    Err(AetherError::Config(format!(
        "{name} must be an absolute path (got {raw:?}); a relative one is read from \
         whatever directory the process happened to start in"
    )))
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
            let v = v.trim();
            if !v.is_empty() {
                cfg.config_path = absolute_config_path("AETHER_CONFIG", v)?;
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

    /// The identity file's location used to default to `"aether.toml"`, i.e.
    /// whatever the working directory happened to be: a shortcut launch read its
    /// DPAPI envelope out of `C:\Windows`, and a shared writable directory could
    /// supply somebody else's config as this user's identity.
    #[test]
    fn the_config_path_never_depends_on_the_working_directory() {
        let p = default_config_path();
        assert!(
            std::path::Path::new(&p).is_absolute(),
            "{p:?} resolves against the CWD"
        );
        assert!(
            p.ends_with("aether.toml"),
            "{p:?} does not name the config file"
        );
        assert!(
            !std::path::Path::new(&p)
                .components()
                .any(|c| matches!(c, std::path::Component::CurDir)),
            "{p:?} carries a relative component"
        );
    }

    #[test]
    fn a_relative_config_path_is_refused() {
        for rel in ["aether.toml", "./aether.toml", "..\\cfg\\aether.toml", ""] {
            let err = absolute_config_path("AETHER_CONFIG", rel)
                .err()
                .unwrap_or_else(|| panic!("{rel:?} must not be accepted as a config path"));
            assert!(
                err.to_string().contains("absolute"),
                "the error has to say what was wrong: {err}"
            );
        }
        let abs = std::env::temp_dir().join("aether.toml");
        let abs = abs.to_string_lossy().into_owned();
        assert_eq!(
            absolute_config_path("AETHER_CONFIG", &abs).ok().as_deref(),
            Some(&*abs)
        );
    }
}
