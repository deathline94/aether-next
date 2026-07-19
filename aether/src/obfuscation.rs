//! Unified obfuscation profile names for MASQUE (noize) and WireGuard (aethernoize).
use crate::aethernoize::AetherNoizeConfig;
use crate::noize::NoizeConfig;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Masque,
    WireGuard,
}

/// Canonical profile name after alias resolution.
/// Ordered intensity (low → high): off < light < medium < high < max.
pub fn normalize(name: &str) -> &str {
    match name.trim().to_ascii_lowercase().as_str() {
        "" => "default",
        "off" | "none" => "off",
        "light" | "low" => "light",
        // medium: former "balanced" / "firewall" mid-level
        "medium" | "balanced" | "firewall" | "default" => "medium",
        // high: former gfw / slightly above medium
        "high" | "gfw" => "high",
        // max: former aggressive / heavy
        "max" | "aggressive" | "heavy" => "max",
        "custom" => "custom",
        _ => "default",
    }
}

/// Default profile for a transport when env is unset.
pub fn default_profile(transport: Transport) -> &'static str {
    match transport {
        Transport::Masque => "medium",
        Transport::WireGuard => "medium",
    }
}

fn env_usize(key: &str) -> Option<usize> {
    std::env::var(key).ok()?.trim().parse().ok()
}

/// Optional custom knobs from env (used when profile is `custom`).
fn apply_custom_noize(mut cfg: NoizeConfig) -> NoizeConfig {
    if let Some(v) = env_usize("AETHER_NOIZE_JC") {
        cfg.jc_before_hs = v;
        cfg.jc_after_i1 = v.saturating_div(2).max(if v > 0 { 1 } else { 0 });
    }
    if let Some(v) = env_usize("AETHER_NOIZE_JMIN") {
        cfg.jmin = v;
    }
    if let Some(v) = env_usize("AETHER_NOIZE_JMAX") {
        cfg.jmax = v.max(cfg.jmin);
    }
    if let Some(ms) = env_usize("AETHER_NOIZE_INTERVAL_MS") {
        cfg.junk_interval = std::time::Duration::from_millis(ms as u64);
    }
    cfg
}

fn apply_custom_aethernoize(mut cfg: AetherNoizeConfig) -> AetherNoizeConfig {
    if let Some(v) = env_usize("AETHER_NOIZE_JC") {
        cfg.jc = v;
        cfg.jc_before_hs = v;
        cfg.jc_after_i1 = v.saturating_div(2).max(if v > 0 { 1 } else { 0 });
        cfg.jc_after_hs = v.saturating_div(3).max(if v > 0 { 1 } else { 0 });
    }
    if let Some(v) = env_usize("AETHER_NOIZE_JMIN") {
        cfg.jmin = v;
    }
    if let Some(v) = env_usize("AETHER_NOIZE_JMAX") {
        cfg.jmax = v.max(cfg.jmin);
    }
    if let Some(ms) = env_usize("AETHER_NOIZE_INTERVAL_MS") {
        cfg.junk_interval = std::time::Duration::from_millis(ms as u64);
    }
    cfg
}

pub fn masque_from_env() -> NoizeConfig {
    let raw =
        std::env::var("AETHER_NOIZE").unwrap_or_else(|_| default_profile(Transport::Masque).into());
    let name = normalize(&raw);
    log::info!("[+] obfuscation profile (masque): {name}");
    let mut cfg = noize_from_name(name);
    if name == "custom" {
        cfg = apply_custom_noize(cfg);
    }
    cfg
}

pub fn wg_from_env() -> AetherNoizeConfig {
    let raw = std::env::var("AETHER_NOIZE")
        .unwrap_or_else(|_| default_profile(Transport::WireGuard).into());
    let name = normalize(&raw);
    log::info!("[+] obfuscation profile (wireguard): {name}");
    let mut cfg = aethernoize_from_name(name);
    if name == "custom" {
        cfg = apply_custom_aethernoize(cfg);
    }
    cfg
}

pub fn noize_from_name(name: &str) -> NoizeConfig {
    match normalize(name) {
        "off" => NoizeConfig::off(),
        "light" => NoizeConfig::firewall(), // mild
        "medium" | "default" => NoizeConfig::firewall(),
        "high" => NoizeConfig::gfw(),
        "max" => NoizeConfig::gfw(), // MASQUE only has two real profiles; max ≈ high
        "custom" => NoizeConfig::firewall(),
        _ => NoizeConfig::firewall(),
    }
}

pub fn aethernoize_from_name(name: &str) -> AetherNoizeConfig {
    match normalize(name) {
        "off" => AetherNoizeConfig::off(),
        "light" => AetherNoizeConfig::light(),
        "medium" | "default" => AetherNoizeConfig::balanced(),
        "high" => AetherNoizeConfig::balanced(),
        "max" => AetherNoizeConfig::aggressive(),
        "custom" => AetherNoizeConfig::balanced(),
        _ => AetherNoizeConfig::balanced(),
    }
}

/// Profile retry list for WireGuard endpoint hunt.
pub fn wg_profile_retry_names(primary: &str) -> Vec<String> {
    let mut names = vec![normalize(primary).to_string()];
    if std::env::var("AETHER_WG_NO_PROFILE_RETRY").is_err() {
        for fallback in ["medium", "max", "light", "off"] {
            if !names.iter().any(|n| n == fallback) {
                names.push(fallback.to_string());
            }
        }
    }
    names
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_aliases() {
        assert_eq!(normalize("NONE"), "off");
        assert_eq!(normalize("heavy"), "max");
        assert_eq!(normalize("firewall"), "medium");
        assert_eq!(normalize("aggressive"), "max");
        assert_eq!(normalize("gfw"), "high");
        assert_eq!(normalize("balanced"), "medium");
    }

    #[test]
    fn cross_map_never_panics() {
        for n in [
            "off", "light", "medium", "high", "max", "custom", "gfw", "firewall", "balanced",
            "aggressive", "weird",
        ] {
            let _ = noize_from_name(n);
            let _ = aethernoize_from_name(n);
        }
    }
}
