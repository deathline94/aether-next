//! Unified obfuscation profile names for MASQUE (noize) and WireGuard (aethernoize).
use crate::aethernoize::AetherNoizeConfig;
use crate::noize::NoizeConfig;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Masque,
    WireGuard,
}

/// Canonical profile name after alias resolution.
pub fn normalize(name: &str) -> &str {
    match name.trim().to_lowercase().as_str() {
        "off" | "none" => "off",
        "gfw" => "gfw",
        "firewall" => "firewall",
        "light" => "light",
        "aggressive" | "heavy" => "aggressive",
        "balanced" => "balanced",
        other if other.is_empty() => "default",
        _ => "default",
    }
}

/// Default profile for a transport when env is unset.
pub fn default_profile(transport: Transport) -> &'static str {
    match transport {
        Transport::Masque => "firewall",
        Transport::WireGuard => "balanced",
    }
}

pub fn masque_from_env() -> NoizeConfig {
    let raw = std::env::var("AETHER_NOIZE").unwrap_or_else(|_| default_profile(Transport::Masque).into());
    let name = normalize(&raw);
    log::info!("[+] obfuscation profile (masque): {name}");
    noize_from_name(name)
}

pub fn wg_from_env() -> AetherNoizeConfig {
    let raw = std::env::var("AETHER_NOIZE").unwrap_or_else(|_| default_profile(Transport::WireGuard).into());
    let name = normalize(&raw);
    log::info!("[+] obfuscation profile (wireguard): {name}");
    aethernoize_from_name(name)
}

pub fn noize_from_name(name: &str) -> NoizeConfig {
    match normalize(name) {
        "off" => NoizeConfig::off(),
        "gfw" => NoizeConfig::gfw(),
        // WG-only names map sensibly onto MASQUE
        "light" => NoizeConfig::firewall(),
        "aggressive" => NoizeConfig::gfw(),
        "balanced" | "firewall" | "default" | _ => NoizeConfig::firewall(),
    }
}

pub fn aethernoize_from_name(name: &str) -> AetherNoizeConfig {
    match normalize(name) {
        "off" => AetherNoizeConfig::off(),
        "light" => AetherNoizeConfig::light(),
        "aggressive" => AetherNoizeConfig::aggressive(),
        // MASQUE-only names map onto WG
        "gfw" | "firewall" => AetherNoizeConfig::balanced(),
        "balanced" | "default" | _ => AetherNoizeConfig::balanced(),
    }
}

/// Profile retry list for WireGuard endpoint hunt.
pub fn wg_profile_retry_names(primary: &str) -> Vec<String> {
    let mut names = vec![normalize(primary).to_string()];
    if std::env::var("AETHER_WG_NO_PROFILE_RETRY").is_err() {
        for fallback in ["balanced", "aggressive", "light", "off"] {
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
        assert_eq!(normalize("heavy"), "aggressive");
        assert_eq!(normalize("firewall"), "firewall");
    }

    #[test]
    fn cross_map_never_panics() {
        for n in ["off", "gfw", "firewall", "light", "balanced", "aggressive", "weird"] {
            let _ = noize_from_name(n);
            let _ = aethernoize_from_name(n);
        }
    }
}
