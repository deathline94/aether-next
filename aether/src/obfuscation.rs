//! Unified obfuscation profile names for MASQUE (noize) and WireGuard (aethernoize).
//!
//! Also owns the canonical CPS (Custom Packet Signature) parser used by both
//! transport obfuscators. Tags: `<b HEX>`, `<t>`, `<c>`, `<n>`, `<r N|MIN-MAX>`,
//! `<rc N|MIN-MAX>`, `<rd N|MIN-MAX>`.
use crate::aethernoize::AetherNoizeConfig;
use crate::noize::NoizeConfig;

use rand::{Rng, RngCore};
use regex::Regex;

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

/// True if `name` (after trimming/lowercasing) is a recognized profile token.
/// Unknown names fall back to the transport default; callers warn when this happens.
pub fn is_recognized(name: &str) -> bool {
    matches!(
        name.trim().to_ascii_lowercase().as_str(),
        "" | "off" | "none" | "light" | "low" | "medium" | "balanced" | "firewall"
            | "default" | "high" | "gfw" | "max" | "aggressive" | "heavy" | "custom"
    )
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
    let raw = crate::runtime_env::var("AETHER_NOIZE")
        .unwrap_or_else(|| default_profile(Transport::Masque).into());
    let name = normalize(&raw);
    if !is_recognized(&raw) {
        log::warn!("[!] unknown obfuscation profile {raw:?}; falling back to '{name}'");
    }
    if name == "max" {
        log::info!("[i] MASQUE obfuscation 'max' is equivalent to 'high' (only two profiles exist)");
    }
    log::info!("[+] obfuscation profile (masque): {name}");
    let mut cfg = noize_from_name(name);
    if name == "custom" {
        cfg = apply_custom_noize(cfg);
    }
    cfg
}

pub fn wg_from_env() -> AetherNoizeConfig {
    let raw = crate::runtime_env::var("AETHER_NOIZE")
        .unwrap_or_else(|| default_profile(Transport::WireGuard).into());
    let name = normalize(&raw);
    if !is_recognized(&raw) {
        log::warn!("[!] unknown obfuscation profile {raw:?}; falling back to '{name}'");
    }
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

// ─── Canonical CPS parser ───────────────────────────────────────────────────

/// Parse a range spec: either a fixed `N` or a randomized `MIN-MAX`.
fn parse_range(data: &str) -> usize {
    let mut parts = data.split('-');
    if let (Some(min_str), Some(max_str)) = (parts.next(), parts.next()) {
        let min: usize = min_str.trim().parse().unwrap_or(0);
        let max: usize = max_str.trim().parse().unwrap_or(0);
        if max > min && min > 0 {
            return rand::thread_rng().gen_range(min..=max).min(2048);
        }
    }
    data.trim().parse().unwrap_or(0).min(2048)
}

/// Canonical CPS (Custom Packet Signature) parser.
///
/// Recognized tags:
/// - `<b HEX>`     — raw bytes from hex (optionally `0x`-prefixed)
/// - `<t>`         — current UNIX timestamp (u32 BE)
/// - `<c>`         — truncated counter (u32 BE, secs mod 0xFFFFFFFF)
/// - `<n>`         — random nonce (u64 BE)
/// - `<r N|MIN-MAX>` — random bytes
/// - `<rc N|MIN-MAX>` — random ASCII alphabetic bytes
/// - `<rd N|MIN-MAX>` — random ASCII digit bytes
pub fn parse_cps(spec: &str) -> Vec<u8> {
    let mut out = Vec::new();

    let tag_regex = Regex::new(r"<([a-z]+)\s*([^>]*)>").unwrap();

    for cap in tag_regex.captures_iter(spec) {
        let tag_type = cap.get(1).map_or("", |m| m.as_str());
        let tag_data = cap.get(2).map_or("", |m| m.as_str()).trim();

        match tag_type {
            "b" => {
                let hex_str: String = tag_data.chars().filter(|c| !c.is_whitespace()).collect();
                let clean = hex_str
                    .strip_prefix("0x")
                    .or_else(|| hex_str.strip_prefix("0X"))
                    .unwrap_or(&hex_str);
                if let Ok(decoded) = hex::decode(clean) {
                    out.extend_from_slice(&decoded);
                }
            }
            "t" => {
                let ts = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as u32)
                    .unwrap_or(0);
                out.extend_from_slice(&ts.to_be_bytes());
            }
            "c" => {
                let counter = (std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0)
                    % 0xFFFFFFFF) as u32;
                out.extend_from_slice(&counter.to_be_bytes());
            }
            "n" => {
                let nonce: u64 = rand::random();
                out.extend_from_slice(&nonce.to_be_bytes());
            }
            "r" => {
                let len = parse_range(tag_data);
                if len > 0 {
                    let mut r = vec![0u8; len];
                    rand::thread_rng().fill_bytes(&mut r);
                    out.extend_from_slice(&r);
                }
            }
            "rc" => {
                let len = parse_range(tag_data);
                if len > 0 {
                    let chars = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
                    let mut r = vec![0u8; len];
                    for b in r.iter_mut() {
                        *b = chars[rand::thread_rng().gen_range(0..chars.len())];
                    }
                    out.extend_from_slice(&r);
                }
            }
            "rd" => {
                let len = parse_range(tag_data);
                if len > 0 {
                    let chars = b"0123456789";
                    let mut r = vec![0u8; len];
                    for b in r.iter_mut() {
                        *b = chars[rand::thread_rng().gen_range(0..chars.len())];
                    }
                    out.extend_from_slice(&r);
                }
            }
            _ => {}
        }
    }

    out
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

    #[test]
    fn cps_basic_tags() {
        // <b> produces exact bytes
        let out = parse_cps("<b 0d0a0d0a>");
        assert_eq!(out, vec![0x0d, 0x0a, 0x0d, 0x0a]);

        // <t> produces 4 bytes
        let out = parse_cps("<t>");
        assert_eq!(out.len(), 4);

        // <n> produces 8 bytes
        let out = parse_cps("<n>");
        assert_eq!(out.len(), 8);

        // <r N> produces N bytes
        let out = parse_cps("<r 24>");
        assert_eq!(out.len(), 24);

        // <r MIN-MAX> produces between MIN and MAX bytes
        let out = parse_cps("<r 10-20>");
        assert!(out.len() >= 10 && out.len() <= 20);

        // <rc N> produces N alphabetic bytes
        let out = parse_cps("<rc 16>");
        assert_eq!(out.len(), 16);
        assert!(out.iter().all(|&b| b.is_ascii_alphabetic()));

        // <rd N> produces N digit bytes
        let out = parse_cps("<rd 8>");
        assert_eq!(out.len(), 8);
        assert!(out.iter().all(|&b| b.is_ascii_digit()));

        // Combined
        let out = parse_cps("<b 0d0a><t><r 4>");
        assert!(out.len() >= 10); // 2 + 4 + 4
    }
}
