//! Unified obfuscation profile names for MASQUE (noize) and WireGuard (aethernoize).
//!
//! Also owns the canonical CPS (Custom Packet Signature) parser used by both
//! transport obfuscators. Tags: `<b HEX>`, `<t>`, `<c>`, `<n>`, `<r N|MIN-MAX>`,
//! `<rc N|MIN-MAX>`, `<rd N|MIN-MAX>`.
use crate::aethernoize::AetherNoizeConfig;
use crate::error::{AetherError, Result};
use crate::noize::NoizeConfig;

use rand::{Rng, RngCore};
use regex::Regex;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Masque,
    WireGuard,
}

/// The names the shell's vocabulary accepts, kept next to `is_recognized` so the
/// refusal can quote them back.
pub const RECOGNIZED_PROFILES: &[&str] = &[
    "off", "none", "light", "low", "medium", "balanced", "firewall", "default", "high", "gfw",
    "max", "aggressive", "heavy", "custom",
];

/// Refuse a profile name the transports have no definition for.
///
/// `normalize` maps an unrecognised name to `default`, and both transports then
/// built *some* profile from it — so a typo, or a name only one side of the
/// project knows, became a working-looking connection on a profile nobody asked
/// for. The session calls this before anything reads `AETHER_NOIZE`, so the
/// fallback below is unreachable from a live connect rather than merely warned
/// about once in a log the GUI does not show.
pub fn validate_profile_name(name: &str) -> Result<()> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Ok(());
    }
    if is_recognized(trimmed) {
        return Ok(());
    }
    Err(AetherError::Other(format!(
        "unknown obfuscation profile {name:?}; refusing to substitute one nobody asked \
         for. Recognised: {}",
        RECOGNIZED_PROFILES.join(", ")
    )))
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
    crate::runtime_env::var(key)?.trim().parse().ok()
}

/// Optional custom knobs from env (used when profile is `custom`).
fn apply_custom_noize(mut cfg: NoizeConfig) -> NoizeConfig {
    if let Some(v) = env_usize("AETHER_NOIZE_JC") {
        cfg.jc_before_hs = v;
        cfg.jc_after_i1 = 0;
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
        cfg.jc_after_i1 = 0;
        cfg.jc_after_hs = 0;
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

    /// The shell's vocabulary and the transport's used to be two different lists:
    /// `medium`, `high`, `max` and `custom` were all valid names to the UI and all
    /// silently built a `balanced()` profile in `aethernoize::from_profile`. Now
    /// the only silent mapping left is one the tables state out loud, and a name
    /// outside the vocabulary stops the session with the list in its message.
    #[test]
    fn an_unknown_profile_name_is_refused_not_downgraded() {
        for good in RECOGNIZED_PROFILES {
            assert!(validate_profile_name(good).is_ok(), "{good} is a real name");
            assert!(is_recognized(good), "{good} is missing from is_recognized");
        }
        assert!(
            validate_profile_name("  High  ").is_ok(),
            "case and padding are not part of the name"
        );
        assert!(validate_profile_name("").is_ok(), "empty means the default");

        for bad in ["turbo", "max1", "off-x", "medium-ish", "é", "11"] {
            let err = validate_profile_name(bad)
                .expect_err("{bad} must not silently become balanced()");
            assert!(
                err.to_string().contains(bad),
                "the refusal must name what it rejected: {err}"
            );
            assert!(
                err.to_string().contains("medium"),
                "the refusal must list the names that do work: {err}"
            );
        }
    }

    /// Every recognised name resolves to a profile in both transports, so the
    /// refusal above cannot be hiding a hole where a real name has no definition.
    #[test]
    fn every_recognized_name_has_a_profile_in_both_transports() {
        for name in RECOGNIZED_PROFILES {
            let wg = aethernoize_from_name(name);
            let mq = noize_from_name(name);
            let off = name.eq_ignore_ascii_case("off") || name.eq_ignore_ascii_case("none");
            assert_eq!(wg.is_enabled(), !off, "wireguard profile for {name}");
            assert_eq!(mq.is_enabled(), !off, "masque profile for {name}");
        }
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
