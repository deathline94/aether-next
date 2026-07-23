//! Unified endpoint prober for all transport protocols.
//!
//! A single scan engine (candidate generation, concurrent probing, hot-subnet
//! drill-down, tier-0 cache, deadline management) parameterized over:
//! - A [`ProbeConfig`] describing the IP pools, weights, seeds, and cache slot.
//! - A verify closure that performs the transport-specific handshake.

use std::collections::HashSet;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::stream::StreamExt;
use rand::Rng;

use crate::error::{AetherError, Result};

// ─────────────────────────────────────────────────────────────────────────────
// Shared types
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
pub struct ProbeResult {
    pub ip: IpAddr,
    pub port: u16,
    pub rtt: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpScan {
    V4,
    V6,
    Both,
}

impl IpScan {
    pub fn parse(s: &str) -> IpScan {
        match s.trim().to_lowercase().as_str() {
            "6" | "v6" | "ipv6" => IpScan::V6,
            "both" | "all" | "dual" => IpScan::Both,
            _ => IpScan::V4,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            IpScan::V4 => "ipv4",
            IpScan::V6 => "ipv6",
            IpScan::Both => "dual-stack",
        }
    }

    pub fn want_v4(&self) -> bool {
        matches!(self, IpScan::V4 | IpScan::Both)
    }

    pub fn want_v6(&self) -> bool {
        matches!(self, IpScan::V6 | IpScan::Both)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanMode {
    Turbo,
    Balanced,
    Thorough,
    Stealth,
    Ironclad,
}

impl ScanMode {
    pub fn parse(s: &str) -> ScanMode {
        match s.trim().to_lowercase().as_str() {
            "turbo" | "fast" => ScanMode::Turbo,
            "thorough" | "deep" | "pro" | "thorogh" => ScanMode::Thorough,
            "stealth" | "quiet" => ScanMode::Stealth,
            "ironclad" | "real" | "verify" | "guaranteed" => ScanMode::Ironclad,
            _ => ScanMode::Balanced,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            ScanMode::Turbo => "turbo",
            ScanMode::Balanced => "balanced",
            ScanMode::Thorough => "thorough",
            ScanMode::Stealth => "stealth",
            ScanMode::Ironclad => "ironclad",
        }
    }

    fn strategy(&self, profile: &StrategyProfile) -> Strategy {
        match self {
            ScanMode::Turbo => Strategy {
                concurrency: 250,
                per_probe_timeout: Duration::from_millis(1000),
                overall_deadline: Duration::from_secs(15),
                quiet_after_first: Duration::from_secs(0),
                target_successes: 1,
                early_exit_first: true,
                full_subnet: false,
                sample_per_cidr: profile.turbo_sample,
            },
            ScanMode::Balanced => Strategy {
                concurrency: 200,
                per_probe_timeout: Duration::from_millis(1200),
                overall_deadline: Duration::from_secs(30),
                quiet_after_first: Duration::from_secs(8),
                target_successes: profile.balanced_target,
                early_exit_first: false,
                full_subnet: false,
                sample_per_cidr: profile.balanced_sample,
            },
            ScanMode::Thorough => Strategy {
                concurrency: 250,
                per_probe_timeout: Duration::from_millis(1500),
                overall_deadline: Duration::from_secs(60),
                quiet_after_first: Duration::from_secs(10),
                target_successes: 0,
                early_exit_first: false,
                full_subnet: true,
                sample_per_cidr: 0,
            },
            ScanMode::Stealth => Strategy {
                concurrency: 8,
                per_probe_timeout: Duration::from_millis(3000),
                overall_deadline: Duration::from_secs(90),
                quiet_after_first: Duration::from_secs(15),
                target_successes: profile.stealth_target,
                early_exit_first: false,
                full_subnet: false,
                sample_per_cidr: profile.stealth_sample,
            },
            ScanMode::Ironclad => Strategy {
                concurrency: 6,
                per_probe_timeout: Duration::from_millis(5000),
                overall_deadline: Duration::from_secs(120),
                quiet_after_first: Duration::from_secs(15),
                target_successes: 3,
                early_exit_first: false,
                full_subnet: false,
                sample_per_cidr: profile.balanced_sample,
            },
        }
    }
}

/// Per-protocol tuning knobs for scan strategies.
struct StrategyProfile {
    turbo_sample: usize,
    balanced_target: usize,
    balanced_sample: usize,
    stealth_target: usize,
    stealth_sample: usize,
}

struct Strategy {
    concurrency: usize,
    per_probe_timeout: Duration,
    overall_deadline: Duration,
    quiet_after_first: Duration,
    target_successes: usize,
    early_exit_first: bool,
    full_subnet: bool,
    sample_per_cidr: usize,
}

// ─────────────────────────────────────────────────────────────────────────────
// Probe configuration (data that varies per transport)
// ─────────────────────────────────────────────────────────────────────────────

/// Which cache slot to read/write in the endpoint cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheKind {
    Masque,
    WireGuard,
}

/// Static configuration describing the IP pool and cache behavior for a scan.
pub struct ProbeConfig {
    pub cidrs_v4: &'static [&'static str],
    pub cidrs_v6: &'static [&'static str],
    pub cidr_weights_v4: &'static [(&'static str, u8)],
    pub seeds_v4: &'static [&'static str],
    pub seeds_v6: &'static [&'static str],
    pub cache_kind: CacheKind,
    /// Human-readable label for log messages (e.g. "gateway", "wg endpoint").
    pub label: &'static str,
    /// Path used for cache persistence.
    pub config_path: String,
    /// Protocol-specific strategy tuning.
    profile: StrategyProfile,
}

impl CacheKind {
    fn read_sorted(&self, config_path: &str) -> Vec<(SocketAddr, u32)> {
        match self {
            CacheKind::Masque => crate::cache::get_masque_sorted(config_path),
            CacheKind::WireGuard => crate::cache::get_wireguard_sorted(config_path),
        }
    }

    fn write_with_rtt(&self, config_path: &str, endpoints: Vec<(SocketAddr, u32)>) {
        match self {
            CacheKind::Masque => crate::cache::add_to_masque_with_rtt(config_path, endpoints),
            CacheKind::WireGuard => crate::cache::add_to_wireguard_with_rtt(config_path, endpoints),
        }
    }
}

/// The verify closure type: given (ip, port, timeout, ironclad) → Option<ProbeResult>.
pub type VerifyFn<'a> = dyn Fn(IpAddr, u16, Duration, bool) -> Pin<Box<dyn Future<Output = Option<ProbeResult>> + Send + 'a>>
    + Send
    + Sync
    + 'a;

// ─────────────────────────────────────────────────────────────────────────────
// Unified scan engine
// ─────────────────────────────────────────────────────────────────────────────

pub async fn host_has_ipv6() -> bool {
    match tokio::net::UdpSocket::bind("[::]:0").await {
        Ok(sock) => sock.connect("[2606:4700:d0::a29f:c001]:443").await.is_ok(),
        Err(_) => false,
    }
}

/// Run the unified endpoint hunt: tier-0 cache → candidate generation → concurrent
/// probing with hot-subnet drill-down → deadline/quiet-period management.
pub async fn hunt_best(
    config: &ProbeConfig,
    ports: &[u16],
    ip: IpScan,
    mode: ScanMode,
    verify: &VerifyFn<'_>,
) -> Result<ProbeResult> {
    let mut st = mode.strategy(&config.profile);
    // User overrides from the GUI scanner tab (AETHER_SCAN_CONCURRENCY / AETHER_SCAN_TIMEOUT_MS).
    if let Some(c) = crate::runtime_env::usize("AETHER_SCAN_CONCURRENCY") {
        st.concurrency = c.max(1);
    }
    if let Some(ms) = crate::runtime_env::usize("AETHER_SCAN_TIMEOUT_MS") {
        st.per_probe_timeout = Duration::from_millis(ms as u64);
    }
    let timeout = st.per_probe_timeout;
    let ironclad = mode == ScanMode::Ironclad;
    let label = config.label;

    // ── Tier-0: Ultra-fast cache RACE (first-hit-wins, parallel) ──
    // #2: Race top cached endpoints simultaneously. Return the FIRST that
    // verifies successfully instead of waiting for all to complete.
    let cached = config.cache_kind.read_sorted(&config.config_path);
    if !cached.is_empty() {
        let tier0_timeout = Duration::from_millis(600);
        let race_count = cached.len().min(5); // Race top-5 by trust score.
        log::info!("[⚡] Tier-0 race: top {} cached {} endpoints (first-hit-wins)", race_count, label);
        let race_futures: Vec<_> = cached
            .into_iter()
            .take(race_count)
            .map(|(addr, _rtt)| verify(addr.ip(), addr.port(), tier0_timeout, false))
            .collect();

        // Race: return the first successful result.
        let mut set = futures::stream::FuturesUnordered::new();
        for fut in race_futures {
            set.push(fut);
        }
        use futures::StreamExt;
        while let Some(res) = set.next().await {
            if let Some(pr) = res {
                log::info!("[⚡] Tier-0 race winner {}:{} rtt={:?}", pr.ip, pr.port, pr.rtt);
                let rtt_ms = pr.rtt.as_millis() as u32;
                config.cache_kind.write_with_rtt(&config.config_path, vec![(SocketAddr::new(pr.ip, pr.port), rtt_ms)]);
                return Ok(pr);
            }
        }
        log::info!("[-] Tier-0 race: all cached endpoints failed, falling back to full scan");
    }

    let mut effective_ip = ip;
    if ip.want_v6() && !host_has_ipv6().await {
        if ip.want_v4() {
            log::warn!("[-] host has no IPv6 route; falling back to IPv4-only scan");
            effective_ip = IpScan::V4;
        } else {
            log::warn!("[-] host has no IPv6 route; IPv6 scan needs native IPv6 connectivity");
            return Err(AetherError::NoCleanEndpoint);
        }
    }
    let candidates = build_candidates(config, &st, ports, effective_ip);

    log::info!(
        "[*] scan mode={} ip={} candidates={} ports={:?} concurrency={} per_probe={:?} budget={:?}",
        mode.label(),
        effective_ip.label(),
        candidates.len(),
        ports,
        st.concurrency,
        st.per_probe_timeout,
        st.overall_deadline,
    );

    let total_candidates = candidates.len();
    let stream = futures::stream::iter(
        candidates
            .into_iter()
            .map(|(ip, port)| verify(ip, port, timeout, ironclad)),
    )
    .buffer_unordered(st.concurrency);
    tokio::pin!(stream);

    let deadline = Instant::now() + st.overall_deadline;
    let mut best: Option<ProbeResult> = None;
    let mut found = 0usize;
    let mut scanned = 0usize;
    let mut quiet_until: Option<Instant> = None;
    let mut hot_subnets = HashSet::<u128>::new();

    loop {
        let effective = match quiet_until {
            Some(q) => q.min(deadline),
            None => deadline,
        };
        let remaining = effective.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            if best.is_some() {
                if quiet_until.is_some() {
                    log::info!("[+] no new {} recently, finalizing selection", label);
                } else {
                    log::info!("[-] scan deadline reached, finalizing selection");
                }
            } else {
                log::error!("[-] scan deadline reached with no {}", label);
            }
            break;
        }

        tokio::select! {
            item = stream.next() => {
                match item {
                    None => break,
                    Some(res) => {
                        scanned += 1;
                        if scanned % 50 == 0 || scanned == total_candidates {
                            log::info!("[*] scanning... {}/{} ips, found {} working", scanned, total_candidates, found);
                        }

                        match res {
                            None => continue,
                            Some(pr) => {
                                log::info!("[+] {} candidate ok {}:{} rtt={:?}", label, pr.ip, pr.port, pr.rtt);
                                best = Some(match best {
                                    Some(cur) if cur.rtt <= pr.rtt => cur,
                                    _ => pr,
                                });
                                found += 1;

                                let sub_key = match pr.ip {
                                    IpAddr::V4(v4) => u128::from(u32::from(v4) & 0xFFFFFF00),
                                    IpAddr::V6(v6) => u128::from(v6) & 0xFFFFFFFFFFFF00000000000000000000,
                                };
                                if hot_subnets.insert(sub_key) {
                                    log::info!("[🔥] Hot subnet detected near {}! Launching Stage-2 drill-down...", pr.ip);
                                    let hot_hits = drill_down_hot_subnet(verify, pr.ip, pr.port, timeout, ironclad, st.concurrency).await;
                                    for h_pr in hot_hits {
                                        log::info!("[🔥] Hot subnet candidate ok {}:{} rtt={:?}", h_pr.ip, h_pr.port, h_pr.rtt);
                                        best = Some(match best {
                                            Some(cur) if cur.rtt <= h_pr.rtt => cur,
                                            _ => h_pr,
                                        });
                                        found += 1;
                                    }
                                }

                                if st.early_exit_first {
                                    let final_best = best.unwrap_or(pr);
                                    let rtt_ms = final_best.rtt.as_millis() as u32;
                                    config.cache_kind.write_with_rtt(&config.config_path, vec![(SocketAddr::new(final_best.ip, final_best.port), rtt_ms)]);
                                    return Ok(final_best);
                                }

                                if st.target_successes > 0 && found >= st.target_successes && quiet_until.is_none() {
                                    log::info!("[+] reached target of {} {}, selecting best", st.target_successes, label);
                                    if !st.quiet_after_first.is_zero() {
                                        quiet_until = Some(Instant::now() + st.quiet_after_first);
                                    } else {
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            _ = tokio::time::sleep(remaining) => {
                if best.is_some() {
                    if quiet_until.is_some() {
                        log::info!("[+] no new {} recently, finalizing selection", label);
                    } else {
                        log::warn!("[-] scan deadline reached");
                    }
                } else {
                    log::warn!("[-] scan deadline reached with no {}", label);
                }
                break;
            }
        }
    }

    match best {
        Some(pr) => {
            log::info!("[+] best {} {}:{} rtt={:?}", label, pr.ip, pr.port, pr.rtt);
            let rtt_ms = pr.rtt.as_millis() as u32;
            config.cache_kind.write_with_rtt(&config.config_path, vec![(SocketAddr::new(pr.ip, pr.port), rtt_ms)]);
            Ok(pr)
        }
        None => Err(AetherError::NoCleanEndpoint),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Hot-subnet drill-down (shared)
// ─────────────────────────────────────────────────────────────────────────────

async fn drill_down_hot_subnet(
    verify: &VerifyFn<'_>,
    ip: IpAddr,
    port: u16,
    timeout: Duration,
    ironclad: bool,
    concurrency: usize,
) -> Vec<ProbeResult> {
    let mut neighbors = Vec::new();
    match ip {
        IpAddr::V4(v4) => {
            let base = u32::from(v4) & 0xFFFFFF00;
            let current_host = v4.octets()[3] as u32;
            for offset in [1, 2, 3, 4, 5, 8, 10, 15, 20, 25, 30, 40, 50, 60, 75, 90, 100, 120, 150, 180, 200] {
                let host1 = (current_host + offset) % 254 + 1;
                let host2 = (current_host.wrapping_sub(offset)) % 254 + 1;
                for h in [host1, host2] {
                    if h != current_host && h > 0 && h < 255 {
                        let neighbor_ip = IpAddr::V4(Ipv4Addr::from(base + h));
                        if !neighbors.contains(&(neighbor_ip, port)) {
                            neighbors.push((neighbor_ip, port));
                        }
                    }
                }
            }
        }
        IpAddr::V6(v6) => {
            let segs = v6.segments();
            let current_last = segs[7];
            for offset in [1, 2, 3, 4, 5, 10, 20, 50, 100] {
                let last = current_last.wrapping_add(offset);
                if last != current_last {
                    let neighbor_ip = IpAddr::V6(Ipv6Addr::new(segs[0], segs[1], segs[2], segs[3], segs[4], segs[5], segs[6], last));
                    if !neighbors.contains(&(neighbor_ip, port)) {
                        neighbors.push((neighbor_ip, port));
                    }
                }
            }
        }
    }

    if neighbors.is_empty() {
        return Vec::new();
    }

    let stream = futures::stream::iter(
        neighbors
            .into_iter()
            .map(|(nip, nport)| verify(nip, nport, timeout, ironclad)),
    )
    .buffer_unordered(concurrency.min(16));
    tokio::pin!(stream);

    let mut results = Vec::new();
    while let Some(res) = stream.next().await {
        if let Some(pr) = res {
            results.push(pr);
        }
    }
    results
}

// ─────────────────────────────────────────────────────────────────────────────
// Candidate generation (shared)
// ─────────────────────────────────────────────────────────────────────────────

fn build_candidates(config: &ProbeConfig, st: &Strategy, ports: &[u16], ip: IpScan) -> Vec<(IpAddr, u16)> {
    use rand::seq::SliceRandom;
    let mut rng = rand::thread_rng();

    // Port priority: dedup while preserving priority order from caller
    let dedup_ports: Vec<u16> = {
        let mut seen_port: HashSet<u16> = HashSet::new();
        let deduped: Vec<u16> = ports.iter().copied().filter(|p| seen_port.insert(*p)).collect();
        if deduped.is_empty() { vec![443] } else { deduped }
    };

    // ── Port tiering: split ports into T1 (first), T2 (next), T3 (last) ──
    let (t1_ports, t2_ports, t3_ports): (Vec<u16>, Vec<u16>, Vec<u16>) = {
        let is_masque = config.label.contains("gateway");
        if is_masque {
            let t1: Vec<u16> = dedup_ports.iter().copied().filter(|p| MASQUE_PORTS_T1.contains(p)).collect();
            let t2: Vec<u16> = dedup_ports.iter().copied().filter(|p| MASQUE_PORTS_T2.contains(p)).collect();
            let t3: Vec<u16> = dedup_ports.iter().copied().filter(|p| !MASQUE_PORTS_T1.contains(p) && !MASQUE_PORTS_T2.contains(p)).collect();
            (if t1.is_empty() { vec![443] } else { t1 }, t2, t3)
        } else {
            let t1: Vec<u16> = dedup_ports.iter().copied().filter(|p| crate::wireguard::WG_PORTS_T1.contains(p)).collect();
            let t2: Vec<u16> = dedup_ports.iter().copied().filter(|p| crate::wireguard::WG_PORTS_T2.contains(p)).collect();
            let t3: Vec<u16> = dedup_ports.iter().copied().filter(|p| !crate::wireguard::WG_PORTS_T1.contains(p) && !crate::wireguard::WG_PORTS_T2.contains(p)).collect();
            (if t1.is_empty() { vec![500, 4500] } else { t1 }, t2, t3)
        }
    };

    let mut seen: HashSet<(IpAddr, u16)> = HashSet::new();
    let mut tier1_out: Vec<(IpAddr, u16)> = Vec::new();
    let mut tier2_out: Vec<(IpAddr, u16)> = Vec::new();
    let mut tier3_out: Vec<(IpAddr, u16)> = Vec::new();

    // ── Weighted CIDR ranking: sort CIDRs by weight (highest first) ──
    let mut weighted_cidrs: Vec<(&str, u8)> = if ip.want_v4() {
        config.cidr_weights_v4.to_vec()
    } else {
        Vec::new()
    };
    weighted_cidrs.sort_by(|a, b| b.1.cmp(&a.1));
    let max_weight = weighted_cidrs.first().map(|&(_, w)| w.max(1)).unwrap_or(1) as usize;

    // ── Weight-proportional sampling: higher-weight CIDRs get more samples ──
    let sample_for_weight = |weight: u8| -> usize {
        if st.full_subnet { return 0; } // full_subnet ignores sampling
        let base = st.sample_per_cidr;
        if base == 0 { return 0; }
        let proportional = (base * weight as usize) / max_weight;
        proportional.max(base / 5).max(8) // floor: at least 8 or 20% of base
    };

    // Helper: generate candidates for a set of ports across CIDRs
    let mut gen_pool = |port_set: &[u16], out: &mut Vec<(IpAddr, u16)>| {
        if ip.want_v4() {
            for &(cidr, weight) in &weighted_cidrs {
                let n = sample_for_weight(weight);
                let hosts = if st.full_subnet {
                    enumerate_cidr_v4(cidr)
                } else {
                    sample_cidr_v4(cidr, n)
                };
                for a in hosts {
                    for &p in port_set {
                        if seen.insert((IpAddr::V4(a), p)) {
                            out.push((IpAddr::V4(a), p));
                        }
                    }
                }
            }
        }
        if ip.want_v6() {
            let per = if st.sample_per_cidr == 0 { 96 } else { st.sample_per_cidr };
            for c in config.cidrs_v6 {
                let hosts = sample_cidr_v6(c, per, config.cidrs_v4);
                for a in hosts {
                    for &p in port_set {
                        if seen.insert((IpAddr::V6(a), p)) {
                            out.push((IpAddr::V6(a), p));
                        }
                    }
                }
            }
        }
    };

    // Generate in tier order: T1 first (port-443-first for MASQUE), then T2, then T3.
    gen_pool(&t1_ports, &mut tier1_out);
    gen_pool(&t2_ports, &mut tier2_out);
    gen_pool(&t3_ports, &mut tier3_out);

    // ── Seeds: shuffled and prepended to Tier 1 (known-good anchors) ──
    let mut seeds_out: Vec<(IpAddr, u16)> = Vec::new();
    if ip.want_v4() {
        for s in config.seeds_v4 {
            if let Ok(a) = s.parse::<Ipv4Addr>() {
                for &p in &t1_ports {
                    if seen.insert((IpAddr::V4(a), p)) {
                        seeds_out.push((IpAddr::V4(a), p));
                    }
                }
            }
        }
    }
    if ip.want_v6() {
        for s in config.seeds_v6 {
            if let Ok(a) = s.parse::<Ipv6Addr>() {
                for &p in &t1_ports {
                    if seen.insert((IpAddr::V6(a), p)) {
                        seeds_out.push((IpAddr::V6(a), p));
                    }
                }
            }
        }
    }
    seeds_out.shuffle(&mut rng);

    // ── Cap thorough mode to prevent excessive candidate counts ──
    const MAX_CANDIDATES: usize = 20_000;
    let total = seeds_out.len() + tier1_out.len() + tier2_out.len() + tier3_out.len();
    if total > MAX_CANDIDATES {
        // Keep all seeds + tier1, truncate tier2/tier3 proportionally.
        let budget = MAX_CANDIDATES.saturating_sub(seeds_out.len() + tier1_out.len());
        let t2_keep = budget * tier2_out.len() / (tier2_out.len() + tier3_out.len()).max(1);
        tier2_out.truncate(t2_keep);
        tier3_out.truncate(budget.saturating_sub(t2_keep));
    }

    // Final order: seeds → tier1 → tier2 → tier3
    seeds_out.extend(tier1_out);
    seeds_out.extend(tier2_out);
    seeds_out.extend(tier3_out);
    seeds_out
}

// ─────────────────────────────────────────────────────────────────────────────
// CIDR utilities (shared, single copy)
// ─────────────────────────────────────────────────────────────────────────────

fn parse_cidr_v4(cidr: &str) -> Option<(u32, u8)> {
    let (ip, prefix) = cidr.split_once('/')?;
    Some((u32::from(ip.parse::<Ipv4Addr>().ok()?), prefix.parse().ok()?))
}

fn enumerate_cidr_v4(cidr: &str) -> Vec<Ipv4Addr> {
    let (base, prefix) = match parse_cidr_v4(cidr) {
        Some(v) => v,
        None => return Vec::new(),
    };
    let host_bits = 32u32.saturating_sub(prefix as u32);
    if host_bits == 0 {
        return vec![Ipv4Addr::from(base)];
    }
    if host_bits > 12 {
        return Vec::new();
    }
    let size = 1u32 << host_bits;
    (1..size.saturating_sub(1))
        .map(|off| Ipv4Addr::from(base + off))
        .collect()
}

fn sample_cidr_v4(cidr: &str, n: usize) -> Vec<Ipv4Addr> {
    let (base, prefix) = match parse_cidr_v4(cidr) {
        Some(v) => v,
        None => return Vec::new(),
    };
    let host_bits = 32u32.saturating_sub(prefix as u32);
    let size = if host_bits >= 32 { u32::MAX } else { 1u32 << host_bits };
    if size <= 2 {
        return vec![Ipv4Addr::from(base)];
    }

    let usable = size - 2;
    let want = (n as u32).min(usable);
    let mut rng = rand::thread_rng();
    let mut chosen: HashSet<u32> = HashSet::with_capacity(want as usize);
    let mut out = Vec::with_capacity(want as usize);

    while (out.len() as u32) < want {
        let off = 1 + rng.gen_range(0..usable);
        if chosen.insert(off) {
            out.push(Ipv4Addr::from(base + off));
        }
    }

    out
}

fn parse_cidr_v6(cidr: &str) -> Option<(u128, u8)> {
    let (ip, prefix) = cidr.split_once('/')?;
    Some((u128::from(ip.parse::<Ipv6Addr>().ok()?), prefix.parse().ok()?))
}

fn sample_cidr_v6(cidr: &str, n: usize, v4_cidrs: &[&str]) -> Vec<Ipv6Addr> {
    let (base, prefix) = match parse_cidr_v6(cidr) {
        Some(v) => v,
        None => return Vec::new(),
    };
    if 128u32.saturating_sub(prefix as u32) == 0 {
        return vec![Ipv6Addr::from(base)];
    }

    let v4: Vec<(u32, u8)> = v4_cidrs.iter().filter_map(|c| parse_cidr_v4(c)).collect();
    let mut rng = rand::thread_rng();
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let embedded = if v4.is_empty() {
            rng.gen::<u32>() as u128
        } else {
            let (b, p) = v4[rng.gen_range(0..v4.len())];
            let host_bits = 32u32.saturating_sub(p as u32);
            let host = if host_bits == 0 {
                0
            } else {
                rng.gen::<u32>() & ((1u32 << host_bits) - 1)
            };
            (b | host) as u128
        };
        out.push(Ipv6Addr::from(base | embedded));
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// MASQUE protocol constants & helpers
// ─────────────────────────────────────────────────────────────────────────────

pub const MASQUE_CIDRS_V4: &[&str] = &[
    "162.159.36.0/24",
    "162.159.46.0/24",
    "162.159.192.0/24",
    "162.159.193.0/24",
    "162.159.195.0/24",
    "162.159.196.0/24",
    "162.159.197.0/24",
    "162.159.198.0/24",
    "162.159.204.0/24",
    "172.65.251.0/24",
    "188.114.96.0/24",
    "188.114.97.0/24",
    "188.114.98.0/24",
    "188.114.99.0/24",
    "8.34.146.0/24",
    "8.39.214.0/24",
    "8.39.204.0/24",
    "8.6.112.0/24",
    "8.35.211.0/24",
    "8.39.125.0/24",
    "8.47.69.0/24",
];

pub const MASQUE_SEEDS: &[&str] = &[
    "162.159.198.2",
    "162.159.198.1",
    "162.159.192.1",
    "162.159.193.1",
    "162.159.195.1",
    "162.159.196.1",
    "8.34.146.1",
    "8.39.214.1",
    "8.6.112.1",
];

/// Ports ordered by priority: primary web TLS first, then secondary, then legacy.
pub const MASQUE_PORTS: &[u16] = &[443, 8443, 4443, 8095, 2408, 500, 1701, 4500];

/// MASQUE port tiers: Tier 1 scanned first, Tier 2 next, Tier 3 last.
const MASQUE_PORTS_T1: &[u16] = &[443];
const MASQUE_PORTS_T2: &[u16] = &[8443, 4443, 8095];
const MASQUE_PORTS_T3: &[u16] = &[2408, 500, 1701, 4500];

const MASQUE_CIDR_WEIGHTS: &[(&str, u8)] = &[
    ("162.159.198.0/24", 10),
    ("162.159.192.0/24", 10),
    ("162.159.193.0/24", 9),
    ("162.159.195.0/24", 9),
    ("162.159.196.0/24", 8),
    ("162.159.197.0/24", 8),
    ("188.114.96.0/24", 7),
    ("188.114.97.0/24", 7),
    ("188.114.98.0/24", 6),
    ("188.114.99.0/24", 6),
    ("162.159.36.0/24", 5),
    ("162.159.46.0/24", 5),
    ("162.159.204.0/24", 5),
    ("172.65.251.0/24", 4),
    ("8.34.146.0/24", 3),
    ("8.39.214.0/24", 3),
    ("8.39.204.0/24", 3),
    ("8.6.112.0/24", 2),
    ("8.35.211.0/24", 2),
    ("8.39.125.0/24", 2),
    ("8.47.69.0/24", 2),
];

pub const MASQUE_CIDRS_V6: &[&str] = &[
    "2606:4700:d0::/48",
    "2606:4700:d1::/48",
    "2606:4700:102::/48",
];

pub const MASQUE_SEEDS_V6: &[&str] = &[
    "2606:4700:d0::a29f:c602",
    "2606:4700:d1::a29f:c602",
    "2606:4700:d0::a29f:c601",
    "2606:4700:d0::a29f:c001",
];

const IRONCLAD_TCPING_TIMEOUT: Duration = Duration::from_secs(10);

/// MASQUE-specific probe configuration.
#[derive(Clone)]
pub struct MasqueProbe {
    pub sni: String,
    pub authority: String,
    pub path: String,
    pub cert_pem: Arc<[u8]>,
    pub key_pem: Arc<[u8]>,
    pub ech_config_list: Option<Arc<[u8]>>,
    pub noize: crate::noize::NoizeConfig,
    pub ports: Vec<u16>,
    pub ip: IpScan,
    pub local_ipv4: Ipv4Addr,
    pub config_path: String,
}

impl MasqueProbe {
    /// Build a [`ProbeConfig`] for MASQUE scanning.
    pub fn probe_config(&self) -> ProbeConfig {
        ProbeConfig {
            cidrs_v4: MASQUE_CIDRS_V4,
            cidrs_v6: MASQUE_CIDRS_V6,
            cidr_weights_v4: MASQUE_CIDR_WEIGHTS,
            seeds_v4: MASQUE_SEEDS,
            seeds_v6: MASQUE_SEEDS_V6,
            cache_kind: CacheKind::Masque,
            label: "gateway",
            config_path: self.config_path.clone(),
            profile: StrategyProfile {
                turbo_sample: 64,
                balanced_target: 6,
                balanced_sample: 140,
                stealth_target: 4,
                stealth_sample: 64,
            },
        }
    }

    /// Create the verify closure for MASQUE probing.
    pub fn verify_fn(&self) -> impl Fn(IpAddr, u16, Duration, bool) -> Pin<Box<dyn Future<Output = Option<ProbeResult>> + Send + '_>> + Send + Sync + '_ {
        move |ip: IpAddr, port: u16, timeout: Duration, ironclad: bool| {
            Box::pin(async move {
                if ironclad {
                    let params = crate::tunnelping::MasquePingParams {
                        peer: SocketAddr::new(ip, port),
                        sni: self.sni.clone(),
                        authority: self.authority.clone(),
                        path: self.path.clone(),
                        cert_pem: self.cert_pem.to_vec(),
                        key_pem: self.key_pem.to_vec(),
                        noize: self.noize.clone(),
                        local_ipv4: self.local_ipv4,
                        local_ipv4_str: self.local_ipv4.to_string(),
                        local_ipv6_str: String::new(),
                    };
                    return match crate::tunnelping::masque_http_ping(&params, IRONCLAD_TCPING_TIMEOUT).await {
                        Ok(rtt) => {
                            log::info!("[+] ironclad verified {ip}:{port} real http round trip rtt={:?}", rtt);
                            Some(ProbeResult { ip, port, rtt })
                        }
                        Err(e) => {
                            log::debug!("[-] ironclad {ip}:{port} failed real http check: {e}");
                            None
                        }
                    };
                }

                if crate::masque_h2::enabled() {
                    let cfg = crate::masque_h2::H2TunnelConfig {
                        peer: SocketAddr::new(ip, port),
                        sni: self.sni.clone(),
                        authority: self.authority.clone(),
                        path: self.path.clone(),
                        cert_pem: self.cert_pem.to_vec(),
                        key_pem: self.key_pem.to_vec(),
                        probe_src: Some(self.local_ipv4),
                    };
                    return match crate::masque_h2::verify_h2(&cfg, timeout).await {
                        Ok(rtt) => Some(ProbeResult { ip, port, rtt }),
                        Err(e) => {
                            log::debug!("h2 probe {ip}:{port} -> {e}");
                            None
                        }
                    };
                }

                let vp = crate::quic::VerifyParams {
                    peer: SocketAddr::new(ip, port),
                    sni: self.sni.clone(),
                    authority: self.authority.clone(),
                    path: self.path.clone(),
                    cert_pem: self.cert_pem.to_vec(),
                    key_pem: self.key_pem.to_vec(),
                    ech_config_list: self.ech_config_list.as_ref().map(|a| a.to_vec()),
                    noize: self.noize.clone(),
                    timeout,
                    local_ipv4: self.local_ipv4,
                };

                match crate::quic::verify_masque(&vp).await {
                    Ok(rtt) => Some(ProbeResult { ip, port, rtt }),
                    Err(e) => {
                        log::debug!("probe {ip}:{port} -> {e}");
                        None
                    }
                }
            })
        }
    }
}

/// Convenience: hunt the best MASQUE gateway.
pub async fn hunt_best_gateway(probe: &MasqueProbe, mode: ScanMode) -> Result<ProbeResult> {
    let config = probe.probe_config();
    let verify = probe.verify_fn();
    hunt_best(&config, &probe.ports, probe.ip, mode, &verify).await
}

// ─────────────────────────────────────────────────────────────────────────────
// WireGuard protocol constants & helpers
// ─────────────────────────────────────────────────────────────────────────────

const WG_CIDR_WEIGHTS: &[(&str, u8)] = &[
    ("162.159.192.0/24", 10),
    ("162.159.195.0/24", 10),
    ("188.114.96.0/24", 8),
    ("188.114.97.0/24", 8),
    ("188.114.98.0/24", 7),
    ("188.114.99.0/24", 7),
    ("8.34.146.0/24", 5),
    ("8.39.214.0/24", 5),
    ("8.39.204.0/24", 4),
    ("8.6.112.0/24", 3),
    ("8.35.211.0/24", 3),
    ("8.39.125.0/24", 2),
    ("8.47.69.0/24", 2),
];

const WG_IRONCLAD_TCPING_TIMEOUT: Duration = Duration::from_secs(10);

/// WireGuard-specific probe configuration.
#[derive(Clone)]
pub struct WgProbe {
    pub private_key: Arc<[u8; 32]>,
    pub peer_public_key: Arc<[u8; 32]>,
    pub client_id: [u8; 3],
    pub local_ipv4: Ipv4Addr,
    pub ports: Vec<u16>,
    pub ip: IpScan,
    pub aethernoize: crate::aethernoize::AetherNoizeConfig,
    pub config_path: String,
}

impl WgProbe {
    /// Build a [`ProbeConfig`] for WireGuard scanning.
    pub fn probe_config(&self) -> ProbeConfig {
        ProbeConfig {
            cidrs_v4: crate::wireguard::WG_PREFIXES_V4,
            cidrs_v6: crate::wireguard::WG_PREFIXES_V6,
            cidr_weights_v4: WG_CIDR_WEIGHTS,
            seeds_v4: crate::wireguard::WG_SEEDS_V4,
            seeds_v6: crate::wireguard::WG_SEEDS_V6,
            cache_kind: CacheKind::WireGuard,
            label: "wg endpoint",
            config_path: self.config_path.clone(),
            profile: StrategyProfile {
                turbo_sample: 40,
                balanced_target: 5,
                balanced_sample: 120,
                stealth_target: 3,
                stealth_sample: 50,
            },
        }
    }

    /// Create the verify closure for WireGuard probing.
    pub fn verify_fn(&self) -> impl Fn(IpAddr, u16, Duration, bool) -> Pin<Box<dyn Future<Output = Option<ProbeResult>> + Send + '_>> + Send + Sync + '_ {
        move |ip: IpAddr, port: u16, timeout: Duration, ironclad: bool| {
            Box::pin(async move {
                let peer = SocketAddr::new(ip, port);

                let (rtt, session) = match crate::wireguard::verify_endpoint_keep_session(
                    peer,
                    *self.private_key,
                    *self.peer_public_key,
                    self.client_id,
                    self.local_ipv4,
                    &self.aethernoize,
                    timeout,
                )
                .await
                {
                    Ok(v) => v,
                    Err(e) => {
                        log::debug!("wg probe {ip}:{port} -> {e}");
                        return None;
                    }
                };

                if !ironclad {
                    return Some(ProbeResult { ip, port, rtt });
                }

                let params = crate::tunnelping::WgPingParams {
                    local_ipv4: self.local_ipv4,
                    local_ipv6: "::1".parse().unwrap(),
                    aethernoize: self.aethernoize.clone(),
                };
                match crate::tunnelping::wg_http_ping_established(session, &params, WG_IRONCLAD_TCPING_TIMEOUT).await {
                    Ok(http_rtt) => {
                        log::info!("[+] ironclad verified wg {ip}:{port} real http round trip rtt={:?}", http_rtt);
                        Some(ProbeResult { ip, port, rtt: http_rtt })
                    }
                    Err(e) => {
                        log::debug!("[-] ironclad wg {ip}:{port} failed real http check: {e}");
                        None
                    }
                }
            })
        }
    }
}

/// Convenience: hunt the best WireGuard endpoint.
pub async fn hunt_best_wg_endpoint(probe: &WgProbe, mode: ScanMode) -> Result<ProbeResult> {
    let config = probe.probe_config();
    let verify = probe.verify_fn();
    hunt_best(&config, &probe.ports, probe.ip, mode, &verify).await
}
