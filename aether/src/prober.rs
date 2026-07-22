use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::stream::StreamExt;
use rand::Rng;

use crate::error::{AetherError, Result};
use crate::noize::NoizeConfig;
use crate::quic;

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

/// Weighted CIDR ranking — higher weight = probed earlier.
/// Based on empirical Cloudflare edge health & responsiveness.
const MASQUE_CIDR_WEIGHTS: &[(&str, u8)] = &[
    ("162.159.198.0/24", 10),  // Historically most responsive
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

pub const MASQUE_SEEDS_V6: &[&str] = &["2606:4700:d0::a29f:c602", "2606:4700:d1::a29f:c602", "2606:4700:d0::a29f:c601", "2606:4700:d0::a29f:c001"];

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

    fn strategy(&self) -> Strategy {
        match self {
            ScanMode::Turbo => Strategy {
                concurrency: 250,
                per_probe_timeout: Duration::from_millis(1000),
                overall_deadline: Duration::from_secs(15),
                quiet_after_first: Duration::from_secs(0),
                target_successes: 1,
                early_exit_first: true,
                full_subnet: false,
                sample_per_cidr: 64,
            },
            ScanMode::Balanced => Strategy {
                concurrency: 200,
                per_probe_timeout: Duration::from_millis(1200),
                overall_deadline: Duration::from_secs(30),
                quiet_after_first: Duration::from_secs(8),
                target_successes: 6,
                early_exit_first: false,
                full_subnet: false,
                sample_per_cidr: 140,
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
                target_successes: 4,
                early_exit_first: false,
                full_subnet: false,
                sample_per_cidr: 64,
            },
            ScanMode::Ironclad => Strategy {
                concurrency: 6,
                per_probe_timeout: Duration::from_millis(5000),
                overall_deadline: Duration::from_secs(120),
                quiet_after_first: Duration::from_secs(15),
                target_successes: 3,
                early_exit_first: false,
                full_subnet: false,
                sample_per_cidr: 140,
            },
        }
    }
}

const IRONCLAD_TCPING_TIMEOUT: Duration = Duration::from_secs(10);

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

#[derive(Clone)]
pub struct MasqueProbe {
    pub sni: String,
    pub authority: String,
    pub path: String,
    pub cert_pem: Arc<[u8]>,
    pub key_pem: Arc<[u8]>,
    pub ech_config_list: Option<Arc<[u8]>>,
    pub noize: NoizeConfig,
    pub ports: Vec<u16>,
    pub ip: IpScan,
    pub local_ipv4: Ipv4Addr,
    pub config_path: String,
}

pub async fn host_has_ipv6() -> bool {
    match tokio::net::UdpSocket::bind("[::]:0").await {
        Ok(sock) => sock.connect("[2606:4700:d0::a29f:c001]:443").await.is_ok(),
        Err(_) => false,
    }
}

pub async fn hunt_best_gateway(probe: &MasqueProbe, mode: ScanMode) -> Result<ProbeResult> {
    let st = mode.strategy();
    let timeout = st.per_probe_timeout;
    let ironclad = mode == ScanMode::Ironclad;

    // ── Tier-0: Ultra-fast cache probe (500ms timeout, parallel) ──
    let cached = crate::cache::get_masque_sorted(&probe.config_path);
    if !cached.is_empty() {
        let tier0_timeout = Duration::from_millis(500);
        let tier0_concurrency = cached.len().min(10);
        log::info!("[⚡] Tier-0 instant probe: {} cached endpoints (500ms timeout)", cached.len());
        let stream = futures::stream::iter(
            cached.into_iter().map(|(addr, _rtt)| verify_one(probe, addr.ip(), addr.port(), tier0_timeout, false))
        ).buffer_unordered(tier0_concurrency);
        tokio::pin!(stream);

        let mut best: Option<ProbeResult> = None;
        while let Some(res) = stream.next().await {
            if let Some(pr) = res {
                log::info!("[⚡] Tier-0 cache hit {}:{} rtt={:?}", pr.ip, pr.port, pr.rtt);
                best = Some(match best {
                    Some(cur) if cur.rtt <= pr.rtt => cur,
                    _ => pr,
                });
            }
        }
        if let Some(pr) = best {
            log::info!("[⚡] Tier-0 instant connect via cached gateway {}:{} rtt={:?}", pr.ip, pr.port, pr.rtt);
            let rtt_ms = pr.rtt.as_millis() as u32;
            crate::cache::add_to_masque_with_rtt(&probe.config_path, vec![(std::net::SocketAddr::new(pr.ip, pr.port), rtt_ms)]);
            return Ok(pr);
        }
        log::info!("[-] Tier-0 cache miss, falling back to full scan");
    }

    let mut effective_ip = probe.ip;
    if probe.ip.want_v6() && !host_has_ipv6().await {
        if probe.ip.want_v4() {
            log::warn!("[-] host has no IPv6 route; falling back to IPv4-only scan");
            effective_ip = IpScan::V4;
        } else {
            log::warn!("[-] host has no IPv6 route; IPv6 scan needs native IPv6 connectivity");
            return Err(AetherError::NoCleanEndpoint);
        }
    }
    let candidates = build_candidates(&st, &probe.ports, effective_ip);

    log::info!(
        "[*] scan mode={} ip={} candidates={} ports={:?} concurrency={} per_probe={:?} budget={:?}",
        mode.label(),
        effective_ip.label(),
        candidates.len(),
        probe.ports,
        st.concurrency,
        st.per_probe_timeout,
        st.overall_deadline,
    );

    let total_candidates = candidates.len();
    let stream = futures::stream::iter(
        candidates
            .into_iter()
            .map(|(ip, port)| verify_one(probe, ip, port, timeout, ironclad)),
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
                    log::info!("[+] no new gateways recently, finalizing selection");
                } else {
                    log::info!("[-] scan deadline reached, finalizing selection");
                }
            } else {
                log::error!("[-] scan deadline reached with no gateway");
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
                                log::info!("[+] candidate ok {}:{} rtt={:?}", pr.ip, pr.port, pr.rtt);
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
                                    log::info!("[🔥] Hot subnet detected near {}! Launching Stage-2 subnet drill-down...", pr.ip);
                                    let hot_hits = drill_down_hot_subnet(probe, pr.ip, pr.port, timeout, ironclad, st.concurrency).await;
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
                                    crate::cache::add_to_masque_with_rtt(&probe.config_path, vec![(std::net::SocketAddr::new(final_best.ip, final_best.port), rtt_ms)]);
                                    return Ok(final_best);
                                }

                                if st.target_successes > 0 && found >= st.target_successes && quiet_until.is_none() {
                                    log::info!("[+] reached target of {} gateways, selecting best", st.target_successes);
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
                        log::info!("[+] no new gateways recently, finalizing selection");
                    } else {
                        log::warn!("[-] scan deadline reached");
                    }
                } else {
                    log::warn!("[-] scan deadline reached with no gateway");
                }
                break;
            }
        }
    }

    match best {
        Some(pr) => {
            log::info!("[+] best gateway {}:{} rtt={:?}", pr.ip, pr.port, pr.rtt);
            let rtt_ms = pr.rtt.as_millis() as u32;
            crate::cache::add_to_masque_with_rtt(&probe.config_path, vec![(SocketAddr::new(pr.ip, pr.port), rtt_ms)]);
            Ok(pr)
        }
        None => Err(AetherError::NoCleanEndpoint),
    }
}

async fn verify_one(
    probe: &MasqueProbe,
    ip: IpAddr,
    port: u16,
    timeout: Duration,
    ironclad: bool,
) -> Option<ProbeResult> {
    if ironclad {
        let params = crate::tunnelping::MasquePingParams {
            peer: SocketAddr::new(ip, port),
            sni: probe.sni.clone(),
            authority: probe.authority.clone(),
            path: probe.path.clone(),
            cert_pem: probe.cert_pem.to_vec(),
            key_pem: probe.key_pem.to_vec(),
            noize: probe.noize.clone(),
            local_ipv4: probe.local_ipv4,
            local_ipv4_str: probe.local_ipv4.to_string(),
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
            sni: probe.sni.clone(),
            authority: probe.authority.clone(),
            path: probe.path.clone(),
            cert_pem: probe.cert_pem.to_vec(),
            key_pem: probe.key_pem.to_vec(),
            probe_src: Some(probe.local_ipv4),
        };
        return match crate::masque_h2::verify_h2(&cfg, timeout).await {
            Ok(rtt) => Some(ProbeResult { ip, port, rtt }),
            Err(e) => {
                log::debug!("h2 probe {ip}:{port} -> {e}");
                None
            }
        };
    }

    let vp = quic::VerifyParams {
        peer: SocketAddr::new(ip, port),
        sni: probe.sni.clone(),
        authority: probe.authority.clone(),
        path: probe.path.clone(),
        cert_pem: probe.cert_pem.to_vec(),
        key_pem: probe.key_pem.to_vec(),
        ech_config_list: probe.ech_config_list.as_ref().map(|a| a.to_vec()),
        noize: probe.noize.clone(),
        timeout,
    };

    match quic::verify_masque(&vp).await {
        Ok(rtt) => Some(ProbeResult { ip, port, rtt }),
        Err(e) => {
            log::debug!("probe {ip}:{port} -> {e}");
            None
        }
    }
}

async fn drill_down_hot_subnet(
    probe: &MasqueProbe,
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
            .map(|(nip, nport)| verify_one(probe, nip, nport, timeout, ironclad)),
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

fn build_candidates(st: &Strategy, ports: &[u16], ip: IpScan) -> Vec<(IpAddr, u16)> {
    use rand::seq::SliceRandom;
    let mut rng = rand::thread_rng();

    let mut seen: HashSet<(IpAddr, u16)> = HashSet::new();
    let mut seeds_out: Vec<(IpAddr, u16)> = Vec::new();
    let mut pool_out: Vec<(IpAddr, u16)> = Vec::new();

    let seeds: Vec<Ipv4Addr> = MASQUE_SEEDS.iter().filter_map(|s| s.parse().ok()).collect();
    let seeds6: Vec<Ipv6Addr> = MASQUE_SEEDS_V6.iter().filter_map(|s| s.parse().ok()).collect();

    // ── Weighted CIDR ranking: sort CIDRs by weight (highest first) ──
    let mut weighted_cidrs: Vec<(&str, u8)> = if ip.want_v4() {
        MASQUE_CIDR_WEIGHTS.to_vec()
    } else {
        Vec::new()
    };
    weighted_cidrs.sort_by(|a, b| b.1.cmp(&a.1));

    let mut pool_v4 = Vec::new();
    if ip.want_v4() {
        for &(cidr, _weight) in &weighted_cidrs {
            let hosts = if st.full_subnet {
                enumerate_cidr_v4(cidr)
            } else {
                sample_cidr_v4(cidr, st.sample_per_cidr)
            };
            pool_v4.extend(hosts);
        }
    }
    
    let mut pool_v6 = Vec::new();
    if ip.want_v6() {
        let per = if st.sample_per_cidr == 0 { 96 } else { st.sample_per_cidr };
        for c in MASQUE_CIDRS_V6 {
            let hosts = sample_cidr_v6(c, per, MASQUE_CIDRS_V4);
            pool_v6.extend(hosts);
        }
    }

    // ── Port priority: dedup while preserving priority order from MASQUE_PORTS ──
    let dedup_ports: Vec<u16> = {
        let mut sp = HashSet::new();
        ports.iter().copied().filter(|&p| sp.insert(p)).collect()
    };
    
    // Seeds get highest priority — probe them on the primary port (443) first
    if ip.want_v4() {
        for a in &seeds {
            for &p in &dedup_ports {
                if seen.insert((IpAddr::V4(*a), p)) {
                    seeds_out.push((IpAddr::V4(*a), p));
                }
            }
        }
    }
    if ip.want_v6() {
        for a in &seeds6 {
            for &p in &dedup_ports {
                if seen.insert((IpAddr::V6(*a), p)) {
                    seeds_out.push((IpAddr::V6(*a), p));
                }
            }
        }
    }

    // Pool candidates: port-priority ordering — for each IP, probe primary port first
    for a in pool_v4 {
        for &p in &dedup_ports {
            if seen.insert((IpAddr::V4(a), p)) {
                pool_out.push((IpAddr::V4(a), p));
            }
        }
    }
    for a in pool_v6 {
        for &p in &dedup_ports {
            if seen.insert((IpAddr::V6(a), p)) {
                pool_out.push((IpAddr::V6(a), p));
            }
        }
    }

    // Shuffle seeds among themselves; pool stays in weighted-CIDR then port-priority order
    seeds_out.shuffle(&mut rng);

    seeds_out.extend(pool_out);
    seeds_out
}

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
