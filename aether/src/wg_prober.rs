use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::stream::StreamExt;
use rand::Rng;

#[allow(unused_imports)]
use crate::aethernoize::AetherNoizeConfig;

use crate::error::{AetherError, Result};
use crate::prober::IpScan;
use crate::wireguard;

#[derive(Debug, Clone, Copy)]
pub struct WgProbeResult {
    pub ip: IpAddr,
    pub port: u16,
    pub rtt: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WgScanMode {
    Turbo,
    Balanced,
    Thorough,
    Stealth,
    Ironclad,
}

impl WgScanMode {
    pub fn parse(s: &str) -> WgScanMode {
        match s.trim().to_lowercase().as_str() {
            "turbo" | "fast" => WgScanMode::Turbo,
            "thorough" | "deep" | "pro" | "thorogh" => WgScanMode::Thorough,
            "stealth" | "quiet" => WgScanMode::Stealth,
            "ironclad" | "real" | "verify" | "guaranteed" => WgScanMode::Ironclad,
            _ => WgScanMode::Balanced,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            WgScanMode::Turbo => "turbo",
            WgScanMode::Balanced => "balanced",
            WgScanMode::Thorough => "thorough",
            WgScanMode::Stealth => "stealth",
            WgScanMode::Ironclad => "ironclad",
        }
    }

    fn strategy(&self) -> WgStrategy {
        match self {
            WgScanMode::Turbo => WgStrategy {
                concurrency: 12,
                per_probe_timeout: Duration::from_millis(5000),
                overall_deadline: Duration::from_secs(30),
                quiet_after_first: Duration::from_secs(0),
                target_successes: 1,
                early_exit_first: true,
                full_subnet: false,
                sample_per_cidr: 40,
            },
            WgScanMode::Balanced => WgStrategy {
                concurrency: 8,
                per_probe_timeout: Duration::from_millis(7000),
                overall_deadline: Duration::from_secs(80),
                quiet_after_first: Duration::from_secs(12),
                target_successes: 5,
                early_exit_first: false,
                full_subnet: false,
                sample_per_cidr: 120,
            },
            WgScanMode::Thorough => WgStrategy {
                concurrency: 10,
                per_probe_timeout: Duration::from_millis(9000),
                overall_deadline: Duration::from_secs(250),
                quiet_after_first: Duration::from_secs(25),
                target_successes: 0,
                early_exit_first: false,
                full_subnet: true,
                sample_per_cidr: 0,
            },
            WgScanMode::Stealth => WgStrategy {
                concurrency: 3,
                per_probe_timeout: Duration::from_millis(10000),
                overall_deadline: Duration::from_secs(150),
                quiet_after_first: Duration::from_secs(20),
                target_successes: 3,
                early_exit_first: false,
                full_subnet: false,
                sample_per_cidr: 50,
            },
            WgScanMode::Ironclad => WgStrategy {
                concurrency: 4,
                per_probe_timeout: Duration::from_millis(15000),
                overall_deadline: Duration::from_secs(180),
                quiet_after_first: Duration::from_secs(15),
                target_successes: 3,
                early_exit_first: false,
                full_subnet: false,
                sample_per_cidr: 120,
            },
        }
    }
}

const WG_IRONCLAD_TCPING_TIMEOUT: Duration = Duration::from_secs(10);

struct WgStrategy {
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
pub struct WgProbe {
    pub private_key: Arc<[u8; 32]>,
    pub peer_public_key: Arc<[u8; 32]>,
    pub client_id: [u8; 3],
    pub local_ipv4: std::net::Ipv4Addr,
    pub ports: Vec<u16>,
    pub ip: IpScan,
    pub aethernoize: crate::aethernoize::AetherNoizeConfig,
    pub config_path: String,
}

pub async fn hunt_best_wg_endpoint(probe: &WgProbe, mode: WgScanMode) -> Result<WgProbeResult> {
    let st = mode.strategy();
    let timeout = st.per_probe_timeout;
    let ironclad = mode == WgScanMode::Ironclad;

    // 1. Try cached endpoints first
    let cached = crate::cache::get_wireguard(&probe.config_path);
    if !cached.is_empty() {
        log::info!("[*] probing {} cached wg endpoints...", cached.len());
        let stream = futures::stream::iter(
            cached.into_iter().map(|addr| verify_one_wg(probe, addr.ip(), addr.port(), timeout, ironclad))
        ).buffer_unordered(st.concurrency);
        tokio::pin!(stream);

        let mut best: Option<WgProbeResult> = None;
        while let Some(res) = stream.next().await {
            if let Some(pr) = res {
                log::info!("[+] cached wg candidate ok {}:{} rtt={:?}", pr.ip, pr.port, pr.rtt);
                best = Some(match best {
                    Some(cur) if cur.rtt <= pr.rtt => cur,
                    _ => pr,
                });
            }
        }
        if let Some(pr) = best {
            log::info!("[+] using best cached wg endpoint {}:{} rtt={:?}", pr.ip, pr.port, pr.rtt);
            crate::cache::add_to_wireguard(&probe.config_path, vec![SocketAddr::new(pr.ip, pr.port)]);
            return Ok(pr);
        }
        log::info!("[-] cached wg endpoints failed, falling back to full scan");
    }

    let mut effective_ip = probe.ip;
    if probe.ip.want_v6() && !crate::prober::host_has_ipv6().await {
        if probe.ip.want_v4() {
            log::warn!("[-] host has no IPv6 route; falling back to IPv4-only scan");
            effective_ip = IpScan::V4;
        } else {
            log::warn!("[-] host has no IPv6 route; IPv6 scan needs native IPv6 connectivity");
            return Err(AetherError::NoCleanEndpoint);
        }
    }
    let candidates = build_wg_candidates(&st, &probe.ports, effective_ip);

    log::info!(
        "[*] wireguard scan mode={} ip={} candidates={} ports={:?} concurrency={} per_probe={:?} budget={:?}",
        mode.label(),
        effective_ip.label(),
        candidates.len(),
        probe.ports,
        st.concurrency,
        st.per_probe_timeout,
        st.overall_deadline,
    );

    let ironclad = mode == WgScanMode::Ironclad;

    let total_candidates = candidates.len();
    let stream = futures::stream::iter(
        candidates
            .into_iter()
            .map(|(ip, port)| verify_one_wg(probe, ip, port, timeout, ironclad)),
    )
    .buffer_unordered(st.concurrency);
    tokio::pin!(stream);

    let deadline = Instant::now() + st.overall_deadline;
    let mut best: Option<WgProbeResult> = None;
    let mut found = 0usize;
    let mut scanned = 0usize;
    let mut quiet_until: Option<Instant> = None;
    let mut hot_subnets = std::collections::HashSet::<u128>::new();

    loop {
        let effective = match quiet_until {
            Some(q) => q.min(deadline),
            None => deadline,
        };
        let remaining = effective.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            if best.is_some() {
                if quiet_until.is_some() {
                    log::info!("[+] no new endpoints recently, finalizing selection");
                } else {
                    log::info!("[-] scan deadline reached, finalizing selection");
                }
            } else {
                log::error!("[-] scan deadline reached with no endpoint");
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
                            log::info!("[*] wg scanning... {}/{} ips, found {} working", scanned, total_candidates, found);
                        }
                        
                        match res {
                            None => continue,
                            Some(pr) => {
                                log::info!("[+] wg candidate ok {}:{} rtt={:?}", pr.ip, pr.port, pr.rtt);
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
                                    log::info!("[🔥] Hot wg subnet detected near {}! Launching Stage-2 subnet drill-down...", pr.ip);
                                    let hot_hits = drill_down_hot_subnet_wg(probe, pr.ip, pr.port, timeout, ironclad, st.concurrency).await;
                                    for h_pr in hot_hits {
                                        log::info!("[🔥] Hot wg subnet candidate ok {}:{} rtt={:?}", h_pr.ip, h_pr.port, h_pr.rtt);
                                        best = Some(match best {
                                            Some(cur) if cur.rtt <= h_pr.rtt => cur,
                                            _ => h_pr,
                                        });
                                        found += 1;
                                    }
                                }

                                if st.early_exit_first {
                                    let final_best = best.unwrap_or(pr);
                                    crate::cache::add_to_wireguard(&probe.config_path, vec![SocketAddr::new(final_best.ip, final_best.port)]);
                                    return Ok(final_best);
                                }

                                if st.target_successes > 0 && found >= st.target_successes && quiet_until.is_none() {
                                    log::info!("[+] reached target of {} endpoints, selecting best", st.target_successes);
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
                        log::info!("[+] no new endpoints recently, finalizing selection");
                    } else {
                        log::warn!("[-] scan deadline reached");
                    }
                } else {
                    log::warn!("[-] scan deadline reached with no endpoint");
                }
                break;
            }
        }
    }

    match best {
        Some(pr) => {
            log::info!("[+] best wg endpoint {}:{} rtt={:?}", pr.ip, pr.port, pr.rtt);
            crate::cache::add_to_wireguard(&probe.config_path, vec![SocketAddr::new(pr.ip, pr.port)]);
            Ok(pr)
        }
        None => Err(AetherError::NoCleanEndpoint),
    }
}

async fn verify_one_wg(
    probe: &WgProbe,
    ip: IpAddr,
    port: u16,
    timeout: Duration,
    ironclad: bool,
) -> Option<WgProbeResult> {
    let peer = SocketAddr::new(ip, port);

    let (rtt, session) = match wireguard::verify_endpoint_keep_session(
        peer,
        *probe.private_key,
        *probe.peer_public_key,
        probe.client_id,
        probe.local_ipv4,
        &probe.aethernoize,
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
        return Some(WgProbeResult { ip, port, rtt });
    }

    let params = crate::tunnelping::WgPingParams {
        local_ipv4: probe.local_ipv4,
        local_ipv6: "::1".parse().unwrap(),
        aethernoize: probe.aethernoize.clone(),
    };
    match crate::tunnelping::wg_http_ping_established(session, &params, WG_IRONCLAD_TCPING_TIMEOUT).await {
        Ok(http_rtt) => {
            log::info!(
                "[+] ironclad verified wg {ip}:{port} real http round trip rtt={:?}",
                http_rtt
            );
            Some(WgProbeResult { ip, port, rtt: http_rtt })
        }
        Err(e) => {
            log::debug!("[-] ironclad wg {ip}:{port} failed real http check: {e}");
            None
        }
    }
}

async fn drill_down_hot_subnet_wg(
    probe: &WgProbe,
    ip: IpAddr,
    port: u16,
    timeout: Duration,
    ironclad: bool,
    concurrency: usize,
) -> Vec<WgProbeResult> {
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
            .map(|(nip, nport)| verify_one_wg(probe, nip, nport, timeout, ironclad)),
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

fn build_wg_candidates(st: &WgStrategy, ports: &[u16], ip: IpScan) -> Vec<(IpAddr, u16)> {
    use rand::seq::SliceRandom;
    let mut rng = rand::thread_rng();

    let dedup_ports: Vec<u16> = {
        let mut seen_port: HashSet<u16> = HashSet::new();
        let deduped: Vec<u16> = ports.iter().copied().filter(|p| seen_port.insert(*p)).collect();
        if deduped.is_empty() {
            vec![2408]
        } else {
            deduped
        }
    };

    let mut anchors: Vec<IpAddr> = Vec::new();
    let mut pool: Vec<IpAddr> = Vec::new();

    if ip.want_v4() {
        for s in wireguard::WG_SEEDS_V4 {
            if let Ok(a) = s.parse::<Ipv4Addr>() {
                anchors.push(IpAddr::V4(a));
            }
        }
        for c in wireguard::WG_PREFIXES_V4 {
            let hosts = if st.full_subnet {
                enumerate_cidr_v4(c)
            } else {
                sample_cidr_v4(c, st.sample_per_cidr)
            };
            for a in hosts {
                pool.push(IpAddr::V4(a));
            }
        }
    }

    if ip.want_v6() {
        for s in wireguard::WG_SEEDS_V6 {
            if let Ok(a) = s.parse::<Ipv6Addr>() {
                anchors.push(IpAddr::V6(a));
            }
        }
        let per = if st.sample_per_cidr == 0 { 80 } else { st.sample_per_cidr };
        for c in wireguard::WG_PREFIXES_V6 {
            let hosts = sample_cidr_v6(c, per, wireguard::WG_PREFIXES_V4);
            for a in hosts {
                pool.push(IpAddr::V6(a));
            }
        }
    }

    let mut seen: HashSet<(IpAddr, u16)> = HashSet::new();
    let mut anchors_out: Vec<(IpAddr, u16)> = Vec::new();
    let mut pool_out: Vec<(IpAddr, u16)> = Vec::new();

    for a in anchors {
        for &p in &dedup_ports {
            if seen.insert((a, p)) {
                anchors_out.push((a, p));
            }
        }
    }

    for a in pool {
        for &p in &dedup_ports {
            if seen.insert((a, p)) {
                pool_out.push((a, p));
            }
        }
    }

    anchors_out.shuffle(&mut rng);
    pool_out.shuffle(&mut rng);

    anchors_out.extend(pool_out);
    anchors_out
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
