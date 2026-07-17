use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::stream::StreamExt;
use rand::Rng;

use crate::aethernoize::AetherNoizeConfig;
use crate::error::{AetherError, Result};
use crate::prober::IpScan;
use crate::scan::{HuntStrategy, ScanMode};
use crate::wireguard;

// Unified scan mode (alias for call-site clarity).
pub type WgScanMode = ScanMode;

#[derive(Debug, Clone, Copy)]
pub struct WgProbeResult {
    pub ip: IpAddr,
    pub port: u16,
    pub rtt: Duration,
}

#[derive(Clone)]
pub struct WgProbe {
    pub private_key: Arc<[u8; 32]>,
    pub peer_public_key: Arc<[u8; 32]>,
    pub client_id: [u8; 3],
    pub local_ipv4: Ipv4Addr,
    pub aethernoize: AetherNoizeConfig,
    pub ports: Vec<u16>,
    pub ip: IpScan,
}

pub async fn hunt_best_wg_endpoint(probe: &WgProbe, mode: ScanMode) -> Result<WgProbeResult> {
    let st = mode.wg_strategy();
    // Hard wall-clock so hung probes can never strand the session.
    let hard = st.overall_deadline + Duration::from_secs(3);
    match tokio::time::timeout(hard, hunt_best_wg_endpoint_inner(probe, mode)).await {
        Ok(r) => r,
        Err(_) => {
            log::warn!(
                "[-] wireguard scan hard-timeout after {:?} — giving up cleanly",
                hard
            );
            Err(AetherError::NoCleanEndpoint)
        }
    }
}

async fn hunt_best_wg_endpoint_inner(probe: &WgProbe, mode: ScanMode) -> Result<WgProbeResult> {
    let st = mode.wg_strategy();
    let timeout = st.per_probe_timeout;
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

    // Warm path first.
    if let Some(warm) = crate::endpoint_cache::load("wg") {
        if (warm.is_ipv4() && effective_ip.want_v4())
            || (warm.is_ipv6() && effective_ip.want_v6())
        {
            log::info!("[*] trying warm WireGuard endpoint {warm}");
            if let Some(pr) = verify_one_wg(probe, warm.ip(), warm.port(), timeout).await {
                crate::endpoint_cache::save("wg", SocketAddr::new(pr.ip, pr.port));
                return Ok(pr);
            }
            log::info!("[-] warm endpoint missed; full scan");
        }
    }

    let candidates = build_wg_candidates(&st, &probe.ports, effective_ip, mode);

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

    let stream = futures::stream::iter(
        candidates
            .into_iter()
            .map(|(ip, port)| verify_one_wg(probe, ip, port, timeout)),
    )
    .buffer_unordered(st.concurrency);
    tokio::pin!(stream);

    let deadline = Instant::now() + st.overall_deadline;
    let mut best: Option<WgProbeResult> = None;
    let mut found = 0usize;
    let mut quiet_until: Option<Instant> = None;

    loop {
        let effective = match quiet_until {
            Some(q) => q.min(deadline),
            None => deadline,
        };
        let remaining = effective.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            if best.is_some() {
                log::info!("[+] wireguard scan budget exhausted; using best so far");
            } else {
                log::warn!("[-] scan deadline reached with no endpoint");
            }
            break;
        }

        tokio::select! {
            biased;
            _ = tokio::time::sleep(remaining) => {
                if best.is_some() {
                    log::info!("[+] wireguard scan budget exhausted; using best so far");
                } else {
                    log::warn!("[-] scan deadline reached with no endpoint");
                }
                break;
            }
            item = stream.next() => {
                match item {
                    None => break,
                    Some(None) => continue,
                    Some(Some(pr)) => {
                        log::info!("[+] wg candidate ok {}:{} rtt={:?}", pr.ip, pr.port, pr.rtt);
                        if st.early_exit_first {
                            crate::endpoint_cache::save("wg", SocketAddr::new(pr.ip, pr.port));
                            return Ok(pr);
                        }
                        best = Some(match best {
                            Some(cur) if cur.rtt <= pr.rtt => cur,
                            _ => pr,
                        });
                        found += 1;

                        if st.target_successes > 0 && found >= st.target_successes {
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

    match best {
        Some(pr) => {
            log::info!("[+] best wg endpoint {}:{} rtt={:?}", pr.ip, pr.port, pr.rtt);
            crate::endpoint_cache::save("wg", SocketAddr::new(pr.ip, pr.port));
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
) -> Option<WgProbeResult> {
    let peer = SocketAddr::new(ip, port);

    match wireguard::verify_endpoint(
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
        Ok(rtt) => Some(WgProbeResult { ip, port, rtt }),
        Err(e) => {
            log::debug!("wg probe {ip}:{port} -> {e}");
            None
        }
    }
}

/// Priority WARP ports first — 2408 is the classic engage port.
const WG_PRIORITY_PORTS: &[u16] = &[2408, 500, 4500, 1701, 878, 880, 890, 854, 864];

fn build_wg_candidates(
    st: &HuntStrategy,
    ports: &[u16],
    ip: IpScan,
    mode: ScanMode,
) -> Vec<(IpAddr, u16)> {
    // Turbo: only high-value ports to finish quickly.
    let ports: Vec<u16> = if matches!(mode, ScanMode::Turbo) {
        let mut out = WG_PRIORITY_PORTS.to_vec();
        for p in ports {
            if !out.contains(p) && out.len() < 16 {
                out.push(*p);
            }
        }
        out
    } else {
        let mut seen_port: HashSet<u16> = HashSet::new();
        let mut deduped: Vec<u16> = WG_PRIORITY_PORTS
            .iter()
            .copied()
            .chain(ports.iter().copied())
            .filter(|p| seen_port.insert(*p))
            .collect();
        if deduped.is_empty() {
            deduped = vec![2408];
        }
        deduped
    };

    let mut anchors: Vec<IpAddr> = Vec::new();
    let mut pool: Vec<IpAddr> = Vec::new();

    if ip.want_v4() {
        for s in wireguard::WG_SEEDS_V4 {
            if let Ok(a) = s.parse::<Ipv4Addr>() {
                anchors.push(IpAddr::V4(a));
            }
        }
        // DNS warm seeds for engage-style edges.
        // (lookup is sync-free; call sites can also cache via endpoint_cache)
        let sample = if matches!(mode, ScanMode::Turbo) {
            st.sample_per_cidr.min(16)
        } else {
            st.sample_per_cidr
        };
        let cidr_hosts: Vec<Vec<Ipv4Addr>> = wireguard::WG_PREFIXES_V4
            .iter()
            .map(|c| {
                if st.full_subnet {
                    enumerate_cidr_v4(c)
                } else {
                    sample_cidr_v4(c, sample)
                }
            })
            .collect();
        let max_len = cidr_hosts.iter().map(|v| v.len()).max().unwrap_or(0);
        for i in 0..max_len {
            for hosts in &cidr_hosts {
                if let Some(a) = hosts.get(i) {
                    pool.push(IpAddr::V4(*a));
                }
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
        let cidr6: Vec<Vec<Ipv6Addr>> = wireguard::WG_PREFIXES_V6
            .iter()
            .map(|c| sample_cidr_v6(c, per, wireguard::WG_PREFIXES_V4))
            .collect();
        let max6 = cidr6.iter().map(|v| v.len()).max().unwrap_or(0);
        for i in 0..max6 {
            for hosts in &cidr6 {
                if let Some(a) = hosts.get(i) {
                    pool.push(IpAddr::V6(*a));
                }
            }
        }
    }

    let mut ips: Vec<IpAddr> = Vec::with_capacity(anchors.len() + pool.len());
    ips.extend(anchors.iter().copied());
    ips.extend(pool.iter().copied());

    let mut out: Vec<(IpAddr, u16)> = Vec::new();
    let mut seen: HashSet<(IpAddr, u16)> = HashSet::new();

    // Phase 1: every anchor × priority ports (highest hit rate).
    for a in &anchors {
        for &port in &ports {
            if seen.insert((*a, port)) {
                out.push((*a, port));
            }
        }
    }
    // Phase 2: pool IPs with round-robin ports (capped hard for turbo so hunts always end).
    let cap = if matches!(mode, ScanMode::Turbo) {
        48
    } else if matches!(mode, ScanMode::Balanced) {
        280
    } else {
        800
    };
    for (idx, a) in ips.iter().enumerate() {
        if out.len() >= cap {
            break;
        }
        let port = ports[idx % ports.len()];
        if seen.insert((*a, port)) {
            out.push((*a, port));
        }
    }

    out
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
