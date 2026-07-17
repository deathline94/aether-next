use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::stream::StreamExt;
use rand::Rng;

use crate::error::{AetherError, Result};
use crate::noize::NoizeConfig;
use crate::quic;
use crate::scan::HuntStrategy;

// Re-export unified ScanMode for existing call sites.
pub use crate::scan::ScanMode;

// MASQUE CONNECT-IP edges live in 162.159.19x — NOT general CF CDN / WG anycast
// (188.114.x accepts TLS but returns connect-ip 400).
pub const MASQUE_CIDRS_V4: &[&str] = &[
    "162.159.192.0/24",
    "162.159.193.0/24",
    "162.159.195.0/24",
    "162.159.196.0/24",
    "162.159.197.0/24",
    "162.159.198.0/24",
];

// Prefer diverse / known-good edges first; DNS discovery appends live A records.
pub const MASQUE_SEEDS: &[&str] = &[
    "162.159.198.1",
    "162.159.198.2",
    "162.159.192.1",
    "162.159.192.2",
    "162.159.193.1",
    "162.159.193.2",
    "162.159.195.1",
    "162.159.195.2",
    "162.159.196.1",
    "162.159.196.2",
    "162.159.197.1",
];

pub const MASQUE_PORTS: &[u16] = &[443];

/// Only hosts that resolve into WARP client / MASQUE ranges. General CDN names
/// pollute the pool with edges that TLS-handshake but reject CONNECT-IP.
pub const MASQUE_DISCOVERY_HOSTS: &[&str] = &[
    "engage.cloudflareclient.com",
];

pub const MASQUE_CIDRS_V6: &[&str] = &["2606:4700:d0::/48", "2606:4700:d1::/48"];

pub const MASQUE_SEEDS_V6: &[&str] = &[
    "2606:4700:d0::a29f:c602",
    "2606:4700:d1::a29f:c602",
    "2606:4700:d0::a29f:c601",
    "2606:4700:d0::a29f:c001",
    "2606:4700:d0::a29f:c001",
];

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
}

pub async fn host_has_ipv6() -> bool {
    match tokio::net::UdpSocket::bind("[::]:0").await {
        Ok(sock) => sock.connect("[2606:4700:d0::a29f:c001]:443").await.is_ok(),
        Err(_) => false,
    }
}

pub async fn hunt_best_gateway(probe: &MasqueProbe, mode: ScanMode) -> Result<ProbeResult> {
    let st = mode.masque_strategy();
    let hard = st.overall_deadline + Duration::from_secs(5);
    match tokio::time::timeout(hard, hunt_best_gateway_inner(probe, mode)).await {
        Ok(r) => r,
        Err(_) => {
            log::warn!(
                "[-] masque scan hard-timeout after {:?} — giving up cleanly",
                hard
            );
            Err(AetherError::NoCleanEndpoint)
        }
    }
}

async fn hunt_best_gateway_inner(probe: &MasqueProbe, mode: ScanMode) -> Result<ProbeResult> {
    let st = mode.masque_strategy();
    let timeout = st.per_probe_timeout;
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

    let cache_kind = if crate::masque_h2::enabled() {
        "masque-h2"
    } else {
        "masque-h3"
    };
    if let Some(warm) = crate::endpoint_cache::load(cache_kind) {
        if (warm.is_ipv4() && effective_ip.want_v4())
            || (warm.is_ipv6() && effective_ip.want_v6())
        {
            log::info!("[*] trying warm MASQUE endpoint {warm}");
            if let Some(pr) = verify_one(probe, warm.ip(), warm.port(), timeout).await {
                crate::endpoint_cache::save(cache_kind, SocketAddr::new(pr.ip, pr.port));
                return Ok(pr);
            }
            log::info!("[-] warm endpoint missed; full scan");
        }
    }

    let dns_seeds = resolve_discovery_seeds(effective_ip).await;
    if !dns_seeds.is_empty() {
        log::info!(
            "[+] discovery DNS added {} extra edge IP(s)",
            dns_seeds.len()
        );
    }
    let candidates = build_candidates(&st, &probe.ports, effective_ip, &dns_seeds);

    log::info!(
        "[*] scan mode={} ip={} candidates={} ports={:?} concurrency={} per_probe={:?} budget={:?} transport={}",
        mode.label(),
        effective_ip.label(),
        candidates.len(),
        probe.ports,
        st.concurrency,
        st.per_probe_timeout,
        st.overall_deadline,
        if crate::masque_h2::enabled() { "h2" } else { "h3" },
    );

    let stream = futures::stream::iter(
        candidates
            .into_iter()
            .map(|(ip, port)| verify_one(probe, ip, port, timeout)),
    )
    .buffer_unordered(st.concurrency);
    tokio::pin!(stream);

    let deadline = Instant::now() + st.overall_deadline;
    let mut best: Option<ProbeResult> = None;
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
                log::info!("[+] masque scan budget exhausted; using best so far");
            } else {
                log::warn!("[-] scan deadline reached with no gateway");
            }
            break;
        }

        tokio::select! {
            biased;
            _ = tokio::time::sleep(remaining) => {
                if best.is_some() {
                    log::info!("[+] masque scan budget exhausted; using best so far");
                } else {
                    log::warn!("[-] scan deadline reached with no gateway");
                }
                break;
            }
            item = stream.next() => {
                match item {
                    None => break,
                    Some(None) => continue,
                    Some(Some(pr)) => {
                        log::info!("[+] candidate ok {}:{} rtt={:?}", pr.ip, pr.port, pr.rtt);
                        if st.early_exit_first {
                            crate::endpoint_cache::save(cache_kind, SocketAddr::new(pr.ip, pr.port));
                            return Ok(pr);
                        }
                        best = Some(match best {
                            Some(cur) if cur.rtt <= pr.rtt => cur,
                            _ => pr,
                        });
                        found += 1;

                        if st.target_successes > 0 && found >= st.target_successes {
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

    match best {
        Some(pr) => {
            log::info!("[+] best gateway {}:{} rtt={:?}", pr.ip, pr.port, pr.rtt);
            crate::endpoint_cache::save(cache_kind, SocketAddr::new(pr.ip, pr.port));
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
) -> Option<ProbeResult> {
    if crate::masque_h2::enabled() {
        let cfg = crate::masque_h2::H2TunnelConfig {
            peer: SocketAddr::new(ip, port),
            sni: probe.sni.clone(),
            authority: probe.authority.clone(),
            path: probe.path.clone(),
            cert_pem: probe.cert_pem.to_vec(),
            key_pem: probe.key_pem.to_vec(),
        };
        return match crate::masque_h2::verify_h2(&cfg, timeout).await {
            Ok(rtt) => Some(ProbeResult { ip, port, rtt }),
            Err(e) => {
                log::debug!("h2 probe {ip}:{port} -> {e}");
                None
            }
        };
    }

    // Try with configured noize first; if that fails, retry clean (noize off).
    // Many paths accept plain QUIC while junk-before-handshake breaks Initial.
    let attempts: Vec<crate::noize::NoizeConfig> = if probe.noize.is_enabled() {
        vec![probe.noize.clone(), crate::noize::NoizeConfig::off()]
    } else {
        vec![crate::noize::NoizeConfig::off()]
    };

    for (i, noize) in attempts.into_iter().enumerate() {
        let vp = quic::VerifyParams {
            peer: SocketAddr::new(ip, port),
            sni: probe.sni.clone(),
            authority: probe.authority.clone(),
            path: probe.path.clone(),
            cert_pem: probe.cert_pem.to_vec(),
            key_pem: probe.key_pem.to_vec(),
            ech_config_list: probe.ech_config_list.as_ref().map(|a| a.to_vec()),
            noize,
            timeout,
        };
        match quic::verify_masque(&vp).await {
            Ok(rtt) => {
                if i > 0 {
                    log::info!(
                        "[+] h3 probe {ip}:{port} succeeded without noize (rtt {:?})",
                        rtt
                    );
                }
                return Some(ProbeResult { ip, port, rtt });
            }
            Err(e) => {
                log::debug!("h3 probe {ip}:{port} attempt{} -> {e}", i + 1);
            }
        }
    }
    None
}

fn is_masque_range(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            // 162.159.192-198.x
            o[0] == 162 && o[1] == 159 && (192..=198).contains(&o[2])
        }
        IpAddr::V6(v6) => {
            // 2606:4700:d0::/44-ish WARP MASQUE
            let s = v6.segments();
            s[0] == 0x2606 && s[1] == 0x4700 && (s[2] == 0xd0 || s[2] == 0xd1)
        }
    }
}

async fn resolve_discovery_seeds(ip: IpScan) -> Vec<IpAddr> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for host in MASQUE_DISCOVERY_HOSTS {
        match tokio::net::lookup_host((*host, 443)).await {
            Ok(iter) => {
                for sa in iter {
                    let addr = sa.ip();
                    if !is_masque_range(addr) {
                        log::debug!("discovery skip non-masque {addr} from {host}");
                        continue;
                    }
                    if (addr.is_ipv4() && ip.want_v4()) || (addr.is_ipv6() && ip.want_v6()) {
                        if seen.insert(addr) {
                            out.push(addr);
                        }
                    }
                }
            }
            Err(e) => log::debug!("discovery DNS {host}: {e}"),
        }
    }
    out
}

fn build_candidates(
    st: &HuntStrategy,
    ports: &[u16],
    ip: IpScan,
    dns_seeds: &[IpAddr],
) -> Vec<(IpAddr, u16)> {
    let primary = ports.first().copied().unwrap_or(443);
    let mut out: Vec<(IpAddr, u16)> = Vec::new();
    let mut seen: HashSet<(IpAddr, u16)> = HashSet::new();

    let seeds: Vec<Ipv4Addr> = MASQUE_SEEDS.iter().filter_map(|s| s.parse().ok()).collect();
    let seeds6: Vec<Ipv6Addr> = MASQUE_SEEDS_V6.iter().filter_map(|s| s.parse().ok()).collect();

    // Live DNS first — often lowest-latency anycast for this network.
    for a in dns_seeds {
        if seen.insert((*a, primary)) {
            out.push((*a, primary));
        }
    }

    if ip.want_v4() {
        for a in &seeds {
            if seen.insert((IpAddr::V4(*a), primary)) {
                out.push((IpAddr::V4(*a), primary));
            }
        }
        let cidr_hosts: Vec<Vec<Ipv4Addr>> = MASQUE_CIDRS_V4
            .iter()
            .map(|c| {
                if st.full_subnet {
                    enumerate_cidr_v4(c)
                } else {
                    sample_cidr_v4(c, st.sample_per_cidr)
                }
            })
            .collect();
        let max_len = cidr_hosts.iter().map(|v| v.len()).max().unwrap_or(0);
        for i in 0..max_len {
            for hosts in &cidr_hosts {
                if let Some(a) = hosts.get(i) {
                    if seen.insert((IpAddr::V4(*a), primary)) {
                        out.push((IpAddr::V4(*a), primary));
                    }
                }
            }
        }
    }

    if ip.want_v6() {
        for a in &seeds6 {
            if seen.insert((IpAddr::V6(*a), primary)) {
                out.push((IpAddr::V6(*a), primary));
            }
        }
        let per = if st.sample_per_cidr == 0 { 96 } else { st.sample_per_cidr };
        let cidr6: Vec<Vec<Ipv6Addr>> = MASQUE_CIDRS_V6
            .iter()
            .map(|c| sample_cidr_v6(c, per, MASQUE_CIDRS_V4))
            .collect();
        let max6 = cidr6.iter().map(|v| v.len()).max().unwrap_or(0);
        for i in 0..max6 {
            for hosts in &cidr6 {
                if let Some(a) = hosts.get(i) {
                    if seen.insert((IpAddr::V6(*a), primary)) {
                        out.push((IpAddr::V6(*a), primary));
                    }
                }
            }
        }
    }

    if ip.want_v4() {
        for a in &seeds {
            for &port in ports {
                if port != primary && seen.insert((IpAddr::V4(*a), port)) {
                    out.push((IpAddr::V4(*a), port));
                }
            }
        }
    }
    if ip.want_v6() {
        for a in &seeds6 {
            for &port in ports {
                if port != primary && seen.insert((IpAddr::V6(*a), port)) {
                    out.push((IpAddr::V6(*a), port));
                }
            }
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
