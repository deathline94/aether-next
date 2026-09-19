//! Unified endpoint prober for all transport protocols.
//!
//! A single scan engine (candidate generation, concurrent probing, hot-subnet
//! drill-down, tier-0 cache, deadline management) parameterized over:
//! - A [`ProbeConfig`] describing the IP pools, weights, seeds, and cache slot.
//! - A verify closure that performs the transport-specific handshake.

use std::collections::{HashMap, HashSet};
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

/// How expensive a single verify probe is. QUIC/H3 verification runs a full
/// handshake + CONNECT-IP + data-plane round-trip and builds a BoringSSL context
/// per probe, so it needs a longer timeout and a hard concurrency ceiling; TCP/H2
/// and WireGuard handshakes are comparatively cheap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyCost {
    Cheap,
    Expensive,
}

/// Per-probe budget floors/ceilings for expensive (QUIC/BoringSSL) verification.
const EXPENSIVE_MIN_TIMEOUT: Duration = Duration::from_millis(6000);
const EXPENSIVE_DEFAULT_CONCURRENCY: usize = 8;
const EXPENSIVE_MAX_CONCURRENCY: usize = 16;

/// Static configuration describing the IP pool and cache behavior for a scan.
pub struct ProbeConfig {
    /// Cost of one verify probe; drives concurrency/timeout tuning below.
    pub verify_cost: VerifyCost,
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

#[allow(dead_code)]
impl ProbeConfig {
    pub fn for_test() -> Self {
        Self {
            verify_cost: VerifyCost::Cheap,
            cidrs_v4: &["10.0.0.0/24"],
            cidrs_v6: &[],
            cidr_weights_v4: &[("10.0.0.0/24", 1)],
            seeds_v4: &["10.0.0.1", "10.0.0.2"],
            seeds_v6: &[],
            cache_kind: CacheKind::Masque,
            label: "test",
            config_path: String::new(),
            profile: StrategyProfile {
                turbo_sample: 2,
                balanced_target: 1,
                balanced_sample: 2,
                stealth_target: 1,
                stealth_sample: 2,
            },
        }
    }
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
    let sock = match tokio::net::UdpSocket::bind("[::]:0").await {
        Ok(s) => s,
        Err(_) => return false, // no IPv6 stack at all
    };
    // UDP connect() only performs a route lookup (no packet is sent), so this
    // tests "is there a route to a global v6 address", not reachability of one
    // specific host. Try more than one target so a single withdrawn prefix does
    // not produce a false negative.
    for target in ["[2606:4700:d0::a29f:c001]:443", "[2001:4860:4860::8888]:443"] {
        if sock.connect(target).await.is_ok() {
            return true;
        }
    }
    false
}

/// Emit a structured scan hit event so the GUI standalone scanner can list
/// every working endpoint (not just the final best). Protocol is derived from
/// the probe label + current MASQUE transport.
fn emit_scan_hit(label: &str, ip: IpAddr, port: u16, rtt: Duration) {
    let protocol = if label.contains("wg") {
        "WireGuard"
    } else if crate::masque_h2::enabled() {
        "MASQUE H2"
    } else {
        "MASQUE H3"
    };
    crate::session_event::emit(crate::session_event::SessionEvent::ScanHit {
        addr: format!("{ip}:{port}"),
        rtt: format!("{}ms", rtt.as_millis()),
        rtt_ms: rtt.as_secs_f64() * 1000.0,
        protocol: protocol.to_string(),
    });
}

/// Run the unified endpoint hunt: tier-0 cache → candidate generation → concurrent
/// probing with hot-subnet drill-down → deadline/quiet-period management.
/// Cooperative scan cancellation. `hunt_best` checks this each iteration and
/// stops gracefully (returning the best endpoint found so far), so a scan can be
/// Cooperative scan cancellation. `hunt_best` checks this each iteration and
/// stops gracefully (returning the best endpoint found so far), so a scan can be
/// stopped without killing the process mid-work. Wire `request_scan_cancel` to a
/// Ctrl-C / SIGTERM handler or an IPC "stop" command.
use tokio_util::sync::CancellationToken;

#[derive(Clone, Default)]
#[allow(dead_code)]
pub struct ScanCancellationToken {
    inner: CancellationToken,
}

#[allow(dead_code)]
impl ScanCancellationToken {
    pub fn new() -> Self {
        Self {
            inner: CancellationToken::new(),
        }
    }

    pub fn cancel(&self) {
        self.inner.cancel();
    }

    pub fn is_cancelled(&self) -> bool {
        self.inner.is_cancelled()
    }

    pub fn child_token(&self) -> CancellationToken {
        self.inner.child_token()
    }

    pub async fn cancelled(&self) {
        self.inner.cancelled().await;
    }
}

pub static SCAN_GENERATION: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static SCAN_CANCEL: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static GLOBAL_CANCEL: parking_lot::RwLock<Option<CancellationToken>> = parking_lot::RwLock::new(None);

struct ScanRunGuard(#[allow(dead_code)] u64);
impl Drop for ScanRunGuard {
    fn drop(&mut self) {
        SCAN_CANCEL.store(false, std::sync::atomic::Ordering::SeqCst);
    }
}

pub fn request_scan_cancel() {
    SCAN_CANCEL.store(true, std::sync::atomic::Ordering::SeqCst);
    if let Some(token) = GLOBAL_CANCEL.read().as_ref() {
        token.cancel();
    }
}

pub fn current_cancel_token() -> CancellationToken {
    let mut w = GLOBAL_CANCEL.write();
    let token = CancellationToken::new();
    *w = Some(token.clone());
    token
}

fn scan_cancelled() -> bool {
    if SCAN_CANCEL.load(std::sync::atomic::Ordering::SeqCst) {
        return true;
    }
    if let Some(token) = GLOBAL_CANCEL.read().as_ref() {
        return token.is_cancelled();
    }
    false
}

pub async fn hunt_best(
    config: &ProbeConfig,
    ports: &[u16],
    ip: IpScan,
    mode: ScanMode,
    verify: &VerifyFn<'_>,
) -> Result<ProbeResult> {
    if SCAN_CANCEL.load(std::sync::atomic::Ordering::SeqCst) {
        SCAN_CANCEL.store(false, std::sync::atomic::Ordering::SeqCst);
        return Err(AetherError::NoCleanEndpoint);
    }
    let gen = SCAN_GENERATION.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
    let _guard = ScanRunGuard(gen);
    let cancel_token = current_cancel_token();
    let mut st = mode.strategy(&config.profile);
    // Expensive (QUIC/H3) verification needs a longer per-probe budget than the
    // fast TCP/UDP defaults, or every probe times out mid-handshake. This is the
    // BASELINE applied before user overrides so an unconfigured scan behaves well.
    if config.verify_cost == VerifyCost::Expensive {
        st.per_probe_timeout = st.per_probe_timeout.max(EXPENSIVE_MIN_TIMEOUT);
        st.concurrency = st.concurrency.min(EXPENSIVE_DEFAULT_CONCURRENCY);
    }
    // User overrides from the GUI scanner tab (AETHER_SCAN_CONCURRENCY / AETHER_SCAN_TIMEOUT_MS).
    if let Some(c) = crate::runtime_env::usize("AETHER_SCAN_CONCURRENCY") {
        st.concurrency = c.max(1);
    }
    if let Some(ms) = crate::runtime_env::usize("AETHER_SCAN_TIMEOUT_MS") {
        st.per_probe_timeout = Duration::from_millis(ms as u64);
    }
    // M4 fix: safety limits enforced AFTER env overrides, mirroring how the
    // concurrency ceiling already worked. Previously only concurrency was
    // re-clamped, so a GUI timeout of e.g. 3000ms silently pushed every H3 probe
    // BELOW its 5s handshake floor and scans failed mid-handshake everywhere.
    st.concurrency = st.concurrency.min(1000);
    if config.verify_cost == VerifyCost::Expensive {
        st.per_probe_timeout = st.per_probe_timeout.max(EXPENSIVE_MIN_TIMEOUT);
        // Hard safety ceiling for expensive verifies: many concurrent BoringSSL
        // handshakes abort the process (0xC0000409). Enforced AFTER env overrides so
        // no user/GUI setting can crash an H3 scan.
        st.concurrency = st.concurrency.min(EXPENSIVE_MAX_CONCURRENCY);
    }
    // Exhaustive mode: standalone scanner runs until stopped or pool exhausted.
    // No target_successes limit, no early exit, unbounded deadline (user stops via UI).
    let exhaustive = crate::runtime_env::flag("AETHER_SCAN_EXHAUSTIVE");
    if exhaustive {
        st.target_successes = 0;
        st.early_exit_first = false;
        st.overall_deadline = Duration::ZERO;
        st.quiet_after_first = Duration::ZERO;
    }
    let timeout = st.per_probe_timeout;
    let ironclad = mode == ScanMode::Ironclad;
    let label = config.label;

    // ── Tier-0: Ultra-fast cache RACE (first-hit-wins, parallel) ──
    // #2: Race top cached endpoints simultaneously. Return the FIRST that
    // verifies successfully instead of waiting for all to complete.
    // Skipped for the standalone scanner (exhaustive): it must enumerate the whole
    // pool and stream ScanStart/ScanHit/progress to the UI, not short-circuit to one
    // cached endpoint (which left the scanner tab stuck at 0/0 with no results).
    let cached = if exhaustive {
        Vec::new()
    } else {
        config.cache_kind.read_sorted(&config.config_path)
    };
    if !cached.is_empty() {
        // M3 fix: the tier-0 race used a hardcoded 600ms budget while expensive
        // (H3) verification needs >=5s — every cached endpoint "failed" on any
        // network with >600ms handshake time, evicting good entries and forcing
        // a pointless full scan on every connect. Race with the same per-probe
        // budget the strategy settled on (first-hit-wins is unchanged).
        let tier0_timeout = st.per_probe_timeout;
        let race_count = cached.len().min(5); // Race top-5 by trust score.
        let race_child = cancel_token.clone();
        let race_futures: Vec<_> = cached
            .into_iter()
            .take(race_count)
            .map(|(addr, _rtt)| {
                let tok = race_child.clone();
                async move {
                    tokio::select! {
                        _ = tok.cancelled() => None,
                        res = verify(addr.ip(), addr.port(), tier0_timeout, false) => res,
                    }
                }
            })
            .collect();

        // Race: return the first successful result.
        let mut set = futures::stream::FuturesUnordered::new();
        for fut in race_futures {
            set.push(fut);
        }
        use futures::StreamExt;
        loop {
            tokio::select! {
                _ = cancel_token.cancelled() => {
                    log::info!("[*] scan cancelled during Tier-0 race");
                    return Err(AetherError::NoCleanEndpoint);
                }
                res = set.next() => {
                    match res {
                        Some(Some(pr)) => {
                            log::info!("[⚡] Tier-0 race winner {}:{} rtt={:?}", pr.ip, pr.port, pr.rtt);
                            let rtt_ms = pr.rtt.as_millis() as u32;
                            config.cache_kind.write_with_rtt(&config.config_path, vec![(SocketAddr::new(pr.ip, pr.port), rtt_ms)]);
                            return Ok(pr);
                        }
                        Some(None) => continue,
                        None => break,
                    }
                }
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
    crate::session_event::emit(crate::session_event::SessionEvent::ScanStart {
        mode: mode.label().to_string(),
        total: total_candidates,
        concurrency: st.concurrency,
    });
    let cancel_child = cancel_token.clone();
    let stream = futures::stream::iter(
        candidates
            .into_iter()
            .map(|(ip, port)| {
                let tok = cancel_child.clone();
                async move {
                    tokio::select! {
                        _ = tok.cancelled() => None,
                        res = verify(ip, port, timeout, ironclad) => res,
                    }
                }
            }),
    )
    .buffer_unordered(st.concurrency);
    tokio::pin!(stream);

    let deadline: Option<Instant> = if exhaustive {
        None
    } else {
        Some(Instant::now() + st.overall_deadline)
    };
    let mut best: Option<ProbeResult> = None;
    let mut found = 0usize;
    let mut scanned = 0usize;
    let mut quiet_until: Option<Instant> = None;
    let mut hot_subnets = HashSet::<u128>::new();

    loop {
        let effective = match (quiet_until, deadline) {
            (Some(q), Some(d)) => Some(q.min(d)),
            (Some(q), None) => Some(q),
            (None, Some(d)) => Some(d),
            (None, None) => None,
        };
        if let Some(eff) = effective {
            if eff.saturating_duration_since(Instant::now()).is_zero() {
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
        }

        if scan_cancelled() {
            log::info!("[*] scan cancelled by request; finalizing with best so far");
            break;
        }

        tokio::select! {
            _ = cancel_token.cancelled() => {
                log::info!("[*] scan cancelled by request; finalizing with best so far");
                break;
            }
            item = stream.next() => {
                match item {
                    None => break,
                    Some(res) => {
                        scanned += 1;
                        if scanned.is_multiple_of(50) || scanned == total_candidates {
                            log::info!("[*] scanning... {}/{} ips, found {} working", scanned, total_candidates, found);
                            crate::session_event::emit(crate::session_event::SessionEvent::ScanProgress {
                                scanned,
                                total: total_candidates,
                                working: found,
                            });
                        }

                        match res {
                            None => continue,
                            Some(pr) => {
                                log::info!("[+] {} candidate ok {}:{} rtt={:?}", label, pr.ip, pr.port, pr.rtt);
                                emit_scan_hit(label, pr.ip, pr.port, pr.rtt);
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
                                    // Note: kept inline — the verify closure is not
                                    // 'static, so this cannot be spawned off. Cost is
                                    // bounded: drill-downs probe a small fixed
                                    // neighbor list at min(concurrency,16).
                                    let hot_hits = drill_down_hot_subnet(verify, pr.ip, pr.port, timeout, ironclad, st.concurrency, cancel_token.clone()).await;
                                    for h_pr in hot_hits {
                                        log::info!("[🔥] Hot subnet candidate ok {}:{} rtt={:?}", h_pr.ip, h_pr.port, h_pr.rtt);
                                        emit_scan_hit(label, h_pr.ip, h_pr.port, h_pr.rtt);
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
            _ = async {
                match effective {
                    Some(eff) => tokio::time::sleep(eff.saturating_duration_since(Instant::now())).await,
                    None => std::future::pending().await,
                }
            } => {
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
        None => {
            // A completed scan that found nothing usually means the endpoints are
            // fine but the network is dropping this transport on every port. Say so
            // explicitly so the user doesn't blame the IPs and rescan forever.
            let hint = if label.contains("gateway") {
                if crate::masque_h2::enabled() {
                    "no MASQUE/HTTP2 gateway answered on any port; the network may be blocking TLS to Cloudflare (try WireGuard)"
                } else {
                    "no MASQUE/HTTP3 gateway answered on any port; the network may be blocking QUIC/UDP (try HTTP/2 or WireGuard)"
                }
            } else {
                "no WireGuard endpoint answered on any port; the network may be blocking UDP"
            };
            log::warn!("[-] scan found no reachable endpoint — {hint}");
            Err(AetherError::NoCleanEndpoint)
        }
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
    cancel_token: CancellationToken,
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

    let cancel_child = cancel_token.clone();
    let stream = futures::stream::iter(
        neighbors
            .into_iter()
            .map(|(nip, nport)| {
                let tok = cancel_child.clone();
                async move {
                    tokio::select! {
                        _ = tok.cancelled() => None,
                        res = verify(nip, nport, timeout, ironclad) => res,
                    }
                }
            }),
    )
    .buffer_unordered(concurrency.min(16));
    tokio::pin!(stream);

    let mut results = Vec::new();
    loop {
        tokio::select! {
            _ = cancel_token.cancelled() => break,
            res = stream.next() => {
                match res {
                    Some(Some(pr)) => results.push(pr),
                    Some(None) => continue,
                    None => break,
                }
            }
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

    let is_masque = config.label.contains("gateway");

    // ── Port tiering: split ports into T1 (first), T2 (next), T3 (last) ──
    let (t1_ports, t2_ports, t3_ports): (Vec<u16>, Vec<u16>, Vec<u16>) = {
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

    // ── Seeds on ALL tiered ports (443 group first, then 8443/4443/8095, then
    // 2408/500/1701/4500), placed at the FRONT of the probe order by the assembly
    // below. Pairing the known-good seed VIPs with every port — not just 443 — is
    // what lets the scan punch through networks that DPI-drop QUIC on :443 while
    // leaving the alternate UDP ports (the ones WARP uses) open. Generated BEFORE
    // the CIDR sweep so a seed IP that also falls inside a sampled CIDR stays in the
    // seed set (guaranteed first) instead of being randomly demoted into a tier.
    let tiered_ports: Vec<u16> = t1_ports
        .iter()
        .chain(t2_ports.iter())
        .chain(t3_ports.iter())
        .copied()
        .collect();
    let mut v4_seeds: Vec<Ipv4Addr> =
        config.seeds_v4.iter().filter_map(|s| s.parse().ok()).collect();
    let mut v6_seeds: Vec<Ipv6Addr> =
        config.seeds_v6.iter().filter_map(|s| s.parse().ok()).collect();
    v4_seeds.shuffle(&mut rng);
    v6_seeds.shuffle(&mut rng);
    let mut seeds_out: Vec<(IpAddr, u16)> = Vec::new();
    for &p in &tiered_ports {
        if ip.want_v4() {
            for a in &v4_seeds {
                if seen.insert((IpAddr::V4(*a), p)) {
                    seeds_out.push((IpAddr::V4(*a), p));
                }
            }
        }
        if ip.want_v6() {
            for a in &v6_seeds {
                if seen.insert((IpAddr::V6(*a), p)) {
                    seeds_out.push((IpAddr::V6(*a), p));
                }
            }
        }
    }

    // CIDR sweep per tier.
    // For MASQUE, standard Cloudflare CDN edges only listen on 443;
    // the known-good seed VIPs (already queued above across all ports) handle alternate ports.
    // Sweeping non-443 ports on thousands of generic CDN hosts causes futile timeouts.
    // WireGuard uses multiple ports across all its prefixes.
    cidr_pool(config, st, ip, &t1_ports, &mut seen, &mut tier1_out);
    if !is_masque {
        cidr_pool(config, st, ip, &t2_ports, &mut seen, &mut tier2_out);
        cidr_pool(config, st, ip, &t3_ports, &mut seen, &mut tier3_out);
    }

    cap_and_order(seeds_out, tier1_out, tier2_out, tier3_out)
}

/// Weight-proportional sample size for one v4 CIDR: higher weight -> more
/// samples; `full_subnet` or a zero base disables sampling.
fn sample_for_weight(st: &Strategy, weight: u8, max_weight: usize) -> usize {
    if st.full_subnet || st.sample_per_cidr == 0 {
        return 0;
    }
    let base = st.sample_per_cidr;
    ((base * weight as usize) / max_weight).max(base / 5).max(8)
}

/// Append weighted-sampled CIDR candidates for one port set to `out` (unique by
/// (ip, port) via `seen`). v4 CIDRs are weighted so hot subnets are sampled
/// harder; v6 uses a flat per-CIDR sample.
fn cidr_pool(
    config: &ProbeConfig,
    st: &Strategy,
    ip: IpScan,
    port_set: &[u16],
    seen: &mut HashSet<(IpAddr, u16)>,
    out: &mut Vec<(IpAddr, u16)>,
) {
    if ip.want_v4() {
        let mut weighted: Vec<(&str, u8)> = config.cidr_weights_v4.to_vec();
        weighted.sort_by_key(|&(_, w)| std::cmp::Reverse(w));
        let max_weight = weighted.first().map(|&(_, w)| w.max(1)).unwrap_or(1) as usize;
        for &(cidr, weight) in &weighted {
            let hosts = if st.full_subnet {
                enumerate_cidr_v4(cidr)
            } else {
                sample_cidr_v4(cidr, sample_for_weight(st, weight, max_weight))
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
            for a in sample_cidr_v6(c, per, config.cidrs_v4) {
                for &p in port_set {
                    if seen.insert((IpAddr::V6(a), p)) {
                        out.push((IpAddr::V6(a), p));
                    }
                }
            }
        }
    }
}

/// Cap the total candidate count while guaranteeing tier3 (alt ports) a floor —
/// on a DPI-blocked-443 network those are the only ports that can answer — then
/// return candidates in probe order: seeds first, then T1, T2, T3.
fn cap_and_order(
    mut seeds: Vec<(IpAddr, u16)>,
    mut t1: Vec<(IpAddr, u16)>,
    mut t2: Vec<(IpAddr, u16)>,
    mut t3: Vec<(IpAddr, u16)>,
) -> Vec<(IpAddr, u16)> {
    const MAX_CANDIDATES: usize = 20_000;
    const TIER3_FLOOR: usize = 1_000;
    let total = seeds.len() + t1.len() + t2.len() + t3.len();
    if total > MAX_CANDIDATES {
        let budget = MAX_CANDIDATES.saturating_sub(seeds.len());
        let t3_floor = t3.len().min(TIER3_FLOOR).min(budget);
        let rest = budget - t3_floor;
        let t1_keep = t1.len().min(rest);
        let rest = rest - t1_keep;
        let t2_keep = t2.len().min(rest);
        let rest = rest - t2_keep;
        let t3_keep = (t3_floor + rest).min(t3.len());
        t1.truncate(t1_keep);
        t2.truncate(t2_keep);
        t3.truncate(t3_keep);
    }
    seeds.extend(t1);
    seeds.extend(t2);
    seeds.extend(t3);
    seeds
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
    // Cap enumeration so a large CIDR (e.g. /16) can't explode the candidate set.
    // Prefixes shorter than /20 are capped to their first block AND logged, rather
    // than silently returning nothing (the old behaviour skipped them entirely).
    const MAX_ENUM_HOST_BITS: u32 = 12; // 4096 hosts
    if host_bits > MAX_ENUM_HOST_BITS {
        log::debug!(
            "[scan] {cidr} larger than /{}; enumerating first {} hosts only",
            32 - MAX_ENUM_HOST_BITS,
            1u32 << MAX_ENUM_HOST_BITS
        );
    }
    let size = 1u32 << host_bits.min(MAX_ENUM_HOST_BITS);
    (1..size.saturating_sub(1))
        .map(|off| Ipv4Addr::from(base.saturating_add(off)))
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
    "162.159.196.0/24",
    "162.159.195.0/24",
    "162.159.192.0/24",
    "162.159.193.0/24",
    "162.159.204.0/24",
    "162.159.197.0/24",
    "162.159.198.0/24",
    "172.65.251.0/24",
    "188.114.96.0/24",
    "188.114.97.0/24",
    "188.114.98.0/24",
    "188.114.99.0/24",
    "162.159.36.0/24",
    "162.159.46.0/24",
];

pub const MASQUE_SEEDS: &[&str] = &[
    "162.159.196.1",
    "162.159.195.1",
    "162.159.192.1",
    "162.159.197.3",
    "162.159.197.1",
    "162.159.198.2",
    "162.159.198.1",
    "162.159.193.1",
];

/// Ports ordered by priority: primary web TLS first, then secondary, then legacy.
pub const MASQUE_PORTS: &[u16] = &[443, 500, 1701, 4500, 4443, 8443, 8095];

/// MASQUE port tiers: Tier 1 scanned first, Tier 2 next, Tier 3 last.
const MASQUE_PORTS_T1: &[u16] = &[443];
const MASQUE_PORTS_T2: &[u16] = &[500, 1701, 4500];

const MASQUE_CIDR_WEIGHTS: &[(&str, u8)] = &[
    ("162.159.198.0/24", 10),
    ("162.159.197.0/24", 10),
    ("162.159.192.0/24", 9),
    ("162.159.193.0/24", 9),
    ("162.159.195.0/24", 9),
    ("162.159.196.0/24", 8),
    ("188.114.96.0/24", 7),
    ("188.114.97.0/24", 7),
    ("188.114.98.0/24", 6),
    ("188.114.99.0/24", 6),
    ("162.159.204.0/24", 5),
    ("172.65.251.0/24", 4),
    // 162.159.36/46.0/24 are Cloudflare's 1.1.1.1 DNS-over-HTTPS ranges: they never
    // answer a MASQUE handshake, so weight them lowest (swept last) rather than
    // mid-pack where they waste probe budget ahead of ranges that actually work.
    ("162.159.36.0/24", 1),
    ("162.159.46.0/24", 1),
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
            verify_cost: if crate::masque_h2::enabled() {
                VerifyCost::Cheap
            } else {
                VerifyCost::Expensive
            },
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
    pub fn verify_fn<'a>(&'a self) -> impl Fn(IpAddr, u16, Duration, bool) -> Pin<Box<dyn Future<Output = Option<ProbeResult>> + Send + 'a>> + Send + Sync + 'a {
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
    /// M2 fix: sessions verified during the scan, keyed by endpoint. The tunnel
    /// runner reuses the matching one instead of performing a SECOND handshake —
    /// the exact double-handshake the session code documents Cloudflare edges
    /// as rate-limiting/confusing. Capped small; entries live only seconds.
    pub sessions: WgSessionCache,
}

/// Cache of handshakes established by the scanner, shared with the tunnel runner.
#[derive(Clone)]
pub struct WgSessionCache(Arc<std::sync::Mutex<HashMap<SocketAddr, crate::wireguard::EstablishedSession>>>);

impl WgSessionCache {
    pub fn new() -> Self {
        Self(Arc::new(std::sync::Mutex::new(HashMap::new())))
    }

    pub fn insert_capped(
        &self,
        peer: SocketAddr,
        session: crate::wireguard::EstablishedSession,
    ) {
        let mut map = self.0.lock().unwrap();
        if map.len() >= 4 {
            map.clear();
        }
        map.insert(peer, session);
    }

    pub fn take(&self, peer: &SocketAddr) -> Option<crate::wireguard::EstablishedSession> {
        self.0.lock().unwrap().remove(peer)
    }
}

impl WgProbe {
    /// Build a [`ProbeConfig`] for WireGuard scanning.
    pub fn probe_config(&self) -> ProbeConfig {
        ProbeConfig {
            verify_cost: VerifyCost::Cheap,
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
    pub fn verify_fn<'a>(&'a self) -> impl Fn(IpAddr, u16, Duration, bool) -> Pin<Box<dyn Future<Output = Option<ProbeResult>> + Send + 'a>> + Send + Sync + 'a {
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
                    // M2 fix: keep the verified session for the tunnel runner
                    // instead of discarding it (which forced a second handshake).
                    self.sessions.insert_capped(peer, session);
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

#[cfg(test)]
mod candidate_tests {
    use super::*;
    use std::net::IpAddr;

    fn test_config() -> ProbeConfig {
        ProbeConfig {
            verify_cost: VerifyCost::Cheap,
            cidrs_v4: &["10.0.0.0/24", "10.0.1.0/24"],
            cidrs_v6: &[],
            cidr_weights_v4: &[("10.0.0.0/24", 10), ("10.0.1.0/24", 5)],
            seeds_v4: &["10.0.0.1", "10.0.1.1"],
            seeds_v6: &[],
            cache_kind: CacheKind::Masque,
            label: "gateway",
            config_path: String::new(),
            profile: StrategyProfile {
                turbo_sample: 4,
                balanced_target: 1,
                balanced_sample: 4,
                stealth_target: 1,
                stealth_sample: 4,
            },
        }
    }

    fn test_strategy() -> Strategy {
        Strategy {
            concurrency: 8,
            per_probe_timeout: Duration::from_secs(1),
            overall_deadline: Duration::from_secs(10),
            quiet_after_first: Duration::from_secs(0),
            target_successes: 1,
            early_exit_first: true,
            full_subnet: false,
            sample_per_cidr: 4,
        }
    }

    #[test]
    fn seeds_come_first_across_all_ports() {
        let cands = build_candidates(&test_config(), &test_strategy(), &[443, 500], IpScan::V4);
        // 2 seeds x 2 tiered ports = 4 seed candidates, ahead of any CIDR sample.
        let seed_ips: std::collections::HashSet<IpAddr> = ["10.0.0.1", "10.0.1.1"]
            .iter()
            .map(|s| s.parse().unwrap())
            .collect();
        for c in cands.iter().take(4) {
            assert!(seed_ips.contains(&c.0), "first candidates must be seeds, got {c:?}");
        }
        // Both the primary (443) and alt port (500) are covered by seeds first, so a
        // DPI-blocked 443 still reaches the alt port early.
        assert!(cands.iter().take(4).any(|c| c.1 == 443));
        assert!(cands.iter().take(4).any(|c| c.1 == 500));
    }

    #[test]
    fn candidates_are_deduplicated() {
        let cands = build_candidates(&test_config(), &test_strategy(), &[443, 500, 443], IpScan::V4);
        let set: std::collections::HashSet<(IpAddr, u16)> = cands.iter().copied().collect();
        assert_eq!(set.len(), cands.len(), "duplicate (ip, port) candidates must not appear");
    }

    #[test]
    fn enumerate_cidr_caps_large_prefix_instead_of_empty() {
        // Regression: host_bits > 12 used to return an empty vec (silent skip).
        let big = enumerate_cidr_v4("10.5.0.0/16");
        assert!(!big.is_empty(), "large CIDR must not silently yield nothing");
        assert!(big.len() <= 4096, "enumeration must be capped");
        // A small CIDR still enumerates fully (excludes network + broadcast).
        assert_eq!(enumerate_cidr_v4("10.9.9.0/30").len(), 2);
    }

    // QA-1 verification: a scan cancelled mid-flight (e.g. the user pressing Stop)
    // must finalize with, and persist, the best endpoint found so far rather than
    // discarding it. Exercises request_scan_cancel() -> hunt_best break -> cache write.
    #[test]
    fn cancel_persists_best_so_far() {
        use std::future::Future;
        use std::pin::Pin;

        // Fresh temp cache so the persisted best-so-far can be read back.
        let dir = std::env::temp_dir().join(format!("aether-cancel-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let cfg_path = dir.join("aether.toml").to_string_lossy().to_string();

        let mut config = test_config();
        config.config_path = cfg_path.clone();

        // The seed VIP verifies and, like a user hitting Stop, requests cancellation
        // on that first hit; every other candidate fails.
        let hit: IpAddr = "10.0.0.1".parse().unwrap();
        let verify = move |ip: IpAddr, port: u16, _t: Duration, _iron: bool|
            -> Pin<Box<dyn Future<Output = Option<ProbeResult>> + Send>> {
            Box::pin(async move {
                if ip == hit {
                    request_scan_cancel();
                    Some(ProbeResult { ip, port, rtt: Duration::from_millis(10) })
                } else {
                    None
                }
            })
        };

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let res = rt.block_on(hunt_best(&config, &[443], IpScan::V4, ScanMode::Balanced, &verify));

        assert!(res.is_ok(), "a cancelled scan that already found an endpoint must finalize Ok");
        assert_eq!(res.unwrap().ip, hit);
        // The best-so-far must be written to the cache on cancel, not discarded.
        let cached = crate::cache::get_masque_sorted(&cfg_path);
        assert!(
            cached.iter().any(|(a, _)| a.ip() == hit && a.port() == 443),
            "cancelled scan must persist its best-so-far endpoint; cache was {cached:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
