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
            "thorough" | "deep" | "pro" => ScanMode::Thorough,
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
/// Ceiling on an adaptive scan budget: past this the user is better served by
/// the Stop button than by a scan that keeps running.
const MAX_SCAN_DEADLINE: Duration = Duration::from_secs(300);
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

    pub fn write_with_rtt(
        &self,
        config_path: &str,
        endpoints: Vec<(SocketAddr, u32)>,
        measurement: crate::cache::Measurement,
    ) -> crate::cache::Mutation {
        match self {
            CacheKind::Masque => {
                crate::cache::add_to_masque_with_rtt(config_path, endpoints, measurement)
            }
            CacheKind::WireGuard => {
                crate::cache::add_to_wireguard_with_rtt(config_path, endpoints, measurement)
            }
        }
    }
}

/// Which measurement a cached RTT actually represents. Ironclad hits are a real
/// HTTP round trip through a live tunnel; everything else is a handshake probe.
/// The two are not comparable, and the cache ranks them apart.
fn measured_as(ironclad: bool) -> crate::cache::Measurement {
    if ironclad {
        crate::cache::Measurement::HttpRoundTrip
    } else {
        crate::cache::Measurement::HandshakeProbe
    }
}

/// The verify closure type: given (ip, port, timeout, ironclad) → Option<ProbeResult>.
pub type VerifyFn<'a> = dyn Fn(
        IpAddr,
        u16,
        Duration,
        bool,
    ) -> Pin<Box<dyn Future<Output = Option<ProbeResult>> + Send + 'a>>
    + Send
    + Sync
    + 'a;

/// What the cached-endpoint race came back with.
#[derive(Debug)]
pub enum Tier0Outcome {
    Winner(ProbeResult),
    Cancelled,
    Miss,
}

/// Re-verify the cached endpoints before paying for a scan.
///
/// A cached endpoint may be **re-verified**, never preferred over verification:
/// this call used to pass `ironclad = false` unconditionally, so in Ironclad mode
/// a cache hit was accepted on a bare handshake — the one path where "this
/// address answered once, weeks ago" outranked "prove you still forward traffic",
/// which is the entire reason Ironclad exists.
pub async fn race_cached_endpoints(
    cached: Vec<(SocketAddr, u32)>,
    verify: &VerifyFn<'_>,
    cache_kind: &CacheKind,
    config_path: &str,
    timeout: Duration,
    ironclad: bool,
    cancel: CancellationToken,
) -> Tier0Outcome {
    if cached.is_empty() {
        return Tier0Outcome::Miss;
    }
    // Checked before anything is spawned: a cancel that arrives between "press
    // Connect" and here used to still fire up to five live probes.
    if cancel.is_cancelled() {
        return Tier0Outcome::Cancelled;
    }
    let race_count = cached.len().min(5); // Race top-5 by trust score.
    let race_futures: Vec<_> = cached
        .into_iter()
        .take(race_count)
        .map(|(addr, _rtt)| {
            let tok = cancel.clone();
            async move {
                tokio::select! {
                    _ = tok.cancelled() => None,
                    res = verify(addr.ip(), addr.port(), timeout, ironclad) => res,
                }
            }
        })
        .collect();

    let mut set = futures::stream::FuturesUnordered::new();
    for fut in race_futures {
        set.push(fut);
    }
    use futures::StreamExt;
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return Tier0Outcome::Cancelled,
            res = set.next() => {
                match res {
                    Some(Some(pr)) => {
                        log::info!("[⚡] Tier-0 race winner {}:{} rtt={:?}", pr.ip, pr.port, pr.rtt);
                        let rtt_ms = pr.rtt.as_millis() as u32;
                        if cache_kind
                            .write_with_rtt(
                                config_path,
                                vec![(SocketAddr::new(pr.ip, pr.port), rtt_ms)],
                                // Whatever was actually measured: `verify` above is
                                // called with the scan's `ironclad` flag, so in
                                // Ironclad mode this race carried a real HTTP round
                                // trip through a live tunnel. Recording that as a
                                // handshake probe ranked a tunnel-inclusive RTT
                                // against bare handshake RTTs — the exact comparison
                                // `Measurement` exists to keep apart.
                                measured_as(ironclad),
                            )
                            .was_skipped()
                        {
                            log::warn!(
                                "[scan] could not record the winner: another process holds the cache lock"
                            );
                        }
                        return Tier0Outcome::Winner(pr);
                    }
                    Some(None) => continue,
                    None => {
                        log::info!("[-] Tier-0 race: all cached endpoints failed, falling back to full scan");
                        return Tier0Outcome::Miss;
                    }
                }
            }
        }
    }
}

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
    for target in [
        "[2606:4700:d0::a29f:c001]:443",
        "[2001:4860:4860::8888]:443",
    ] {
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

struct ScanRegistry {
    generation: u64,
    /// One token per **live** scan, keyed by the generation that minted it.
    ///
    /// A single `Option<CancellationToken>` slot meant the second
    /// `register_scan_session` overwrote the first scan's token: `request_scan_cancel`
    /// could only ever reach the newest scan, and the older scan's own guard could
    /// not clean up after it either (generation mismatch). Two scans then probed at
    /// twice the intended concurrency while the UI's Stop hit only one of them.
    tokens: std::collections::BTreeMap<u64, CancellationToken>,
    /// The newest generation a Stop was requested *against*. Monotonic, and a fresh
    /// scan registers with a strictly larger generation, so a Stop pressed while
    /// nothing runs can never be consumed by the next Connect — it used to be, and
    /// that Connect failed once with a misleading "no working gateway".
    cancelled_through: u64,
}

static SCAN_REGISTRY: parking_lot::Mutex<ScanRegistry> = parking_lot::Mutex::new(ScanRegistry {
    generation: 0,
    tokens: std::collections::BTreeMap::new(),
    cancelled_through: 0,
});

pub struct ScanRunGuard(pub u64);

impl Drop for ScanRunGuard {
    fn drop(&mut self) {
        let mut reg = SCAN_REGISTRY.lock();
        // Retire *this* scan's token whatever else is live. The old code only acted
        // when the generation was the newest, so an older scan left a cancelled-by-
        // nobody entry behind that could still be reached by a later Stop.
        if let Some(t) = reg.tokens.remove(&self.0) {
            t.cancel();
        }
    }
}

pub fn request_scan_cancel() {
    let mut reg = SCAN_REGISTRY.lock();
    // Stamp the generation that is current *now*; a scan started after this point
    // gets a higher number and is not covered by it.
    reg.cancelled_through = reg.generation;
    if reg.tokens.is_empty() {
        // Nothing was running: the Stop is dropped, and that has to be visible.
        crate::counters::bump(&crate::counters::STALE_SCAN_CANCELS);
    }
    // Every live scan, not just the newest one.
    for t in reg.tokens.values() {
        t.cancel();
    }
}

#[allow(dead_code)]
pub fn current_cancel_token() -> CancellationToken {
    let reg = SCAN_REGISTRY.lock();
    reg.tokens.values().next_back().cloned().unwrap_or_default()
}

pub fn scan_cancelled() -> bool {
    let reg = SCAN_REGISTRY.lock();
    (reg.cancelled_through != 0 && reg.cancelled_through >= reg.generation)
        || reg.tokens.values().any(|t| t.is_cancelled())
}

/// Cancellation as seen by one specific scan: a Stop raised while it (or any newer
/// scan) was live, or a cancel of its own token. Per-generation so a Stop aimed at a
/// finished or unrelated scan cannot end this one, and the reverse.
pub fn scan_cancelled_for(gen: u64) -> bool {
    let reg = SCAN_REGISTRY.lock();
    (reg.cancelled_through != 0 && reg.cancelled_through >= gen)
        || reg
            .tokens
            .get(&gen)
            .map(|t| t.is_cancelled())
            .unwrap_or(false)
}

/// Mint a run id and a cancellation token for one scan.
///
/// Returns `Err` only as an API guard for callers that already handle it: a
/// cancellation raised *before* this call belongs to an older generation and is
/// deliberately not inherited. Once a scan is registered, `cancel_token` and
/// `scan_cancelled_for(gen)` are the only paths that can stop it.
pub fn register_scan_session() -> Result<(u64, CancellationToken)> {
    let mut reg = SCAN_REGISTRY.lock();
    reg.generation += 1;
    let gen = reg.generation;
    SCAN_GENERATION.store(gen, std::sync::atomic::Ordering::SeqCst);
    let token = CancellationToken::new();
    reg.tokens.insert(gen, token.clone());
    Ok((gen, token))
}

/// Progress accounting, split out of the scan loop so it can be tested without a
/// network.
///
/// `scanned` answers one question — how much of the queued sweep is done — and the
/// UI compares it against the `total` announced by `ScanStart` to decide whether
/// the scan finished. Stage-2 drill-downs probe a neighbour list that was **never
/// queued**, so folding their count into `scanned` pushed it past the total, the
/// completion line never fired, and the bar read "1431/1200". Drill probes are
/// therefore tallied apart, and the reported number is clamped to the total.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ScanTally {
    scanned: usize,
    drill_probes: usize,
    total: usize,
}

impl ScanTally {
    pub fn new(total: usize) -> Self {
        Self {
            scanned: 0,
            drill_probes: 0,
            total,
        }
    }

    /// One queued candidate came back (hit or miss).
    pub fn candidate_done(&mut self) {
        self.scanned += 1;
    }

    /// A drill-down wave examined `examined` neighbours nobody queued.
    pub fn drill_down_done(&mut self, examined: usize) {
        self.drill_probes = self.drill_probes.saturating_add(examined);
    }

    /// What the UI may be told, never more than the total it was promised.
    pub fn reported(&self) -> usize {
        self.scanned.min(self.total)
    }

    /// Drill-down probes, reported apart from the sweep.
    pub fn drill_probes(&self) -> usize {
        self.drill_probes
    }

    /// Total probe work, for the log line only.
    pub fn probes_sent(&self) -> usize {
        self.scanned.saturating_add(self.drill_probes)
    }

    /// Terminal condition — `>=` rather than `==` so overshoot cannot strand it.
    pub fn is_complete(&self) -> bool {
        self.scanned >= self.total
    }

    /// Whether this tick deserves a progress event: every 50 candidates, and always
    /// at completion.
    pub fn should_report(&self) -> bool {
        self.reported().is_multiple_of(50) || self.is_complete()
    }
}

pub async fn hunt_best(
    config: &ProbeConfig,
    ports: &[u16],
    ip: IpScan,
    mode: ScanMode,
    verify: &VerifyFn<'_>,
) -> Result<ProbeResult> {
    let (gen, cancel_token) = register_scan_session()?;
    let _guard = ScanRunGuard(gen);
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
    // M3 fix: the tier-0 race used a hardcoded 600ms budget while expensive
    // (H3) verification needs >=5s — every cached endpoint "failed" on any
    // network with >600ms handshake time, evicting good entries and forcing
    // a pointless full scan on every connect. Race with the same per-probe
    // budget the strategy settled on (first-hit-wins is unchanged).
    match race_cached_endpoints(
        cached,
        verify,
        &config.cache_kind,
        &config.config_path,
        st.per_probe_timeout,
        ironclad,
        cancel_token.clone(),
    )
    .await
    {
        Tier0Outcome::Winner(pr) => return Ok(pr),
        Tier0Outcome::Cancelled => {
            log::info!("[*] scan cancelled during Tier-0 race");
            return Err(AetherError::NoCleanEndpoint);
        }
        Tier0Outcome::Miss => {}
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
    // A fixed 30/60 s budget against 1 400-20 000 candidates covered ~5 % of
    // the pool while `scan_start` announced the whole count: the progress bar
    // and the "no clean endpoint" verdict were both describing a scan that had
    // never happened. Size the budget from the queued work (waves of
    // `concurrency`, each costing at most `per_probe`), plus two waves of
    // slack, and clamp so an enormous pool still cannot hang a connect.
    if !exhaustive {
        let waves = total_candidates.div_ceil(st.concurrency.max(1)) as u64;
        let needed = st
            .per_probe_timeout
            .saturating_mul(waves.saturating_add(2) as u32);
        let before = st.overall_deadline;
        st.overall_deadline = needed.max(before).min(MAX_SCAN_DEADLINE);
        if st.overall_deadline > before {
            log::debug!(
                "[prober] {} candidates / {} concurrent at {:?} => deadline {:?} (was {:?}, cap {:?})",
                total_candidates,
                st.concurrency,
                st.per_probe_timeout,
                st.overall_deadline,
                before,
                MAX_SCAN_DEADLINE,
            );
        }
    }
    crate::session_event::emit(crate::session_event::SessionEvent::ScanStart {
        mode: mode.label().to_string(),
        total: total_candidates,
        concurrency: st.concurrency,
    });
    let cancel_child = cancel_token.clone();
    let stream = futures::stream::iter(candidates.into_iter().map(|(ip, port)| {
        let tok = cancel_child.clone();
        async move {
            tokio::select! {
                _ = tok.cancelled() => None,
                res = verify(ip, port, timeout, ironclad) => res,
            }
        }
    }))
    .buffer_unordered(st.concurrency);
    tokio::pin!(stream);

    let deadline: Option<Instant> = if exhaustive {
        None
    } else {
        Some(Instant::now() + st.overall_deadline)
    };
    let mut best: Option<ProbeResult> = None;
    let mut found = 0usize;
    // Queued candidates vs drill-down probes, kept apart: see `ScanTally`.
    let mut tally = ScanTally::new(total_candidates);
    // `(ip, port)` already reported. Without it a drill-down that reached the
    // same neighbour as the main sweep counted one working gateway as two, and
    // `target_successes` stopped the scan early on phantom hits.
    let mut reported: std::collections::HashSet<(IpAddr, u16)> = std::collections::HashSet::new();
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

        if scan_cancelled_for(gen) {
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
                        tally.candidate_done();
                        if tally.should_report() {
                            let scanned = tally.reported();
                            log::info!(
                                "[*] scanning... {}/{} ips, found {} working, {} probes so far",
                                scanned,
                                total_candidates,
                                found,
                                tally.probes_sent()
                            );
                            crate::session_event::emit(crate::session_event::SessionEvent::ScanProgress {
                                scanned,
                                total: total_candidates,
                                working: found,
                            });
                        }

                        match res {
                            None => continue,
                            Some(pr) => {
                                if reported.insert((pr.ip, pr.port)) {
                                    log::info!("[+] {} candidate ok {}:{} rtt={:?}", label, pr.ip, pr.port, pr.rtt);
                                    emit_scan_hit(label, pr.ip, pr.port, pr.rtt);
                                }
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
                                    // The verify closure is not 'static so the wave
                                    // cannot be spawned off — but awaiting it inline
                                    // used to freeze this whole `select!`: while it
                                    // ran, neither `cancel_token` nor the scan
                                    // deadline was polled, so one wave per hot /24
                                    // (>=6 s per probe in expensive H3) overshot both
                                    // Stop and the budget. Race it against the two
                                    // things that are meant to end a scan.
                                    let drill_budget = match effective {
                                        Some(eff) => eff
                                            .saturating_duration_since(Instant::now())
                                            .min(Duration::from_secs(DRILL_DOWN_MAX_SECS)),
                                        // Exhaustive scans have no deadline; the
                                        // drill-down still has a bound of its own.
                                        None => Duration::from_secs(DRILL_DOWN_MAX_SECS),
                                    };
                                    let drilled = tokio::select! {
                                        r = drill_down_hot_subnet(
                                            verify,
                                            pr.ip,
                                            pr.port,
                                            timeout,
                                            ironclad,
                                            st.concurrency,
                                            cancel_token.clone(),
                                        ) => Some(r),
                                        _ = cancel_token.cancelled() => None,
                                        _ = tokio::time::sleep(drill_budget) => None,
                                    };
                                    let (hot_hits, drill_examined) = match drilled {
                                        Some(done) => done,
                                        None => {
                                            // The neighbours it never reached were not
                                            // probed, and the tally must not claim
                                            // they were.
                                            crate::counters::bump(
                                                &crate::counters::DRILL_DOWN_WAVES_ABANDONED,
                                            );
                                            (Vec::new(), 0usize)
                                        }
                                    };
                                    // Drill probes are counted apart from the queued
                                    // sweep — see `ScanTally`.
                                    tally.drill_down_done(drill_examined);
                                    for h_pr in hot_hits {
                                        if !reported.insert((h_pr.ip, h_pr.port)) {
                                            continue;
                                        }
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
                                    config.cache_kind.write_with_rtt(&config.config_path, vec![(SocketAddr::new(final_best.ip, final_best.port), rtt_ms)], measured_as(ironclad));
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
            config.cache_kind.write_with_rtt(
                &config.config_path,
                vec![(SocketAddr::new(pr.ip, pr.port), rtt_ms)],
                measured_as(ironclad),
            );
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

/// Host offsets Stage-2 probes around a hit inside its /24.
const STAGE2_OFFSETS: [u32; 21] = [
    1, 2, 3, 4, 5, 8, 10, 15, 20, 25, 30, 40, 50, 60, 75, 90, 100, 120, 150, 180, 200,
];

/// Hard ceiling on one drill-down wave, in seconds.
///
/// A wave is ~40 neighbours at `min(concurrency, 16)` lanes, so at the
/// `EXPENSIVE_MIN_TIMEOUT` per-probe budget it can outlast the whole remaining
/// scan. The caller races this against cancel and the scan deadline; exhaustive
/// scans, which have no deadline, still get this bound.
const DRILL_DOWN_MAX_SECS: u64 = 8;

/// Both directions from `current`, saturating and confined to usable hosts.
///
/// Saturating rather than `% 254` is the fix: a hit on `.250` used to wrap its
/// upward neighbours onto `.6/.7`, and `wrapping_sub` sent its downward
/// neighbours to pseudo-random hosts, so "dense enumeration" re-probed some
/// addresses while never looking at the rest of the /24.
fn v4_neighbor_hosts(current: u32, offsets: &[u32]) -> Vec<u32> {
    let mut out: Vec<u32> = Vec::with_capacity(offsets.len() * 2);
    for &offset in offsets {
        for h in [
            current.saturating_add(offset),
            current.saturating_sub(offset),
        ] {
            if h != current && (1..=254).contains(&h) && !out.contains(&h) {
                out.push(h);
            }
        }
    }
    out
}

async fn drill_down_hot_subnet(
    verify: &VerifyFn<'_>,
    ip: IpAddr,
    port: u16,
    timeout: Duration,
    ironclad: bool,
    concurrency: usize,
    cancel_token: CancellationToken,
) -> (Vec<ProbeResult>, usize) {
    let mut neighbors = Vec::new();
    match ip {
        IpAddr::V4(v4) => {
            let base = u32::from(v4) & 0xFFFFFF00;
            let current_host = v4.octets()[3] as u32;
            for h in v4_neighbor_hosts(current_host, &STAGE2_OFFSETS) {
                let neighbor_ip = IpAddr::V4(Ipv4Addr::from(base + h));
                if !neighbors.contains(&(neighbor_ip, port)) {
                    neighbors.push((neighbor_ip, port));
                }
            }
        }
        IpAddr::V6(v6) => {
            let segs = v6.segments();
            let current_last = segs[7];
            for offset in [1, 2, 3, 4, 5, 10, 20, 50, 100] {
                let last = current_last.saturating_add(offset);
                if last != current_last && last != 0 {
                    let neighbor_ip = IpAddr::V6(Ipv6Addr::new(
                        segs[0], segs[1], segs[2], segs[3], segs[4], segs[5], segs[6], last,
                    ));
                    if !neighbors.contains(&(neighbor_ip, port)) {
                        neighbors.push((neighbor_ip, port));
                    }
                }
            }
        }
    }

    let examined = neighbors.len();
    if neighbors.is_empty() {
        return (Vec::new(), 0);
    }

    let cancel_child = cancel_token.clone();
    let stream = futures::stream::iter(neighbors.into_iter().map(|(nip, nport)| {
        let tok = cancel_child.clone();
        async move {
            tokio::select! {
                _ = tok.cancelled() => None,
                res = verify(nip, nport, timeout, ironclad) => res,
            }
        }
    }))
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
    (results, examined)
}

// ─────────────────────────────────────────────────────────────────────────────
// Candidate generation (shared)
// ─────────────────────────────────────────────────────────────────────────────

fn build_candidates(
    config: &ProbeConfig,
    st: &Strategy,
    ports: &[u16],
    ip: IpScan,
) -> Vec<(IpAddr, u16)> {
    use rand::seq::SliceRandom;
    let mut rng = rand::thread_rng();

    // Port priority: dedup while preserving priority order from caller
    let dedup_ports: Vec<u16> = {
        let mut seen_port: HashSet<u16> = HashSet::new();
        let deduped: Vec<u16> = ports
            .iter()
            .copied()
            .filter(|p| seen_port.insert(*p))
            .collect();
        if deduped.is_empty() {
            vec![443]
        } else {
            deduped
        }
    };

    let is_masque = config.label.contains("gateway");

    // ── Port tiering: split ports into T1 (first), T2 (next), T3 (last) ──
    let (t1_ports, t2_ports, t3_ports): (Vec<u16>, Vec<u16>, Vec<u16>) = {
        if is_masque {
            let t1: Vec<u16> = dedup_ports
                .iter()
                .copied()
                .filter(|p| MASQUE_PORTS_T1.contains(p))
                .collect();
            let t2: Vec<u16> = dedup_ports
                .iter()
                .copied()
                .filter(|p| MASQUE_PORTS_T2.contains(p))
                .collect();
            let t3: Vec<u16> = dedup_ports
                .iter()
                .copied()
                .filter(|p| !MASQUE_PORTS_T1.contains(p) && !MASQUE_PORTS_T2.contains(p))
                .collect();
            (if t1.is_empty() { vec![443] } else { t1 }, t2, t3)
        } else {
            let t1: Vec<u16> = dedup_ports
                .iter()
                .copied()
                .filter(|p| crate::wireguard::WG_PORTS_T1.contains(p))
                .collect();
            let t2: Vec<u16> = dedup_ports
                .iter()
                .copied()
                .filter(|p| crate::wireguard::WG_PORTS_T2.contains(p))
                .collect();
            let t3: Vec<u16> = dedup_ports
                .iter()
                .copied()
                .filter(|p| {
                    !crate::wireguard::WG_PORTS_T1.contains(p)
                        && !crate::wireguard::WG_PORTS_T2.contains(p)
                })
                .collect();
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
    let mut v4_seeds: Vec<Ipv4Addr> = config
        .seeds_v4
        .iter()
        .filter_map(|s| s.parse().ok())
        .collect();
    let mut v6_seeds: Vec<Ipv6Addr> = config
        .seeds_v6
        .iter()
        .filter_map(|s| s.parse().ok())
        .collect();
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
        let per = if st.sample_per_cidr == 0 {
            96
        } else {
            st.sample_per_cidr
        };
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
    Some((
        u32::from(ip.parse::<Ipv4Addr>().ok()?),
        prefix.parse().ok()?,
    ))
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
    let size = if host_bits >= 32 {
        u32::MAX
    } else {
        1u32 << host_bits
    };
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
    Some((
        u128::from(ip.parse::<Ipv6Addr>().ok()?),
        prefix.parse().ok()?,
    ))
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
            } else if host_bits >= 32 {
                // A /0 v4 prefix leaves nothing to mask: the shift below would be
                // `1u32 << 32`, which panics in debug and wraps in release. The
                // v4 sampler beside this one already guards exactly this.
                rng.gen::<u32>()
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
    pub fn verify_fn<'a>(
        &'a self,
    ) -> impl Fn(
        IpAddr,
        u16,
        Duration,
        bool,
    ) -> Pin<Box<dyn Future<Output = Option<ProbeResult>> + Send + 'a>>
           + Send
           + Sync
           + 'a {
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
                    return match crate::tunnelping::masque_http_ping(
                        &params,
                        IRONCLAD_TCPING_TIMEOUT,
                    )
                    .await
                    {
                        Ok(rtt) => {
                            log::info!(
                                "[+] ironclad verified {ip}:{port} real http round trip rtt={:?}",
                                rtt
                            );
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
                    header_mode: crate::masque::H3HeaderMode::Standard,
                    protocol: None,
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
pub struct WgSessionCache(
    Arc<parking_lot::Mutex<HashMap<SocketAddr, (crate::wireguard::EstablishedSession, Instant)>>>,
);

/// A cached handshake is only a shortcut while both ends still hold the keys:
/// boringtun rejects a packet older than `REJECT_AFTER_TIME` (180 s) and starts
/// rekeying `REKEY_TIMEOUT` (5 s) before that, so past 175 s a cached session is a
/// handshake that will be dropped — and handing it out turns that into a timeout
/// with no reason attached.
pub const WG_SESSION_TTL: Duration = Duration::from_secs(175);
/// How many peers keep a live handshake. Hitting the cap used to `clear()` the map,
/// so a hunt that found five endpoints discarded all four established sessions and
/// every later reconnect paid a fresh commitment plus a fresh race.
pub const WG_SESSION_CAPACITY: usize = 4;

fn wg_session_fresh(inserted_at: Instant, now: Instant, ttl: Duration) -> bool {
    // `duration_since` panics when the clock went backwards between the two reads,
    // which is precisely the case this has to survive: keep the session rather than
    // deleting live state over a jump nobody asked for.
    if now <= inserted_at {
        return true;
    }
    now.duration_since(inserted_at) < ttl
}

/// Which peers to drop before making room for one more: everything expired, then the
/// oldest live sessions until `capacity - 1` remain. Oldest-first is the point — a
/// reconnect wants the handshake it used most recently, not the first one found.
fn wg_evictions(
    entries: &[(SocketAddr, Instant)],
    now: Instant,
    ttl: Duration,
    capacity: usize,
) -> Vec<SocketAddr> {
    let mut drop: Vec<SocketAddr> = entries
        .iter()
        .filter(|(_, at)| !wg_session_fresh(*at, now, ttl))
        .map(|(addr, _)| *addr)
        .collect();
    let mut alive: Vec<(SocketAddr, Instant)> = entries
        .iter()
        .filter(|(_, at)| wg_session_fresh(*at, now, ttl))
        .copied()
        .collect();
    alive.sort_by_key(|(_, at)| *at);
    let room = capacity.saturating_sub(1);
    let overflow = alive.len().saturating_sub(room);
    drop.extend(alive.into_iter().take(overflow).map(|(addr, _)| addr));
    drop
}

impl WgSessionCache {
    pub fn new() -> Self {
        Self(Arc::new(parking_lot::Mutex::new(HashMap::new())))
    }

    pub fn insert_capped(&self, peer: SocketAddr, session: crate::wireguard::EstablishedSession) {
        let mut map = self.0.lock();
        let now = Instant::now();
        let entries: Vec<(SocketAddr, Instant)> =
            map.iter().map(|(k, (_, at))| (*k, *at)).collect();
        for key in wg_evictions(&entries, now, WG_SESSION_TTL, WG_SESSION_CAPACITY) {
            map.remove(&key);
        }
        map.insert(peer, (session, now));
    }

    pub fn take(&self, peer: &SocketAddr) -> Option<crate::wireguard::EstablishedSession> {
        let (session, inserted_at) = self.0.lock().remove(peer)?;
        wg_session_fresh(inserted_at, Instant::now(), WG_SESSION_TTL).then_some(session)
    }

    /// Held sessions, including any not yet reaped.
    pub fn len(&self) -> usize {
        self.0.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for WgSessionCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod wg_cache_tests {
    use super::*;

    fn peer(i: u8) -> SocketAddr {
        format!("10.0.0.{i}:51820").parse().expect("test address")
    }

    #[test]
    fn an_expired_session_is_never_handed_out() {
        assert!(wg_session_fresh(
            Instant::now() - Duration::from_secs(174),
            Instant::now(),
            WG_SESSION_TTL
        ));
        assert!(!wg_session_fresh(
            Instant::now() - Duration::from_secs(176),
            Instant::now(),
            WG_SESSION_TTL
        ));
    }

    /// The old rule dropped *every* cached handshake once a fourth peer arrived, so
    /// a five-endpoint hunt left nothing reusable at all.
    #[test]
    fn a_full_cache_loses_the_oldest_session_not_all_of_them() {
        let now = Instant::now();
        let entries = vec![
            (peer(1), now - Duration::from_secs(6)),
            (peer(2), now - Duration::from_secs(5)),
            (peer(3), now - Duration::from_secs(4)),
            (peer(4), now - Duration::from_secs(3)),
        ];
        let dropped = wg_evictions(&entries, now, WG_SESSION_TTL, WG_SESSION_CAPACITY);
        assert_eq!(dropped, vec![peer(1)], "only the oldest makes room");
    }

    #[test]
    fn expired_sessions_make_room_without_evicting_live_ones() {
        let now = Instant::now();
        let stale = Duration::from_secs(200);
        let entries = vec![
            (peer(1), now - stale),
            (peer(2), now - stale),
            (peer(3), now - Duration::from_secs(2)),
            (peer(4), now - Duration::from_secs(1)),
        ];
        let dropped = wg_evictions(&entries, now, WG_SESSION_TTL, WG_SESSION_CAPACITY);
        assert_eq!(dropped.len(), 2, "the two expired ones and nothing else");
        assert!(dropped.contains(&peer(1)) && dropped.contains(&peer(2)));
    }

    #[test]
    fn nothing_is_dropped_while_there_is_room() {
        let now = Instant::now();
        let entries = vec![(peer(1), now), (peer(2), now - Duration::from_secs(1))];
        assert!(wg_evictions(&entries, now, WG_SESSION_TTL, WG_SESSION_CAPACITY).is_empty());
    }

    #[test]
    fn a_zero_capacity_cache_does_not_underflow() {
        let now = Instant::now();
        let entries = vec![(peer(1), now)];
        assert_eq!(
            wg_evictions(&entries, now, WG_SESSION_TTL, 0),
            vec![peer(1)]
        );
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
    pub fn verify_fn<'a>(
        &'a self,
    ) -> impl Fn(
        IpAddr,
        u16,
        Duration,
        bool,
    ) -> Pin<Box<dyn Future<Output = Option<ProbeResult>> + Send + 'a>>
           + Send
           + Sync
           + 'a {
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
                match crate::tunnelping::wg_http_ping_established(
                    session,
                    &params,
                    WG_IRONCLAD_TCPING_TIMEOUT,
                )
                .await
                {
                    Ok(http_rtt) => {
                        log::info!(
                            "[+] ironclad verified wg {ip}:{port} real http round trip rtt={:?}",
                            http_rtt
                        );
                        Some(ProbeResult {
                            ip,
                            port,
                            rtt: http_rtt,
                        })
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
    use crate::prober::v4_neighbor_hosts;

    /// Stage-2 must enumerate *both* directions inside the /24 and must never
    /// wrap a neighbour onto the other side of the subnet.
    #[test]
    fn stage2_neighbours_saturate_inside_the_subnet() {
        let offsets: Vec<u32> = vec![1, 2, 3, 5, 10, 20, 50, 100, 150, 200];

        let near_top = v4_neighbor_hosts(250, &offsets);
        assert!(!near_top.contains(&6), "250 + offset wrapped onto .6");
        assert!(near_top.contains(&249) && near_top.contains(&248));
        assert!(
            near_top.iter().all(|h| (1..=254).contains(h)),
            "a stage-2 neighbour left the usable host range: {near_top:?}"
        );
        assert!(
            !near_top.contains(&250),
            "the hit itself must not be re-probed"
        );

        let near_bottom = v4_neighbor_hosts(3, &offsets);
        assert!(!near_bottom.contains(&0) && !near_bottom.contains(&255));
        assert!(near_bottom.contains(&4) && near_bottom.contains(&5));
        // Saturating clamps: every offset past the edge collapses onto .1, so the
        // enumeration stops at the subnet boundary instead of teleporting.
        assert_eq!(near_bottom.iter().filter(|h| **h == 1).count(), 1);

        let mid = v4_neighbor_hosts(100, &offsets);
        assert!(mid.contains(&99) && mid.contains(&101));
        assert_eq!(
            mid.len(),
            mid.iter().collect::<std::collections::HashSet<_>>().len(),
            "duplicate neighbour probed twice"
        );
    }
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
            assert!(
                seed_ips.contains(&c.0),
                "first candidates must be seeds, got {c:?}"
            );
        }
        // Both the primary (443) and alt port (500) are covered by seeds first, so a
        // DPI-blocked 443 still reaches the alt port early.
        assert!(cands.iter().take(4).any(|c| c.1 == 443));
        assert!(cands.iter().take(4).any(|c| c.1 == 500));
    }

    #[test]
    fn candidates_are_deduplicated() {
        let cands = build_candidates(
            &test_config(),
            &test_strategy(),
            &[443, 500, 443],
            IpScan::V4,
        );
        let set: std::collections::HashSet<(IpAddr, u16)> = cands.iter().copied().collect();
        assert_eq!(
            set.len(),
            cands.len(),
            "duplicate (ip, port) candidates must not appear"
        );
    }

    #[test]
    fn enumerate_cidr_caps_large_prefix_instead_of_empty() {
        // Regression: host_bits > 12 used to return an empty vec (silent skip).
        let big = enumerate_cidr_v4("10.5.0.0/16");
        assert!(
            !big.is_empty(),
            "large CIDR must not silently yield nothing"
        );
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
        let verify = move |ip: IpAddr,
                           port: u16,
                           _t: Duration,
                           _iron: bool|
              -> Pin<Box<dyn Future<Output = Option<ProbeResult>> + Send>> {
            Box::pin(async move {
                if ip == hit {
                    request_scan_cancel();
                    Some(ProbeResult {
                        ip,
                        port,
                        rtt: Duration::from_millis(10),
                    })
                } else {
                    None
                }
            })
        };

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let res = rt.block_on(hunt_best(
            &config,
            &[443],
            IpScan::V4,
            ScanMode::Balanced,
            &verify,
        ));

        assert!(
            res.is_ok(),
            "a cancelled scan that already found an endpoint must finalize Ok"
        );
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

#[cfg(test)]
mod tier0_tests {
    use super::*;
    use parking_lot::Mutex;

    /// A cache entry is a memory of a proof, not a substitute for one. Tier-0 used
    /// to call `verify(.., false)` unconditionally, so in Ironclad mode a cached
    /// address was accepted on a bare handshake while a freshly generated candidate
    /// had to complete a real HTTP round trip — the mode's whole guarantee applied
    /// to the endpoints nobody had ever connected to, and not to the one from last
    /// week.
    #[tokio::test]
    async fn a_cache_hit_must_pass_the_proof_the_mode_asks_for() {
        let dir = std::env::temp_dir().join(format!("aether_tier0_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let base = dir.join("aether.toml").to_string_lossy().to_string();
        let gw: SocketAddr = "162.159.193.1:443".parse().unwrap();
        let seen: std::sync::Arc<Mutex<Vec<bool>>> = Default::default();

        let recorder = seen.clone();
        let verify =
            move |ip: IpAddr,
                  port: u16,
                  _t: Duration,
                  ironclad: bool|
                  -> Pin<Box<dyn Future<Output = Option<ProbeResult>> + Send + '_>> {
                let recorder = recorder.clone();
                Box::pin(async move {
                    recorder.lock().push(ironclad);
                    Some(ProbeResult {
                        ip,
                        port,
                        rtt: Duration::from_millis(25),
                    })
                })
            };

        let out = race_cached_endpoints(
            vec![(gw, 25)],
            &verify,
            &CacheKind::Masque,
            &base,
            Duration::from_secs(1),
            true,
            CancellationToken::new(),
        )
        .await;
        assert!(
            matches!(out, Tier0Outcome::Winner(ref pr) if pr.ip == gw.ip()),
            "the race must still take a cached hit when it passes: {out:?}"
        );
        let flags: Vec<bool> = seen.lock().iter().copied().collect();
        assert_eq!(flags.len(), 1);
        assert!(
            flags[0],
            "Tier-0 asked for a handshake-only proof while Ironclad was on"
        );

        // The same call with the mode off must not start demanding HTTP proofs.
        seen.lock().clear();
        let out = race_cached_endpoints(
            vec![(gw, 25)],
            &verify,
            &CacheKind::Masque,
            &base,
            Duration::from_secs(1),
            false,
            CancellationToken::new(),
        )
        .await;
        assert!(matches!(out, Tier0Outcome::Winner(_)));
        assert_eq!(seen.lock().as_slice(), &[false]);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The proof Tier-0 runs and the label it writes must be the same act. The
    /// race above is entered with `ironclad = true`, so the winner's RTT includes a
    /// real HTTP round trip through a live tunnel — but the entry was written as a
    /// bare `HandshakeProbe` unconditionally, which is exactly the cross-kind
    /// comparison `Measurement` exists to keep apart: the cache then ranked a
    /// tunnel-inclusive RTT against handshake RTTs and trusted the cheaper number.
    #[tokio::test]
    async fn an_ironclad_race_records_an_http_round_trip() {
        let dir = std::env::temp_dir().join(format!("aether_tier0_meas_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let base = dir.join("aether.toml").to_string_lossy().to_string();
        let gw: SocketAddr = "162.159.193.1:443".parse().unwrap();

        let verify =
            move |ip: IpAddr,
                  port: u16,
                  _t: Duration,
                  _ironclad: bool|
                  -> Pin<Box<dyn Future<Output = Option<ProbeResult>> + Send + '_>> {
                Box::pin(async move {
                    Some(ProbeResult {
                        ip,
                        port,
                        rtt: Duration::from_millis(25),
                    })
                })
            };

        let out = race_cached_endpoints(
            vec![(gw, 25)],
            &verify,
            &CacheKind::Masque,
            &base,
            Duration::from_secs(1),
            true,
            CancellationToken::new(),
        )
        .await;
        assert!(matches!(out, Tier0Outcome::Winner(_)), "{out:?}");

        let entry = crate::cache::load_endpoints(&base)
            .masque
            .iter()
            .find(|e| e.addr == gw)
            .expect("the race winner must be in the cache");
        assert_eq!(
            entry.measurement,
            crate::cache::Measurement::HttpRoundTrip,
            "an ironclad Tier-0 win was recorded as a bare handshake probe"
        );

        // The other direction: a handshake-mode race must not claim to have carried
        // HTTP either.
        let base2 = dir
            .join("aether-handshake.toml")
            .to_string_lossy()
            .to_string();
        let out = race_cached_endpoints(
            vec![(gw, 25)],
            &verify,
            &CacheKind::Masque,
            &base2,
            Duration::from_secs(1),
            false,
            CancellationToken::new(),
        )
        .await;
        assert!(matches!(out, Tier0Outcome::Winner(_)), "{out:?}");
        let entry = crate::cache::load_endpoints(&base2)
            .masque
            .iter()
            .find(|e| e.addr == gw)
            .expect("the race winner must be in the cache");
        assert_eq!(
            entry.measurement,
            crate::cache::Measurement::HandshakeProbe,
            "a handshake Tier-0 win must not be labelled as HTTP"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn an_empty_cache_is_a_miss_not_a_hang() {
        let seen: std::sync::Arc<Mutex<Vec<bool>>> = Default::default();
        let recorder = seen.clone();
        let verify =
            move |_ip: IpAddr,
                  _port: u16,
                  _t: Duration,
                  _ironclad: bool|
                  -> Pin<Box<dyn Future<Output = Option<ProbeResult>> + Send + '_>> {
                let recorder = recorder.clone();
                Box::pin(async move {
                    recorder.lock().push(true);
                    None
                })
            };
        let out = race_cached_endpoints(
            Vec::new(),
            &verify,
            &CacheKind::Masque,
            "unused",
            Duration::from_millis(50),
            false,
            CancellationToken::new(),
        )
        .await;
        assert!(matches!(out, Tier0Outcome::Miss));
        assert!(seen.lock().is_empty(), "no entries, no probes");
    }

    #[tokio::test]
    async fn cancellation_during_the_race_is_reported_as_cancelled() {
        let recorder: std::sync::Arc<Mutex<Vec<bool>>> = Default::default();
        let verify =
            move |ip: IpAddr,
                  port: u16,
                  _t: Duration,
                  _ironclad: bool|
                  -> Pin<Box<dyn Future<Output = Option<ProbeResult>> + Send + '_>> {
                let recorder = recorder.clone();
                Box::pin(async move {
                    recorder.lock().push(true);
                    let _ = (ip, port);
                    None
                })
            };
        let token = CancellationToken::new();
        token.cancel();
        let out = race_cached_endpoints(
            vec![("162.159.193.1:443".parse().unwrap(), 25)],
            &verify,
            &CacheKind::Masque,
            "unused",
            Duration::from_millis(50),
            false,
            token,
        )
        .await;
        assert!(matches!(out, Tier0Outcome::Cancelled), "{out:?}");
    }
}

#[cfg(test)]
mod scan_mode_tests {
    use super::ScanMode;

    /// One string, one mode. The shell now ships a `ScanMode` enum, so the engine
    /// must not keep a private vocabulary where a typo is a legal alias — that
    /// was how `"thorogh"` became a value the Settings UI could select and the
    /// validator could reject.
    #[test]
    fn every_label_parses_back_to_its_own_mode() {
        for mode in [
            ScanMode::Turbo,
            ScanMode::Balanced,
            ScanMode::Thorough,
            ScanMode::Stealth,
            ScanMode::Ironclad,
        ] {
            assert_eq!(ScanMode::parse(mode.label()), mode);
        }
    }

    #[test]
    fn a_misspelled_mode_is_not_a_mode() {
        assert_eq!(ScanMode::parse("thorogh"), ScanMode::Balanced);
        assert_eq!(ScanMode::parse("thoro"), ScanMode::Balanced);
        assert_eq!(ScanMode::parse(""), ScanMode::Balanced);
    }
}
