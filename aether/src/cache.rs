use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use fs2::FileExt;

use crate::error::{AetherError, Result};

/// Maximum cached endpoints per protocol.
const MAX_CACHED: usize = 10;

/// Endpoints older than this are pruned on load. Kept short deliberately:
/// anycast routing and reachability change when the user roams or toggles a
/// VPN, so a day-old "best" endpoint is usually fiction on a new network.
const STALE_THRESHOLD_SECS: u64 = 6 * 60 * 60; // 6 hours

/// Drop an endpoint after this many consecutive failed attempts with no success
/// in between. This is what evicts peers that stopped answering (e.g. after a
/// network change) instead of letting `quick_reconnect` keep timing out on them.
const EVICT_AFTER_CONSECUTIVE_FAILURES: u32 = 3;

/// How long to wait for the cross-process cache lock. Past this the mutation is
/// **skipped**, not performed unlocked: the cache is learned, non-authoritative
/// state, so losing one update is harmless and writing over another process's
/// update is the bug this lock exists to prevent.
const LOCK_WAIT: Duration = Duration::from_millis(1500);

/// Written into every cache file so a reader can tell a legacy layout from the
/// current one instead of guessing from whichever fields happen to be present.
const CACHE_VERSION: u32 = 2;
/// A stamped time this far ahead of the clock is not "recent", it is fabricated
/// or the product of a clock jump. `saturating_sub` made such an entry immortal
/// *and* permanently earn the recency bonus in `trust_score`.
const MAX_FUTURE_SKEW_SECS: u64 = 300;
/// A counter is bounded by what the writer could plausibly have observed;
/// `u32::MAX` successes in a 10-entry cache is an injection, not a history.
const MAX_SUCCESSES: u32 = 1000;
/// Anything above this is not a measured round trip (60 s).
const MAX_PLAUSIBLE_RTT_MS: u32 = 60_000;

/// Which transport produced a measurement, recorded on the entry that carries it.
///
/// Two endpoints that look identical — same IP, same port — are not the same
/// claim under QUIC and under HTTP/2: an edge that refuses UDP entirely is a
/// healthy H2 gateway and a dead QUIC one. Sharing one `successes`/`failures`
/// counter between the two is what evicted working H2 gateways after three
/// QUIC probes failed, and made every later connect pay for a full scan again.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug, Default)]
#[serde(rename_all = "lowercase")]
pub enum TransportKind {
    #[default]
    Quic,
    H2,
}

/// The transport the MASQUE tunnel would actually use right now.
///
/// One function answers "which transport am I in" so that no writer or reader has
/// to re-derive it from the environment — that derivation is how the two ends of
/// the cache disagreed before.
pub fn active_masque_transport() -> TransportKind {
    if crate::masque_h2::enabled() {
        TransportKind::H2
    } else {
        TransportKind::Quic
    }
}

/// Provisioning (account registration / MASQUE enrollment) makes network calls to
/// Cloudflare that can take several seconds, so its cross-process lock waits much
/// longer and treats the holder as stale much later than the fast cache lock.
const PROVISION_LOCK_WAIT: Duration = Duration::from_secs(20);

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct EndpointsCache {
    /// `0` means "written by a version that had no schema field".
    #[serde(default)]
    pub version: u32,
    #[serde(default)]
    pub written_at: u64,
    /// Both collections default so a partial or older document can never fatal a
    /// reader that only needs one of them.
    #[serde(default)]
    pub masque: Vec<CachedEndpoint>,
    #[serde(default)]
    pub wireguard: Vec<CachedEndpoint>,
}

/// What sanitising a persisted cache had to throw away.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Rejected {
    pub future_timestamp: u32,
    pub implausible_address: u32,
    pub clamped_counters: u32,
    pub implausible_rtt: u32,
}

impl Rejected {
    pub fn is_empty(&self) -> bool {
        *self == Rejected::default()
    }
}

fn address_is_plausible(addr: SocketAddr) -> bool {
    let ip = addr.ip();
    // A learned-endpoint cache must never hand the tunnel a loopback,
    // link-local, multicast or "this host" address: those are the targets a
    // hostile local writer would plant to make the engine connect to something
    // it was never shown by a scan.
    let v4_link_local = match ip {
        IpAddr::V4(v4) => v4.is_link_local(),
        IpAddr::V6(v6) => v6.segments()[0] & 0xffc0 == 0xfe80,
    };
    !(ip.is_loopback() || ip.is_unspecified() || v4_link_local || ip.is_multicast())
}

/// Validate untrusted on-disk entries before anything scores or connects with
/// them. Mutates in place, returns the tally of what was dropped or clamped.
pub fn sanitise(endpoints: &mut Vec<CachedEndpoint>, now: u64) -> Rejected {
    let mut out = Rejected::default();
    for e in endpoints.iter_mut() {
        if e.successes > MAX_SUCCESSES || e.failures > MAX_SUCCESSES {
            out.clamped_counters += 1;
            e.successes = e.successes.min(MAX_SUCCESSES);
            e.failures = e.failures.min(MAX_SUCCESSES);
        }
        if e.rtt_ms > MAX_PLAUSIBLE_RTT_MS {
            out.implausible_rtt += 1;
            e.rtt_ms = 0;
        }
    }
    let mut kept = Vec::with_capacity(endpoints.len());
    for e in endpoints.drain(..) {
        if e.timestamp > now.saturating_add(MAX_FUTURE_SKEW_SECS) {
            out.future_timestamp += 1;
            continue;
        }
        if !address_is_plausible(e.addr) {
            out.implausible_address += 1;
            continue;
        }
        kept.push(e);
    }
    *endpoints = kept;
    let rejected = (out.future_timestamp + out.implausible_address) as u64;
    if rejected > 0 {
        crate::counters::bump_by(&crate::counters::CACHE_ENTRIES_REJECTED, rejected);
    }
    out
}

#[derive(Serialize, Deserialize, Clone)]
pub struct CachedEndpoint {
    pub addr: SocketAddr,
    pub timestamp: u64,
    /// Round-trip time in milliseconds (0 means unknown / legacy entry).
    #[serde(default)]
    pub rtt_ms: u32,
    /// Number of successful connections through this endpoint.
    #[serde(default)]
    pub successes: u32,
    /// Number of failed connection attempts.
    #[serde(default)]
    pub failures: u32,
    /// Consecutive failures since the last success. Reset on success; used to
    /// evict endpoints that died (e.g. after a network change).
    #[serde(default)]
    pub consecutive_failures: u32,
    /// Which transport this measurement came from. Entries from another transport
    /// are not shown to a connect that will not use it — and a legacy entry with
    /// no field decodes as `Quic`, which is what every pre-v2 file meant.
    #[serde(default)]
    pub transport: TransportKind,
    /// Which measurement produced `rtt_ms`. Legacy files decode as
    /// `HandshakeProbe`, which is what every pre-existing writer did.
    #[serde(default)]
    pub measurement: Measurement,
}

impl CachedEndpoint {
    /// Trust score: weighted success rate, RTT, recency, minus a penalty for
    /// recent consecutive failures. Higher is better. Always finite (no NaN),
    /// so ordering by it is well-defined.
    pub fn trust_score(&self) -> f64 {
        self.trust_score_for(self.measurement)
    }

    /// Trust score as seen by a consumer whose own numbers are of `expected`
    /// kind. When the entry was measured differently, the RTT term is dropped
    /// outright — not folded in, and not treated as a missing (zero) reading,
    /// which would silently rank it with the "unknown latency" crowd.
    pub fn trust_score_for(&self, expected: Measurement) -> f64 {
        let comparable = self.measurement == expected;
        let total = self.successes + self.failures;
        let base = if total == 0 {
            // No history — neutral score based on RTT only.
            if !comparable {
                30.0
            } else if self.rtt_ms > 0 {
                50.0 - (self.rtt_ms as f64 * 0.1).min(40.0)
            } else {
                30.0
            }
        } else {
            let rate = self.successes as f64 / total as f64;
            let rtt_penalty = if !comparable {
                0.0
            } else if self.rtt_ms > 0 {
                (self.rtt_ms as f64 * 0.05).min(20.0)
            } else {
                10.0
            };
            let age_secs = now_secs().saturating_sub(self.timestamp);
            let recency = if age_secs < 3600 {
                10.0
            } else if age_secs < 86_400 {
                5.0
            } else {
                0.0
            };
            (rate * 70.0) - rtt_penalty + recency
        };
        // A flapping endpoint sinks fast so we stop preferring it.
        base - (self.consecutive_failures as f64 * 15.0)
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Drop entries older than `STALE_THRESHOLD_SECS`, then validate what is left.
fn decay_stale(endpoints: &mut Vec<CachedEndpoint>) {
    let now = now_secs();
    endpoints.retain(|e| now.saturating_sub(e.timestamp) < STALE_THRESHOLD_SECS);
    let rejected = sanitise(endpoints, now);
    if !rejected.is_empty() {
        log::warn!("[cache] rejected untrusted entries: {rejected:?}");
    }
}

/// Move an unreadable cache aside *while the caller holds the lock*, under a
/// name that cannot collide with a previous bad file.
fn quarantine_corrupt(path: &Path) {
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut bad = path.as_os_str().to_os_string();
    bad.push(format!(".corrupt.{}.{}", std::process::id(), seq));
    match std::fs::rename(path, PathBuf::from(&bad)) {
        Ok(()) => log::error!(
            "[cache] {} was unreadable; preserved as {} for inspection",
            path.display(),
            PathBuf::from(&bad).display()
        ),
        Err(e) => log::error!("[cache] could not preserve corrupt {}: {e}", path.display()),
    }
}

fn parses_as_cache(path: &Path) -> bool {
    match std::fs::read_to_string(path) {
        Ok(data) => serde_json::from_str::<EndpointsCache>(&data).is_ok(),
        // Absent or unreadable is not "corrupt": nothing is preserved, and the
        // caller starts from an empty cache.
        Err(_) => true,
    }
}

pub fn cache_path(base_config: &str) -> PathBuf {
    let base = Path::new(base_config);
    if base.is_dir() {
        base.join("aether-endpoints.json")
    } else if let Some(parent) = base.parent() {
        if parent.as_os_str().is_empty() {
            PathBuf::from("aether-endpoints.json")
        } else {
            parent.join("aether-endpoints.json")
        }
    } else {
        PathBuf::from("aether-endpoints.json")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Cross-process advisory lock
//
// The cache file is a read-modify-write hot spot shared by the connect engine
// and the standalone scan engine (separate processes). Without a lock, two
// load-save cycles race and silently lose each other's updates. This is a
// lockfile-based advisory lock: best-effort (we proceed after LOCK_WAIT rather
// than block forever) and self-healing (a lock left by a killed process is
// stolen once it goes stale).
// ─────────────────────────────────────────────────────────────────────────────
/// Cross-process serialisation for one read-modify-write of the cache, held on
/// an advisory lock kept by the OS on an open file descriptor.
///
/// The previous implementation was a `create_new` marker file whose age decided
/// whether it could be deleted. That failed in three ways at once: a live holder
/// older than five seconds lost the lock to the next arrival; an `elapsed()`
/// error mapped to `unwrap_or(true)`, i.e. "always stale", so the lock was
/// routinely stolen; the retry `continue`d without re-checking the deadline and
/// could spin; and `Drop` unlinked whichever file existed, not just its own.
struct CacheGuard {
    file: std::fs::File,
}

impl CacheGuard {
    /// `wait` is how long to keep retrying before giving up. Scan writers pass
    /// `Duration::ZERO`: they run on async workers, and sleeping there to wait
    /// for a lock another process holds stalls the very probes whose PTO the
    /// wait is inflating.
    fn acquire(cache_file: &Path, wait: Duration) -> Option<CacheGuard> {
        let path = {
            let mut s = cache_file.as_os_str().to_os_string();
            s.push(".lock");
            PathBuf::from(s)
        };
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                let _ = std::fs::create_dir_all(parent);
            }
        }
        let file = match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
        {
            Ok(f) => f,
            Err(e) => {
                log::warn!("[cache] cannot open lock {}: {e}", path.display());
                return None;
            }
        };
        let deadline = Instant::now() + wait;
        loop {
            match file.try_lock_exclusive() {
                Ok(()) => return Some(CacheGuard { file }),
                Err(_) => {
                    if deadline.checked_duration_since(Instant::now()).is_none() {
                        log::error!(
                            "[cache] {} is locked by another process; skipping this update",
                            path.display()
                        );
                        return None;
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
            }
        }
    }
}

// `fs2::FileExt::unlock` shares its name with the (newer) inherent
// `std::fs::File::unlock`, which trips the MSRV check the same way it does for
// `ProvisionGuard` below.
#[allow(clippy::incompatible_msrv)]
impl Drop for CacheGuard {
    fn drop(&mut self) {
        // Release the advisory lock; the file stays, exactly like the
        // provisioning guard, so two processes can never be holding "the" lock
        // file that the other one unlinked.
        let _ = self.file.unlock();
    }
}

fn is_process_alive(pid: u32) -> bool {
    #[cfg(windows)]
    {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::Threading::{
            GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
        };
        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if handle.is_null() {
                let err = std::io::Error::last_os_error();
                return err.raw_os_error() == Some(5);
            }
            let mut code = 0u32;
            let ok = GetExitCodeProcess(handle, &mut code);
            CloseHandle(handle);
            ok != 0 && code == 259 // 259 == STILL_ACTIVE
        }
    }
    #[cfg(unix)]
    {
        unsafe { libc::kill(pid as i32, 0) == 0 }
    }
    #[cfg(not(any(windows, unix)))]
    {
        true
    }
}

/// A held cross-process lock serializing one-time work that must not run twice
/// concurrently — specifically account provisioning / MASQUE enrollment, so a
/// scan process and a connect process don't both register a device (device churn)
/// or race writes to the shared identity file. Never fails open. Released on drop.
pub struct ProvisionGuard {
    file: std::fs::File,
}

#[allow(clippy::incompatible_msrv)]
impl ProvisionGuard {
    pub fn try_acquire(lock_file_path: &Path, wait: Duration) -> Result<Self> {
        if let Some(parent) = lock_file_path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    AetherError::Other(format!(
                        "create dir for provision lock {}: {e}",
                        parent.display()
                    ))
                })?;
            }
        }
        let start = Instant::now();
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(lock_file_path)
            .map_err(|e| AetherError::Other(format!("open provision lock {}: {e}", lock_file_path.display())))?;

        loop {
            match file.try_lock_exclusive() {
                Ok(()) => {
                    use std::io::{Seek, SeekFrom, Write as _};
                    let mut f = &file;
                    f.seek(SeekFrom::Start(0)).map_err(|e| {
                        let _ = file.unlock();
                        AetherError::Other(format!("seek provision lock {}: {e}", lock_file_path.display()))
                    })?;
                    f.set_len(0).map_err(|e| {
                        let _ = file.unlock();
                        AetherError::Other(format!("truncate provision lock {}: {e}", lock_file_path.display()))
                    })?;
                    writeln!(f, "pid={}", std::process::id()).map_err(|e| {
                        let _ = file.unlock();
                        AetherError::Other(format!("write pid to provision lock {}: {e}", lock_file_path.display()))
                    })?;
                    f.flush().map_err(|e| {
                        let _ = file.unlock();
                        AetherError::Other(format!("flush provision lock {}: {e}", lock_file_path.display()))
                    })?;

                    // Also write unlocked companion owner file for non-blocking diagnostics
                    let mut owner_path = lock_file_path.as_os_str().to_os_string();
                    owner_path.push(".owner");
                    let _ = std::fs::write(&owner_path, format!("pid={}\n", std::process::id()));

                    return Ok(Self { file });
                }
                Err(_) => {
                    if start.elapsed() >= wait {
                        let mut owner_path = lock_file_path.as_os_str().to_os_string();
                        owner_path.push(".owner");
                        let content = std::fs::read_to_string(&owner_path)
                            .or_else(|_| std::fs::read_to_string(lock_file_path));
                        let owner_diag = match content {
                            Ok(content) => {
                                let pid_str = content
                                    .lines()
                                    .find(|l| l.starts_with("pid="))
                                    .map(|l| l.trim_start_matches("pid=").trim())
                                    .unwrap_or("unknown");
                                if let Ok(pid) = pid_str.parse::<u32>() {
                                    let alive = is_process_alive(pid);
                                    format!("held by pid={pid} (alive={alive})")
                                } else {
                                    format!("raw lock content: {content:?}")
                                }
                            }
                            Err(e) => format!("could not inspect lock owner: {e}"),
                        };
                        return Err(AetherError::Other(format!(
                            "provisioning lock acquisition timed out after {:?} on {} [{}]",
                            wait,
                            lock_file_path.display(),
                            owner_diag
                        )));
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
            }
        }
    }
}

#[allow(clippy::incompatible_msrv)]
impl Drop for ProvisionGuard {
    fn drop(&mut self) {
        let _ = self.file.unlock();
        // The lock file is permanently retained to avoid unlinked-inode races across processes.
    }
}

/// Acquire the provisioning lock, sited next to the endpoint cache. Held until
/// the returned guard is dropped. Never fails open.
pub fn provision_lock(base_config: &str) -> Result<ProvisionGuard> {
    let mut p = cache_path(base_config).into_os_string();
    p.push(".provision.lock");
    ProvisionGuard::try_acquire(&PathBuf::from(p), PROVISION_LOCK_WAIT)
}

/// Write `data` to `path` atomically (temp file + rename) so a crash or a
/// concurrent reader never observes a half-written / truncated file.
fn write_atomic(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    // Per-process, per-call unique temp name. A shared "<file>.tmp" made two engine
    // processes (scan + connect) collide on the same temp and fail the rename with
    // ERROR_ACCESS_DENIED on Windows; a unique name removes that collision.
    let seq = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let mut tmp = path.as_os_str().to_os_string();
    tmp.push(format!(".{}.{}.tmp", std::process::id(), seq));
    let tmp = PathBuf::from(tmp);
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    // std::fs::rename replaces an existing destination on both Unix and Windows.
    // Windows can still transiently return ERROR_ACCESS_DENIED when the destination
    // is briefly held (AV/indexer, or a racing writer), so retry with backoff.
    let mut last = Ok(());
    for attempt in 0..8u32 {
        match std::fs::rename(&tmp, path) {
            Ok(()) => return Ok(()),
            Err(e) => {
                last = Err(e);
                std::thread::sleep(Duration::from_millis(20 * u64::from(attempt + 1)));
            }
        }
    }
    let _ = std::fs::remove_file(&tmp);
    last
}

/// Run `f` under the cross-process lock: acquire, load (pruning stale), mutate,
/// then persist atomically. The single entry point for every mutation.
/// Whether a mutation actually reached the file.
///
/// `with_cache` deliberately **skips** rather than writing unlocked when another
/// process holds the lock, so "we updated the cache" was a claim nobody could
/// check: the caller could not retry, the log could not say which endpoint stayed
/// stale, and a test could not tell a lost update apart from an intentional skip.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mutation {
    Applied,
    Skipped,
}

impl Mutation {
    pub fn was_skipped(self) -> bool {
        self == Mutation::Skipped
    }
}

fn with_cache<F: FnOnce(&mut EndpointsCache)>(base_config: &str, f: F) -> Mutation {
    with_cache_locked(base_config, f, LOCK_WAIT)
}

/// As `with_cache`, but never blocks: a contended lock means the update is
/// skipped and logged, not that an async worker sleeps for it.
fn with_cache_nowait<F: FnOnce(&mut EndpointsCache)>(base_config: &str, f: F) -> Mutation {
    with_cache_locked(base_config, f, Duration::ZERO)
}

fn with_cache_locked<F: FnOnce(&mut EndpointsCache)>(
    base_config: &str,
    f: F,
    wait: Duration,
) -> Mutation {
    let path = cache_path(base_config);
    let Some(_guard) = CacheGuard::acquire(&path, wait) else {
        return Mutation::Skipped;
    };
    if !parses_as_cache(&path) {
        quarantine_corrupt(&path);
    }
    let mut cache = load_endpoints(base_config);
    f(&mut cache);
    cache.version = CACHE_VERSION;
    cache.written_at = now_secs();
    save_endpoints(base_config, &cache);
    Mutation::Applied
}

/// Read the cache. Never writes, never renames: a read that destroyed evidence
/// (or a working file, when the rename raced) made "I looked at the cache" an
/// operation with side effects, and `get_*_sorted` are called on the connect
/// path.
pub fn load_endpoints(base_config: &str) -> EndpointsCache {
    let path = cache_path(base_config);
    let mut cache = match std::fs::read_to_string(&path) {
        Ok(data) => match serde_json::from_str::<EndpointsCache>(&data) {
            Ok(c) => c,
            Err(e) => {
                log::warn!(
                    "[cache] {} is unreadable ({e}); starting empty without touching it",
                    path.display()
                );
                EndpointsCache::default()
            }
        },
        Err(_) => EndpointsCache::default(),
    };
    decay_stale(&mut cache.masque);
    decay_stale(&mut cache.wireguard);
    cache
}

pub fn save_endpoints(base_config: &str, cache: &EndpointsCache) {
    let path = cache_path(base_config);
    match serde_json::to_string_pretty(cache) {
        Ok(data) => {
            if let Err(e) = write_atomic(&path, data.as_bytes()) {
                log::warn!("[cache] failed to persist {}: {e}", path.display());
            }
        }
        Err(e) => log::warn!("[cache] failed to encode endpoints: {e}"),
    }
}

/// Which act produced an RTT number.
///
/// A handshake probe and a full Ironclad HTTP round trip are not the same
/// measurement — the second includes a real request/response over the tunnel, so
/// it is systematically larger, and ranking the two together let the cheaper
/// number decide the order. Entries therefore say how they were measured, and a
/// reader that is comparing against one kind ignores the RTT term of the other
/// rather than treating it as absent (which `sanitise` already reads as unknown).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Measurement {
    /// QUIC/TLS handshake or WireGuard handshake probe — the cheap default.
    #[default]
    HandshakeProbe,
    /// Real HTTP round trip through a live tunnel (Ironclad mode).
    HttpRoundTrip,
}

fn upsert(
    list: &mut Vec<CachedEndpoint>,
    endpoints: Vec<(SocketAddr, u32)>,
    transport: TransportKind,
    measurement: Measurement,
) {
    let now = now_secs();
    for (addr, rtt_ms) in endpoints.into_iter().rev() {
        // Preserve accumulated trust when re-adding a known endpoint.
        let prev = list.iter().find(|e| e.addr == addr).cloned();
        list.retain(|e| e.addr != addr);
        list.insert(
            0,
            CachedEndpoint {
                addr,
                timestamp: now,
                rtt_ms,
                successes: prev.as_ref().map(|p| p.successes).unwrap_or(0),
                failures: prev.as_ref().map(|p| p.failures).unwrap_or(0),
                consecutive_failures: 0,
                transport,
                measurement,
            },
        );
    }
    list.truncate(MAX_CACHED);
}

/// Scan hits, measured however `measurement` says.
pub fn add_to_masque_with_rtt(
    base_config: &str,
    endpoints: Vec<(SocketAddr, u32)>,
    measurement: Measurement,
) -> Mutation {
    let transport = active_masque_transport();
    with_cache_nowait(base_config, move |cache| {
        upsert(&mut cache.masque, endpoints, transport, measurement)
    })
}

/// Cached masque endpoints that were measured over `transport`, best first.
pub fn get_masque_sorted_for(base_config: &str, transport: TransportKind) -> Vec<(SocketAddr, u32)> {
    let mut eps = load_endpoints(base_config).masque;
    eps.retain(|e| e.transport == transport);
    // The connect path compares against handshake numbers.
    sorted(eps, Measurement::HandshakeProbe)
}

/// Cached masque endpoints for the transport the tunnel would use now.
pub fn get_masque_sorted(base_config: &str) -> Vec<(SocketAddr, u32)> {
    get_masque_sorted_for(base_config, active_masque_transport())
}

pub fn add_to_wireguard_with_rtt(
    base_config: &str,
    endpoints: Vec<(SocketAddr, u32)>,
    measurement: Measurement,
) -> Mutation {
    with_cache_nowait(base_config, move |cache| {
        upsert(&mut cache.wireguard, endpoints, TransportKind::default(), measurement)
    })
}

/// Cached wireguard endpoints sorted by trust score (highest first).
pub fn get_wireguard_sorted(base_config: &str) -> Vec<(SocketAddr, u32)> {
    sorted(load_endpoints(base_config).wireguard, Measurement::HandshakeProbe)
}

fn sorted(mut eps: Vec<CachedEndpoint>, expected: Measurement) -> Vec<(SocketAddr, u32)> {
    // total_cmp is NaN-safe; trust_score is finite regardless.
    eps.sort_by(|a, b| {
        b.trust_score_for(expected)
            .total_cmp(&a.trust_score_for(expected))
    });
    eps.into_iter().map(|e| (e.addr, e.rtt_ms)).collect()
}

/// Record a successful connection. Upserts: an endpoint reached via the
/// enroll/anycast fallback (never a scan hit) still accrues trust.
pub fn record_success(base_config: &str, addr: SocketAddr, is_masque: bool) -> Mutation {
    let transport = if is_masque { active_masque_transport() } else { TransportKind::default() };
    with_cache(base_config, move |cache| {
        let list = if is_masque {
            &mut cache.masque
        } else {
            &mut cache.wireguard
        };
        record_success_on(list, addr, transport, now_secs());
    })
}

fn record_success_on(
    list: &mut Vec<CachedEndpoint>,
    addr: SocketAddr,
    transport: TransportKind,
    now: u64,
) {
    if let Some(ep) = list.iter_mut().find(|e| e.addr == addr && e.transport == transport) {
        ep.successes = ep.successes.saturating_add(1);
        ep.consecutive_failures = 0;
        ep.timestamp = now;
    } else {
        list.insert(
            0,
            CachedEndpoint {
                addr,
                timestamp: now,
                rtt_ms: 0,
                successes: 1,
                failures: 0,
                consecutive_failures: 0,
                transport,
                // A connect that succeeds proves reachability, not latency: the
                // entry keeps whatever measurement it already carried, or none.
                measurement: Measurement::default(),
            },
        );
        list.truncate(MAX_CACHED);
    }
}

/// Record a failed connection attempt. Evicts the endpoint after
/// `EVICT_AFTER_CONSECUTIVE_FAILURES` consecutive failures so a peer that died
/// (e.g. the network changed) stops being tried first on every reconnect.
///
/// The strike lands on the entry for *this* transport only. Probing an H2-capable
/// gateway over QUIC used to add a failure that evicted it from the H2 list too,
/// so a gateway that had never once failed over the transport in use was deleted
/// after three failures of a transport we were not even using.
pub fn record_failure(base_config: &str, addr: SocketAddr, is_masque: bool) -> Mutation {
    let transport = if is_masque { active_masque_transport() } else { TransportKind::default() };
    with_cache(base_config, move |cache| {
        let list = if is_masque {
            &mut cache.masque
        } else {
            &mut cache.wireguard
        };
        record_failure_on(list, addr, transport, now_secs());
    })
}

fn record_failure_on(
    list: &mut Vec<CachedEndpoint>,
    addr: SocketAddr,
    transport: TransportKind,
    now: u64,
) {
    if let Some(idx) = list.iter().position(|e| e.addr == addr && e.transport == transport) {
        list[idx].failures = list[idx].failures.saturating_add(1);
        list[idx].consecutive_failures = list[idx].consecutive_failures.saturating_add(1);
        list[idx].timestamp = now;
        if list[idx].consecutive_failures >= EVICT_AFTER_CONSECUTIVE_FAILURES {
            list.remove(idx);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(addr: &str, stamp: u64, succ: u32, rtt: u32) -> CachedEndpoint {
        CachedEndpoint {
            addr: addr.parse().unwrap(),
            timestamp: stamp,
            rtt_ms: rtt,
            successes: succ,
            failures: 0,
            consecutive_failures: 0,
            transport: TransportKind::default(),
            measurement: Measurement::default(),
        }
    }

    /// A "healthy" gateway is a claim about a transport, not just an address.
    /// Sharing one failure counter across QUIC and H2 evicted gateways that had
    /// never failed over the transport the tunnel was actually using.
    #[test]
    fn a_failure_over_one_transport_cannot_evict_the_other() {
        let dir = std::env::temp_dir().join(format!("aether_cache_transport_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let base = dir.join("aether.toml").to_string_lossy().to_string();
        let gw: SocketAddr = "162.159.193.1:443".parse().unwrap();

        // The H2-mode shape: this gateway is only ever known to work over H2.
        record_success_h2(&base, gw);
        for _ in 0..EVICT_AFTER_CONSECUTIVE_FAILURES {
            record_failure_quic(&base, gw);
        }
        assert_eq!(
            get_masque_sorted_for(&base, TransportKind::H2).len(),
            1,
            "a gateway that never failed over H2 must not be evicted by QUIC failures"
        );

        // And the strikes do land where they belong — an assertion that passes on
        // an empty list would prove nothing.
        record_success_quic(&base, gw);
        assert_eq!(get_masque_sorted_for(&base, TransportKind::Quic).len(), 1);
        for _ in 0..EVICT_AFTER_CONSECUTIVE_FAILURES {
            record_failure_quic(&base, gw);
        }
        assert!(get_masque_sorted_for(&base, TransportKind::Quic).is_empty());
        assert_eq!(get_masque_sorted_for(&base, TransportKind::H2).len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A success over one transport must not launder another transport's record.
    #[test]
    fn a_success_over_one_transport_does_not_reset_the_other() {
        let dir = std::env::temp_dir().join(format!("aether_cache_xport_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let base = dir.join("aether.toml").to_string_lossy().to_string();
        let gw: SocketAddr = "162.159.193.1:443".parse().unwrap();

        record_success_quic(&base, gw);
        record_failure_quic(&base, gw);
        record_success_h2(&base, gw);
        with_cache(&base, |cache| {
            let quic = cache
                .masque
                .iter()
                .find(|e| e.addr == gw && e.transport == TransportKind::Quic)
                .expect("quic entry");
            assert_eq!(
                quic.consecutive_failures, 1,
                "the H2 connect says nothing about this endpoint over QUIC"
            );
        });
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A file written before the discriminator existed carries measurements that
    /// were all taken over QUIC, so it must decode that way rather than be
    /// invisible (or worse, be read as H2 history).
    #[test]
    fn a_legacy_entry_without_a_transport_is_a_quic_measurement() {
        let dir = std::env::temp_dir().join(format!("aether_cache_legacy_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let base = dir.join("aether.toml").to_string_lossy().to_string();
        // Stamped "now": an old timestamp is pruned as stale before anything can
        // look at its transport, and the test would pass for the wrong reason.
        let doc = format!(
            r#"{{"version":2,"written_at":{n},"masque":[{{"addr":"162.159.193.1:443","timestamp":{n},"rtt_ms":30,"successes":4,"failures":0,"consecutive_failures":0}}],"wireguard":[]}}"#,
            n = now_secs()
        );
        std::fs::write(cache_path(&base), doc).unwrap();
        let entries = get_masque_sorted_for(&base, TransportKind::Quic);
        assert_eq!(entries.len(), 1, "legacy entry must decode, not vanish");
        assert!(get_masque_sorted_for(&base, TransportKind::H2).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// These helpers pin the transport explicitly so the assertions are about the
    /// cache, not about the ambient `AETHER_MASQUE_HTTP2` value another test in
    /// this binary may have left set.
    fn record_failure_quic(base: &str, addr: SocketAddr) {
        with_cache(base, |cache| {
            record_failure_on(&mut cache.masque, addr, TransportKind::Quic, now_secs())
        });
    }

    fn record_success_quic(base: &str, addr: SocketAddr) {
        with_cache(base, |cache| {
            record_success_on(&mut cache.masque, addr, TransportKind::Quic, now_secs())
        });
    }

    fn record_success_h2(base: &str, addr: SocketAddr) {
        with_cache(base, |cache| {
            record_success_on(&mut cache.masque, addr, TransportKind::H2, now_secs())
        });
    }

    /// A cached endpoint is untrusted input. The scanner is not the only writer
    /// to that file, and the entry that wins `trust_score` decides where every
    /// later tunnel connection goes.
    #[test]
    fn sanitising_rejects_fabricated_history() {
        let now = 1_800_000_000;
        let mut list = vec![
            entry("93.184.216.34:443", now, 5, 40),
            // A year ahead: `saturating_sub` made it immortal *and* max recency.
            entry("93.184.216.35:443", now + 3600, 5, 40),
            // The metadata service, planted as a "great" gateway.
            entry("169.254.169.254:443", now, 9, 1),
            entry("127.0.0.1:1080", now, 9, 1),
            entry("224.0.0.5:443", now, 9, 1),
        ];
        let rejected = sanitise(&mut list, now);
        assert_eq!(rejected.future_timestamp, 1, "{rejected:?}");
        assert_eq!(rejected.implausible_address, 3, "{rejected:?}");
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].addr.port(), 443);

        // Counters clamp rather than drop: the address may be real.
        let mut clamped = vec![entry("93.184.216.34:443", now, u32::MAX, 999_999)];
        let r = sanitise(&mut clamped, now);
        assert_eq!(r.clamped_counters, 1);
        assert_eq!(r.implausible_rtt, 1);
        assert_eq!(clamped[0].successes, MAX_SUCCESSES);
        assert_eq!(clamped[0].rtt_ms, 0, "an impossible rtt must not earn points");
    }

    #[test]
    fn a_read_does_not_disturb_the_file_on_disk() {
        let dir = std::env::temp_dir().join(format!("aether_cache_read_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let base = dir.join("aether.toml").to_string_lossy().to_string();
        let path = cache_path(&base);
        std::fs::write(&path, b"{ not json at all").unwrap();

        let cache = load_endpoints(&base);
        assert!(cache.masque.is_empty());
        assert!(path.exists(), "a read must not rename or delete the cache file");
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "{ not json at all",
            "a read must not modify the file"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn partial_and_legacy_documents_still_parse() {
        // Data-model rule: a reader must never fatal on a missing optional field.
        let c: EndpointsCache = serde_json::from_str("{}").unwrap();
        assert_eq!(c.version, 0);
        let c: EndpointsCache = serde_json::from_str(r#"{"masque":[]}"#).unwrap();
        assert!(c.wireguard.is_empty());

        let dir = std::env::temp_dir().join(format!("aether_cache_ver_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let base = dir.join("aether.toml").to_string_lossy().to_string();
        add_to_masque_with_rtt(&base, vec![("93.184.216.34:443".parse().unwrap(), 42)], Measurement::default());
        let written = std::fs::read_to_string(cache_path(&base)).unwrap();
        let doc: EndpointsCache = serde_json::from_str(&written).unwrap();
        assert_eq!(doc.version, CACHE_VERSION, "a writer must stamp its schema");
        assert!(doc.written_at > 0);
        assert_eq!(doc.masque.len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn ep(addr: &str, successes: u32, failures: u32, consec: u32, rtt: u32) -> CachedEndpoint {
        CachedEndpoint {
            addr: addr.parse().unwrap(),
            timestamp: now_secs(),
            rtt_ms: rtt,
            successes,
            failures,
            consecutive_failures: consec,
            transport: TransportKind::default(),
            measurement: Measurement::HandshakeProbe,
        }
    }

    /// A handshake probe and a real HTTP round trip are different numbers. The
    /// cheaper one must not win the ranking by being cheaper.
    #[test]
    fn an_incomparable_measurement_contributes_no_rtt_term() {
        let fast_probe = ep("1.1.1.1:443", 3, 0, 0, 5);
        let mut slow_http = ep("2.2.2.2:443", 3, 0, 0, 400);
        slow_http.measurement = Measurement::HttpRoundTrip;

        // Same kind: the 400 ms entry really is behind the 5 ms one.
        assert!(
            fast_probe.trust_score_for(Measurement::HandshakeProbe)
                > slow_http.trust_score_for(Measurement::HandshakeProbe)
        );
        // Different kind: the RTT term is dropped, so history alone decides and
        // the two tie rather than the probe pulling ahead on latency.
        let probe_as_http = fast_probe.trust_score_for(Measurement::HttpRoundTrip);
        let tied = slow_http.trust_score_for(Measurement::HttpRoundTrip);
        assert!(
            (probe_as_http - tied).abs() < f64::EPSILON,
            "expected {probe_as_http} == {tied}"
        );
        // And a dropped term is not the same as a zero reading, which `sanitise`
        // would otherwise treat as "latency unknown".
        let mut unknown = ep("3.3.3.3:443", 3, 0, 0, 0);
        unknown.measurement = Measurement::HttpRoundTrip;
        assert!(
            (probe_as_http - unknown.trust_score_for(Measurement::HttpRoundTrip)).abs()
                > f64::EPSILON,
            "an incomparable RTT must not be scored as an absent one"
        );
    }

    #[test]
    fn trust_score_is_finite_and_orders_by_success() {
        let good = ep("1.1.1.1:443", 10, 0, 0, 20);
        let bad = ep("2.2.2.2:443", 1, 9, 0, 20);
        assert!(good.trust_score().is_finite());
        assert!(bad.trust_score().is_finite());
        assert!(good.trust_score() > bad.trust_score());
    }

    #[test]
    fn consecutive_failures_sink_the_score() {
        let healthy = ep("1.1.1.1:443", 5, 0, 0, 20);
        let flapping = ep("1.1.1.1:443", 5, 0, 3, 20);
        assert!(healthy.trust_score() > flapping.trust_score());
    }

    #[test]
    fn zero_history_scores_are_finite() {
        assert!(ep("1.1.1.1:443", 0, 0, 0, 0).trust_score().is_finite());
        assert!(ep("1.1.1.1:443", 0, 0, 0, 500).trust_score().is_finite());
    }

    #[test]
    fn sorted_prefers_higher_trust() {
        let eps = vec![
            ep("2.2.2.2:443", 1, 9, 0, 20),
            ep("1.1.1.1:443", 10, 0, 0, 20),
        ];
        let out = sorted(eps, Measurement::HandshakeProbe);
        assert_eq!(out[0].0.to_string(), "1.1.1.1:443");
    }

    #[test]
    fn lock_path_and_atomic_roundtrip() {
        let dir = std::env::temp_dir().join(format!("aether-cache-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let base = dir.join("aether.toml");
        let base = base.to_string_lossy().to_string();
        add_to_masque_with_rtt(&base, vec![("1.1.1.1:443".parse().unwrap(), 42)], Measurement::default());
        let got = get_masque_sorted(&base);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].1, 42);
        record_success(&base, "1.1.1.1:443".parse().unwrap(), true);
        record_failure(&base, "9.9.9.9:443".parse().unwrap(), true); // absent -> no-op
        let _ = std::fs::remove_dir_all(&dir);
    }
}
