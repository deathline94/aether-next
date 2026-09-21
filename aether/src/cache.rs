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
}

impl CachedEndpoint {
    /// Trust score: weighted success rate, RTT, recency, minus a penalty for
    /// recent consecutive failures. Higher is better. Always finite (no NaN),
    /// so ordering by it is well-defined.
    pub fn trust_score(&self) -> f64 {
        let total = self.successes + self.failures;
        let base = if total == 0 {
            // No history — neutral score based on RTT only.
            if self.rtt_ms > 0 {
                50.0 - (self.rtt_ms as f64 * 0.1).min(40.0)
            } else {
                30.0
            }
        } else {
            let rate = self.successes as f64 / total as f64;
            let rtt_penalty = if self.rtt_ms > 0 {
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
    fn acquire(cache_file: &Path) -> Option<CacheGuard> {
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
        let deadline = Instant::now() + LOCK_WAIT;
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
fn with_cache<F: FnOnce(&mut EndpointsCache)>(base_config: &str, f: F) {
    let path = cache_path(base_config);
    let Some(_guard) = CacheGuard::acquire(&path) else {
        return;
    };
    if !parses_as_cache(&path) {
        quarantine_corrupt(&path);
    }
    let mut cache = load_endpoints(base_config);
    f(&mut cache);
    cache.version = CACHE_VERSION;
    cache.written_at = now_secs();
    save_endpoints(base_config, &cache);
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

fn upsert(list: &mut Vec<CachedEndpoint>, endpoints: Vec<(SocketAddr, u32)>) {
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
            },
        );
    }
    list.truncate(MAX_CACHED);
}

pub fn add_to_masque_with_rtt(base_config: &str, endpoints: Vec<(SocketAddr, u32)>) {
    with_cache(base_config, |cache| upsert(&mut cache.masque, endpoints));
}

/// Cached masque endpoints sorted by trust score (highest first).
pub fn get_masque_sorted(base_config: &str) -> Vec<(SocketAddr, u32)> {
    sorted(load_endpoints(base_config).masque)
}

pub fn add_to_wireguard_with_rtt(base_config: &str, endpoints: Vec<(SocketAddr, u32)>) {
    with_cache(base_config, |cache| upsert(&mut cache.wireguard, endpoints));
}

/// Cached wireguard endpoints sorted by trust score (highest first).
pub fn get_wireguard_sorted(base_config: &str) -> Vec<(SocketAddr, u32)> {
    sorted(load_endpoints(base_config).wireguard)
}

fn sorted(mut eps: Vec<CachedEndpoint>) -> Vec<(SocketAddr, u32)> {
    // total_cmp is NaN-safe; trust_score is finite regardless.
    eps.sort_by(|a, b| b.trust_score().total_cmp(&a.trust_score()));
    eps.into_iter().map(|e| (e.addr, e.rtt_ms)).collect()
}

/// Record a successful connection. Upserts: an endpoint reached via the
/// enroll/anycast fallback (never a scan hit) still accrues trust.
pub fn record_success(base_config: &str, addr: SocketAddr, is_masque: bool) {
    with_cache(base_config, |cache| {
        let list = if is_masque {
            &mut cache.masque
        } else {
            &mut cache.wireguard
        };
        if let Some(ep) = list.iter_mut().find(|e| e.addr == addr) {
            ep.successes += 1;
            ep.consecutive_failures = 0;
            ep.timestamp = now_secs();
        } else {
            list.insert(
                0,
                CachedEndpoint {
                    addr,
                    timestamp: now_secs(),
                    rtt_ms: 0,
                    successes: 1,
                    failures: 0,
                    consecutive_failures: 0,
                },
            );
            list.truncate(MAX_CACHED);
        }
    });
}

/// Record a failed connection attempt. Evicts the endpoint after
/// `EVICT_AFTER_CONSECUTIVE_FAILURES` consecutive failures so a peer that died
/// (e.g. the network changed) stops being tried first on every reconnect.
pub fn record_failure(base_config: &str, addr: SocketAddr, is_masque: bool) {
    with_cache(base_config, |cache| {
        let list = if is_masque {
            &mut cache.masque
        } else {
            &mut cache.wireguard
        };
        if let Some(idx) = list.iter().position(|e| e.addr == addr) {
            list[idx].failures += 1;
            list[idx].consecutive_failures += 1;
            list[idx].timestamp = now_secs();
            if list[idx].consecutive_failures >= EVICT_AFTER_CONSECUTIVE_FAILURES {
                list.remove(idx);
            }
        }
    });
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
        }
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
        add_to_masque_with_rtt(&base, vec![("93.184.216.34:443".parse().unwrap(), 42)]);
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
        }
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
        let out = sorted(eps);
        assert_eq!(out[0].0.to_string(), "1.1.1.1:443");
    }

    #[test]
    fn lock_path_and_atomic_roundtrip() {
        let dir = std::env::temp_dir().join(format!("aether-cache-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let base = dir.join("aether.toml");
        let base = base.to_string_lossy().to_string();
        add_to_masque_with_rtt(&base, vec![("1.1.1.1:443".parse().unwrap(), 42)]);
        let got = get_masque_sorted(&base);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].1, 42);
        record_success(&base, "1.1.1.1:443".parse().unwrap(), true);
        record_failure(&base, "9.9.9.9:443".parse().unwrap(), true); // absent -> no-op
        let _ = std::fs::remove_dir_all(&dir);
    }
}
