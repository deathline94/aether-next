//! Path MTU selection for the userspace netstack.
//!
//! WARP-safe default is 1280. On clean paths 1400 reduces packet count and
//! improves high-RTT throughput for MASQUE h2. Auto mode probes once per
//! protocol per process — the ceiling that is right for one transport is a stall
//! for another, so nothing is shared across them (see [`MtuCache`]).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{OnceLock, RwLock};
use std::time::Duration;

use tokio::net::UdpSocket;

const CANDIDATES: &[usize] = &[1400, 1280];
const SAFE_DEFAULT: usize = 1280;

/// IPv6's link minimum (RFC 8200 §5). smoltcp cannot fragment IPv6, so with a v6
/// address on the interface any MTU below this kills every v6 flow silently
/// while v4 keeps working — a configured 1000 is a broken tunnel, not a choice.
pub const IPV6_MIN_MTU: usize = 1280;

/// Resolved MTUs, keyed by protocol.
///
/// The single global answer is the bug this replaces: the 1400 that is correct
/// for MASQUE-over-TCP is a stall for WireGuard, whose outer packets carry ~60 B
/// more, and a process that connected to MASQUE first used to hand that 1400 to
/// every later WireGuard session without ever probing it (handshake fine, pages
/// never load). A protocol that has not been resolved is absent from the map, so
/// it gets its own probe.
#[derive(Debug, Default)]
pub struct MtuCache {
    by_protocol: HashMap<String, usize>,
}

impl MtuCache {
    /// Callers spell the protocol `"masque"`, `"MASQUE"`, `"wireguard"`; those are
    /// one key, not three probes.
    fn key(protocol: &str) -> String {
        protocol.trim().to_ascii_lowercase()
    }

    fn get(&self, protocol: &str) -> Option<usize> {
        self.by_protocol.get(&Self::key(protocol)).copied()
    }

    fn put(&mut self, protocol: &str, mtu: usize) {
        self.by_protocol.insert(Self::key(protocol), mtu);
    }

    /// The smallest MTU any protocol has resolved to.
    ///
    /// For readers that cannot say which protocol they are on. Under-claiming is
    /// merely conservative here; over-claiming is the WireGuard stall, so an
    /// unkeyed read must never return the largest thing it has seen.
    fn conservative(&self) -> Option<usize> {
        self.by_protocol.values().copied().min()
    }

    fn shared() -> &'static RwLock<MtuCache> {
        static CACHE: OnceLock<RwLock<MtuCache>> = OnceLock::new();
        CACHE.get_or_init(|| RwLock::new(MtuCache::default()))
    }
}

/// Shared by readers that cannot name their protocol; see [`MtuCache::conservative`].
fn cached_mtu() -> Option<usize> {
    let cache = MtuCache::shared();
    let guard = match cache.read() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    guard.conservative()
}

fn cached_for(protocol: &str) -> Option<usize> {
    let cache = MtuCache::shared();
    let guard = match cache.read() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    guard.get(protocol)
}

fn remember(protocol: &str, mtu: usize) {
    let cache = MtuCache::shared();
    let mut guard = match cache.write() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    guard.put(protocol, mtu);
}

/// Serialises `auto_probe`: several tunnels can come up at once (gool inner and
/// outer, or a reconnect racing a scan), and each probe sends its own oversized
/// datagrams at the same anycast. Under backpressure that inflates RTT for the
/// real handshake sitting next to it.
static PROBING: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Raise anything below IPv6's minimum when v6 is configured; leave it alone
/// otherwise, where a small MTU is a legitimate trade.
pub fn clamp_for_ip_families(mtu: usize, ipv6_configured: bool) -> usize {
    if ipv6_configured && mtu < IPV6_MIN_MTU {
        IPV6_MIN_MTU
    } else {
        mtu
    }
}

/// The operator's explicit `AETHER_MTU`, if it is present and usable.
///
/// Read, never written: publishing a probe result back into the environment made
/// one protocol's measurement the ambient answer for every other one, which is
/// the leak [`MtuCache`] exists to close.
fn env_override(ipv6_configured: bool) -> Option<usize> {
    let v = crate::runtime_env::var("AETHER_MTU")?;
    match v.trim().parse::<usize>() {
        Ok(n) if (576..=1500).contains(&n) => Some(clamp_for_ip_families(n, ipv6_configured)),
        Ok(n) => {
            log::warn!("[mtu] ignoring invalid value: {n}");
            None
        }
        Err(_) => {
            log::warn!("[mtu] ignoring non-numeric AETHER_MTU={v:?}");
            None
        }
    }
}

/// Resolve MTU: env `AETHER_MTU` wins; otherwise auto-probe, cached per protocol.
pub async fn resolve_mtu(protocol: &str, ipv6_configured: bool) -> usize {
    if let Some(n) = env_override(ipv6_configured) {
        log::info!("[+] MTU from AETHER_MTU={n}");
        return n;
    }

    if let Some(n) = cached_for(protocol) {
        return n;
    }

    let _serialised = PROBING.lock().await;
    // Re-check under the lock, for this protocol: the first probe of a given
    // ceiling publishes the answer for everyone asking with that ceiling.
    if let Some(n) = cached_for(protocol) {
        return n;
    }

    let n = auto_probe(protocol, ipv6_configured).await;
    remember(protocol, n);
    log::info!("[+] auto MTU selected: {n} (protocol={protocol})");
    n
}

async fn auto_probe(protocol: &str, ipv6_configured: bool) -> usize {
    // WireGuard outer packets add ~60B; stay conservative (<=1280) — especially
    // when a system-wide VPN sits underneath, whose own overhead shrinks the path.
    // Only MASQUE (H2 over TCP) may try the larger 1400 inner MTU; MASQUE H3 is
    // re-capped to 1280 by the tunnel runner. The old check also keyed off
    // AETHER_MASQUE_HTTP2, which the desktop sets from the transport setting even
    // for a WireGuard connection — that leaked a 1400 MTU into WG and stalled the
    // data plane (handshake ok, pages never load).
    let prefer_large = protocol.eq_ignore_ascii_case("masque");

    for &mtu in CANDIDATES {
        if !prefer_large && mtu > 1280 {
            continue;
        }
        if probe_udp_size(mtu).await {
            return mtu;
        }
        log::debug!("[mtu] probe {mtu} not confirmed; trying smaller");
    }
    clamp_for_ip_families(SAFE_DEFAULT, ipv6_configured)
}

/// True only when a datagram of this size actually round-tripped.
///
/// `send_to` returning Ok proves nothing beyond "the local stack accepted the
/// bytes": the NIC, a tunnel underneath, or the first router can still drop it,
/// which is exactly the case the probe exists to catch. So a reply must come back
/// within the window *and from the address that was probed*; anything else means
/// no confirmation, and auto mode falls to the safe 1280 instead of claiming 1400
/// on a path it never measured. An anycast edge that answers from a neighbouring
/// address therefore costs us the larger MTU, which is the safe direction.
///
/// A DF (don't-fragment) request would make this airtight — a size that arrives
/// fragmented is not a size the path supports — but neither `tokio::net::UdpSocket`
/// nor the `socket2` version in this tree exposes `IP_MTU_DISCOVER`/`IP_DONTFRAG`,
/// and adding a dependency to reach one socket option is not worth the supply
/// chain surface. The reply requirement is the part that removes the false
/// positive, which was the actual bug ("auto" always answered 1400).
async fn probe_udp_size(payload: usize) -> bool {
    let targets: &[SocketAddr] = &[
        "1.1.1.1:443".parse().unwrap(),
        "162.159.192.1:443".parse().unwrap(),
    ];
    for dest in targets {
        let sock = match UdpSocket::bind("0.0.0.0:0").await {
            Ok(s) => s,
            Err(e) => {
                log::debug!("[mtu] cannot bind probe socket: {e}");
                continue;
            }
        };
        // 28B of IP+UDP header on top, so the on-wire size is the MTU asked about.
        let buf = vec![0u8; payload.saturating_sub(28).max(64)];
        if let Err(e) = sock.send_to(&buf, dest).await {
            log::debug!("[mtu] probe send to {dest} failed at {payload}: {e}");
            continue;
        }
        let mut rx = [0u8; 2048];
        // `recv` would accept a datagram from *anyone* the ephemeral port happens
        // to receive one from, and the engine would then claim a 1400-byte path it
        // never measured to that target. The reply has to come from the address we
        // probed.
        match tokio::time::timeout(Duration::from_millis(400), sock.recv_from(&mut rx)).await {
            Ok(Ok((_, from))) if from == *dest => return true,
            Ok(Ok((_, from))) => log::debug!("[mtu] probe reply from {from}, not {dest}: unasked"),
            Ok(Err(e)) => log::debug!("[mtu] probe reply from {dest} failed: {e}"),
            Err(_) => log::debug!("[mtu] probe to {dest} at {payload}: no reply inside window"),
        }
    }
    false
}

/// Current MTU for a reader that cannot say which protocol it is on.
///
/// An explicit `AETHER_MTU` still wins. Otherwise this is the **smallest** value
/// any protocol has resolved to — never the largest, and never a number some
/// other protocol measured. `session::tunnel_mtu()` is the only such caller and
/// it runs after `resolve_mtu("wireguard", ..)`, so under-claiming here is
/// conservative while over-claiming is the WireGuard stall this API leaked before.
pub fn current() -> usize {
    if let Some(v) = crate::runtime_env::var("AETHER_MTU") {
        if let Ok(n) = v.trim().parse::<usize>() {
            if (576..=1500).contains(&n) {
                return n;
            }
        }
    }
    cached_mtu().unwrap_or(SAFE_DEFAULT)
}

/// The MTU resolved for one protocol, or the safe default if it has not been
/// resolved yet. Callers that know their transport should prefer this over
/// [`current`].
pub fn current_for(protocol: &str) -> usize {
    if let Some(v) = crate::runtime_env::var("AETHER_MTU") {
        if let Ok(n) = v.trim().parse::<usize>() {
            if (576..=1500).contains(&n) {
                return n;
            }
        }
    }
    cached_for(protocol).unwrap_or(SAFE_DEFAULT)
}

#[cfg(test)]
mod tests {
    use super::{clamp_for_ip_families, MtuCache, IPV6_MIN_MTU};

    /// The WireGuard stall, in one line: the 1400 measured for MASQUE used to be
    /// the process's single answer, so a later WireGuard connect inherited a
    /// ceiling its encapsulation cannot carry and never probed for one.
    #[test]
    fn a_resolved_mtu_is_never_shared_with_another_protocol() {
        let mut cache = MtuCache::default();
        cache.put("masque", 1400);
        assert_eq!(cache.get("masque"), Some(1400));
        assert_eq!(
            cache.get("wireguard"),
            None,
            "wireguard inherited masque's 1400 without probing"
        );
        // Spelling and padding are not separate protocols.
        assert_eq!(cache.get("MASQUE"), Some(1400));
        assert_eq!(cache.get(" masque "), Some(1400));

        cache.put("wireguard", 1280);
        assert_eq!(
            cache.get("masque"),
            Some(1400),
            "resolving one protocol overwrote another"
        );
        assert_eq!(cache.get("wireguard"), Some(1280));
        // The unkeyed read a caller with no protocol can take is the smallest, so
        // it can under-claim but never over-claim.
        assert_eq!(cache.conservative(), Some(1280));
    }

    #[test]
    fn an_unresolved_cache_reads_as_empty_not_as_something_else() {
        let cache = MtuCache::default();
        assert_eq!(cache.conservative(), None);
        assert_eq!(cache.get("wireguard"), None);
    }

    /// `resolve_mtu` reads and writes the process-global cache, so the keyed
    /// behaviour has to hold there too — a per-test `MtuCache` proving it would
    /// still leave the production path sharing one slot.
    #[test]
    fn the_shared_cache_is_keyed_by_protocol_too() {
        super::remember("selftest-a", 1400);
        assert_eq!(super::cached_for("selftest-a"), Some(1400));
        assert_eq!(
            super::cached_for("selftest-b"),
            None,
            "the shared cache handed selftest-a's answer to a protocol that never probed"
        );
        assert!(
            super::cached_mtu().is_none() || super::cached_mtu() <= Some(1400),
            "the unkeyed read over-claimed: {:?}",
            super::cached_mtu()
        );
    }

    #[test]
    fn a_v6_interface_never_gets_an_mtu_below_the_ipv6_minimum() {
        // The regression: AETHER_MTU=1000 (or a probe that settles low) used to
        // be honoured verbatim, and every IPv6 flow simply stopped.
        assert_eq!(clamp_for_ip_families(576, true), IPV6_MIN_MTU);
        assert_eq!(clamp_for_ip_families(1279, true), IPV6_MIN_MTU);
        assert_eq!(clamp_for_ip_families(1280, true), 1280);
        assert_eq!(clamp_for_ip_families(1400, true), 1400);
    }

    #[test]
    fn an_ipv4_only_interface_keeps_the_configured_value() {
        assert_eq!(clamp_for_ip_families(576, false), 576);
        assert_eq!(clamp_for_ip_families(1280, false), 1280);
    }
}
