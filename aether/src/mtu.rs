//! Path MTU selection for the userspace netstack.
//!
//! WARP-safe default is 1280. On clean paths 1400 reduces packet count and
//! improves high-RTT throughput for MASQUE h2. Auto mode probes once per process.

use std::net::SocketAddr;
use std::sync::OnceLock;
use std::time::Duration;

use tokio::net::UdpSocket;

const CANDIDATES: &[usize] = &[1400, 1280];
const SAFE_DEFAULT: usize = 1280;

/// IPv6's link minimum (RFC 8200 §5). smoltcp cannot fragment IPv6, so with a v6
/// address on the interface any MTU below this kills every v6 flow silently
/// while v4 keeps working — a configured 1000 is a broken tunnel, not a choice.
pub const IPV6_MIN_MTU: usize = 1280;

static CHOSEN: OnceLock<usize> = OnceLock::new();
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

/// Resolve MTU: env `AETHER_MTU` wins; otherwise auto-probe (cached).
pub async fn resolve_mtu(protocol: &str, ipv6_configured: bool) -> usize {
    if let Some(v) = crate::runtime_env::var("AETHER_MTU") {
        if let Ok(n) = v.trim().parse::<usize>() {
            if (576..=1500).contains(&n) {
                let n = clamp_for_ip_families(n, ipv6_configured);
                log::info!("[+] MTU from AETHER_MTU={n}");
                let _ = CHOSEN.set(n);
                return n;
            }
            log::warn!("[mtu] ignoring invalid value: {n}");
        } else {
            log::warn!("[mtu] ignoring non-numeric AETHER_MTU={v:?}");
        }
    }

    if let Some(&n) = CHOSEN.get() {
        return n;
    }

    let _serialised = PROBING.lock().await;
    // Re-check under the lock: the first probe publishes the answer for everyone.
    if let Some(&n) = CHOSEN.get() {
        return n;
    }

    let n = auto_probe(protocol, ipv6_configured).await;
    let _ = CHOSEN.set(n);
    // So routing_plane::tunnel_mtu() and other readers see the same value.
    crate::runtime_env::set("AETHER_MTU", &n.to_string());
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
/// within the window; no reply means no confirmation, and auto mode falls to the
/// safe 1280 instead of claiming 1400 on a path it never measured.
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
        match tokio::time::timeout(Duration::from_millis(400), sock.recv(&mut rx)).await {
            Ok(Ok(_)) => return true,
            Ok(Err(e)) => log::debug!("[mtu] probe reply from {dest} failed: {e}"),
            Err(_) => log::debug!("[mtu] probe to {dest} at {payload}: no reply inside window"),
        }
    }
    false
}

/// Current MTU (env or last resolve). Safe default if never resolved.
pub fn current() -> usize {
    if let Some(v) = crate::runtime_env::var("AETHER_MTU") {
        if let Ok(n) = v.trim().parse::<usize>() {
            if (576..=1500).contains(&n) {
                return n;
            }
        }
    }
    *CHOSEN.get().unwrap_or(&SAFE_DEFAULT)
}

#[cfg(test)]
mod tests {
    use super::{clamp_for_ip_families, IPV6_MIN_MTU};

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
