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

static CHOSEN: OnceLock<usize> = OnceLock::new();

/// Resolve MTU: env `AETHER_MTU` wins; otherwise auto-probe (cached).
pub async fn resolve_mtu(protocol: &str) -> usize {
    if let Ok(v) = std::env::var("AETHER_MTU") {
        if let Ok(n) = v.trim().parse::<usize>() {
            if (576..=1500).contains(&n) {
                log::info!("[+] MTU from AETHER_MTU={n}");
                let _ = CHOSEN.set(n);
                return n;
            }
        }
    }

    if let Some(&n) = CHOSEN.get() {
        return n;
    }

    let n = auto_probe(protocol).await;
    let _ = CHOSEN.set(n);
    // So routing_plane::tunnel_mtu() and other readers see the same value.
    std::env::set_var("AETHER_MTU", n.to_string());
    log::info!("[+] auto MTU selected: {n} (protocol={protocol})");
    n
}

async fn auto_probe(protocol: &str) -> usize {
    // WireGuard outer packets add ~60B; stay conservative unless probe says OK.
    // MASQUE h2 is TCP to :443 — slightly more tolerant of larger inner MTU.
    let prefer_large = protocol.eq_ignore_ascii_case("masque")
        || std::env::var("AETHER_MASQUE_HTTP2")
            .map(|v| {
                let v = v.to_ascii_lowercase();
                v == "1" || v == "true" || v == "h2" || v == "on"
            })
            .unwrap_or(false);

    for &mtu in CANDIDATES {
        if !prefer_large && mtu > 1280 {
            continue;
        }
        if probe_udp_size(mtu).await {
            return mtu;
        }
        log::debug!("[mtu] probe {mtu} not confirmed; trying smaller");
    }
    SAFE_DEFAULT
}

/// Send a large UDP datagram toward a well-known CF anycast. Success means the
/// local path accepts the size (no local ENOBUFS / message-too-long). Remote
/// ICMP is ignored — we only filter local MTU failures.
async fn probe_udp_size(payload: usize) -> bool {
    let targets: &[SocketAddr] = &[
        "1.1.1.1:443".parse().unwrap(),
        "162.159.192.1:443".parse().unwrap(),
    ];
    let sock = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(_) => return false,
    };
    let buf = vec![0u8; payload.saturating_sub(28).max(64)]; // IP+UDP headers ≈ 28
    for dest in targets {
        match tokio::time::timeout(Duration::from_millis(300), sock.send_to(&buf, dest)).await {
            Ok(Ok(_)) => return true,
            Ok(Err(e)) => {
                let msg = e.to_string().to_ascii_lowercase();
                if msg.contains("message too long")
                    || msg.contains("buffer")
                    || e.raw_os_error() == Some(10040)
                // WSAEMSGSIZE
                {
                    return false;
                }
            }
            Err(_) => {}
        }
    }
    // Ambiguous: allow 1280 always, allow 1400 only if prefer path already filtered.
    payload <= 1280
}

/// Current MTU (env or last resolve). Safe default if never resolved.
pub fn current() -> usize {
    if let Ok(v) = std::env::var("AETHER_MTU") {
        if let Ok(n) = v.trim().parse::<usize>() {
            if (576..=1500).contains(&n) {
                return n;
            }
        }
    }
    *CHOSEN.get().unwrap_or(&SAFE_DEFAULT)
}
