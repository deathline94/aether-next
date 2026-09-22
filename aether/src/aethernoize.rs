use std::net::SocketAddr;
use std::time::Duration;

use rand::{Rng, RngCore};
use tokio::net::UdpSocket;

use crate::error::{AetherError, Result};
use crate::obfuscation::parse_cps;

/// Gap between the intro packets of one profile.
///
/// Every shipped profile used to set `junk_interval: ZERO`, which made
/// `jitter_from_cfg` return immediately and the `if !cfg.junk_interval.is_zero()`
/// guards below never fire: five junk packets plus the signatures went out
/// back-to-back in a single burst — the exact periodic burst the comments claim to
/// break. A real base interval makes those guards reachable; `off` keeps `ZERO`.
const JUNK_INTERVAL_LIGHT: Duration = Duration::from_millis(8);
const JUNK_INTERVAL_BALANCED: Duration = Duration::from_millis(12);
const JUNK_INTERVAL_AGGRESSIVE: Duration = Duration::from_millis(16);

#[derive(Debug, Clone)]
pub struct AetherNoizeConfig {
    pub i1: Option<String>,
    pub i2: Option<String>,
    pub i3: Option<String>,
    pub i4: Option<String>,
    pub i5: Option<String>,
    pub jc: usize,
    pub jc_before_hs: usize,
    pub jc_after_i1: usize,
    pub jc_after_hs: usize,
    pub jmin: usize,
    pub jmax: usize,
    pub junk_interval: Duration,
    pub handshake_delay: Duration,
    pub allow_zero_size: bool,
}

impl AetherNoizeConfig {
    pub fn off() -> Self {
        Self {
            i1: None,
            i2: None,
            i3: None,
            i4: None,
            i5: None,
            jc: 0,
            jc_before_hs: 0,
            jc_after_i1: 0,
            jc_after_hs: 0,
            jmin: 0,
            jmax: 0,
            junk_interval: Duration::ZERO,
            handshake_delay: Duration::ZERO,
            allow_zero_size: false,
        }
    }

    pub fn light() -> Self {
        Self {
            i1: Some("<b 0d0a0d0a><t><r 20-32>".to_string()),
            i2: Some("<rc 24-48>".to_string()),
            i3: None,
            i4: None,
            i5: None,
            jc: 5,
            jc_before_hs: 5,
            jc_after_i1: 0,
            jc_after_hs: 0,
            jmin: 50,
            jmax: 128,
            junk_interval: JUNK_INTERVAL_LIGHT,
            handshake_delay: Duration::ZERO,
            allow_zero_size: false,
        }
    }

    pub fn balanced() -> Self {
        Self {
            i1: Some("<b 0d0a0d0a><t><rc 20-40>".to_string()),
            i2: Some("<b 504f5354><rd 10-20><rc 20-30>".to_string()),
            i3: Some("<r 30-50>".to_string()),
            i4: None,
            i5: None,
            jc: 5,
            jc_before_hs: 5,
            jc_after_i1: 0,
            jc_after_hs: 0,
            jmin: 50,
            jmax: 128,
            junk_interval: JUNK_INTERVAL_BALANCED,
            handshake_delay: Duration::ZERO,
            allow_zero_size: false,
        }
    }

    pub fn aggressive() -> Self {
        Self {
            i1: Some("<b 0d0a0d0a><t><rc 40-64>".to_string()),
            i2: Some("<b 504f5354><t><rd 15-30><rc 30-50>".to_string()),
            i3: Some("<b 474554><rc 40-60>".to_string()),
            i4: Some("<r 60-100>".to_string()),
            i5: Some("<c><rd 20-40>".to_string()),
            jc: 5,
            jc_before_hs: 5,
            jc_after_i1: 0,
            jc_after_hs: 0,
            jmin: 50,
            jmax: 128,
            junk_interval: JUNK_INTERVAL_AGGRESSIVE,
            handshake_delay: Duration::ZERO,
            allow_zero_size: false,
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.jc > 0 || self.i1.is_some()
    }
}

pub fn from_profile(name: &str) -> AetherNoizeConfig {
    // Delegated to `obfuscation`, which owns the profile vocabulary. This match
    // was a second, smaller copy of it: `medium`, `high`, `max` and `custom` were
    // all accepted by the shell and all silently became `balanced()` here, with
    // nothing said anywhere. Unknown names are rejected upstream by
    // `obfuscation::validate_profile_name`, at session start.
    crate::obfuscation::aethernoize_from_name(name)
}

fn wrap_ikev2(payload: &[u8]) -> Vec<u8> {
    if payload.is_empty() {
        return payload.to_vec();
    }

    let mut initiator_spi = [0u8; 8];
    let mut responder_spi = [0u8; 8];

    if payload.len() >= 8 {
        initiator_spi.copy_from_slice(&payload[..8]);
    } else {
        rand::thread_rng().fill_bytes(&mut initiator_spi);
    }
    rand::thread_rng().fill_bytes(&mut responder_spi);

    let total_length = 28u32 + 24 + payload.len() as u32;
    let sa_payload_length = 24u16 + payload.len() as u16;

    let mut header = Vec::with_capacity(total_length as usize);

    header.extend_from_slice(&initiator_spi);
    header.extend_from_slice(&responder_spi);
    header.push(0x21);
    header.push(0x20);
    header.push(0x22);
    header.push(0x08);
    header.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    header.extend_from_slice(&total_length.to_be_bytes());

    header.push(0x00);
    header.push(0x00);
    header.extend_from_slice(&sa_payload_length.to_be_bytes());

    header.extend_from_slice(&[
        0x00, 0x00, 0x00, 0x14, 0x01, 0x01, 0x00, 0x04, 0x03, 0x00, 0x00, 0x08, 0x01, 0x00, 0x00,
        0x0c, 0x00, 0x00, 0x00, 0x00,
    ]);

    header.extend_from_slice(payload);
    header
}

fn generate_junk(cfg: &AetherNoizeConfig) -> Vec<u8> {
    let (min_size, max_size) = match (cfg.jmin, cfg.jmax) {
        (0, 0) if cfg.allow_zero_size => return vec![],
        (0, 0) => return vec![0x00],
        (min, 0) if !cfg.allow_zero_size => (min.max(1), min.max(1)),
        (min, max) if !cfg.allow_zero_size => (min.max(1), max.max(min)),
        (min, max) => (min, max.max(min)),
    };

    let size = if max_size == min_size {
        min_size
    } else {
        rand::thread_rng().gen_range(min_size..=max_size)
    };

    if size == 0 {
        return if cfg.allow_zero_size {
            vec![]
        } else {
            vec![0x00]
        };
    }

    let mut junk = vec![0u8; size];
    rand::thread_rng().fill_bytes(&mut junk);
    junk
}

/// Send one intro packet, and say so if it did not leave.
///
/// Two defects fixed here. The old `let _ = sock.send()` threw the error away, so
/// a UDP socket that had already taken an ICMP refusal (Linux answers
/// `ECONNREFUSED` on every later write) silently dropped the rest of the signature
/// sequence — and the WireGuard handshake then went out un-prefixed, which is the
/// failure the whole module exists to prevent. And `send()` requires a connected
/// socket while the `peer` argument was ignored entirely: an unconnected socket
/// made every intro packet fail with `ENOTCONN`, be discarded, and the handshake
/// still go out first in cleartext. Both spellings now work, and neither is
/// allowed to fail quietly.
async fn send_intro(sock: &UdpSocket, peer: SocketAddr, pkt: &[u8], what: &str) -> Result<()> {
    let sent = if sock.peer_addr().is_ok() {
        sock.send(pkt).await
    } else {
        sock.send_to(pkt, peer).await
    };
    match sent {
        Ok(n) if n == pkt.len() => Ok(()),
        Ok(n) => Err(AetherError::Other(format!(
            "{what}: wrote {n} of {} intro bytes",
            pkt.len()
        ))),
        Err(e) => Err(AetherError::Other(format!(
            "{what} never reached the wire: {e}"
        ))),
    }
}

/// Random delay between `lo` and `hi` milliseconds. Breaks timing correlation
/// so DPI cannot fingerprint the obfuscation sequence by inter-packet gaps.
async fn jitter(lo: u64, hi: u64) {
    let ms = rand::thread_rng().gen_range(lo..=hi);
    tokio::time::sleep(Duration::from_millis(ms)).await;
}

/// Jitter derived from the config's junk_interval: uses the configured interval
/// as a base and adds 0-4ms random noise on top.
async fn jitter_from_cfg(cfg: &AetherNoizeConfig) {
    if cfg.junk_interval.is_zero() {
        return;
    }
    let base = cfg.junk_interval.as_millis() as u64;
    let extra = rand::thread_rng().gen_range(0..=4);
    tokio::time::sleep(Duration::from_millis(base + extra)).await;
}

pub async fn apply_obfuscation(
    sock: &UdpSocket,
    peer: SocketAddr,
    cfg: &AetherNoizeConfig,
) -> Result<()> {
    if !cfg.is_enabled() {
        return Ok(());
    }

    if let Some(ref i1) = cfg.i1 {
        let payload = parse_cps(i1);
        if !payload.is_empty() {
            let framed = wrap_ikev2(&payload);
            send_intro(sock, peer, &framed, "signature i1").await?;
            jitter(2, 8).await;
        }
    }

    for _ in 0..cfg.jc_after_i1 {
        let junk = generate_junk(cfg);
        send_intro(sock, peer, &junk, "junk").await?;
        jitter_from_cfg(cfg).await;
    }

    for _ in 0..cfg.jc_before_hs {
        let junk = generate_junk(cfg);
        send_intro(sock, peer, &junk, "junk").await?;
        jitter_from_cfg(cfg).await;
    }

    for s in [&cfg.i2, &cfg.i3, &cfg.i4, &cfg.i5]
        .into_iter()
        .filter_map(|opt| opt.as_ref())
    {
        let pkt = parse_cps(s);
        if !pkt.is_empty() {
            send_intro(sock, peer, &pkt, "signature").await?;
            jitter(2, 6).await;
        }
    }

    if !cfg.handshake_delay.is_zero() {
        tokio::time::sleep(cfg.handshake_delay).await;
    }
    Ok(())
}

pub async fn send_post_handshake_junk(
    sock: &UdpSocket,
    peer: SocketAddr,
    cfg: &AetherNoizeConfig,
) -> Result<()> {
    for _ in 0..cfg.jc_after_hs {
        let junk = generate_junk(cfg);
        send_intro(sock, peer, &junk, "post-handshake junk").await?;
        jitter_from_cfg(cfg).await;
    }
    Ok(())
}

/// Data-phase decoy packets sent alongside keepalives. Blurs the size and
/// timing profile of the tunnel during steady-state operation, making it
/// harder for DPI to fingerprint WireGuard data packets by their predictable
/// cadence and length distribution.
///
/// Takes no `peer` and returns nothing: the caller is the keepalive timer on a
/// socket it already connected, and a decoy lost mid-session is not a reason to
/// end a working tunnel. It is counted and logged, which the old `let _ =` was not.
pub async fn send_keepalive_junk(sock: &UdpSocket, cfg: &AetherNoizeConfig) {
    if !cfg.is_enabled() {
        return;
    }

    // More aggressive: base count + up to 2x extra random packets.
    let base = cfg.jc_before_hs.max(2);
    let extra = rand::thread_rng().gen_range(0..=(base * 2));
    let count = base + extra;

    for _ in 0..count {
        let mut junk = generate_junk(cfg);
        // Avoid first byte matching WireGuard message types (1-4).
        if let Some(first) = junk.first_mut() {
            if *first >= 1 && *first <= 4 {
                *first = first.wrapping_add(0x40);
            }
        }
        if let Err(e) = sock.send(&junk).await {
            crate::counters::bump(&crate::counters::DATAGRAM_SEND_DROPPED);
            log::error!(
                "[-] aethernoize: keepalive decoy lost ({e}); the socket is not \
                         answering, so the rest of this batch is abandoned"
            );
            return;
        }

        // Wider jitter: 1-12ms random gap to break periodicity.
        let gap_ms = rand::thread_rng().gen_range(1..=12);
        tokio::time::sleep(Duration::from_millis(gap_ms)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aethernoize_profiles() {
        let b = AetherNoizeConfig::balanced();
        assert_eq!(b.jc, 5);
        assert_eq!(b.jc_before_hs, 5);
        assert_eq!(b.jmin, 50);
        assert_eq!(b.jmax, 128);
        assert!(!b.junk_interval.is_zero());
        assert!(b.handshake_delay.is_zero());

        let l = AetherNoizeConfig::light();
        assert_eq!(l.jc, 5);
        assert_eq!(l.jc_before_hs, 5);
        assert_eq!(l.jmin, 50);
        assert_eq!(l.jmax, 128);
        assert!(!l.junk_interval.is_zero());

        let a = AetherNoizeConfig::aggressive();
        assert_eq!(a.jc, 5);
        assert_eq!(a.jc_before_hs, 5);
        assert_eq!(a.jmin, 50);
        assert_eq!(a.jmax, 128);
        assert!(!a.junk_interval.is_zero());
    }

    /// The guards at `jitter_from_cfg` and the two `jitter(...)` calls inside
    /// `apply_obfuscation` only do anything while the interval is non-zero, and
    /// "the profiles set a real one" is the whole reason they are not dead code.
    /// The `off` profile must keep answering zero, or disabling obfuscation would
    /// still cost an intro delay.
    #[test]
    fn every_enabled_profile_spaces_its_intro_packets() {
        for cfg in [
            AetherNoizeConfig::light(),
            AetherNoizeConfig::balanced(),
            AetherNoizeConfig::aggressive(),
        ] {
            assert!(cfg.is_enabled());
            assert!(
                !cfg.junk_interval.is_zero(),
                "{}ms interval: the jitter guards cannot fire",
                cfg.junk_interval.as_millis()
            );
        }
        assert!(AetherNoizeConfig::off().junk_interval.is_zero());
    }

    #[test]
    fn test_aethernoize_generate_junk_bounds() {
        let cfg = AetherNoizeConfig::balanced();
        for _ in 0..100 {
            let junk = generate_junk(&cfg);
            assert!(
                junk.len() >= 50 && junk.len() <= 128,
                "junk len {} out of bounds",
                junk.len()
            );
        }
    }

    /// A signature that never left the socket has to be an error, not a `let _ =`.
    /// The reachable failure is a connected UDP socket that already took an ICMP
    /// refusal: every later write answers `ConnectionRefused`, so the remaining
    /// intro packets vanish and the WireGuard handshake goes out un-prefixed.
    #[tokio::test]
    async fn a_signature_that_cannot_be_sent_is_an_error() {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        // Port 0 is not a destination, so the send cannot be addressed at all —
        // the deterministic stand-in for the ICMP-refused socket above.
        let bogus: SocketAddr = "[::ffff:127.0.0.1]:0".parse().unwrap();
        let err = send_intro(&sock, bogus, b"payload", "signature i1")
            .await
            .expect_err("port 0 cannot accept a datagram");
        assert!(err.to_string().contains("never reached the wire"), "{err}");
        assert!(
            err.to_string().contains("signature i1"),
            "the failure must say which packet was lost: {err}"
        );
    }

    /// An unconnected socket must still get the intro sequence out: `send()` alone
    /// answered `ENOTCONN` for every packet while the caller saw no failure, which
    /// is the "handshake first, in cleartext" case.
    #[tokio::test]
    async fn an_unconnected_socket_addresses_the_peer_it_was_given() {
        let listener = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer = listener.local_addr().unwrap();
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        assert!(
            sock.peer_addr().is_err(),
            "the fixture must start unconnected"
        );
        let cfg = AetherNoizeConfig::light();
        apply_obfuscation(&sock, peer, &cfg)
            .await
            .expect("an unconnected socket must still send to `peer`");

        let mut buf = [0u8; 2048];
        let (n, from) = tokio::time::timeout(Duration::from_secs(5), listener.recv_from(&mut buf))
            .await
            .expect("nothing arrived: the intro packets were dropped")
            .expect("recv_from");
        assert_eq!(from, sock.local_addr().unwrap());
        // i1 is wrapped in the IKEv2 header: 28 + 24 + payload bytes.
        assert!(n > 52, "first packet was only {n} bytes");
    }

    /// The profile name is the operator's request; silently substituting another
    /// one is how `medium` became `balanced` with nothing on screen.
    #[test]
    fn from_profile_uses_the_shared_vocabulary() {
        for name in ["off", "light", "medium", "high", "max", "custom"] {
            let by_name = super::from_profile(name);
            let by_vocab = crate::obfuscation::aethernoize_from_name(name);
            assert_eq!(
                (by_name.jc, by_name.jmin, by_name.jmax),
                (by_vocab.jc, by_vocab.jmin, by_vocab.jmax),
                "{name} resolved differently in the two places"
            );
        }
        assert!(!super::from_profile("off").is_enabled());
        assert!(super::from_profile("max").jc_before_hs > 0);
    }
}
