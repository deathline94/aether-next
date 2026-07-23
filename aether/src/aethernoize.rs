use std::net::SocketAddr;
use std::time::Duration;

use rand::{Rng, RngCore};
use tokio::net::UdpSocket;

use crate::obfuscation::parse_cps;

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
            jc: 4,
            jc_before_hs: 2,
            jc_after_i1: 1,
            jc_after_hs: 1,
            jmin: 48,
            jmax: 190,
            junk_interval: Duration::from_millis(3),
            handshake_delay: Duration::from_millis(5),
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
            jc: 6,
            jc_before_hs: 3,
            jc_after_i1: 2,
            jc_after_hs: 1,
            jmin: 64,
            jmax: 256,
            junk_interval: Duration::from_millis(2),
            handshake_delay: Duration::from_millis(8),
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
            jc: 10,
            jc_before_hs: 4,
            jc_after_i1: 3,
            jc_after_hs: 3,
            jmin: 80,
            jmax: 384,
            junk_interval: Duration::from_millis(1),
            handshake_delay: Duration::from_millis(12),
            allow_zero_size: false,
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.jc > 0 || self.i1.is_some()
    }
}

pub fn from_profile(name: &str) -> AetherNoizeConfig {
    match name {
        "off" | "none" => AetherNoizeConfig::off(),
        "light" => AetherNoizeConfig::light(),
        "aggressive" | "heavy" => AetherNoizeConfig::aggressive(),
        _ => AetherNoizeConfig::balanced(),
    }
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
        0x00, 0x00, 0x00, 0x14, 0x01, 0x01, 0x00, 0x04, 0x03, 0x00, 0x00, 0x08, 0x01, 0x00,
        0x00, 0x0c, 0x00, 0x00, 0x00, 0x00,
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
        return if cfg.allow_zero_size { vec![] } else { vec![0x00] };
    }

    let mut junk = vec![0u8; size];
    rand::thread_rng().fill_bytes(&mut junk);
    junk
}

async fn send_connected(sock: &UdpSocket, pkt: &[u8]) {
    let _ = sock.send(pkt).await;
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
    let base = cfg.junk_interval.as_millis() as u64;
    let extra = rand::thread_rng().gen_range(0..=4);
    let total = base + extra;
    if total > 0 {
        tokio::time::sleep(Duration::from_millis(total)).await;
    }
}

pub async fn apply_obfuscation(sock: &UdpSocket, _peer: SocketAddr, cfg: &AetherNoizeConfig) {
    if !cfg.is_enabled() {
        return;
    }

    if let Some(ref i1) = cfg.i1 {
        let payload = parse_cps(i1);
        if !payload.is_empty() {
            let framed = wrap_ikev2(&payload);
            send_connected(sock, &framed).await;
            // Jitter: 2-8ms random delay breaks timing correlation.
            jitter(2, 8).await;
        }
    }

    for _ in 0..cfg.jc_after_i1 {
        let junk = generate_junk(cfg);
        send_connected(sock, &junk).await;
        jitter_from_cfg(cfg).await;
    }

    for _ in 0..cfg.jc_before_hs {
        let junk = generate_junk(cfg);
        send_connected(sock, &junk).await;
        jitter_from_cfg(cfg).await;
    }

    for s in [&cfg.i2, &cfg.i3, &cfg.i4, &cfg.i5]
        .into_iter()
        .filter_map(|opt| opt.as_ref())
    {
        let pkt = parse_cps(s);
        if !pkt.is_empty() {
            send_connected(sock, &pkt).await;
            jitter(2, 6).await;
        }
    }

    if !cfg.handshake_delay.is_zero() {
        tokio::time::sleep(cfg.handshake_delay).await;
    }
}

pub async fn send_post_handshake_junk(sock: &UdpSocket, _peer: SocketAddr, cfg: &AetherNoizeConfig) {
    for _ in 0..cfg.jc_after_hs {
        let junk = generate_junk(cfg);
        send_connected(sock, &junk).await;
        jitter_from_cfg(cfg).await;
    }
}

/// Data-phase decoy packets sent alongside keepalives. Blurs the size and
/// timing profile of the tunnel during steady-state operation, making it
/// harder for DPI to fingerprint WireGuard data packets by their predictable
/// cadence and length distribution.
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
        send_connected(sock, &junk).await;

        // Wider jitter: 1-12ms random gap to break periodicity.
        let gap_ms = rand::thread_rng().gen_range(1..=12);
        tokio::time::sleep(Duration::from_millis(gap_ms)).await;
    }
}
