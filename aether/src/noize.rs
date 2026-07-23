use std::net::SocketAddr;
use std::time::Duration;

use rand::Rng;
use rand::RngCore;
use tokio::net::UdpSocket;

use crate::obfuscation::parse_cps;

#[derive(Debug, Clone)]
pub struct NoizeConfig {
    pub jc_before_hs: usize,
    pub jc_after_i1: usize,
    pub jmin: usize,
    pub jmax: usize,
    pub i1: Option<String>,
    pub i2: Option<String>,
    pub junk_interval: Duration,
}

impl NoizeConfig {
    pub fn off() -> Self {
        Self {
            jc_before_hs: 0,
            jc_after_i1: 0,
            jmin: 0,
            jmax: 0,
            i1: None,
            i2: None,
            junk_interval: Duration::ZERO,
        }
    }

    pub fn firewall() -> Self {
        Self {
            jc_before_hs: 2,
            jc_after_i1: 2,
            jmin: 48,
            jmax: 190,
            i1: Some("<b 0d0a0d0a><t><r 24>".to_string()),
            i2: Some("<r 48>".to_string()),
            junk_interval: Duration::from_millis(4),
        }
    }

    pub fn gfw() -> Self {
        Self {
            jc_before_hs: 2,
            jc_after_i1: 1,
            jmin: 64,
            jmax: 256,
            i1: Some("<b 0d0a0d0a><t><r 24>".to_string()),
            i2: Some("<r 32>".to_string()),
            junk_interval: Duration::from_millis(5),
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.jc_before_hs > 0 || self.jc_after_i1 > 0 || self.i1.is_some()
    }
}

pub fn from_profile(name: &str) -> NoizeConfig {
    match name {
        "off" | "none" => NoizeConfig::off(),
        "gfw" => NoizeConfig::gfw(),
        _ => NoizeConfig::firewall(),
    }
}

fn junk_packet(cfg: &NoizeConfig) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let (lo, hi) = if cfg.jmax > cfg.jmin && cfg.jmin > 0 {
        (cfg.jmin, cfg.jmax)
    } else {
        (40, 90)
    };
    let size = rng.gen_range(lo..=hi);
    let mut buf = vec![0u8; size];
    rand::thread_rng().fill_bytes(&mut buf);
    buf
}

pub async fn pre_handshake(sock: &UdpSocket, peer: SocketAddr, cfg: &NoizeConfig) {
    if !cfg.is_enabled() {
        return;
    }

    log::debug!("sending {} junk packets before handshake", cfg.jc_before_hs);

    for i in 0..cfg.jc_before_hs {
        let pkt = junk_packet(cfg);
        match sock.send_to(&pkt, peer).await {
            Ok(n) => log::debug!("junk[{i}] sent {n} bytes"),
            Err(e) => log::debug!("junk[{i}] send failed: {e}"),
        }
        if !cfg.junk_interval.is_zero() {
            tokio::time::sleep(cfg.junk_interval).await;
        }
    }

    if let Some(i1) = &cfg.i1 {
        let pkt = parse_cps(i1);
        if !pkt.is_empty() {
            match sock.send_to(&pkt, peer).await {
                Ok(n) => log::debug!("signature i1 sent {n} bytes"),
                Err(e) => log::debug!("signature i1 send failed: {e}"),
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    }

    for i in 0..cfg.jc_after_i1 {
        let pkt = junk_packet(cfg);
        match sock.send_to(&pkt, peer).await {
            Ok(n) => log::debug!("junk_after[{i}] sent {n} bytes"),
            Err(e) => log::debug!("junk_after[{i}] send failed: {e}"),
        }
        if !cfg.junk_interval.is_zero() {
            tokio::time::sleep(cfg.junk_interval).await;
        }
    }

    if let Some(i2) = &cfg.i2 {
        let pkt = parse_cps(i2);
        if !pkt.is_empty() {
            match sock.send_to(&pkt, peer).await {
                Ok(n) => log::debug!("signature i2 sent {n} bytes"),
                Err(e) => log::debug!("signature i2 send failed: {e}"),
            }
        }
    }
    
    log::debug!("obfuscation pre-handshake complete");
}
