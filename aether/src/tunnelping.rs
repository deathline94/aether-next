use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

use tokio::sync::oneshot;

use crate::aethernoize::AetherNoizeConfig;
use crate::error::{AetherError, Result};
use crate::masque_h2;
use crate::netstack;
use crate::noize::NoizeConfig;
use crate::quic;
use crate::socks;
use crate::wireguard;

const PING_MTU: usize = 1280;
const HTTP_PROBE_HOST: &str = "www.gstatic.com";
const HTTP_PROBE_PATH: &str = "/generate_204";

struct AbortGuard<T>(tokio::task::JoinHandle<T>);

impl<T> Drop for AbortGuard<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn http_probe_port() -> u16 {
    crate::runtime_env::var("AETHER_IRONCLAD_PORT")
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(80)
}

async fn http_probe(stack: &netstack::StackHandle) -> Result<()> {
    let ip = socks::dns_resolve(stack, HTTP_PROBE_HOST).await?;
    let dst = SocketAddr::new(ip, http_probe_port());

    let conn = stack.open_tcp(dst).await?;
    let (sender, mut from_stack) = conn.into_split();

    let request = format!(
        "GET {HTTP_PROBE_PATH} HTTP/1.1\r\nHost: {HTTP_PROBE_HOST}\r\nConnection: close\r\nUser-Agent: aether-ironclad\r\n\r\n"
    );
    sender.send(request.into_bytes()).await?;

    // M5 fix: read until the full status line (CRLF-terminated) arrives, then
    // parse the actual 3-digit status code. The old check — `buffer.contains("204")`
    // on the first ≥12 bytes — accepted captive-portal redirects like
    // "HTTP/1.1 302 Found\r\nLocation: /generate_204..." and counted them as
    // verified-working endpoints.
    let mut buf: Vec<u8> = Vec::with_capacity(256);
    let eol = loop {
        match tokio::time::timeout(Duration::from_secs(6), from_stack.recv()).await {
            Ok(Some(chunk)) => {
                buf.extend_from_slice(&chunk);
                if let Some(at) = buf.windows(2).position(|w| w == b"\r\n") {
                    break at;
                }
                if buf.len() > 8192 {
                    return Err(AetherError::Other("http probe: oversized response".into()));
                }
            }
            Ok(None) => return Err(AetherError::Other("http probe: connection closed".into())),
            Err(_) => return Err(AetherError::Other("http probe response timeout".into())),
        }
    };

    sender.close().await;

    let status_line = String::from_utf8_lossy(&buf[..eol]);
    let code: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .ok_or_else(|| AetherError::Other(format!("http probe: bad status line {status_line:?}")))?;
    if code == 204 {
        Ok(())
    } else {
        Err(AetherError::Other(format!(
            "http probe: unexpected status {code} ({status_line})"
        )))
    }
}

pub struct MasquePingParams {
    pub peer: SocketAddr,
    pub sni: String,
    pub authority: String,
    pub path: String,
    pub cert_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
    pub noize: NoizeConfig,
    pub local_ipv4: Ipv4Addr,
    pub local_ipv4_str: String,
    pub local_ipv6_str: String,
}

pub async fn masque_http_ping(p: &MasquePingParams, timeout: Duration) -> Result<Duration> {
    let attempt = async {
        let (chans, internals) = quic::channels();
        let quic::Channels {
            outbound_tx,
            inbound_rx,
        } = chans;

        let stack = netstack::spawn(
            &p.local_ipv4_str,
            &p.local_ipv6_str,
            PING_MTU,
            inbound_rx,
            outbound_tx,
        )?;

        let (ready_tx, ready_rx) = oneshot::channel();

        let tunnel_task = if masque_h2::enabled() {
            let h2cfg = masque_h2::H2TunnelConfig {
                peer: masque_h2::h2_peer(p.peer),
                sni: p.sni.clone(),
                authority: p.authority.clone(),
                cert_pem: p.cert_pem.clone(),
                key_pem: p.key_pem.clone(),
                probe_src: Some(p.local_ipv4),
            };
            AbortGuard(tokio::spawn(masque_h2::run(h2cfg, internals, None, ready_tx)))
        } else {
            let cfg = quic::TunnelConfig {
                peer: p.peer,
                sni: p.sni.clone(),
                authority: p.authority.clone(),
                path: p.path.clone(),
                cert_pem: p.cert_pem.clone(),
                key_pem: p.key_pem.clone(),
                local_ipv4: p.local_ipv4,
                ech_config_list: None,
                noize: p.noize.clone(),
            };
            AbortGuard(tokio::spawn(quic::run(cfg, internals, None, ready_tx)))
        };

        if ready_rx.await.is_err() {
            return Err(AetherError::Other(
                "tunnel exited before data-plane validation".into(),
            ));
        }

        let start = Instant::now();
        let result = http_probe(&stack).await.map(|()| start.elapsed());

        drop(tunnel_task);
        result
    };

    match tokio::time::timeout(timeout, attempt).await {
        Ok(Ok(rtt)) => Ok(rtt),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(AetherError::Other("ironclad http probe timeout".into())),
    }
}

pub struct WgPingParams {
    pub local_ipv4: Ipv4Addr,
    pub local_ipv6: Ipv6Addr,
    pub aethernoize: AetherNoizeConfig,
}

pub async fn wg_http_ping_established(
    session: wireguard::EstablishedSession,
    p: &WgPingParams,
    timeout: Duration,
) -> Result<Duration> {
    let attempt = async {
        let (outbound_tx, outbound_rx) = tokio::sync::mpsc::channel(1024);
        let (inbound_tx, inbound_rx) = tokio::sync::mpsc::channel(1024);

        let tunnel = wireguard::WgTunnel::from_established(
            session,
            std::sync::Arc::new(p.aethernoize.clone()),
            inbound_tx,
        );

        let local_ipv4_str = p.local_ipv4.to_string();
        let local_ipv6_str = p.local_ipv6.to_string();
        let stack = netstack::spawn(
            &local_ipv4_str,
            &local_ipv6_str,
            PING_MTU,
            inbound_rx,
            outbound_tx,
        )?;

        let tunnel_task = AbortGuard(tokio::spawn(tunnel.run(outbound_rx)));

        let start = Instant::now();
        let result = http_probe(&stack).await.map(|()| start.elapsed());

        drop(tunnel_task);
        result
    };

    match tokio::time::timeout(timeout, attempt).await {
        Ok(Ok(rtt)) => Ok(rtt),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(AetherError::Other("ironclad http probe timeout".into())),
    }
}
