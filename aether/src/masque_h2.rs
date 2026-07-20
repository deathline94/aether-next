use std::net::IpAddr;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use boring::pkey::PKey;
use boring::ssl::{SslConnector, SslMethod, SslVerifyMode, SslVersion};
use boring::x509::X509;
use bytes::Bytes;
use http::Method;
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use crate::consts;
use crate::error::{AetherError, Result};
use crate::masque::{self, Capsule, CapsuleParser};
use crate::quic::{AssignedAddr, Control, Internals};

// OpenSSL wire format: length-prefixed protocol list.
const H2_ALPN: &[u8] = b"\x02h2";
const CHROME_GROUPS: &str = "X25519:P-256:P-384";

pub struct H2TunnelConfig {
    pub peer: SocketAddr,
    pub sni: String,
    pub authority: String,
    pub path: String,
    pub cert_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
    /// Preferred IPv4 source for data-plane DNS probe (edge-assigned / identity).
    pub probe_src: Option<std::net::Ipv4Addr>,
}

pub fn enabled() -> bool {
    match crate::runtime_env::var("AETHER_MASQUE_HTTP2") {
        Some(v) => {
            let v = v.trim().to_lowercase();
            v == "1" || v == "true" || v == "h2" || v == "yes" || v == "on"
        }
        None => false,
    }
}

pub fn h2_peer(quic_peer: SocketAddr) -> SocketAddr {
    if let Ok(v) = std::env::var("AETHER_MASQUE_H2_PEER") {
        if let Ok(addr) = v.trim().parse::<SocketAddr>() {
            return addr;
        }
    }
    quic_peer
}

fn build_tls(cfg: &H2TunnelConfig) -> Result<boring::ssl::ConnectConfiguration> {
    let mut builder =
        SslConnector::builder(SslMethod::tls()).map_err(|e| AetherError::Tls(e.to_string()))?;

    builder
        .set_min_proto_version(Some(SslVersion::TLS1_2))
        .map_err(|e| AetherError::Tls(e.to_string()))?;
    builder
        .set_max_proto_version(Some(SslVersion::TLS1_3))
        .map_err(|e| AetherError::Tls(e.to_string()))?;

    builder.set_grease_enabled(true);

    let groups = std::env::var("AETHER_TLS_GROUPS").ok();
    let groups = groups
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(CHROME_GROUPS);
    builder
        .set_curves_list(groups)
        .map_err(|e| AetherError::Tls(e.to_string()))?;

    builder
        .set_alpn_protos(H2_ALPN)
        .map_err(|e| AetherError::Tls(e.to_string()))?;

    let cert = X509::from_pem(&cfg.cert_pem).map_err(|e| AetherError::Tls(e.to_string()))?;
    let key =
        PKey::private_key_from_pem(&cfg.key_pem).map_err(|e| AetherError::Tls(e.to_string()))?;
    builder
        .set_certificate(&cert)
        .map_err(|e| AetherError::Tls(e.to_string()))?;
    builder
        .set_private_key(&key)
        .map_err(|e| AetherError::Tls(e.to_string()))?;

    let dangerous = std::env::var("AETHER_DANGEROUS_DISABLE_TLS_VERIFY")
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false);
    if dangerous {
        builder.set_verify(SslVerifyMode::NONE);
        log::warn!("[tls] DANGER: H2 server authentication explicitly disabled");
    } else {
        if let Ok(path) = std::env::var("AETHER_TLS_CA_FILE") {
            builder.set_ca_file(path.trim()).map_err(|e| AetherError::Tls(format!("load TLS CA file: {e}")))?;
        } else {
            builder.set_default_verify_paths().map_err(|e| AetherError::Tls(format!("load system TLS roots: {e}")))?;
        }
        builder.set_verify(SslVerifyMode::PEER);
    }

    let connector = builder.build();
    let mut config = connector
        .configure()
        .map_err(|e| AetherError::Tls(e.to_string()))?;
    config.set_verify_hostname(!dangerous);
    config.set_use_server_name_indication(true);

    Ok(config)
}

fn build_connect_request(cfg: &H2TunnelConfig) -> Result<http::Request<()>> {
    let authority = format!("{}:443", cfg.authority);
    let uri = format!("https://{}", authority);
    http::Request::builder()
        .method(Method::CONNECT)
        .uri(uri)
        .header("cf-connect-proto", consts::CF_CONNECT_PROTOCOL)
        .header("pq-enabled", "false")
        .header("user-agent", "")
        .body(())
        .map_err(|e| AetherError::Masque(format!("build request: {e}")))
}

pub async fn verify_h2(cfg: &H2TunnelConfig, timeout: Duration) -> Result<Duration> {
    let start = Instant::now();
    let attempt = async {
        let tls_config = build_tls(cfg)?;
        let tcp = TcpStream::connect(cfg.peer).await.map_err(AetherError::Io)?;
        let _ = tcp.set_nodelay(true);
        let tls = tokio_boring::connect(tls_config, &cfg.sni, tcp)
            .await
            .map_err(|e| AetherError::Tls(format!("h2 tls handshake: {e}")))?;
        let (h2, connection) = h2::client::handshake(tls)
            .await
            .map_err(|e| AetherError::Masque(format!("h2 handshake: {e}")))?;
        let driver = tokio::spawn(async move {
            let _ = connection.await;
        });
        let mut h2 = h2
            .ready()
            .await
            .map_err(|e| AetherError::Masque(format!("h2 ready: {e}")))?;
        let req = build_connect_request(cfg)?;
        let (resp_fut, _send_stream) = h2
            .send_request(req, false)
            .map_err(|e| AetherError::Masque(format!("send_request: {e}")))?;
        let response = resp_fut
            .await
            .map_err(|e| AetherError::Masque(format!("await response: {e}")))?;
        driver.abort();
        let status = response.status();
        if !status.is_success() {
            return Err(AetherError::Masque(format!(
                "h2 connect-ip status {}",
                status.as_u16()
            )));
        }
        Ok(())
    };

    match tokio::time::timeout(timeout, attempt).await {
        Ok(Ok(())) => Ok(start.elapsed()),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(AetherError::Other("h2 verify timeout".into())),
    }
}

pub async fn run(
    cfg: H2TunnelConfig,
    internals: Internals,
    addr_tx: Option<mpsc::Sender<AssignedAddr>>,
    ready_tx: tokio::sync::oneshot::Sender<()>,
) -> Result<()> {
    let (mut outbound_rx, inbound_tx, mut ctrl_rx) = internals.into_parts();

    let tls_config = build_tls(&cfg)?;

    log::info!("[h2] connecting tcp to {}", cfg.peer);
    let tcp = TcpStream::connect(cfg.peer).await.map_err(AetherError::Io)?;
    let _ = tcp.set_nodelay(true);

    let tls = tokio_boring::connect(tls_config, &cfg.sni, tcp)
        .await
        .map_err(|e| AetherError::Tls(format!("h2 tls handshake: {e}")))?;
    log::info!(
        "[h2] tls established; alpn={}",
        String::from_utf8_lossy(tls.ssl().selected_alpn_protocol().unwrap_or(b""))
    );

    // Flow-control windows sized to unblock a single CONNECT-IP stream without
    // over-allocating per tunnel (S6 fix). Defaults are modest; AETHER_H2_WINDOW_MB
    // can raise the stream window up to a hard cap of 32 MiB for high-BDP links.
    let win_mb = crate::runtime_env::var("AETHER_H2_WINDOW_MB")
        .and_then(|v| v.trim().parse::<u32>().ok())
        .unwrap_or(4)
        .clamp(1, 32);
    let stream_window = win_mb * 1024 * 1024;
    let conn_window = stream_window.saturating_mul(2);
    let mut h2_builder = h2::client::Builder::new();
    h2_builder.initial_window_size(stream_window);
    h2_builder.initial_connection_window_size(conn_window);
    h2_builder.max_frame_size(256 * 1024);
    let (h2, connection) = h2_builder
        .handshake(tls)
        .await
        .map_err(|e| AetherError::Masque(format!("h2 handshake: {e}")))?;
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            log::debug!("[h2] connection driver ended: {e}");
        }
    });

    let mut h2 = h2
        .ready()
        .await
        .map_err(|e| AetherError::Masque(format!("h2 ready: {e}")))?;

    let req = build_connect_request(&cfg)?;

    let (resp_fut, mut send_stream) = h2
        .send_request(req, false)
        .map_err(|e| AetherError::Masque(format!("send_request: {e}")))?;
    log::info!("[h2] connect-ip request sent to {}", cfg.authority);

    let response = resp_fut
        .await
        .map_err(|e| AetherError::Masque(format!("await response: {e}")))?;
    let status = response.status();
    log::info!("[h2] connect-ip status: {}", status.as_u16());
    if !status.is_success() {
        return Err(AetherError::Masque(format!(
            "h2 connect-ip status {}",
            status.as_u16()
        )));
    }

    let mut recv_body = response.into_body();
    let mut capsules = CapsuleParser::new();

    // Prove data plane before advertising readiness (CONNECT 200 alone is insufficient).
    let probe_src = cfg
        .probe_src
        .unwrap_or_else(|| std::net::Ipv4Addr::new(198, 18, 0, 1));
    verify_dataplane(&mut send_stream, &mut recv_body, &mut capsules, probe_src).await?;
    log::info!("AETHER_EVENT {{\"type\":\"tunnel_ready\",\"transport\":\"h2\"}}");
    let _ = ready_tx.send(());

    // Shared last traffic timestamp for stall detection (send OR recv activity resets).
    let last_traffic = std::sync::Arc::new(tokio::sync::Mutex::new(Instant::now()));
    let last_send = last_traffic.clone();
    let last_recv = last_traffic.clone();
    let probe_src_ka = probe_src;

    // CRITICAL: send and recv must not share one select. Waiting on H2 send capacity
    // used to block DATA recv + window updates → download collapsed under load.
    let send_task = tokio::spawn(async move {
        let mut idle = tokio::time::interval(Duration::from_secs(20));
        idle.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = idle.tick() => {
                    let last = *last_send.lock().await;
                    if last.elapsed() > Duration::from_secs(90) {
                        return Err(AetherError::Masque(
                            "h2 stall: no traffic for 90s".into(),
                        ));
                    }
                    // Keep-alive: small DNS probe so half-open links fail fast.
                    if last.elapsed() > Duration::from_secs(25) {
                        let probe = build_dns_probe_packet(probe_src_ka);
                        if let Err(e) = send_ip_batch(&mut send_stream, vec![probe]).await {
                            log::debug!("[h2] keepalive: {e}");
                            return Err(e);
                        }
                        *last_send.lock().await = Instant::now();
                    }
                }
                ctrl = ctrl_rx.recv() => {
                    match ctrl {
                        Some(Control::Close) | None => {
                            let _ = send_stream.send_data(Bytes::new(), true);
                            log::info!("[h2] closing tunnel (send)");
                            return Ok::<(), AetherError>(());
                        }
                        Some(Control::Migrate) => {}
                    }
                }
                pkt = outbound_rx.recv() => {
                    match pkt {
                        Some(ip_packet) => {
                            *last_send.lock().await = Instant::now();
                            let mut batch = Vec::with_capacity(64);
                            batch.push(ip_packet);
                            while batch.len() < 128 {
                                match outbound_rx.try_recv() {
                                    Ok(p) => batch.push(p),
                                    Err(_) => break,
                                }
                            }
                            if let Err(e) = send_ip_batch(&mut send_stream, batch).await {
                                log::debug!("[h2] send: {e}");
                                return Err(e);
                            }
                        }
                        None => {
                            let _ = send_stream.send_data(Bytes::new(), true);
                            return Ok(());
                        }
                    }
                }
            }
        }
    });

    let recv_task = tokio::spawn(async move {
        loop {
            match tokio::time::timeout(
                Duration::from_secs(45),
                futures::future::poll_fn(|cx| recv_body.poll_data(cx)),
            )
            .await
            {
                Ok(Some(Ok(chunk))) => {
                    *last_recv.lock().await = Instant::now();
                    let _ = recv_body.flow_control().release_capacity(chunk.len());
                    capsules.push(&chunk);
                    drain_capsules(&mut capsules, &inbound_tx, &addr_tx).await;
                }
                Ok(Some(Err(e))) => {
                    log::warn!("[h2] recv body error: {e}");
                    return Err(AetherError::Masque(format!("h2 body: {e}")));
                }
                Ok(None) => {
                    log::info!("[h2] server closed stream");
                    return Ok::<(), AetherError>(());
                }
                Err(_) => {
                    let last = *last_recv.lock().await;
                    if last.elapsed() > Duration::from_secs(90) {
                        return Err(AetherError::Masque(
                            "h2 stall: no data from edge for 90s".into(),
                        ));
                    }
                }
            }
        }
    });

    tokio::select! {
        r = send_task => {
            match r {
                Ok(Ok(())) => Ok(()),
                Ok(Err(e)) => Err(e),
                Err(e) => Err(AetherError::Masque(format!("h2 send task: {e}"))),
            }
        }
        r = recv_task => {
            match r {
                Ok(Ok(())) => Ok(()),
                Ok(Err(e)) => Err(e),
                Err(e) => Err(AetherError::Masque(format!("h2 recv task: {e}"))),
            }
        }
    }
}

fn build_dns_probe_packet(src: std::net::Ipv4Addr) -> Vec<u8> {
    // Minimal IPv4 UDP DNS query: src → 1.1.1.1:53 A for cloudflare.com.
    // NOTE (L3): this query travels inside the encrypted tunnel purely to prove
    // the data plane works. It is not the user's system resolver and does not leak
    // DNS outside the tunnel.
    let mut dns = Vec::with_capacity(64);
    let id: u16 = rand::random();
    dns.extend_from_slice(&id.to_be_bytes());
    dns.extend_from_slice(&[0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    for label in ["cloudflare", "com"] {
        dns.push(label.len() as u8);
        dns.extend_from_slice(label.as_bytes());
    }
    dns.push(0);
    dns.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // A IN

    let udp_len = 8 + dns.len();
    let total = 20 + udp_len;
    let mut pkt = Vec::with_capacity(total);
    pkt.push(0x45);
    pkt.push(0x00);
    pkt.extend_from_slice(&(total as u16).to_be_bytes());
    pkt.extend_from_slice(&rand::random::<u16>().to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00, 64, 17, 0x00, 0x00]);
    pkt.extend_from_slice(&src.octets());
    pkt.extend_from_slice(&[1, 1, 1, 1]);
    let csum = ipv4_header_checksum(&pkt[0..20]);
    pkt[10..12].copy_from_slice(&csum.to_be_bytes());
    let sport: u16 = 40000 + (rand::random::<u16>() % 20000);
    pkt.extend_from_slice(&sport.to_be_bytes());
    pkt.extend_from_slice(&53u16.to_be_bytes());
    pkt.extend_from_slice(&(udp_len as u16).to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt.extend_from_slice(&dns);
    pkt
}

/// Strictly validate that an inbound IPv4 datagram is a UDP DNS reply from
/// 1.1.1.1:53 (the resolver our probe targets). Prevents an unrelated or stray
/// datagram from being treated as data-plane proof (S4 fix).
fn is_dns_reply_from_resolver(pkt: &[u8]) -> bool {
    if pkt.len() < 28 || pkt[0] >> 4 != 4 {
        return false;
    }
    let ihl = ((pkt[0] & 0x0f) as usize) * 4;
    if ihl < 20 || pkt.len() < ihl + 8 || pkt[9] != 17 {
        return false;
    }
    if pkt[12..16] != [1, 1, 1, 1] {
        return false;
    }
    u16::from_be_bytes([pkt[ihl], pkt[ihl + 1]]) == 53
}

fn ipv4_header_checksum(header: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut i = 0;
    while i + 1 < header.len() {
        if i == 10 {
            i += 2;
            continue;
        }
        sum += u16::from_be_bytes([header[i], header[i + 1]]) as u32;
        i += 2;
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

async fn verify_dataplane(
    send: &mut h2::SendStream<Bytes>,
    recv_body: &mut h2::RecvStream,
    capsules: &mut CapsuleParser,
    probe_src: std::net::Ipv4Addr,
) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(8);
    let mut confirms = 0u8;
    let mut resend_at = Instant::now();
    while Instant::now() < deadline {
        if Instant::now() >= resend_at {
            let probe = build_dns_probe_packet(probe_src);
            send_ip_batch(send, vec![probe]).await?;
            resend_at = Instant::now() + Duration::from_millis(700);
        }
        let wait = deadline
            .saturating_duration_since(Instant::now())
            .min(Duration::from_millis(400));
        match tokio::time::timeout(wait, futures::future::poll_fn(|cx| recv_body.poll_data(cx)))
            .await
        {
            Ok(Some(Ok(chunk))) => {
                let _ = recv_body.flow_control().release_capacity(chunk.len());
                capsules.push(&chunk);
                loop {
                    match capsules.next() {
                        Ok(Some(Capsule::Datagram(pkt))) if pkt.len() >= 28 => {
                            // S4 fix: require a genuine UDP DNS reply from 1.1.1.1:53
                            // rather than accepting any inbound datagram as proof.
                            if is_dns_reply_from_resolver(&pkt) {
                                confirms += 1;
                                if confirms >= 1 {
                                    log::info!("[h2] data-plane verified (dns reply from 1.1.1.1:53)");
                                    return Ok(());
                                }
                            } else {
                                log::debug!("[h2] ignoring unrelated inbound datagram during verify");
                            }
                        }
                        Ok(Some(_)) => {}
                        Ok(None) => break,
                        Err(_) => break,
                    }
                }
            }
            Ok(Some(Err(e))) => {
                return Err(AetherError::Masque(format!("h2 verify recv: {e}")));
            }
            Ok(None) => {
                return Err(AetherError::Masque("h2 closed during data-plane verify".into()));
            }
            Err(_) => {}
        }
    }
    Err(AetherError::Masque(
        "h2 data-plane verify timeout (CONNECT ok, no traffic)".into(),
    ))
}

async fn send_capsule(send: &mut h2::SendStream<Bytes>, mut data: Bytes) -> Result<()> {
    if data.is_empty() {
        return Ok(());
    }

    // Send in whatever capacity the stream grants — waiting for full `len` stalls the
    // whole tunnel under load (single-stream CONNECT-IP carries every IP packet).
    while !data.is_empty() {
        let want = data.len();
        send.reserve_capacity(want);
        let n = match futures::future::poll_fn(|cx| send.poll_capacity(cx)).await {
            Some(Ok(n)) if n > 0 => n.min(want),
            Some(Ok(_)) => {
                send.reserve_capacity(want);
                continue;
            }
            Some(Err(e)) => return Err(AetherError::Masque(format!("h2 capacity: {e}"))),
            None => return Err(AetherError::Masque("h2 stream closed".into())),
        };
        let chunk = data.split_to(n);
        send.send_data(chunk, false)
            .map_err(|e| AetherError::Masque(format!("h2 send_data: {e}")))?;
    }
    Ok(())
}

/// Coalesce many IP packets into one or few H2 DATA frames.
async fn send_ip_batch(send: &mut h2::SendStream<Bytes>, packets: Vec<Vec<u8>>) -> Result<()> {
    if packets.is_empty() {
        return Ok(());
    }
    // Target ~32KB frames to cut H2 framing overhead without huge latency.
    const TARGET: usize = 32 * 1024;
    let mut buf = Vec::with_capacity(TARGET);
    for pkt in packets {
        let framed = masque::encode_datagram_capsule(&pkt);
        if !buf.is_empty() && buf.len() + framed.len() > TARGET {
            send_capsule(send, Bytes::from(std::mem::take(&mut buf))).await?;
            buf.reserve(TARGET);
        }
        buf.extend_from_slice(&framed);
    }
    if !buf.is_empty() {
        send_capsule(send, Bytes::from(buf)).await?;
    }
    Ok(())
}

async fn drain_capsules(
    capsules: &mut CapsuleParser,
    inbound_tx: &mpsc::Sender<Vec<u8>>,
    addr_tx: &Option<mpsc::Sender<AssignedAddr>>,
) {
    loop {
        match capsules.next() {
            Ok(Some(Capsule::Datagram(pkt))) => {
                // Prefer try_send so H2 recv keeps releasing windows. Fall back to await.
                match inbound_tx.try_send(pkt) {
                    Ok(()) => {}
                    Err(tokio::sync::mpsc::error::TrySendError::Full(pkt)) => {
                        if inbound_tx.send(pkt).await.is_err() {
                            return;
                        }
                    }
                    Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => return,
                }
            }
            Ok(Some(Capsule::AddressAssign(addrs))) => {
                for a in addrs {
                    if let Some(ip) = bytes_to_ip(a.ip_version, &a.address) {
                        log::info!("[h2] edge assigned {}/{}", ip, a.prefix_len);
                        if let Some(tx) = addr_tx {
                            let _ = tx.try_send(AssignedAddr {
                                ip,
                                prefix: a.prefix_len,
                            });
                        }
                    }
                }
            }
            Ok(Some(Capsule::RouteAdvertisement(routes))) => {
                log::info!("[h2] received {} route advertisements", routes.len());
            }
            Ok(Some(_)) => {}
            Ok(None) => break,
            Err(e) => {
                log::debug!("[h2] capsule parse: {e}");
                break;
            }
        }
    }
}

fn bytes_to_ip(version: u8, bytes: &[u8]) -> Option<IpAddr> {
    match version {
        4 if bytes.len() == 4 => Some(IpAddr::V4([bytes[0], bytes[1], bytes[2], bytes[3]].into())),
        6 if bytes.len() == 16 => {
            let mut b = [0u8; 16];
            b.copy_from_slice(bytes);
            Some(IpAddr::V6(b.into()))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::masque::CapsuleParser;

    #[test]
    fn dns_probe_is_ipv4_udp_to_1111() {
        let src = std::net::Ipv4Addr::new(198, 18, 0, 1);
        let pkt = build_dns_probe_packet(src);
        assert!(pkt.len() >= 28, "header+udp min");
        assert_eq!(pkt[0] >> 4, 4, "IPv4");
        assert_eq!(pkt[9], 17, "UDP");
        assert_eq!(&pkt[12..16], &src.octets());
        assert_eq!(&pkt[16..20], &[1, 1, 1, 1]);
        assert_eq!(u16::from_be_bytes([pkt[22], pkt[23]]), 53);
    }

    #[test]
    fn ipv4_checksum_field_zeroed_in_sum() {
        let pkt = build_dns_probe_packet(std::net::Ipv4Addr::new(10, 0, 0, 2));
        // Recompute: with stored checksum, ones-complement sum of header should be 0xffff.
        let mut sum = 0u32;
        for i in (0..20).step_by(2) {
            sum += u16::from_be_bytes([pkt[i], pkt[i + 1]]) as u32;
        }
        while sum > 0xffff {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        assert_eq!(sum as u16, 0xffff);
    }

    #[test]
    fn dataplane_accepts_only_dns_reply_from_resolver() {
        // Outbound probe is a query (src != 1.1.1.1) and must NOT count as a reply.
        let probe = build_dns_probe_packet(std::net::Ipv4Addr::new(198, 18, 0, 1));
        assert!(!is_dns_reply_from_resolver(&probe));

        // Minimal IPv4/UDP datagram from 1.1.1.1:53 must be accepted.
        let mut reply = vec![0u8; 28];
        reply[0] = 0x45; // IPv4, IHL=5
        reply[9] = 17; // UDP
        reply[12..16].copy_from_slice(&[1, 1, 1, 1]); // src = 1.1.1.1
        reply[20..22].copy_from_slice(&53u16.to_be_bytes()); // src port 53
        assert!(is_dns_reply_from_resolver(&reply));
    }

    #[test]
    fn datagram_capsule_roundtrip_for_probe() {
        let pkt = build_dns_probe_packet(std::net::Ipv4Addr::new(198, 18, 0, 1));
        let framed = masque::encode_datagram_capsule(&pkt);
        let mut parser = CapsuleParser::new();
        parser.push(&framed);
        match parser.next().expect("parse") {
            Some(Capsule::Datagram(got)) => assert_eq!(got, pkt),
            other => panic!("expected datagram, got {other:?}"),
        }
    }
}
