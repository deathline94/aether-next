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
}

pub fn enabled() -> bool {
    match std::env::var("AETHER_MASQUE_HTTP2") {
        Ok(v) => {
            let v = v.trim().to_lowercase();
            v == "1" || v == "true" || v == "h2" || v == "yes" || v == "on"
        }
        Err(_) => false,
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

    builder.set_verify(SslVerifyMode::NONE);

    let connector = builder.build();
    let mut config = connector
        .configure()
        .map_err(|e| AetherError::Tls(e.to_string()))?;
    config.set_verify_hostname(false);
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

    // Large windows — default h2 crate limits throttle a single CONNECT-IP stream hard.
    let mut h2_builder = h2::client::Builder::new();
    h2_builder.initial_window_size(16 * 1024 * 1024);
    h2_builder.initial_connection_window_size(32 * 1024 * 1024);
    h2_builder.max_frame_size(1024 * 1024);
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
    log::info!("AETHER_EVENT {{\"type\":\"tunnel_ready\",\"transport\":\"h2\"}}");
    log::info!("AETHER_EVENT {{\"type\":\"connected\",\"detail\":\"masque h2 ready\"}}");

    let mut recv_body = response.into_body();
    let mut capsules = CapsuleParser::new();

    // CRITICAL: send and recv must not share one select. Waiting on H2 send capacity
    // used to block DATA recv + window updates → download collapsed under load.
    let send_task = tokio::spawn(async move {
        loop {
            tokio::select! {
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
            match futures::future::poll_fn(|cx| recv_body.poll_data(cx)).await {
                Some(Ok(chunk)) => {
                    let _ = recv_body.flow_control().release_capacity(chunk.len());
                    capsules.push(&chunk);
                    drain_capsules(&mut capsules, &inbound_tx, &addr_tx).await;
                }
                Some(Err(e)) => {
                    log::warn!("[h2] recv body error: {e}");
                    return Err(AetherError::Masque(format!("h2 body: {e}")));
                }
                None => {
                    log::info!("[h2] server closed stream");
                    return Ok::<(), AetherError>(());
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
