use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use quiche::h3;
use quiche::h3::NameValue;
use rand::RngCore;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::masque::{self, CapsuleParser};
#[allow(unused_imports)]
use crate::noize::{self, NoizeConfig};
use crate::tls::{self, TlsParams};
use crate::{consts, error::AetherError, error::Result};

const MAX_DATAGRAM_SIZE: usize = 1350;
const NET_QUEUE: usize = 2048;

use std::sync::atomic::{AtomicU64, Ordering};

static QLOG_SEQ: AtomicU64 = AtomicU64::new(0);

/// Resolve the SNI for the H3 (QUIC) MASQUE path.
/// Precedence: `AETHER_MASQUE_H3_SNI` > `AETHER_MASQUE_SNI` > consumer-masque default.
pub fn resolve_h3_sni() -> String {
    resolve_h3_sni_from(
        crate::runtime_env::var("AETHER_MASQUE_H3_SNI"),
        crate::runtime_env::var("AETHER_MASQUE_SNI"),
    )
}

fn resolve_h3_sni_from(h3_override: Option<String>, generic: Option<String>) -> String {
    let pick = |o: Option<String>| o.map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    pick(h3_override)
        .or_else(|| pick(generic))
        .unwrap_or_else(|| consts::CONNECT_SNI.to_string())
}

/// Resolve the H3 CONNECT-IP `:authority` (override: `AETHER_MASQUE_H3_AUTHORITY`).
pub fn resolve_h3_authority() -> String {
    crate::runtime_env::var("AETHER_MASQUE_H3_AUTHORITY")
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| default_authority().to_string())
}

/// Resolve the H3 CONNECT-IP `:path` (override: `AETHER_MASQUE_H3_PATH`).
pub fn resolve_h3_path() -> String {
    crate::runtime_env::var("AETHER_MASQUE_H3_PATH")
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| default_path().to_string())
}

/// Send one IP packet over the H3 data plane, choosing QUIC DATAGRAM or a
/// DATAGRAM capsule on the request stream per `use_capsule` (RFC 9297 fallback).
fn send_ip_h3(
    conn: &mut quiche::Connection,
    h3c: &mut h3::Connection,
    sid: u64,
    ip_packet: &[u8],
    use_capsule: bool,
) {
    if use_capsule {
        let cap = masque::encode_datagram_capsule(ip_packet);
        if let Err(e) = h3c.send_body(conn, sid, &cap, false) {
            log::debug!("capsule dgram send: {e}");
        }
    } else {
        match masque::encode_ip_datagram(sid, ip_packet) {
            Ok(framed) => {
                if let Err(e) = conn.dgram_send(&framed) {
                    log::debug!("dgram_send: {e}");
                }
            }
            Err(e) => log::debug!("encap: {e}"),
        }
    }
}

/// Emit a labeled H3 milestone to logs + as a structured `AETHER_EVENT` so the
/// exact failing stage is unambiguous. `detail` must not contain double quotes.
fn h3_stage(stage: &str, detail: &str) {
    log::info!("[h3][stage] {stage} \u{2014} {detail}");
    log::info!("AETHER_EVENT {{\"type\":\"h3_stage\",\"stage\":\"{stage}\",\"detail\":\"{detail}\"}}");
}

/// True when H3 per-stage tracing is requested (`AETHER_H3_TRACE`). The probe
/// harness enables it; normal scans stay quiet to avoid per-probe log spam.
fn h3_trace_on() -> bool {
    crate::runtime_env::flag("AETHER_H3_TRACE")
}

/// Attach qlog (when `AETHER_QLOG_DIR` is set) and TLS keylog (`SSLKEYLOGFILE`) to
/// a fresh connection for offline decryption/analysis. Must be called right
/// after `quiche::connect`, before the first flush, or early events are lost.
fn maybe_enable_diagnostics(conn: &mut quiche::Connection, tag: &str) {
    if let Some(dir) = crate::runtime_env::var("AETHER_QLOG_DIR") {
        let dir = dir.trim().to_string();
        if !dir.is_empty() {
            let _ = std::fs::create_dir_all(&dir);
            let seq = QLOG_SEQ.fetch_add(1, Ordering::Relaxed);
            let file =
                std::path::Path::new(&dir).join(format!("{tag}-{}-{seq}.qlog", std::process::id()));
            match std::fs::File::create(&file) {
                Ok(f) => {
                    conn.set_qlog(Box::new(f), "aether-h3".to_string(), format!("qlog {tag}"));
                    log::info!("[h3] qlog -> {}", file.display());
                }
                Err(e) => log::debug!("[h3] qlog create failed: {e}"),
            }
        }
    }
    if let Ok(path) = std::env::var("SSLKEYLOGFILE") {
        let path = path.trim().to_string();
        if !path.is_empty() {
            if let Ok(f) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
                conn.set_keylog(Box::new(f));
                log::info!("[h3] keylog -> {path}");
            }
        }
    }
}

async fn bind_udp_fast(bind_addr: SocketAddr) -> Result<UdpSocket> {
    use socket2::{Socket, Domain, Type};
    let domain = if bind_addr.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
    let sock = Socket::new(domain, Type::DGRAM, None).map_err(AetherError::Io)?;
    sock.set_nonblocking(true).map_err(AetherError::Io)?;
    
    let buf_size = 7 * 1024 * 1024; // 7MB
    let _ = sock.set_recv_buffer_size(buf_size);
    let _ = sock.set_send_buffer_size(buf_size);
    
    sock.bind(&bind_addr.into()).map_err(AetherError::Io)?;
    UdpSocket::from_std(sock.into()).map_err(AetherError::Io)
}

#[derive(Debug, Clone)]
pub struct AssignedAddr {
    pub ip: IpAddr,
    pub prefix: u8,
}

#[derive(Debug, Clone)]
pub struct TunnelConfig {
    pub peer: SocketAddr,
    pub sni: String,
    pub authority: String,
    pub path: String,
    pub cert_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
    /// Tunnel identity IPv4, used as the data-plane probe source. Threaded here
    /// instead of via a process-global AETHER_PROBE_SRC that a concurrent scan
    /// could clobber.
    pub local_ipv4: std::net::Ipv4Addr,
    pub ech_config_list: Option<Vec<u8>>,
    pub noize: NoizeConfig,
}

pub struct Channels {
    pub outbound_tx: mpsc::Sender<Vec<u8>>,
    pub inbound_rx: mpsc::Receiver<Vec<u8>>,
}

pub fn channels() -> (Channels, Internals) {
    let (outbound_tx, outbound_rx) = crate::tunnel::packet_channels();
    let (inbound_tx, inbound_rx) = crate::tunnel::packet_channels();

    (
        Channels {
            outbound_tx,
            inbound_rx,
        },
        Internals {
            outbound_rx,
            inbound_tx,
        },
    )
}

pub struct Internals {
    outbound_rx: mpsc::Receiver<Vec<u8>>,
    inbound_tx: mpsc::Sender<Vec<u8>>,
}

impl Internals {
    pub fn into_parts(
        self,
    ) -> (
        mpsc::Receiver<Vec<u8>>,
        mpsc::Sender<Vec<u8>>,
    ) {
        (self.outbound_rx, self.inbound_tx)
    }
}

type NetPacket = (SocketAddr, SocketAddr, Vec<u8>);

/// Holds spawned UDP-reader tasks; aborts them on drop so old readers
/// cannot leak when the tunnel migrates sockets, reconnects, or unwinds.
/// Without this, a long-lived session that reconnects many times accumulates
/// orphaned tokio tasks each holding a dedicated read buffer (>=64KB × N leaks).
struct ReaderGuard {
    handles: Vec<tokio::task::JoinHandle<()>>,
}

impl ReaderGuard {
    fn new() -> Self {
        Self { handles: Vec::new() }
    }
    fn push(&mut self, h: tokio::task::JoinHandle<()>) {
        self.handles.push(h);
    }
}

impl Drop for ReaderGuard {
    fn drop(&mut self) {
        for h in self.handles.drain(..) {
            h.abort();
        }
    }
}

fn bind_addr_for(peer: &SocketAddr) -> SocketAddr {
    if peer.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    }
}

fn random_scid() -> [u8; 16] {
    let mut scid = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut scid);
    scid
}

pub const QUIC_V2_BAIT_WAIT: Duration = Duration::from_millis(600);
pub const QUIC_V2_BAIT_LEN: usize = 1200;
pub const DATA_PROBE_REQUIRED_SUCCESSES: u32 = 2;

pub fn quic_v2_bait_enabled() -> bool {
    let val = crate::runtime_env::var("AETHER_QUIC_V2")
        .or_else(|| std::env::var("AETHER_QUIC_V2").ok());
    !matches!(
        val.as_deref(),
        Some("0") | Some("off") | Some("false") | Some("no")
    )
}

fn quic_varint2(value: u64) -> [u8; 2] {
    (((value & 0x3fff) as u16) | 0x4000).to_be_bytes()
}

pub fn build_version_bait() -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut dcid = [0u8; 8];
    let mut scid = [0u8; 8];
    rng.fill_bytes(&mut dcid);
    rng.fill_bytes(&mut scid);

    let mut pkt = Vec::with_capacity(QUIC_V2_BAIT_LEN);
    pkt.push(0xc3);
    pkt.extend_from_slice(&consts::QUIC_V2_VERSION.to_be_bytes());
    pkt.push(dcid.len() as u8);
    pkt.extend_from_slice(&dcid);
    pkt.push(scid.len() as u8);
    pkt.extend_from_slice(&scid);
    pkt.push(0x00);

    let remaining = QUIC_V2_BAIT_LEN - pkt.len() - 2;
    pkt.extend_from_slice(&quic_varint2(remaining as u64));
    let mut pn = [0u8; 4];
    rng.fill_bytes(&mut pn);
    pkt.extend_from_slice(&pn);
    pkt.resize(QUIC_V2_BAIT_LEN, 0);
    pkt
}

pub async fn send_version_bait(sock: &UdpSocket, target: SocketAddr, wait: Duration, tries: usize) {
    let bait = build_version_bait();
    let connected = sock.peer_addr().is_ok();
    let mut buf = [0u8; 2048];

    for attempt in 0..tries.max(1) {
        let sent = if connected {
            sock.send(&bait).await
        } else {
            sock.send_to(&bait, target).await
        };
        if sent.is_err() {
            return;
        }

        let answered = tokio::time::timeout(wait, async {
            if connected {
                sock.recv(&mut buf).await
            } else {
                sock.recv_from(&mut buf).await.map(|(n, _)| n)
            }
        })
        .await;

        match answered {
            Ok(Ok(n)) => {
                log::debug!(
                    "[quic] version-negotiation bait answered with {n} bytes; path is open for v1"
                );
                return;
            }
            Ok(Err(_)) => return,
            Err(_) => log::trace!(
                "[quic] version-negotiation bait attempt {} went unanswered",
                attempt + 1
            ),
        }
    }
}

fn spawn_reader(sock: Arc<UdpSocket>, local: SocketAddr, tx: mpsc::Sender<NetPacket>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            match sock.recv_from(&mut buf).await {
                Ok((n, from)) => {
                    log::debug!("recv {n} bytes from {from}");
                    if tx.send((local, from, buf[..n].to_vec())).await.is_err() {
                        break;
                    }
                },
                Err(e) => {
                    log::debug!("recv error: {e}");
                    break;
                }
            }
        }
    })
}

pub async fn run(
    cfg: TunnelConfig,
    mut internals: Internals,
    addr_tx: Option<mpsc::Sender<AssignedAddr>>,
    ready_tx: tokio::sync::oneshot::Sender<()>,
) -> Result<()> {
    let peer = cfg.peer;
    let mut ready_tx = Some(ready_tx);
    let mut h3_ready = false;
    let mut dataplane_ok = false;
    let mut probe_deadline: Option<Instant> = None;
    let mut last_probe = Instant::now()
        .checked_sub(Duration::from_secs(1))
        .unwrap_or_else(Instant::now);
    // Data-plane probe source = the tunnel's own identity IPv4, threaded via the
    // config rather than read from a process-global. AETHER_PROBE_SRC remains a
    // diagnostic-only override.
    let mut probe_src = crate::runtime_env::var("AETHER_PROBE_SRC")
        .and_then(|s| s.parse().ok())
        .unwrap_or(cfg.local_ipv4);

    let init_sock = bind_udp_fast(bind_addr_for(&peer)).await?;
    let local = init_sock.local_addr()?;
    let init_sock = Arc::new(init_sock);

    if quic_v2_bait_enabled() {
        send_version_bait(&init_sock, peer, QUIC_V2_BAIT_WAIT, 2).await;
    }

    let (net_tx, mut net_rx) = mpsc::channel::<NetPacket>(NET_QUEUE);

    let mut sockets: HashMap<SocketAddr, Arc<UdpSocket>> = HashMap::new();
    sockets.insert(local, init_sock.clone());
    // ReaderGuard aborts ALL spawned readers when this scope exits (reconnect,
    // tunnel-close, panic). Without it, every Migrate spawns a fresh reader
    // that holds a 64KB buffer + task slot forever — long sessions leak.
    let mut readers = ReaderGuard::new();
    readers.push(spawn_reader(init_sock, local, net_tx.clone()));

    let mut config = tls::build_config(&TlsParams {
        cert_pem: &cfg.cert_pem,
        key_pem: &cfg.key_pem,
    })?;

    // #1: Load cached session ticket for 0-RTT resumption (faster reconnect).
    // Note: quiche fork doesn't expose set_session; 0-RTT relies on enable_early_data()
    // in tls.rs and quiche's internal session caching.
    let _session_cache_path = crate::lastconn::session_ticket_path();

    let mut current_ech = cfg.ech_config_list.clone();

    let scid_bytes = random_scid();
    let scid = quiche::ConnectionId::from_ref(&scid_bytes);

    let mut conn = quiche::connect(Some(&cfg.sni), &scid, local, peer, &mut config)?;
    maybe_enable_diagnostics(&mut conn, "tunnel");

    if let Some(ref ech) = current_ech {
        tls::inject_ech(&mut conn, ech)?;
        log::info!("ech config injected ({} bytes)", ech.len());
    }

    let mut h3_config = h3::Config::new()?;
    h3_config.enable_extended_connect(true);
    let mut h3_conn: Option<h3::Connection> = None;
    let mut req_stream: Option<u64> = None;
    let mut capsules = CapsuleParser::new();
    let mut established_ever = false;
    let mut ech_retried = false;
    let mut udp_seen = false;
    let mut h3_settings_logged = false;
    let mut dgram_by_peer = false;
    let mut addr_assigned = false;
    let mut ready_since: Option<Instant> = None;
    let h3_dgram_mode = crate::masque::H3DgramMode::from_env();
    let inbound_tx = internals.inbound_tx.clone();
    log::info!("[h3] data-plane mode: {}", h3_dgram_mode.label());

    // Send obfuscation noise before the QUIC Initial. Cloudflare's edge drops
    // non-QUIC datagrams silently, but DPI boxes see the junk and lose flow
    // correlation. The mother repo (CluvexStudio/Aether) confirms this works.
    if let Some(sock) = sockets.get(&local) {
        noize::pre_handshake(sock.as_ref(), peer, &cfg.noize).await;
    }

    flush(&mut conn, &sockets).await?;

    let mut out_buf = vec![0u8; 65535];
    let mut keepalive_interval = tokio::time::interval(Duration::from_secs(20));
    keepalive_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut started = Instant::now();

    loop {
        // Fast-fail on a QUIC-hostile path: instead of burning the session's full
        // data-plane budget (and hanging the UI for ~45s), bail quickly with a
        // clear reason when there is no sign of QUIC life. Only before the data
        // plane is up; once traffic flows these checks are inert.
        if !dataplane_ok {
            let elapsed = started.elapsed();
            if !udp_seen && elapsed >= Duration::from_secs(6) {
                let msg = "no UDP reply from gateway; the network may be blocking QUIC/UDP (try HTTP/2 or WireGuard)";
                log::warn!("[h3] fast-fail: {msg}");
                return Err(AetherError::Other(msg.into()));
            }
            if udp_seen && !established_ever && elapsed >= Duration::from_secs(12) {
                let msg = "QUIC handshake did not complete; the path may be interfering with QUIC (try HTTP/2 or WireGuard)";
                log::warn!("[h3] fast-fail: {msg}");
                return Err(AetherError::Other(msg.into()));
            }
        }
        let timeout = conn.timeout();

        tokio::select! {
            biased;
            
            _ = keepalive_interval.tick() => {
                if conn.is_established() {
                    if let Err(e) = conn.send_ack_eliciting() {
                        log::debug!("keepalive ping failed: {e}");
                    }
                }
            }

            maybe = net_rx.recv() => {
                // L6 fix: this arm previously used a `Some(..)` pattern, which
                // silently disabled it once all UDP readers died and left the
                // loop spinning between PTO wakes forever. Reader death means
                // the socket is gone — close cleanly so run() returns.
                match maybe {
                    Some((to_local, from, mut data)) => {
                        if !udp_seen {
                            udp_seen = true;
                            h3_stage("udp_first_reply", &format!("from {from} bytes {}", data.len()));
                        }
                        let mut hdr_buf = data.clone();
                        if let Ok(hdr) = quiche::Header::from_slice(&mut hdr_buf, quiche::MAX_CONN_ID_LEN) {
                            log::debug!("recv {} bytes type={:?} version=0x{:x} from {}", data.len(), hdr.ty, hdr.version, from);
                        }
                        let info = quiche::RecvInfo { from, to: to_local };
                        if let Err(e) = conn.recv(&mut data, info) {
                            log::debug!("recv error: {e}");
                        }
                    }
                    None => {
                        let _ = conn.close(true, 0x00, b"udp readers gone");
                    }
                }
            }

            pkt = internals.outbound_rx.recv() => {
                match pkt {
                    Some(ip_packet) => {
                        let use_capsule = h3_dgram_mode.use_capsule(dgram_by_peer);
                        if let (Some(sid), Some(h3c)) = (req_stream, h3_conn.as_mut()) {
                            send_ip_h3(&mut conn, h3c, sid, &ip_packet, use_capsule);
                            // Batch remaining IP packets same tick.
                            while let Ok(more) = internals.outbound_rx.try_recv() {
                                send_ip_h3(&mut conn, h3c, sid, &more, use_capsule);
                            }
                        }
                    }
                    None => {
                        let _ = conn.close(true, 0x00, b"eof");
                    }
                }
            }

            _ = tokio::time::sleep(Duration::from_millis(200)), if h3_ready && !dataplane_ok => {
                // Drive the CONNECT-IP data-plane probe + its 8s timeout promptly.
                // Otherwise, after a 200 with no inbound traffic this loop only
                // wakes on QUIC timers / the 20s keepalive, stalling readiness
                // (observed: connect_ip_status 200 then no progress for ~15s).
            }

            _ = sleep_opt(timeout) => {
                conn.on_timeout();
            }
        }

        if conn.is_established() && h3_conn.is_none() {
            established_ever = true;
            log::info!(
                "quic handshake established; alpn={}",
                String::from_utf8_lossy(conn.application_proto())
            );
            h3_stage(
                "quic_established",
                &format!("alpn={}", String::from_utf8_lossy(conn.application_proto())),
            );
            // #1: Cache session ticket for 0-RTT on next connect.
            if let Some(session) = conn.session() {
                crate::lastconn::save_session_ticket(session);
            }
            let mut h3c = h3::Connection::with_transport(&mut conn, &h3_config)?;
            let headers = masque::connect_ip_request(&cfg.authority, &cfg.path);
            let sid = h3c.send_request(&mut conn, &headers, false)?;
            log::info!("connect-ip request sent on stream {sid}");
            req_stream = Some(sid);
            h3_conn = Some(h3c);
        }

        if let (Some(h3c), Some(sid)) = (h3_conn.as_mut(), req_stream) {
            poll_h3(
                &mut conn,
                h3c,
                sid,
                &mut capsules,
                &addr_tx,
                &mut h3_ready,
                &mut probe_src,
                &inbound_tx,
                &mut dataplane_ok,
                &mut addr_assigned,
            )?;
        }

        // Once the peer's SETTINGS are in, record whether H3 DATAGRAM + extended
        // CONNECT were negotiated — the make-or-break capabilities for CONNECT-IP.
        if !h3_settings_logged {
            if let Some(h3c) = h3_conn.as_ref() {
                if h3c.peer_settings_raw().is_some() {
                    let dgram = h3c.dgram_enabled_by_peer(&conn);
                    let ext = h3c.extended_connect_enabled_by_peer();
                    dgram_by_peer = dgram;
                    h3_stage("h3_settings", &format!("dgram_by_peer={dgram} ext_connect={ext}"));
                    h3_settings_logged = true;
                }
            }
        }

        // After CONNECT-IP 200, prove data-plane with a DNS probe before ready signal.
        if h3_ready && !dataplane_ok {
            if probe_deadline.is_none() {
                probe_deadline = Some(Instant::now() + Duration::from_secs(8));
                ready_since = Some(Instant::now());
            }
            // #4: prefer probing with a real edge-assigned source. Fall back to
            // the default source only after a short grace period so endpoints
            // that never send ADDRESS_ASSIGN are still exercised.
            let grace_elapsed = ready_since
                .map(|t| t.elapsed() >= Duration::from_secs(2))
                .unwrap_or(false);
            let may_probe = addr_assigned || grace_elapsed;
            if may_probe && last_probe.elapsed() >= Duration::from_millis(700) {
                if let (Some(sid), Some(h3c)) = (req_stream, h3_conn.as_mut()) {
                    let probe = crate::dns::build_dataplane_probe(probe_src, crate::dns::dataplane_probe_target());
                    let use_capsule = h3_dgram_mode.use_capsule(dgram_by_peer);
                    send_ip_h3(&mut conn, h3c, sid, &probe, use_capsule);
                }
                last_probe = Instant::now();
            }
            if let Some(deadline) = probe_deadline {
                if Instant::now() >= deadline {
                    return Err(AetherError::Other(
                        "h3 data-plane verify timeout (CONNECT ok, no traffic)".into(),
                    ));
                }
            }
        }

        // Any inbound datagram after CONNECT-IP 200 counts as data-plane proof.
        if h3_ready && !dataplane_ok {
            // drain_datagrams below will deliver; also check capsule parser side effects via inbound
        }

        drain_datagrams(
            &mut conn,
            req_stream,
            &internals.inbound_tx,
            &mut out_buf,
            h3_ready && !dataplane_ok,
            &mut dataplane_ok,
        )
        .await;

        if h3_ready && dataplane_ok {
            if let Some(tx) = ready_tx.take() {
                log::info!("AETHER_EVENT {{\"type\":\"tunnel_ready\",\"transport\":\"h3\"}}");
                let _ = tx.send(());
            }
        }

        flush(&mut conn, &sockets).await?;

        if conn.is_closed() {
            if !established_ever && !ech_retried && current_ech.is_some() {
                if let Some(retry) = tls::extract_ech_retry_configs(&mut conn) {
                    log::warn!(
                        "ech_required: retrying handshake with server retry_configs ({} bytes)",
                        retry.len()
                    );
                    ech_retried = true;
                    current_ech = Some(retry);

                    let scid_bytes = random_scid();
                    let scid = quiche::ConnectionId::from_ref(&scid_bytes);
                    conn = quiche::connect(Some(&cfg.sni), &scid, local, peer, &mut config)?;
                    maybe_enable_diagnostics(&mut conn, "tunnel-retry");
                    if let Some(ref ech) = current_ech {
                        tls::inject_ech(&mut conn, ech)?;
                    }

                    // L4 fix: reset the fast-fail clock for the retry handshake —
                    // the old code kept the ORIGINAL `started`/`udp_seen` state, so
                    // the retry inherited whatever budget the failed attempt had
                    // already burned and could fast-fail before its own handshake
                    // got a fair chance.
                    started = Instant::now();
                    udp_seen = false;
                    established_ever = false;

                    h3_conn = None;
                    req_stream = None;
                    capsules = CapsuleParser::new();
                    flush(&mut conn, &sockets).await?;
                    continue;
                }
            }

            log::info!("connection closed: {:?}", conn.stats());
            if let Some(e) = conn.peer_error() {
                log::warn!(
                    "peer closed: code=0x{:x} app={} reason={}",
                    e.error_code,
                    e.is_app,
                    String::from_utf8_lossy(&e.reason)
                );
            }
            if let Some(e) = conn.local_error() {
                log::warn!(
                    "local closed: code=0x{:x} app={} reason={}",
                    e.error_code,
                    e.is_app,
                    String::from_utf8_lossy(&e.reason)
                );
            }
            return Ok(());
        }
    }
}

async fn sleep_opt(timeout: Option<Duration>) {
    match timeout {
        Some(d) => tokio::time::sleep(d).await,
        None => std::future::pending::<()>().await,
    }
}

/// Returns true when CONNECT-IP response status is 200.
#[allow(clippy::too_many_arguments)]
fn poll_h3(
    conn: &mut quiche::Connection,
    h3c: &mut h3::Connection,
    req_stream: u64,
    capsules: &mut CapsuleParser,
    addr_tx: &Option<mpsc::Sender<AssignedAddr>>,
    h3_ready: &mut bool,
    probe_src: &mut std::net::Ipv4Addr,
    inbound_tx: &mpsc::Sender<Vec<u8>>,
    dataplane_ok: &mut bool,
    addr_assigned: &mut bool,
) -> Result<()> {
    let mut body = vec![0u8; 65535];

    loop {
        match h3c.poll(conn) {
            Ok((stream_id, h3::Event::Headers { list, .. })) => {
                for h in &list {
                    if h.name() == b":status" {
                        let status = String::from_utf8_lossy(h.value()).to_string();
                        log::info!("connect-ip status: {status}");
                        h3_stage("connect_ip_status", &format!("code={status}"));
                        if stream_id == req_stream && !status.starts_with('2') {
                            return Err(AetherError::Masque(format!(
                                "the edge refused connect-ip with status {status}"
                            )));
                        }
                        if h.value() == b"200" {
                            *h3_ready = true;
                        }
                    }
                }
            }

            Ok((stream_id, h3::Event::Data)) => {
                if stream_id != req_stream {
                    continue;
                }
                while let Ok(n) = h3c.recv_body(conn, stream_id, &mut body) {
                    if n == 0 {
                        break;
                    }
                    capsules.push(&body[..n]);
                }
                drain_capsules(capsules, addr_tx, probe_src, inbound_tx, dataplane_ok, addr_assigned);
            }

            Ok((stream_id, h3::Event::Finished)) if stream_id == req_stream => {
                return Err(AetherError::Masque(
                    "the edge closed the connect-ip stream".into(),
                ));
            }
            Ok((stream_id, h3::Event::Reset(code))) if stream_id == req_stream => {
                return Err(AetherError::Masque(format!(
                    "the edge reset the connect-ip stream (code 0x{code:x})"
                )));
            }
            Ok(_) => {}

            Err(h3::Error::Done) => break,
            Err(e) => return Err(AetherError::H3(e)),
        }
    }

    Ok(())
}


fn drain_capsules(
    capsules: &mut CapsuleParser,
    addr_tx: &Option<mpsc::Sender<AssignedAddr>>,
    probe_src: &mut std::net::Ipv4Addr,
    inbound_tx: &mpsc::Sender<Vec<u8>>,
    dataplane_ok: &mut bool,
    addr_assigned: &mut bool,
) {
    loop {
        match capsules.next() {
            Ok(Some(masque::Capsule::AddressAssign(addrs))) => {
                for a in addrs {
                    if let Some(ip) = bytes_to_ip(a.ip_version, &a.address) {
                        log::info!("edge assigned {}/{}", ip, a.prefix_len);
                        h3_stage("address_assign", &format!("{}/{}", ip, a.prefix_len));
                        *addr_assigned = true;
                        if let IpAddr::V4(v4) = ip {
                            *probe_src = v4;
                        }
                        if let Some(tx) = addr_tx {
                            let _ = tx.try_send(AssignedAddr {
                                ip,
                                prefix: a.prefix_len,
                            });
                        }
                    }
                }
            }
            Ok(Some(masque::Capsule::RouteAdvertisement(routes))) => {
                for r in &routes {
                    log::info!(
                        "route advertisement: v{} proto {} {:?}-{:?}",
                        r.ip_version, r.protocol, r.start, r.end
                    );
                }
            }
            Ok(Some(masque::Capsule::Datagram(payload))) => {
                // RFC 9297 stream fallback: IP packets arriving as DATAGRAM
                // capsules (used when H3 DATAGRAM was not negotiated).
                if !*dataplane_ok {
                    h3_stage("first_inbound_datagram", "dataplane capsule received");
                }
                *dataplane_ok = true;
                let _ = inbound_tx.try_send(payload);
            }
            Ok(Some(_)) => {}
            Ok(None) => break,
            Err(e) => {
                log::debug!("capsule parse: {e}");
                break;
            }
        }
    }
}

fn bytes_to_ip(version: u8, bytes: &[u8]) -> Option<IpAddr> {
    match version {
        4 if bytes.len() == 4 => {
            Some(IpAddr::V4([bytes[0], bytes[1], bytes[2], bytes[3]].into()))
        }
        6 if bytes.len() == 16 => {
            let mut b = [0u8; 16];
            b.copy_from_slice(bytes);
            Some(IpAddr::V6(b.into()))
        }
        _ => None,
    }
}

async fn drain_datagrams(
    conn: &mut quiche::Connection,
    req_stream: Option<u64>,
    inbound_tx: &mpsc::Sender<Vec<u8>>,
    buf: &mut [u8],
    watch_dataplane: bool,
    dataplane_ok: &mut bool,
) {
    let sid = match req_stream {
        Some(s) => s,
        None => return,
    };

    loop {
        match conn.dgram_recv(buf) {
            Ok(n) => match masque::decode_ip_datagram(&buf[..n], sid) {
                Ok(Some(ip_packet)) => {
                    // S4 fix rollback: accept any datagram (even ICMP errors) as proof 
                    // the tunnel isn't a zombie.
                    if watch_dataplane {
                        if !*dataplane_ok {
                            h3_stage("first_inbound_datagram", "dataplane packet received");
                        }
                        *dataplane_ok = true;
                    }
                    // Prefer try_send so QUIC recv keeps moving; await only under backpressure.
                    match inbound_tx.try_send(ip_packet) {
                        Ok(()) => {}
                        Err(tokio::sync::mpsc::error::TrySendError::Full(pkt)) => {
                            if inbound_tx.send(pkt).await.is_err() {
                                return;
                            }
                        }
                        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => return,
                    }
                }
                Ok(None) => {}
                Err(e) => log::debug!("decap: {e}"),
            },
            Err(quiche::Error::Done) => break,
            Err(e) => {
                log::debug!("dgram_recv: {e}");
                break;
            }
        }
    }
}

async fn flush(
    conn: &mut quiche::Connection,
    sockets: &HashMap<SocketAddr, Arc<UdpSocket>>,
) -> Result<()> {
    let mut out = vec![0u8; MAX_DATAGRAM_SIZE];

    loop {
        match conn.send(&mut out) {
            Ok((write, send_info)) => {
                if let Some(sock) = sockets.get(&send_info.from) {
                    sock.send_to(&out[..write], send_info.to).await?;
                } else if let Some((_, sock)) = sockets.iter().next() {
                    sock.send_to(&out[..write], send_info.to).await?;
                }
            }
            Err(quiche::Error::Done) => break,
            Err(e) => return Err(AetherError::Quic(e)),
        }
    }

    Ok(())
}

pub fn default_authority() -> &'static str {
    "cloudflareaccess.com"
}

pub fn default_path() -> &'static str {
    "/"
}

/// Result of a MASQUE endpoint fingerprint.
#[derive(Debug, Clone, Copy)]
pub struct H3Fingerprint {
    pub reachable: bool,
    pub ext_connect: bool,
    pub dgram: bool,
}

impl H3Fingerprint {
    /// A MASQUE-capable endpoint: extended CONNECT + H3 DATAGRAM both negotiated.
    pub fn is_masque(&self) -> bool {
        self.ext_connect && self.dgram
    }
}

/// Fingerprint a QUIC/H3 endpoint by completing the handshake and reading its
/// SETTINGS. Reports whether Extended CONNECT + H3 DATAGRAM are enabled — the
/// make-or-break MASQUE capabilities, which arrive BEFORE any CONNECT-IP auth
/// gate (403). Sends no request; closes immediately. Cheap enough to sweep a
/// CIDR to enumerate the MASQUE endpoint surface. SPKI pins should be disabled
/// by the caller (via env) so the handshake completes against any cert.
pub async fn fingerprint_h3(
    peer: SocketAddr,
    sni: &str,
    cert_pem: &[u8],
    key_pem: &[u8],
    timeout: Duration,
) -> Result<H3Fingerprint> {
    let bind: SocketAddr = if peer.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    let sock = bind_udp_fast(bind).await?;
    let local = sock.local_addr()?;
    let mut config = tls::build_config(&TlsParams { cert_pem, key_pem })?;
    let scid_bytes = random_scid();
    let scid = quiche::ConnectionId::from_ref(&scid_bytes);
    let mut conn = quiche::connect(Some(sni), &scid, local, peer, &mut config)?;
    let mut h3_config = h3::Config::new()?;
    h3_config.enable_extended_connect(true);
    let mut h3c: Option<h3::Connection> = None;
    let start = Instant::now();
    let deadline = start + timeout;
    flush_to(&mut conn, &sock, peer).await?;
    let mut buf = vec![0u8; 65535];
    let mut reachable = false;
    loop {
        if Instant::now() >= deadline {
            break;
        }
        let wait = match conn.timeout() {
            Some(t) => t.min(remaining(deadline)),
            None => remaining(deadline),
        };
        tokio::select! {
            r = sock.recv_from(&mut buf) => {
                if let Ok((n, from)) = r {
                    reachable = true;
                    let info = quiche::RecvInfo { from, to: local };
                    let _ = conn.recv(&mut buf[..n], info);
                }
            }
            _ = tokio::time::sleep(wait) => { conn.on_timeout(); }
        }
        if conn.is_established() && h3c.is_none() {
            h3c = Some(h3::Connection::with_transport(&mut conn, &h3_config)?);
        }
        if let Some(h) = h3c.as_mut() {
            // Drive the H3 control-stream exchange: peer_settings_raw() stays None
            // until poll() processes the peer's SETTINGS frame off its control stream.
            loop {
                if h.poll(&mut conn).is_err() {
                    break;
                }
            }
            if h.peer_settings_raw().is_some() {
                let ext = h.extended_connect_enabled_by_peer();
                let dg = h.dgram_enabled_by_peer(&conn);
                let _ = conn.close(true, 0x00, b"fp");
                let _ = flush_to(&mut conn, &sock, peer).await;
                return Ok(H3Fingerprint {
                    reachable: true,
                    ext_connect: ext,
                    dgram: dg,
                });
            }
        }
        flush_to(&mut conn, &sock, peer).await?;
        if conn.is_closed() {
            break;
        }
    }
    Ok(H3Fingerprint {
        reachable,
        ext_connect: false,
        dgram: false,
    })
}

#[derive(Clone)]
pub struct VerifyParams {
    pub peer: SocketAddr,
    pub sni: String,
    pub authority: String,
    pub path: String,
    pub cert_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
    pub ech_config_list: Option<Vec<u8>>,
    pub noize: NoizeConfig,
    pub timeout: Duration,
    /// Local IPv4 for data-plane probe source address.
    pub local_ipv4: std::net::Ipv4Addr,
}

pub async fn verify_masque(p: &VerifyParams) -> Result<Duration> {
    // Use unconnected send_to/recv_from — more reliable on Windows than connect()+recv
    // when intermediate devices rewrite paths.
    let bind: SocketAddr = if p.peer.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    let sock = bind_udp_fast(bind).await?;
    // NOTE: do NOT connect() the socket. A connected UDP socket only delivers
    // datagrams whose source exactly matches the peer; Cloudflare's anycast QUIC
    // edge frequently replies from a rewritten path, so a connected socket would
    // silently drop every reply (observed as "no UDP reply — QUIC may be filtered").
    // Unconnected send_to/recv_from accepts replies from any source (matches run()).
    // This is not an injection vector: QUIC drops any datagram whose DCID + AEAD tag
    // do not match this connection, and each probe owns a distinct ephemeral socket,
    // so a foreign/spoofed packet is simply ignored by conn.recv() below. (A source
    // prefix filter would instead wrongly drop Cloudflare's rewritten-path replies.)
    let local = sock.local_addr()?;

    // Cheap UDP reachability: if nothing comes back after a QUIC Initial kick,
    // fail fast instead of burning the full probe budget on a black-holed IP.
    // (Full handshake still follows when the path is alive.)

    let mut config = tls::build_config(&TlsParams {
        cert_pem: &p.cert_pem,
        key_pem: &p.key_pem,
    })?;

    let scid_bytes = random_scid();
    let scid = quiche::ConnectionId::from_ref(&scid_bytes);
    let mut conn = quiche::connect(Some(&p.sni), &scid, local, p.peer, &mut config)?;
    maybe_enable_diagnostics(&mut conn, "verify");

    if let Some(ref ech) = p.ech_config_list {
        let _ = tls::inject_ech(&mut conn, ech);
    }

    let mut h3_config = h3::Config::new()?;
    h3_config.enable_extended_connect(true);
    let mut h3_conn: Option<h3::Connection> = None;
    let mut req_stream: Option<u64> = None;

    let start = Instant::now();
    let deadline = start + p.timeout;

    // Pre-handshake QUIC v2 version negotiation bait
    if quic_v2_bait_enabled() {
        send_version_bait(&sock, p.peer, Duration::from_millis(500), 1).await;
    }

    // Obfuscation noise before QUIC Initial (same as run() — works with Cloudflare).
    noize::pre_handshake(&sock, p.peer, &p.noize).await;

    flush_to(&mut conn, &sock, p.peer).await?;

    let mut buf = vec![0u8; 65535];
    let mut saw_udp = false;
    // Handshake RTT (connect -> quic_established). Returned as the ranking metric
    // instead of the full verify time (handshake + CONNECT-IP + data-plane), which
    // isn't comparable to steady-state latency across endpoints.
    let mut handshake_rtt: Option<Duration> = None;
    let trace = h3_trace_on();
    let mut settings_logged = false;

    loop {
        if Instant::now() >= deadline {
            if !saw_udp {
                return Err(AetherError::Other(
                    "verify timeout (no UDP reply — QUIC may be filtered)".into(),
                ));
            }
            return Err(AetherError::Other("verify timeout (UDP ok, no connect-ip 200)".into()));
        }

        // Fast-fail filtered / black-holed ports: a QUIC Initial that draws no UDP
        // reply within a short window will not recover, so don't spend the full
        // (now longer) H3 probe budget on it. Critical when scanning the tiered
        // MASQUE ports, where most (e.g. a DPI-dropped 443) never answer.
        if !saw_udp && start.elapsed() >= Duration::from_millis(2000) {
            return Err(AetherError::Other(
                "verify timeout (no UDP reply — QUIC may be filtered)".into(),
            ));
        }

        let wait = match conn.timeout() {
            Some(t) => t.min(remaining(deadline)),
            None => remaining(deadline),
        };

        tokio::select! {
            r = sock.recv_from(&mut buf) => {
                match r {
                    Ok((n, from)) => {
                        if !saw_udp {
                            saw_udp = true;
                            if trace {
                                h3_stage("udp_first_reply", &format!("from {from} bytes {n}"));
                            }
                        }
                        log::debug!("verify recv {n} bytes from {from}");
                        let info = quiche::RecvInfo { from, to: local };
                        if let Err(e) = conn.recv(&mut buf[..n], info) {
                            log::debug!("verify recv error from {from}: {e}");
                        }
                    }
                    Err(e) => return Err(AetherError::Io(e)),
                }
            }
            _ = tokio::time::sleep(wait) => {
                conn.on_timeout();
            }
        }

        if conn.is_established() && h3_conn.is_none() {
            handshake_rtt.get_or_insert(start.elapsed());
            log::debug!("verify quic established to {}", p.peer);
            let mut h3c = h3::Connection::with_transport(&mut conn, &h3_config)?;
            if trace {
                h3_stage(
                    "quic_established",
                    &format!("alpn={}", String::from_utf8_lossy(conn.application_proto())),
                );
            }
            let headers = masque::connect_ip_request(&p.authority, &p.path);
            let sid = h3c.send_request(&mut conn, &headers, false)?;
            req_stream = Some(sid);
            h3_conn = Some(h3c);
        }

        if let (Some(h3c), Some(sid)) = (h3_conn.as_mut(), req_stream) {
            loop {
                match h3c.poll(&mut conn) {
                    Ok((stream_id, h3::Event::Headers { list, .. })) if stream_id == sid => {
                        for h in &list {
                            if h.name() == b":status" {
                                if trace {
                                    h3_stage(
                                        "connect_ip_status",
                                        &format!("code={}", String::from_utf8_lossy(h.value())),
                                    );
                                }
                                if h.value() == b"200" {
                                    // Control-plane OK. Now verify data-plane:
                                    // send 1 DNS probe through the datagram channel.
                                    // Fast-path: 1 round-trip is enough during scan.
                                    let probe_pkt = crate::dns::build_dataplane_probe(
                                        p.local_ipv4,
                                        crate::dns::dataplane_probe_target(),
                                    );
                                    let use_capsule = crate::masque::H3DgramMode::from_env()
                                        .use_capsule(h3c.dgram_enabled_by_peer(&conn));
                                    let mut dp_capsules = CapsuleParser::new();
                                    let mut dp_body = vec![0u8; 65535];
                                    send_ip_h3(&mut conn, h3c, sid, &probe_pkt, use_capsule);
                                    flush_to(&mut conn, &sock, p.peer).await?;
                                    // Wait for data-plane reply (up to 2s).
                                    let dp_deadline = Instant::now() + Duration::from_secs(2).min(remaining(deadline));
                                    let mut dp_successes: u32 = 0;
                                    loop {
                                        if Instant::now() >= dp_deadline {
                                            // Data-plane timeout — endpoint accepts control but drops traffic.
                                            return Err(AetherError::Other(
                                                "data-plane probe timeout (200 ok, no traffic)".into(),
                                            ));
                                        }
                                        let dp_wait = dp_deadline.saturating_duration_since(Instant::now()).min(Duration::from_millis(200));
                                        tokio::select! {
                                            r = sock.recv_from(&mut buf) => {
                                                if let Ok((n, from)) = r {
                                                    let info = quiche::RecvInfo { from, to: local };
                                                    let _ = conn.recv(&mut buf[..n], info);
                                                    // Check for a QUIC DATAGRAM reply.
                                                    let mut dgram_buf = vec![0u8; 65535];
                                                    let mut got_reply = false;
                                                    loop {
                                                        match conn.dgram_recv(&mut dgram_buf) {
                                                            Ok(dn) => {
                                                                if let Ok(Some(_)) = masque::decode_ip_datagram(&dgram_buf[..dn], sid) {
                                                                    if trace {
                                                                        h3_stage("inbound_datagram", "quic datagram confirmed");
                                                                    }
                                                                    got_reply = true;
                                                                    break;
                                                                }
                                                            }
                                                            Err(quiche::Error::Done) => break,
                                                            Err(_) => break,
                                                        }
                                                    }
                                                    // Also accept a DATAGRAM capsule on the stream (RFC 9297 fallback).
                                                    if !got_reply {
                                                        loop {
                                                            match h3c.poll(&mut conn) {
                                                                Ok((s, h3::Event::Data)) if s == sid => {
                                                                    while let Ok(bn) = h3c.recv_body(&mut conn, sid, &mut dp_body) {
                                                                        if bn == 0 { break; }
                                                                        dp_capsules.push(&dp_body[..bn]);
                                                                    }
                                                                }
                                                                Ok(_) => {}
                                                                Err(_) => break,
                                                            }
                                                        }
                                                        loop {
                                                            match dp_capsules.next() {
                                                                Ok(Some(masque::Capsule::Datagram(_))) => {
                                                                    if trace {
                                                                        h3_stage("inbound_datagram", "capsule datagram confirmed");
                                                                    }
                                                                    got_reply = true;
                                                                    break;
                                                                }
                                                                Ok(Some(_)) => {}
                                                                Ok(None) | Err(_) => break,
                                                            }
                                                        }
                                                    }
                                                    if got_reply {
                                                        dp_successes += 1;
                                                        if dp_successes >= DATA_PROBE_REQUIRED_SUCCESSES {
                                                            return Ok(handshake_rtt.unwrap_or_else(|| start.elapsed()));
                                                        }
                                                        send_ip_h3(&mut conn, h3c, sid, &probe_pkt, use_capsule);
                                                    }
                                                }
                                            }
                                            _ = tokio::time::sleep(dp_wait) => {
                                                conn.on_timeout();
                                                // Resend probe.
                                                send_ip_h3(&mut conn, h3c, sid, &probe_pkt, use_capsule);
                                            }
                                        }
                                        flush_to(&mut conn, &sock, p.peer).await?;
                                        if conn.is_closed() {
                                            return Err(AetherError::Other("closed during data-plane probe".into()));
                                        }
                                    }
                                }
                                return Err(AetherError::Other(format!(
                                    "status {}",
                                    String::from_utf8_lossy(h.value())
                                )));
                            }
                        }
                    }
                    Ok(_) => {}
                    Err(h3::Error::Done) => break,
                    Err(e) => return Err(AetherError::H3(e)),
                }
            }
            if trace && !settings_logged && h3c.peer_settings_raw().is_some() {
                let dg = h3c.dgram_enabled_by_peer(&conn);
                let ext = h3c.extended_connect_enabled_by_peer();
                h3_stage("h3_settings", &format!("dgram_by_peer={dg} ext_connect={ext}"));
                settings_logged = true;
            }
        }

        flush_to(&mut conn, &sock, p.peer).await?;

        if conn.is_closed() {
            let mut reason = String::new();
            if let Some(local_err) = conn.local_error() {
                reason.push_str(&format!("local_error: {:?} (code {}) ", local_err.reason, local_err.error_code));
            }
            if let Some(peer_err) = conn.peer_error() {
                reason.push_str(&format!("peer_error: {:?} (code {}) ", peer_err.reason, peer_err.error_code));
            }
            log::debug!("probe {} -> other: closed before 200, reason: {}", p.peer, reason);
            return Err(AetherError::Other(format!("closed before 200: {reason}")));
        }
    }
}

fn remaining(deadline: Instant) -> Duration {
    deadline.saturating_duration_since(Instant::now())
}

async fn flush_to(
    conn: &mut quiche::Connection,
    sock: &UdpSocket,
    peer: SocketAddr,
) -> Result<()> {
    let mut out = vec![0u8; MAX_DATAGRAM_SIZE];
    loop {
        match conn.send(&mut out) {
            Ok((write, send_info)) => {
                // Prefer quiche's chosen destination; fall back to probe peer.
                let dest = if send_info.to.ip().is_unspecified() {
                    peer
                } else {
                    send_info.to
                };
                if sock.send_to(&out[..write], dest).await.is_err() {
                    let _ = sock.send(&out[..write]).await;
                }
            }
            Err(quiche::Error::Done) => break,
            Err(e) => return Err(AetherError::Quic(e)),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn h3_sni_defaults_to_consumer_masque() {
        assert_eq!(resolve_h3_sni_from(None, None), consts::CONNECT_SNI);
    }

    #[test]
    fn h3_sni_prefers_specific_override() {
        assert_eq!(
            resolve_h3_sni_from(Some("a.example".into()), Some("b.example".into())),
            "a.example"
        );
    }

    #[test]
    fn h3_sni_falls_back_to_generic_then_blank_ignored() {
        assert_eq!(
            resolve_h3_sni_from(Some("   ".into()), Some("b.example".into())),
            "b.example"
        );
        assert_eq!(resolve_h3_sni_from(Some(String::new()), None), consts::CONNECT_SNI);
    }

    #[test]
    fn the_bait_is_a_v2_versioned_long_header_of_the_minimum_size() {
        let pkt = build_version_bait();
        assert_eq!(pkt.len(), QUIC_V2_BAIT_LEN);
        assert_eq!(pkt[0] & 0x80, 0x80, "long header form bit must be set");
        assert_eq!(pkt[0] & 0x40, 0x40, "fixed bit must be set");
        assert_eq!(
            u32::from_be_bytes([pkt[1], pkt[2], pkt[3], pkt[4]]),
            consts::QUIC_V2_VERSION,
            "the version field must be QUIC v2 so the filter treats the flow as v2"
        );
        assert_eq!(pkt[5], 8, "destination connection id length");
        assert_eq!(pkt[14], 8, "source connection id length");
    }

    #[test]
    fn two_baits_do_not_share_connection_ids() {
        let a = build_version_bait();
        let b = build_version_bait();
        assert_ne!(a[6..14], b[6..14], "each bait must use a fresh dcid");
    }

    #[test]
    fn the_bait_is_on_unless_it_is_turned_off() {
        std::env::remove_var("AETHER_QUIC_V2");
        assert!(quic_v2_bait_enabled());
        std::env::set_var("AETHER_QUIC_V2", "0");
        assert!(!quic_v2_bait_enabled());
        std::env::set_var("AETHER_QUIC_V2", "off");
        assert!(!quic_v2_bait_enabled());
        std::env::set_var("AETHER_QUIC_V2", "1");
        assert!(quic_v2_bait_enabled());
        std::env::remove_var("AETHER_QUIC_V2");
    }
}
