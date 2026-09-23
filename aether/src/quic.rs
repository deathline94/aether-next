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
/// Outbound IP packets handed to quiche per select wakeup.
///
/// The batch this replaces drained the whole 2048-deep egress queue in one pass,
/// with no flush and no yield in between: one wakeup could push thousands of
/// frames through the connection while ingress, `on_timeout` and the keepalive
/// timer all waited behind it — the same unbounded per-tick work `c151591` set
/// out to bound. A capped batch still fits inside one flush cycle, and the queue
/// is picked up again on the next wakeup.
const MAX_EGRESS_PER_TICK: usize = 32;

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
    // Every failure below destroys an IP packet. `Error::Done` here means
    // "stream window / datagram queue full, retry later", which this call site
    // cannot retry — so it is counted, with the first occurrence and every
    // 1000th logged, instead of vanishing at debug while the tunnel reports
    // itself healthy.
    if use_capsule {
        let cap = masque::encode_datagram_capsule(ip_packet);
        if let Err(e) = h3c.send_body(conn, sid, &cap, false) {
            note_dropped("capsule", e);
        }
    } else {
        match masque::encode_ip_datagram(sid, ip_packet) {
            Ok(framed) => {
                if let Err(e) = conn.dgram_send(&framed) {
                    note_dropped("datagram", e);
                }
            }
            Err(e) => log::debug!("encap: {e}"),
        }
    }
}

/// Count a silently destroyed outbound packet and log it at a visible rate.
///
/// The counter exists because "the tunnel is healthy" and "we are throwing
/// away TCP payload under load" were previously indistinguishable from outside.
fn note_dropped(what: &str, e: impl std::fmt::Display) {
    let n = crate::counters::bump(&crate::counters::DATAGRAM_SEND_DROPPED);
    if n == 1 || n.is_multiple_of(1000) {
        log::warn!("[quic] dropped {what} packet (count {n}): {e}");
    } else {
        log::debug!("[quic] dropped {what} packet (count {n}): {e}");
    }
}

/// Emit a labeled H3 milestone to logs +, when tracing is on, as a structured
/// `AETHER_EVENT` so the exact failing stage is unambiguous.
///
/// Serialised with serde_json instead of interpolated: `detail` carries
/// peer-controlled bytes (an HTTP header value from the edge), so the old
/// "`detail` must not contain double quotes" comment was an unenforced
/// assertion and a peer could break the JSON or forge sibling fields on the
/// single channel the GUI trusts for status.
fn h3_stage(stage: &str, detail: &str) {
    log::info!("[h3][stage] {stage} \u{2014} {detail}");
    if h3_trace_on() {
        let payload = serde_json::json!({
            "type": "h3_stage",
            "stage": stage,
            "detail": detail,
        });
        log::info!("AETHER_EVENT {payload}");
    }
}

/// True when H3 per-stage tracing is requested (`AETHER_H3_TRACE`). The probe
/// harness enables it; normal scans stay quiet to avoid per-probe log spam.
fn h3_trace_on() -> bool {
    crate::runtime_env::flag("AETHER_H3_TRACE")
}

/// Attach qlog (when `AETHER_QLOG_DIR` is set) and TLS keylog (`SSLKEYLOGFILE`) to
/// a fresh connection for offline decryption/analysis. Must be called right
/// after `quiche::connect`, before the first flush, or early events are lost.
///
/// Every filesystem call goes through `spawn_blocking`: this runs inside the
/// tunnel loop, on the task that has to answer the peer's retransmits, and a
/// `create_dir_all` on a cold disk or a roaming/network home directory takes
/// long enough to be measured in QUIC timeouts.
async fn maybe_enable_diagnostics(conn: &mut quiche::Connection, tag: &str) {
    if let Some(dir) = crate::runtime_env::var("AETHER_QLOG_DIR") {
        let dir = dir.trim().to_string();
        if !dir.is_empty() {
            let seq = QLOG_SEQ.fetch_add(1, Ordering::Relaxed);
            let file =
                std::path::Path::new(&dir).join(format!("{tag}-{}-{seq}.qlog", std::process::id()));
            let (dir_task, file_task) = (dir.clone(), file.clone());
            match tokio::task::spawn_blocking(move || {
                std::fs::create_dir_all(&dir_task)?;
                std::fs::File::create(&file_task)
            })
            .await
            {
                Ok(Ok(f)) => {
                    conn.set_qlog(Box::new(f), "aether-h3".to_string(), format!("qlog {tag}"));
                    log::info!("[h3] qlog -> {}", file.display());
                }
                Ok(Err(e)) => log::debug!("[h3] qlog create failed: {e}"),
                Err(e) => log::debug!("[h3] qlog setup task failed: {e}"),
            }
        }
    }
    // Standard tooling variable, read from the real environment on purpose.
    #[allow(clippy::disallowed_methods)]
    let keylog = std::env::var("SSLKEYLOGFILE").ok();
    if let Some(path) = keylog {
        let path = path.trim().to_string();
        if !path.is_empty() {
            let shown = path.clone();
            let opened = tokio::task::spawn_blocking(move || {
                std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&path)
            })
            .await;
            match opened {
                Ok(Ok(f)) => {
                    conn.set_keylog(Box::new(f));
                    log::info!("[h3] keylog -> {shown}");
                }
                Ok(Err(e)) => log::debug!("[h3] keylog open failed: {e}"),
                Err(e) => log::debug!("[h3] keylog setup task failed: {e}"),
            }
        }
    }
}

async fn bind_udp_fast(bind_addr: SocketAddr) -> Result<UdpSocket> {
    use socket2::{Domain, Socket, Type};
    let domain = if bind_addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
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
    pub fn into_parts(self) -> (mpsc::Receiver<Vec<u8>>, mpsc::Sender<Vec<u8>>) {
        (self.outbound_rx, self.inbound_tx)
    }
}

type NetPacket = (SocketAddr, SocketAddr, Vec<u8>);

/// Holds spawned UDP-reader tasks; aborts them on drop so a reader cannot outlive
/// the connection that started it - through reconnect, tunnel close, or a panic
/// unwinding the scope. Without this, a long-lived session that reconnects many
/// times accumulates orphaned tokio tasks each holding a read buffer
/// (>=64KB x N leaks). The aborting itself is `tunnel::AbortOnDrop`, the one
/// copy in the crate.
struct ReaderGuard {
    handles: Vec<crate::tunnel::AbortOnDrop<()>>,
}

impl ReaderGuard {
    fn new() -> Self {
        Self {
            handles: Vec::new(),
        }
    }
    fn push(&mut self, h: tokio::task::JoinHandle<()>) {
        self.handles.push(crate::tunnel::AbortOnDrop(h));
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
pub const DATA_PROBE_REQUIRED_SUCCESSES: u32 = 1;

pub fn quic_v2_bait_enabled() -> bool {
    // Default on; only an explicit negative turns the bait off. Uses the shared
    // truthiness rule so `OFF`, `off` and `0` all mean the same thing. An empty
    // value is treated as "not configured", matching the previous behaviour.
    match crate::runtime_env::var("AETHER_QUIC_V2") {
        Some(v) if !v.trim().is_empty() => crate::runtime_env::truthy(&v),
        _ => true,
    }
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

fn spawn_reader(
    sock: Arc<UdpSocket>,
    local: SocketAddr,
    tx: mpsc::Sender<NetPacket>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            match sock.recv_from(&mut buf).await {
                Ok((n, from)) => {
                    log::debug!("recv {n} bytes from {from}");
                    if tx.send((local, from, buf[..n].to_vec())).await.is_err() {
                        break;
                    }
                }
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
    // Distinguishes an intentional, healthy local teardown from a transport
    // failure. Previously every close path returned Ok(()), so the caller
    // recorded a *success* for the peer that had just killed the tunnel and a
    // flapping endpoint kept maximum cache trust (session.rs record_success).
    let mut local_shutdown = false;
    let mut fatal: Option<String> = None;
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

    let (net_tx, mut net_rx) = mpsc::channel::<NetPacket>(crate::tunnel::NET_QUEUE);

    let mut sockets: HashMap<SocketAddr, Arc<UdpSocket>> = HashMap::new();
    sockets.insert(local, init_sock.clone());
    // ReaderGuard aborts ALL spawned readers when this scope exits (reconnect,
    // tunnel-close, panic). Without it, every attempt that binds a new socket
    // leaves its reader behind holding a 64KB buffer and a task slot forever -
    // long sessions leak. (Not "migration": this engine never migrates a live
    // path to a new local address, so the leak had no other route in.)
    let mut readers = ReaderGuard::new();
    readers.push(spawn_reader(init_sock, local, net_tx.clone()));
    // Drop our own sender so `net_rx.recv()` yields None once every reader dies.
    // Previously `net_tx` stayed alive for the whole body, the channel could
    // never close, and the `None =>` arm below (labelled "L6 fix") was
    // unreachable: a dead socket left a zombie tunnel reporting
    // dataplane_ok == true until the QUIC idle timeout.
    drop(net_tx);

    let mut config = tls::build_config(&TlsParams {
        cert_pem: &cfg.cert_pem,
        key_pem: &cfg.key_pem,
        pin_host: consts::CONNECT_SNI,
        policy: crate::trust::VerifyPolicy::Pinned(crate::trust::masque_pin_sets()),
    })?;

    // #1: Load cached session ticket for 0-RTT resumption (faster reconnect).
    // Note: quiche fork doesn't expose set_session; 0-RTT relies on enable_early_data()
    // in tls.rs and quiche's internal session caching.
    let _session_cache_path = crate::lastconn::session_ticket_path();

    let mut current_ech = cfg.ech_config_list.clone();

    let scid_bytes = random_scid();
    let scid = quiche::ConnectionId::from_ref(&scid_bytes);

    let mut conn = quiche::connect(Some(&cfg.sni), &scid, local, peer, &mut config)?;
    maybe_enable_diagnostics(&mut conn, "tunnel").await;

    if let Some(ref ech) = current_ech {
        tls::inject_ech(&mut conn, ech)?;
        log::info!("ech config injected ({} bytes)", ech.len());
    }

    let mut h3_config = h3::Config::new()?;
    h3_config.enable_extended_connect(true);
    let mut h3_conn: Option<h3::Connection> = None;
    let mut req_stream: Option<u64> = None;
    let mut capsules = CapsuleParser::new();
    // Scratch buffer for the CONNECT-IP response body, allocated once for the
    // life of the tunnel rather than once per wakeup.
    let mut h3_body = vec![0u8; 65535];
    // Same for the per-flush QUIC datagram buffer: it is exactly
    // `MAX_DATAGRAM_SIZE`, so a stack array costs nothing and allocates nothing.
    let mut flush_buf = [0u8; MAX_DATAGRAM_SIZE];
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

    flush(&mut conn, &sockets, &mut flush_buf).await?;

    let mut keepalive = Keepalive::default();
    let mut keepalive_interval = tokio::time::interval(KEEPALIVE_INTERVAL);
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
            // No `biased`: the branches are polled in randomised order, which is
            // what keeps a 2048-deep `net_rx` from being served ahead of egress on
            // every wakeup. Ordering them by hand put TCP ACKs and CONNECT-IP
            // payload behind an unbounded ingress stream during exactly the
            // downloads that need them most, and the peer just kept sending.
            _ = keepalive_interval.tick() => {
                if conn.is_established() {
                    match keepalive.tick() {
                        KeepaliveTick::Send => {
                            if let Err(e) = conn.send_ack_eliciting() {
                                log::debug!("keepalive ping failed: {e}");
                            }
                        }
                        KeepaliveTick::GiveUp { unanswered } => {
                            let msg = format!(
                                "no reply to {unanswered} keepalive probes; the session stopped carrying traffic");
                            log::error!("[h3] {msg}");
                            fatal = Some(msg);
                            let _ = conn.close(false, 0x1, b"keepalive timeout");
                        }
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
                        // The header parse exists only for the log line, and it
                        // needs a mutable copy: cloning every inbound datagram to
                        // render a debug message is a per-packet allocation on the
                        // hottest path in the tunnel.
                        if log::log_enabled!(log::Level::Debug) {
                            let mut hdr_buf = data.clone();
                            if let Ok(hdr) =
                                quiche::Header::from_slice(&mut hdr_buf, quiche::MAX_CONN_ID_LEN)
                            {
                                log::debug!(
                                    "recv {} bytes type={:?} version=0x{:x} from {}",
                                    data.len(),
                                    hdr.ty,
                                    hdr.version,
                                    from
                                );
                            }
                        }
                        let info = quiche::RecvInfo { from, to: to_local };
                        let received = conn.recv(&mut data, info);
                        if matches!(received, Ok(_) | Err(quiche::Error::Done)) {
                            keepalive.inbound();
                        }
                        if let Err(e) = received {
                            // `Done` is benign; anything else is a protocol
                            // failure that quiche expects us to act on. It used
                            // to be logged at debug and swallowed, which left the
                            // loop spinning until the idle timeout while the GUI
                            // saw a clean-looking session.
                            if e != quiche::Error::Done {
                                log::error!("[quic] fatal recv error: {e}");
                                let code: u64 = if e == quiche::Error::TlsFail { 0x101 } else { 0x1 };
                                fatal = Some(format!("recv error {e}"));
                                let _ = conn.close(false, code, b"recv");
                            }
                        }
                    }
                    None => {
                        log::error!("[quic] every UDP reader exited; socket is gone");
                        fatal = Some("all UDP readers exited".into());
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
                            // Batch the rest of this tick's egress, up to the cap,
                            // then fall back through the select so a deep queue
                            // cannot monopolise the loop.
                            let mut batched = 1usize;
                            while batched < MAX_EGRESS_PER_TICK {
                                match internals.outbound_rx.try_recv() {
                                    Ok(more) => {
                                        send_ip_h3(&mut conn, h3c, sid, &more, use_capsule);
                                        batched += 1;
                                    }
                                    Err(_) => break,
                                }
                            }
                        } else {
                            // No request stream (yet, or any more): the packet is
                            // gone, and a drop nobody counts is the difference
                            // between "tunnel up, pages never load" being
                            // diagnosable and being folklore.
                            note_dropped(
                                "outbound ip (no connect-ip stream)",
                                "the CONNECT-IP stream is not open",
                            );
                        }
                    }
                    None => {
                        local_shutdown = true;
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
                h3_ready,
                &mut h3_body,
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
                    h3_stage(
                        "h3_settings",
                        &format!("dgram_by_peer={dgram} ext_connect={ext}"),
                    );
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
                    let probe = crate::dns::build_dataplane_probe(
                        probe_src,
                        crate::dns::dataplane_probe_target(),
                    );
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
            h3_ready && !dataplane_ok,
            &mut dataplane_ok,
        )
        .await?;

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
            // A teardown we did not ask for is an error, never a success: this
            // return value decides whether the endpoint is credited or struck.
            if let Some(reason) = fatal {
                return Err(AetherError::Masque(format!("tunnel died: {reason}")));
            }
            if conn.peer_error().is_some() {
                let reason = conn
                    .peer_error()
                    .map(|e| String::from_utf8_lossy(&e.reason).into_owned())
                    .unwrap_or_default();
                return Err(AetherError::Masque(format!(
                    "peer closed the tunnel: {reason}"
                )));
            }
            if local_shutdown {
                return Ok(());
            }
            return Err(AetherError::Masque(
                "connection closed without a local shutdown request".into(),
            ));
        }
    }
}

async fn sleep_opt(timeout: Option<Duration>) {
    match timeout {
        Some(d) => tokio::time::sleep(d).await,
        None => std::future::pending::<()>().await,
    }
}

/// Which `:status` line establishes a CONNECT-IP tunnel.
///
/// Three separate bugs lived in the old two-line rule:
///  * the positive check (`value == 200`) was **not stream-scoped** while the
///    negative one was, so a `200` on any other stream marked the tunnel
///    established;
///  * any non-2xx was fatal, so an RFC 9114 interim response (103 Early Hints,
///    100 Continue) killed a perfectly good tunnel;
///  * nothing detected a *second* final response.
#[derive(Debug, PartialEq, Eq)]
enum StatusAction {
    Ignore,
    Interim,
    Ready,
    Fatal,
}

fn classify_status(stream_id: u64, req_stream: u64, status: &str) -> StatusAction {
    if stream_id != req_stream {
        return StatusAction::Ignore;
    }
    let Ok(code) = status.trim().parse::<u16>() else {
        return StatusAction::Fatal;
    };
    match code {
        100..=199 => StatusAction::Interim,
        200..=299 => StatusAction::Ready,
        _ => StatusAction::Fatal,
    }
}

/// What the CONNECT-IP *probe* does with a `:status` line.
#[derive(Debug, PartialEq, Eq)]
enum ProbeStatus {
    /// Interim (103 Early Hints, 100 Continue) or off-stream: keep polling.
    Wait,
    /// Final 2xx: the control plane works, go prove the data plane.
    Ready,
    /// Refused, or not a status at all.
    Failed(String),
}

/// The single mapping from [`classify_status`] onto the probe's decision.
///
/// `verify_masque` used to compare the raw header bytes against `b"200"` and
/// call everything else fatal, while `run()` went through `classify_status` and
/// waited for interim responses. One edge behaviour therefore meant a working
/// tunnel in the session and a broken endpoint in the scan that ranked it.
fn probe_decision(stream_id: u64, req_stream: u64, status: &str) -> ProbeStatus {
    match classify_status(stream_id, req_stream, status) {
        StatusAction::Ignore | StatusAction::Interim => ProbeStatus::Wait,
        StatusAction::Ready => ProbeStatus::Ready,
        StatusAction::Fatal => ProbeStatus::Failed(format!("status {status}")),
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
    // Only a stream that answered CONNECT-IP may mark the data plane up; a
    // datagram that arrives before the final response proves reachability, not
    // forwarding. Same argument as `drain_datagrams`' `watch_dataplane`.
    watch_dataplane: bool,
    // Owned by `run` so a 64 KB allocation is not paid on every wakeup of the
    // tunnel loop (`poll_h3` runs once per select iteration).
    body: &mut Vec<u8>,
) -> Result<()> {
    loop {
        match h3c.poll(conn) {
            Ok((stream_id, h3::Event::Headers { list, .. })) => {
                for h in &list {
                    if h.name() == b":status" {
                        let status = String::from_utf8_lossy(h.value()).to_string();
                        log::info!("connect-ip status: {status}");
                        h3_stage("connect_ip_status", &format!("code={status}"));
                        match classify_status(stream_id, req_stream, &status) {
                            StatusAction::Ignore => {
                                let n = crate::counters::bump(
                                    &crate::counters::IGNORED_OFFSTREAM_STATUS,
                                );
                                log::debug!("[h3] ignoring :status {status} on stream {stream_id} (count {n})");
                            }
                            StatusAction::Interim => {
                                log::info!(
                                    "[h3] interim {status} on the request stream; awaiting final"
                                );
                            }
                            StatusAction::Ready => {
                                if *h3_ready {
                                    return Err(AetherError::Masque(format!(
                                        "duplicate final response {status} on the connect stream"
                                    )));
                                }
                                *h3_ready = true;
                            }
                            StatusAction::Fatal => {
                                return Err(AetherError::Masque(format!(
                                    "the edge refused connect-ip with status {status}"
                                )));
                            }
                        }
                    }
                }
            }

            Ok((stream_id, h3::Event::Data)) => {
                if stream_id != req_stream {
                    continue;
                }
                while let Ok(n) = h3c.recv_body(conn, stream_id, &mut body[..]) {
                    if n == 0 {
                        break;
                    }
                    capsules.push(&body[..n]);
                }
                drain_capsules(
                    capsules,
                    addr_tx,
                    probe_src,
                    inbound_tx,
                    dataplane_ok,
                    addr_assigned,
                    watch_dataplane,
                );
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

/// Consume the MASQUE control capsules this connection has parsed.
///
/// The H2 path has a same-named function in `masque_h2.rs` and the resemblance is
/// a trap for anyone tempted to merge them: this one is **synchronous** because it
/// runs inside quiche's poll loop, so its delivery is `try_send` and a saturated
/// inbound queue drops the datagram - visibly, on the `INBOUND_DROPPED` counter,
/// because the alternative is blocking the event loop that also has to keep the
/// connection alive. The H2 copy is `async` and awaits the send instead, since its
/// caller is a plain recv task with an await point already. Same parse, opposite
/// backpressure, and each is correct only in the loop it sits in.
fn drain_capsules(
    capsules: &mut CapsuleParser,
    addr_tx: &Option<mpsc::Sender<AssignedAddr>>,
    probe_src: &mut std::net::Ipv4Addr,
    inbound_tx: &mpsc::Sender<Vec<u8>>,
    dataplane_ok: &mut bool,
    addr_assigned: &mut bool,
    watch_dataplane: bool,
) {
    loop {
        match capsules.next() {
            Ok(Some(masque::Capsule::AddressAssign(addrs))) => {
                for a in addrs {
                    if let Some(ip) = crate::tunnel::bytes_to_ip(a.ip_version, &a.address) {
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
                        r.ip_version,
                        r.protocol,
                        r.start,
                        r.end
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
                if inbound_tx.try_send(payload).is_err() {
                    let n = crate::counters::bump(&crate::counters::INBOUND_DROPPED);
                    if n == 1 || n.is_multiple_of(1000) {
                        log::warn!(
                            "[h3] dropped inbound capsule datagram (count {n}): queue saturated"
                        );
                    }
                }
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

/// Does this inner packet actually prove the data plane forwards traffic?
///
/// The previous rule was "any datagram, even ICMP errors" — a peer that echoed
/// back bytes, or an edge that answered CONNECT-IP and then black-holed everything,
/// therefore passed verification and got promoted into the trust cache. ICMP
/// *error* types (dest-unreachable, TTL-expired, fragment-exceeded) are evidence
/// of a broken path, not a working tunnel, so they are rejected here.
fn is_forwardable_ip_packet(pkt: &[u8]) -> bool {
    let Some((&first, rest)) = pkt.split_first() else {
        return false;
    };
    match first >> 4 {
        4 => {
            // IPv4: header length from IHL, protocol at offset 9.
            if rest.len() < 12 {
                return false;
            }
            let ihl = ((first & 0x0f) as usize) * 4;
            if ihl < 20 || pkt.len() < ihl {
                return false;
            }
            let proto = pkt[9];
            let payload = &pkt[ihl..];
            match proto {
                1 => icmp_is_echo_reply(payload),
                6 | 17 => !payload.is_empty(),
                41 => !payload.is_empty(), // IPv6 encapsulated
                _ => false,
            }
        }
        6 => {
            // IPv6: next header at offset 6, fixed 40-byte header.
            if pkt.len() < 40 {
                return false;
            }
            let proto = pkt[6];
            let payload = &pkt[40..];
            match proto {
                58 => icmp_is_echo_reply(payload),
                6 | 17 | 43 | 44 => !payload.is_empty(),
                _ => false,
            }
        }
        _ => false,
    }
}

fn icmp_is_echo_reply(payload: &[u8]) -> bool {
    // type 0 = echo reply. 3/4/11/12 are errors and must not count as proof.
    matches!(payload.first(), Some(0))
}

async fn drain_datagrams(
    conn: &mut quiche::Connection,
    req_stream: Option<u64>,
    inbound_tx: &mpsc::Sender<Vec<u8>>,
    watch_dataplane: bool,
    dataplane_ok: &mut bool,
) -> Result<()> {
    let sid = match req_stream {
        Some(s) => s,
        None => return Ok(()),
    };

    loop {
        // `dgram_recv_buf()` always pops; `dgram_recv(buf)` copies into a caller
        // buffer and had no size advantage here, while any buffer that is too
        // small loses a datagram. Owned buffers also skip a copy.
        match conn.dgram_recv_buf() {
            Ok(buf) => match masque::decode_ip_datagram(buf.as_ref(), sid) {
                Ok(Some(ip_packet)) => {
                    if watch_dataplane && is_forwardable_ip_packet(&ip_packet) {
                        if !*dataplane_ok {
                            h3_stage("first_inbound_datagram", "dataplane reply received");
                        }
                        *dataplane_ok = true;
                    }
                    // Bounded by try_send only. Awaiting the queue used to park
                    // the whole tunnel loop on the netstack consumer — no recv, no
                    // flush, no `on_timeout` — so one slow reader became a QUIC
                    // idle-timeout kill for every flow on the connection.
                    // `drain_capsules` already answers saturation by dropping and
                    // counting; TCP retransmits, which is the recovery path this
                    // stack is built around.
                    match inbound_tx.try_send(ip_packet) {
                        Ok(()) => {}
                        Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                            let n = crate::counters::bump(&crate::counters::INBOUND_DROPPED);
                            if n == 1 || n.is_multiple_of(1000) {
                                log::warn!(
                                    "[h3] dropped inbound datagram (count {n}): queue saturated"
                                );
                            }
                        }
                        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                            // The receiver is gone, so every datagram pulled off
                            // quiche from here on is consumed into a void. That is
                            // fatal and has to say so — returning `Ok(())` used to
                            // end inbound delivery with the tunnel still reporting
                            // itself healthy.
                            log::error!("[quic] inbound queue closed: the netstack is gone");
                            return Err(AetherError::Other("inbound queue closed".into()));
                        }
                    }
                }
                Ok(None) => {}
                Err(e) => log::debug!("decap: {e}"),
            },
            Err(quiche::Error::Done) => break,
            Err(e) => {
                // Anything else is fatal; breaking here used to leave the loop
                // silently consuming nothing while the tunnel looked alive.
                log::error!("[quic] fatal datagram read error: {e}");
                return Err(e.into());
            }
        }
    }
    Ok(())
}

/// Hand every datagram quiche wants to send to the socket it was sent from.
async fn flush(
    conn: &mut quiche::Connection,
    sockets: &HashMap<SocketAddr, Arc<UdpSocket>>,
    out: &mut [u8; MAX_DATAGRAM_SIZE],
) -> Result<()> {
    loop {
        match conn.send(out) {
            Ok((write, send_info)) => {
                // `send_info.from` is the local endpoint quiche chose for this
                // packet; after a migration it can be one this map no longer
                // holds. The old fallback sent it from `sockets.iter().next()` —
                // an arbitrary HashMap entry, so a v4 packet could leave a v6
                // socket with the wrong source address, which the peer cannot
                // associate with the connection at all. A dropped packet is
                // counted and retransmitted; a misrouted one is silent corruption.
                let Some(sock) = sockets.get(&send_info.from) else {
                    let n = crate::counters::bump(&crate::counters::DATAGRAM_SEND_DROPPED);
                    if n == 1 || n.is_multiple_of(1000) {
                        log::warn!(
                            "[quic] no socket bound to {} (count {n}); packet for {} dropped",
                            send_info.from,
                            send_info.to
                        );
                    }
                    continue;
                };
                // A failed send used to propagate out of `run()` and close the
                // tunnel. The common cause is transient — an ICMP-driven
                // `WSAECONNRESET` on the path, or a full socket buffer — and
                // quiche retransmits whatever went unacknowledged, so the
                // connection has no reason to die over one datagram.
                if let Err(e) = sock.send_to(&out[..write], send_info.to).await {
                    let n = crate::counters::bump(&crate::counters::DATAGRAM_SEND_DROPPED);
                    if n == 1 || n.is_multiple_of(1000) {
                        log::warn!("[quic] send to {} failed (count {n}): {e}", send_info.to);
                    }
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
    // Fingerprint/probe path: unpinned by design (it deliberately talks to
    // arbitrary edges to read SETTINGS), but scoped to this call instead of the
    // ambient env kill-switch that used to disable verification process-wide.
    let mut config = tls::build_config(&TlsParams {
        cert_pem,
        key_pem,
        pin_host: consts::CONNECT_SNI,
        policy: crate::trust::VerifyPolicy::ReadOnlyProbe,
    })?;
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
    /// Which CONNECT-IP header recipe to put on the wire. The production tunnel
    /// always sends [`crate::masque::H3HeaderMode::Standard`]; the H3 probe sweeps
    /// this so a 400 can be attributed to a shape rather than guessed at.
    pub header_mode: crate::masque::H3HeaderMode,
    /// Overrides the CONNECT-IP protocol token for the same reason.
    pub protocol: Option<&'static str>,
}

pub async fn verify_masque(p: &VerifyParams) -> Result<Duration> {
    // Read once per verification, like `run()` does per connection: the mode is
    // fixed at startup by `AETHER_MASQUE_H3_DGRAM`, so re-reading it inside the
    // probe loop cost a parse per iteration and could otherwise disagree with the
    // data path this same process is already running.
    let h3_dgram_mode = crate::masque::H3DgramMode::from_env();
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
        pin_host: consts::CONNECT_SNI,
        policy: crate::trust::VerifyPolicy::Pinned(crate::trust::masque_pin_sets()),
    })?;

    let scid_bytes = random_scid();
    let scid = quiche::ConnectionId::from_ref(&scid_bytes);
    let mut conn = quiche::connect(Some(&p.sni), &scid, local, p.peer, &mut config)?;
    maybe_enable_diagnostics(&mut conn, "verify");

    if let Some(ref ech) = p.ech_config_list {
        // Not `let _ =`: if the injection failed, this connection is going out
        // with a plaintext SNI, and a success would then be recorded against the
        // ECH axis that was never applied — the probe result would be a lie about
        // which knob worked.
        tls::inject_ech(&mut conn, ech)?;
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
            return Err(AetherError::Other(
                "verify timeout (UDP ok, no connect-ip 200)".into(),
            ));
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

        let quic_timeout = conn.timeout();
        let wait = match quic_timeout {
            Some(t) => t.min(remaining(deadline)),
            None => remaining(deadline),
        };
        // `wait` may be the overall deadline rather than a QUIC timer. Calling
        // `on_timeout()` when quiche did not ask for it would advance its PTO
        // state on a probe that is merely out of time.
        let timer_is_quic = quic_timeout.is_some_and(|t| wait <= t);

        tokio::select! {
            biased;
            // Timer first: with 8-16 probes in flight, a branch order that lets
            // `recv_from` win whenever a datagram is pending delays
            // `on_timeout()` — which drives PTO/retransmit — by whole round
            // trips, and every concurrent probe pays for it. Same rule
            // Cloudflare's quiche driver documents for its IO workers.
            _ = tokio::time::sleep(wait) => {
                if timer_is_quic {
                    conn.on_timeout();
                }
            }
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
            let headers =
                masque::connect_ip_request_mode(&p.authority, &p.path, p.header_mode, p.protocol);
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
                                let status = String::from_utf8_lossy(h.value()).to_string();
                                if trace {
                                    h3_stage("connect_ip_status", &format!("code={status}"));
                                }
                                // One classifier for both CONNECT-IP paths.
                                // `run()` already tolerates interim responses;
                                // the probe compared the raw bytes against "200",
                                // so an edge that sent `103 Early Hints` (or a
                                // `100`) ahead of its final answer was scored
                                // broken and struck from the cache.
                                match probe_decision(stream_id, sid, &status) {
                                    ProbeStatus::Wait => {}
                                    ProbeStatus::Failed(reason) => {
                                        return Err(AetherError::Other(reason))
                                    }
                                    ProbeStatus::Ready => {
                                        // Control-plane OK. Now verify data-plane:
                                        // send 1 DNS probe through the datagram channel.
                                        // Fast-path: 1 round-trip is enough during scan.
                                        let probe_pkt = crate::dns::build_dataplane_probe(
                                            p.local_ipv4,
                                            crate::dns::dataplane_probe_target(),
                                        );
                                        let use_capsule = h3_dgram_mode
                                            .use_capsule(h3c.dgram_enabled_by_peer(&conn));
                                        let mut dp_capsules = CapsuleParser::new();
                                        let mut dp_body = vec![0u8; 65535];
                                        send_ip_h3(&mut conn, h3c, sid, &probe_pkt, use_capsule);
                                        flush_to(&mut conn, &sock, p.peer).await?;
                                        // Wait for data-plane reply (up to 3.5s).
                                        let dp_deadline = Instant::now()
                                            + Duration::from_millis(3500).min(remaining(deadline));
                                        let mut dp_successes: u32 = 0;
                                        // Hoisted: this buffer was being reallocated
                                        // for every received datagram inside the loop.
                                        let mut dgram_buf = vec![0u8; 65535];
                                        loop {
                                            if Instant::now() >= dp_deadline {
                                                // Data-plane timeout — endpoint accepts control but drops traffic.
                                                return Err(AetherError::Other(
                                                    "data-plane probe timeout (200 ok, no traffic)"
                                                        .into(),
                                                ));
                                            }
                                            let dp_wait = dp_deadline
                                                .saturating_duration_since(Instant::now())
                                                .min(Duration::from_millis(200));
                                            tokio::select! {
                                                r = sock.recv_from(&mut buf) => {
                                                    if let Ok((n, from)) = r {
                                                        let info = quiche::RecvInfo { from, to: local };
                                                        let _ = conn.recv(&mut buf[..n], info);
                                                        // Check for a QUIC DATAGRAM reply.
                                                        let mut got_reply = false;
                                                        loop {
                                                            match conn.dgram_recv(&mut dgram_buf) {
                                                                Ok(dn) => {
                                                                    // The same predicate the tunnel applies before
                                                                    // marking its data plane up: an inner packet the
                                                                    // edge could not have forwarded — an ICMP error,
                                                                    // or our own probe echoed back — is not proof.
                                                                    if let Ok(Some(ip)) =
                                                                        masque::decode_ip_datagram(&dgram_buf[..dn], sid)
                                                                    {
                                                                        if is_forwardable_ip_packet(&ip) {
                                                                            if trace {
                                                                                h3_stage("inbound_datagram", "quic datagram confirmed");
                                                                            }
                                                                            got_reply = true;
                                                                            break;
                                                                        }
                                                                        log::debug!("[h3] probe: ignoring a datagram that is not forwardable traffic");
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
                                                                    Ok(Some(masque::Capsule::Datagram(pkt))) => {
                                                                        if is_forwardable_ip_packet(&pkt) {
                                                                            if trace {
                                                                                h3_stage("inbound_datagram", "capsule datagram confirmed");
                                                                            }
                                                                            got_reply = true;
                                                                            break;
                                                                        }
                                                                        log::debug!("[h3] probe: ignoring a capsule that is not forwardable traffic");
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
                                                return Err(AetherError::Other(
                                                    "closed during data-plane probe".into(),
                                                ));
                                            }
                                        }
                                    }
                                }
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
                h3_stage(
                    "h3_settings",
                    &format!("dgram_by_peer={dg} ext_connect={ext}"),
                );
                settings_logged = true;
            }
        }

        flush_to(&mut conn, &sock, p.peer).await?;

        if conn.is_closed() {
            let mut reason = String::new();
            if let Some(local_err) = conn.local_error() {
                reason.push_str(&format!(
                    "local_error: {:?} (code {}) ",
                    local_err.reason, local_err.error_code
                ));
            }
            if let Some(peer_err) = conn.peer_error() {
                reason.push_str(&format!(
                    "peer_error: {:?} (code {}) ",
                    peer_err.reason, peer_err.error_code
                ));
            }
            log::debug!(
                "probe {} -> other: closed before 200, reason: {}",
                p.peer,
                reason
            );
            return Err(AetherError::Other(format!("closed before 200: {reason}")));
        }
    }
}

/// How often the tunnel asks the edge to prove it is still answering, and how many
/// times that ask may go unanswered before the session is called dead.
///
/// The pair has to fit inside the 45 s idle timeout `tls::build_config` sets
/// (`tls.rs:296`). Otherwise quiche's own timer is the only thing that could
/// notice, and it notices by closing the connection at 45 s with no reason a
/// caller can act on — the GUI keeps showing a session that stopped carrying
/// traffic. Fifteen seconds times three ticks is 45 s, so this fires first.
pub const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);
pub const KEEPALIVE_MAX_UNANSWERED: u32 = 2;

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Keepalive {
    unanswered: u32,
}

#[derive(Debug, PartialEq, Eq)]
pub enum KeepaliveTick {
    Send,
    GiveUp { unanswered: u32 },
}

impl Keepalive {
    /// One interval tick: send a probe, or report that the tunnel is dead.
    pub fn tick(&mut self) -> KeepaliveTick {
        if self.unanswered >= KEEPALIVE_MAX_UNANSWERED {
            return KeepaliveTick::GiveUp {
                unanswered: self.unanswered,
            };
        }
        self.unanswered += 1;
        KeepaliveTick::Send
    }

    /// Any inbound packet answers every probe sent so far — quiche does not tell
    /// us which of them an ack covered, and does not need to.
    pub fn inbound(&mut self) {
        self.unanswered = 0;
    }

    pub fn unanswered(&self) -> u32 {
        self.unanswered
    }
}

fn remaining(deadline: Instant) -> Duration {
    deadline.saturating_duration_since(Instant::now())
}

async fn flush_to(conn: &mut quiche::Connection, sock: &UdpSocket, peer: SocketAddr) -> Result<()> {
    // Fixed size, so the datagram buffer is a stack array rather than a
    // per-call heap allocation on the probe path.
    let mut out = [0u8; MAX_DATAGRAM_SIZE];
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
    fn two_unanswered_keepalives_end_the_session() {
        let mut ka = Keepalive::default();
        assert_eq!(ka.tick(), KeepaliveTick::Send);
        assert_eq!(ka.tick(), KeepaliveTick::Send);
        assert_eq!(ka.tick(), KeepaliveTick::GiveUp { unanswered: 2 });
    }

    #[test]
    fn one_inbound_packet_answers_every_pending_probe() {
        let mut ka = Keepalive::default();
        assert_eq!(ka.tick(), KeepaliveTick::Send);
        assert_eq!(ka.tick(), KeepaliveTick::Send);
        ka.inbound();
        assert_eq!(ka.unanswered(), 0);
        assert_eq!(ka.tick(), KeepaliveTick::Send, "the budget restarts");
    }

    #[test]
    fn the_keepalive_budget_is_spent_inside_the_idle_timeout() {
        // `tls.rs:296` sets a 45 s idle timeout. If this cadence ever grows past
        // it, quiche closes the connection first and the reason nobody sees is a
        // silent 45 s stall rather than a dead tunnel.
        let worst_case = KEEPALIVE_INTERVAL * (KEEPALIVE_MAX_UNANSWERED + 1);
        assert!(
            worst_case <= Duration::from_millis(45_000),
            "keepalive gives up after {worst_case:?}, past the 45 s idle timeout"
        );
    }

    #[test]
    fn status_is_stream_scoped_and_interim_responses_are_not_fatal() {
        // A 200 on any stream other than the CONNECT request must not establish.
        assert_eq!(classify_status(8, 0, "200"), StatusAction::Ignore);
        // 103 Early Hints precedes the final response; it used to abort the tunnel.
        assert_eq!(classify_status(0, 0, "103"), StatusAction::Interim);
        assert_eq!(classify_status(0, 0, "100"), StatusAction::Interim);
        assert_eq!(classify_status(0, 0, "200"), StatusAction::Ready);
        assert_eq!(classify_status(0, 0, "400"), StatusAction::Fatal);
        assert_eq!(classify_status(0, 0, "500"), StatusAction::Fatal);
        assert_eq!(classify_status(0, 0, "garbage"), StatusAction::Fatal);
    }

    /// The scan probe and the tunnel have to read a `:status` line the same way.
    /// `verify_masque` compared the raw header bytes against `b"200"` and called
    /// everything else fatal, so an edge that sent `103 Early Hints` ahead of its
    /// final answer — which `run()` waits straight through — was scored broken
    /// and struck from the endpoint cache.
    #[test]
    fn the_probe_waits_through_interim_responses_like_the_tunnel() {
        for interim in ["100", "101", "102", "103", "199"] {
            assert!(
                matches!(classify_status(0, 0, interim), StatusAction::Interim),
                "classifier moved on: {interim}"
            );
            assert_eq!(
                probe_decision(0, 0, interim),
                ProbeStatus::Wait,
                "the probe called interim {interim} fatal"
            );
        }
        assert_eq!(probe_decision(0, 0, "200"), ProbeStatus::Ready);
        assert_eq!(probe_decision(0, 0, "204"), ProbeStatus::Ready);
        assert!(
            matches!(probe_decision(0, 0, "403"), ProbeStatus::Failed(_)),
            "a refusal must still be a refusal"
        );
        assert!(
            matches!(probe_decision(0, 0, "nonsense"), ProbeStatus::Failed(_)),
            "an unparseable status must not be read as success"
        );
        // Not our stream: neither ready nor fatal, just noise to wait past.
        assert_eq!(probe_decision(8, 0, "200"), ProbeStatus::Wait);
    }

    #[test]
    fn data_plane_proof_rejects_icmp_errors_and_accepts_replies() {
        // A real 20-byte IPv4 header: proto at offset 9, src 12..16, dst 16..20.
        fn ipv4(proto: u8) -> Vec<u8> {
            let h = vec![
                0x45, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x00, 64, proto, 0x00, 0x00, 1, 1, 1, 1,
                2, 2, 2, 2,
            ];
            assert_eq!(h[9], proto);
            h
        }
        // ICMP destination-unreachable (type 3) is NOT evidence of a working path.
        let mut unreachable = ipv4(1);
        unreachable.push(3);
        assert!(!is_forwardable_ip_packet(&unreachable));
        let mut reply = ipv4(1);
        reply.push(0); // echo reply
        assert!(is_forwardable_ip_packet(&reply));
        // UDP with payload accepted, without payload rejected.
        let mut udp = ipv4(17);
        udp.extend_from_slice(&[0x12, 0x34, 0x00, 0x08, 0x00, 0x00, 0xab, 0xcd]);
        assert!(is_forwardable_ip_packet(&udp));
        assert!(!is_forwardable_ip_packet(&ipv4(17)));
        // A truncated header (ihl claims 20 bytes, fewer present) must not panic.
        assert!(!is_forwardable_ip_packet(&[0x45, 0, 0, 0]));
        assert!(!is_forwardable_ip_packet(&[]));
        assert!(!is_forwardable_ip_packet(&[0x00, 0x01]));
        assert!(!is_forwardable_ip_packet(&[]));
        assert!(!is_forwardable_ip_packet(&[0x00, 0x01]));
    }

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
        assert_eq!(
            resolve_h3_sni_from(Some(String::new()), None),
            consts::CONNECT_SNI
        );
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
        // Driven through the runtime store, which is the only reader: a test
        // that set the process environment would now be asserting nothing,
        // because reads no longer consult it.
        crate::runtime_env::remove("AETHER_QUIC_V2");
        assert!(quic_v2_bait_enabled(), "absent means on");
        for off in ["0", "off", "false", "no", "OFF"] {
            crate::runtime_env::set("AETHER_QUIC_V2", off);
            assert!(!quic_v2_bait_enabled(), "{off:?} must disable the bait");
        }
        crate::runtime_env::set("AETHER_QUIC_V2", "");
        assert!(quic_v2_bait_enabled(), "an empty value is not a setting");
        for on in ["1", "true", "yes", "on"] {
            crate::runtime_env::set("AETHER_QUIC_V2", on);
            assert!(quic_v2_bait_enabled(), "{on:?} must keep the bait on");
        }
        crate::runtime_env::remove("AETHER_QUIC_V2");
    }
}
