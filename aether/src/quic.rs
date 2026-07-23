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
pub enum Control {
    Migrate,
    Close,
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
    pub ech_config_list: Option<Vec<u8>>,
    pub noize: NoizeConfig,
}

pub struct Channels {
    pub outbound_tx: mpsc::Sender<Vec<u8>>,
    pub inbound_rx: mpsc::Receiver<Vec<u8>>,
    pub ctrl_tx: mpsc::Sender<Control>,
}

pub fn channels() -> (Channels, Internals) {
    let (outbound_tx, outbound_rx) = crate::tunnel::packet_channels();
    let (inbound_tx, inbound_rx) = crate::tunnel::packet_channels();
    let (ctrl_tx, ctrl_rx) = mpsc::channel(16);

    (
        Channels {
            outbound_tx,
            inbound_rx,
            ctrl_tx,
        },
        Internals {
            outbound_rx,
            inbound_tx,
            ctrl_rx,
        },
    )
}

pub struct Internals {
    outbound_rx: mpsc::Receiver<Vec<u8>>,
    inbound_tx: mpsc::Sender<Vec<u8>>,
    ctrl_rx: mpsc::Receiver<Control>,
}

impl Internals {
    pub fn into_parts(
        self,
    ) -> (
        mpsc::Receiver<Vec<u8>>,
        mpsc::Sender<Vec<u8>>,
        mpsc::Receiver<Control>,
    ) {
        (self.outbound_rx, self.inbound_tx, self.ctrl_rx)
    }
}

type NetPacket = (SocketAddr, SocketAddr, Vec<u8>);

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

fn spawn_reader(sock: Arc<UdpSocket>, local: SocketAddr, tx: mpsc::Sender<NetPacket>) {
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
    });
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
    // Prefer assigned edge address when known; else identity-style fallback.
    let mut probe_src = crate::runtime_env::var("AETHER_PROBE_SRC")
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| std::net::Ipv4Addr::new(198, 18, 0, 1));

    let init_sock = bind_udp_fast(bind_addr_for(&peer)).await?;
    let local = init_sock.local_addr()?;
    let init_sock = Arc::new(init_sock);

    let (net_tx, mut net_rx) = mpsc::channel::<NetPacket>(NET_QUEUE);

    let mut sockets: HashMap<SocketAddr, Arc<UdpSocket>> = HashMap::new();
    sockets.insert(local, init_sock.clone());
    spawn_reader(init_sock, local, net_tx.clone());

    let mut config = tls::build_config(&TlsParams {
        cert_pem: &cfg.cert_pem,
        key_pem: &cfg.key_pem,
    })?;

    // #1: Load cached session ticket for 0-RTT resumption (faster reconnect).
    let session_cache_path = crate::lastconn::session_ticket_path();
    if let Ok(ticket) = std::fs::read(&session_cache_path) {
        if !ticket.is_empty() {
            config.set_session(&ticket).ok();
            log::debug!("[quic] loaded cached session ticket ({} bytes) for 0-RTT", ticket.len());
        }
    }

    let mut current_ech = cfg.ech_config_list.clone();

    let scid_bytes = random_scid();
    let scid = quiche::ConnectionId::from_ref(&scid_bytes);

    let mut conn = quiche::connect(Some(&cfg.sni), &scid, local, peer, &mut config)?;

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

    loop {
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

            Some((to_local, from, mut data)) = net_rx.recv() => {
                let mut hdr_buf = data.clone();
                if let Ok(hdr) = quiche::Header::from_slice(&mut hdr_buf, quiche::MAX_CONN_ID_LEN) {
                    log::debug!("recv {} bytes type={:?} version=0x{:x} from {}", data.len(), hdr.ty, hdr.version, from);
                }
                let info = quiche::RecvInfo { from, to: to_local };
                if let Err(e) = conn.recv(&mut data, info) {
                    log::debug!("recv error: {e}");
                }
            }

            ctrl = internals.ctrl_rx.recv() => {
                match ctrl {
                    Some(Control::Migrate) => {
                        if let Err(e) = do_migrate(&mut conn, peer, &mut sockets, &net_tx).await {
                            log::warn!("migration failed: {e}");
                        }
                    }
                    Some(Control::Close) | None => {
                        let _ = conn.close(true, 0x00, b"bye");
                    }
                }
            }

            pkt = internals.outbound_rx.recv() => {
                match pkt {
                    Some(ip_packet) => {
                        if let Some(sid) = req_stream {
                            match masque::encode_ip_datagram(sid, &ip_packet) {
                                Ok(framed) => {
                                    if let Err(e) = conn.dgram_send(&framed) {
                                        log::debug!("dgram_send: {e}");
                                    }
                                }
                                Err(e) => log::debug!("encap: {e}"),
                            }
                            // Batch remaining IP packets same tick.
                            while let Ok(more) = internals.outbound_rx.try_recv() {
                                match masque::encode_ip_datagram(sid, &more) {
                                    Ok(framed) => {
                                        if let Err(e) = conn.dgram_send(&framed) {
                                            log::debug!("dgram_send: {e}");
                                            break;
                                        }
                                    }
                                    Err(e) => log::debug!("encap: {e}"),
                                }
                            }
                        }
                    }
                    None => {
                        let _ = conn.close(true, 0x00, b"eof");
                    }
                }
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
            )?;
        }

        // After CONNECT-IP 200, prove data-plane with a DNS probe before ready signal.
        if h3_ready && !dataplane_ok {
            if probe_deadline.is_none() {
                probe_deadline = Some(Instant::now() + Duration::from_secs(8));
            }
            if last_probe.elapsed() >= Duration::from_millis(700) {
                if let Some(sid) = req_stream {
                    let probe = crate::dns::build_dataplane_probe(probe_src, std::net::Ipv4Addr::new(1, 1, 1, 1));
                    if let Ok(framed) = masque::encode_ip_datagram(sid, &probe) {
                        let _ = conn.dgram_send(&framed);
                    }
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
                    if let Some(ref ech) = current_ech {
                        tls::inject_ech(&mut conn, ech)?;
                    }

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
fn poll_h3(
    conn: &mut quiche::Connection,
    h3c: &mut h3::Connection,
    req_stream: u64,
    capsules: &mut CapsuleParser,
    addr_tx: &Option<mpsc::Sender<AssignedAddr>>,
    h3_ready: &mut bool,
    probe_src: &mut std::net::Ipv4Addr,
) -> Result<()> {
    let mut body = vec![0u8; 65535];

    loop {
        match h3c.poll(conn) {
            Ok((_stream_id, h3::Event::Headers { list, .. })) => {
                for h in &list {
                    if h.name() == b":status" {
                        let status = String::from_utf8_lossy(h.value());
                        log::info!("connect-ip status: {status}");
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
                drain_capsules(capsules, addr_tx, probe_src);
            }

            Ok((_stream_id, h3::Event::Finished)) => {}
            Ok((_stream_id, h3::Event::Reset(_))) => {}
            Ok(_) => {}

            Err(h3::Error::Done) => break,
            Err(e) => return Err(AetherError::H3(e)),
        }
    }

    Ok(())
}


fn drain_capsules(capsules: &mut CapsuleParser, addr_tx: &Option<mpsc::Sender<AssignedAddr>>, probe_src: &mut std::net::Ipv4Addr) {
    loop {
        match capsules.next() {
            Ok(Some(masque::Capsule::AddressAssign(addrs))) => {
                for a in addrs {
                    if let Some(ip) = bytes_to_ip(a.ip_version, &a.address) {
                        log::info!("edge assigned {}/{}", ip, a.prefix_len);
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
                log::info!("received {} route advertisements", routes.len());
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

async fn do_migrate(
    conn: &mut quiche::Connection,
    peer: SocketAddr,
    sockets: &mut HashMap<SocketAddr, Arc<UdpSocket>>,
    net_tx: &mpsc::Sender<NetPacket>,
) -> Result<()> {
    if conn.available_dcids() == 0 {
        return Err(AetherError::Other("no spare dcids for migration".into()));
    }

    let old_locals: Vec<SocketAddr> = sockets.keys().copied().collect();
    let new_sock = bind_udp_fast(bind_addr_for(&peer)).await?;
    let new_local = new_sock.local_addr()?;
    let new_sock = Arc::new(new_sock);

    sockets.insert(new_local, new_sock.clone());
    spawn_reader(new_sock, new_local, net_tx.clone());

    conn.probe_path(new_local, peer)?;
    let seq = conn.migrate_source(new_local)?;
    log::info!("migrated to local {new_local} (path seq {seq})");
    // Drop old sockets so their readers exit on next recv error (no unbounded leak).
    for old in old_locals {
        if old != new_local {
            sockets.remove(&old);
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

pub fn default_sni() -> &'static str {
    consts::L4_CONNECT_SNI
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
    let _ = sock.connect(p.peer).await;
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

    if let Some(ref ech) = p.ech_config_list {
        let _ = tls::inject_ech(&mut conn, ech);
    }

    let mut h3_config = h3::Config::new()?;
    h3_config.enable_extended_connect(true);
    let mut h3_conn: Option<h3::Connection> = None;
    let mut req_stream: Option<u64> = None;

    let start = Instant::now();
    let deadline = start + p.timeout;

    // Obfuscation noise before QUIC Initial (same as run() — works with Cloudflare).
    noize::pre_handshake(&sock, p.peer, &p.noize).await;

    flush_to(&mut conn, &sock, p.peer).await?;

    let mut buf = vec![0u8; 65535];
    let mut saw_udp = false;

    loop {
        if Instant::now() >= deadline {
            if !saw_udp {
                return Err(AetherError::Other(
                    "verify timeout (no UDP reply — QUIC may be filtered)".into(),
                ));
            }
            return Err(AetherError::Other("verify timeout (UDP ok, no connect-ip 200)".into()));
        }

        let wait = match conn.timeout() {
            Some(t) => t.min(remaining(deadline)),
            None => remaining(deadline),
        };

        tokio::select! {
            r = sock.recv_from(&mut buf) => {
                match r {
                    Ok((n, from)) => {
                        saw_udp = true;
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
            log::debug!("verify quic established to {}", p.peer);
            let mut h3c = h3::Connection::with_transport(&mut conn, &h3_config)?;
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
                                if h.value() == b"200" {
                                    // Control-plane OK. Now verify data-plane:
                                    // send 1 DNS probe through the datagram channel.
                                    // Fast-path: 1 round-trip is enough during scan.
                                    let probe_pkt = crate::dns::build_dataplane_probe(
                                        p.local_ipv4,
                                        std::net::Ipv4Addr::new(1, 1, 1, 1),
                                    );
                                    if let Ok(framed) = masque::encode_ip_datagram(sid, &probe_pkt) {
                                        let _ = conn.dgram_send(&framed);
                                        flush_to(&mut conn, &sock, p.peer).await?;
                                    }
                                    // Wait for data-plane reply (up to 2s).
                                    let dp_deadline = Instant::now() + Duration::from_secs(2).min(remaining(deadline));
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
                                                    // Check for datagram reply.
                                                    let mut dgram_buf = vec![0u8; 65535];
                                                    loop {
                                                        match conn.dgram_recv(&mut dgram_buf) {
                                                            Ok(dn) => {
                                                                if let Ok(Some(_)) = masque::decode_ip_datagram(&dgram_buf[..dn], sid) {
                                                                    // Data-plane confirmed!
                                                                    return Ok(start.elapsed());
                                                                }
                                                            }
                                                            Err(quiche::Error::Done) => break,
                                                            Err(_) => break,
                                                        }
                                                    }
                                                }
                                            }
                                            _ = tokio::time::sleep(dp_wait) => {
                                                conn.on_timeout();
                                                // Resend probe.
                                                if let Ok(framed) = masque::encode_ip_datagram(sid, &probe_pkt) {
                                                    let _ = conn.dgram_send(&framed);
                                                }
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

async fn flush_connected(conn: &mut quiche::Connection, sock: &UdpSocket) -> Result<()> {
    let mut out = vec![0u8; MAX_DATAGRAM_SIZE];
    loop {
        match conn.send(&mut out) {
            Ok((write, _info)) => {
                sock.send(&out[..write]).await?;
            }
            Err(quiche::Error::Done) => break,
            Err(e) => return Err(AetherError::Quic(e)),
        }
    }
    Ok(())
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
