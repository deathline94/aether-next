use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex, Notify};

use crate::aethernoize::{self, AetherNoizeConfig};
use crate::error::{AetherError, Result};
use rand::Rng;

const TIMER_TICK: Duration = Duration::from_millis(250);
const MAX_PACKET: usize = 65536;

const WG_MSG_TYPE_MIN: u8 = 1;
const WG_MSG_TYPE_MAX: u8 = 4;

async fn bind_udp_buffered(bind_addr: &str) -> Result<UdpSocket> {
    use socket2::{Domain, Socket, Type};
    let addr: std::net::SocketAddr = bind_addr
        .parse()
        .map_err(|e| AetherError::Other(format!("bind parse: {e}")))?;
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let s = Socket::new(domain, Type::DGRAM, None).map_err(AetherError::Io)?;
    s.set_nonblocking(true).map_err(AetherError::Io)?;
    let _ = s.set_recv_buffer_size(4 * 1024 * 1024);
    let _ = s.set_send_buffer_size(4 * 1024 * 1024);
    s.bind(&addr.into()).map_err(AetherError::Io)?;
    UdpSocket::from_std(s.into()).map_err(AetherError::Io)
}

fn inject_client_id(pkt: &mut [u8], client_id: &[u8; 3]) {
    if pkt.len() < 4 {
        return;
    }
    if pkt[0] < WG_MSG_TYPE_MIN || pkt[0] > WG_MSG_TYPE_MAX {
        return;
    }
    pkt[1..4].copy_from_slice(client_id);
}

fn strip_client_id(pkt: &mut [u8]) {
    if pkt.len() < 4 {
        return;
    }
    if pkt[0] < WG_MSG_TYPE_MIN || pkt[0] > WG_MSG_TYPE_MAX {
        return;
    }
    pkt[1..4].copy_from_slice(&[0u8; 3]);
}

/// boringtun requires calling encapsulate/decapsulate again with an empty buffer
/// until Done after every WriteToNetwork — otherwise handshake/data stalls.
fn drain_to_network(tunn: &mut Tunn, out_buf: &mut [u8], client_id: &[u8; 3]) -> Vec<Vec<u8>> {
    let mut wire = Vec::new();
    while let TunnResult::WriteToNetwork(pkt) = tunn.decapsulate(None, &[], out_buf) {
        let mut pkt_vec = pkt.to_vec();
        inject_client_id(&mut pkt_vec, client_id);
        wire.push(pkt_vec);
    }
    wire
}

fn encapsulate_all(
    tunn: &mut Tunn,
    ip_packet: &[u8],
    out_buf: &mut [u8],
    client_id: &[u8; 3],
) -> Vec<Vec<u8>> {
    let mut wire = Vec::new();
    match tunn.encapsulate(ip_packet, out_buf) {
        TunnResult::WriteToNetwork(pkt) => {
            let mut pkt_vec = pkt.to_vec();
            inject_client_id(&mut pkt_vec, client_id);
            wire.push(pkt_vec);
            // Flush any follow-up (handshake continuation, etc.)
            while let TunnResult::WriteToNetwork(pkt) = tunn.encapsulate(&[], out_buf) {
                let mut pkt_vec = pkt.to_vec();
                inject_client_id(&mut pkt_vec, client_id);
                wire.push(pkt_vec);
            }
        }
        TunnResult::Done => {}
        TunnResult::Err(e) => log::debug!("encapsulate error: {e:?}"),
        TunnResult::WriteToTunnelV4(_, _) | TunnResult::WriteToTunnelV6(_, _) => {}
    }
    wire
}

#[derive(Clone)]
pub struct WgConfig {
    pub local_private_key: [u8; 32],
    pub peer_public_key: [u8; 32],
    pub peer_endpoint: SocketAddr,
    pub local_ipv4: Ipv4Addr,
    pub local_ipv6: Ipv6Addr,
    pub client_id: [u8; 3],
    pub preshared_key: Option<[u8; 32]>,
    pub persistent_keepalive: Option<u16>,
    pub aethernoize: Arc<AetherNoizeConfig>,
}

pub struct WgTunnel {
    tunn: Arc<Mutex<Box<Tunn>>>,
    sock: Arc<UdpSocket>,
    peer: SocketAddr,
    inbound_tx: mpsc::Sender<Vec<u8>>,
    pub obf_sent: Arc<Mutex<bool>>,
    pub aethernoize: Arc<AetherNoizeConfig>,
    pub client_id: [u8; 3],
    /// Set once the Noise handshake has completed (first successful data or HS done).
    established: Arc<std::sync::atomic::AtomicBool>,
    established_notify: Arc<Notify>,
}

impl WgTunnel {
    pub async fn new(cfg: WgConfig, inbound_tx: mpsc::Sender<Vec<u8>>) -> Result<Self> {
        let bind_addr = if cfg.peer_endpoint.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };

        let sock = bind_udp_buffered(bind_addr).await?;
        sock.connect(cfg.peer_endpoint).await?;

        let local_secret = StaticSecret::from(cfg.local_private_key);
        let peer_public = PublicKey::from(cfg.peer_public_key);
        let preshared = cfg.preshared_key;

        let tunn = Tunn::new(
            local_secret,
            peer_public,
            preshared,
            cfg.persistent_keepalive,
            0,
            None,
        )
        .map_err(|e| AetherError::Other(format!("wireguard tunnel init: {e}")))?;

        Ok(Self {
            tunn: Arc::new(Mutex::new(Box::new(tunn))),
            sock: Arc::new(sock),
            peer: cfg.peer_endpoint,
            inbound_tx,
            obf_sent: Arc::new(Mutex::new(false)),
            aethernoize: cfg.aethernoize.clone(),
            client_id: cfg.client_id,
            established: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            established_notify: Arc::new(Notify::new()),
        })
    }

    fn mark_established(&self) {
        if !self
            .established
            .swap(true, std::sync::atomic::Ordering::SeqCst)
        {
            self.established_notify.notify_waiters();
        }
    }

    /// Kick the Noise handshake and wait until the session is ready for data.
    /// Call this BEFORE opening SOCKS/HTTP so the first TCP SYN is not lost.
    pub async fn handshake(&self, timeout: Duration) -> Result<Duration> {
        let start = Instant::now();
        let deadline = start + timeout;

        // Pre-handshake junk once (same as probe path).
        {
            let mut sent = self.obf_sent.lock().await;
            if !*sent && self.aethernoize.is_enabled() {
                *sent = true;
                drop(sent);
                aethernoize::apply_obfuscation(&self.sock, self.peer, &self.aethernoize).await;
            }
        }

        // Initiate handshake with empty encapsulate.
        {
            let mut tunn = self.tunn.lock().await;
            let mut out_buf = vec![0u8; MAX_PACKET];
            let wire = encapsulate_all(&mut tunn, &[], &mut out_buf, &self.client_id);
            drop(tunn);
            for pkt in wire {
                self.sock.send(&pkt).await?;
            }
        }

        let mut recv_buf = vec![0u8; MAX_PACKET];
        let mut tmp_buf = vec![0u8; MAX_PACKET];
        let mut resend_at = Instant::now() + Duration::from_millis(400);

        loop {
            if self.established.load(std::sync::atomic::Ordering::SeqCst) {
                return Ok(start.elapsed());
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(AetherError::Other("wireguard handshake timeout".into()));
            }
            if now >= resend_at {
                let mut tunn = self.tunn.lock().await;
                let mut out_buf = vec![0u8; MAX_PACKET];
                let wire = encapsulate_all(&mut tunn, &[], &mut out_buf, &self.client_id);
                // Also drive timers.
                if let TunnResult::WriteToNetwork(pkt) = tunn.update_timers(&mut out_buf) {
                    let mut pkt_vec = pkt.to_vec();
                    inject_client_id(&mut pkt_vec, &self.client_id);
                    drop(tunn);
                    let _ = self.sock.send(&pkt_vec).await;
                } else {
                    drop(tunn);
                }
                for pkt in wire {
                    let _ = self.sock.send(&pkt).await;
                }
                resend_at = Instant::now() + Duration::from_millis(500);
            }

            let wait = deadline
                .saturating_duration_since(Instant::now())
                .min(resend_at.saturating_duration_since(Instant::now()))
                .max(Duration::from_millis(10));

            tokio::select! {
                r = self.sock.recv(&mut recv_buf) => {
                    let n = r?;
                    strip_client_id(&mut recv_buf[..n]);
                    let mut tunn = self.tunn.lock().await;
                    let mut out_buf = vec![0u8; MAX_PACKET];
                    match tunn.decapsulate(None, &recv_buf[..n], &mut tmp_buf) {
                        TunnResult::Done => {
                            // Flush follow-ups.
                            let more = drain_to_network(&mut tunn, &mut out_buf, &self.client_id);
                            drop(tunn);
                            for pkt in more {
                                let _ = self.sock.send(&pkt).await;
                            }
                            // Done after response often means handshake complete.
                            self.mark_established();
                            return Ok(start.elapsed());
                        }
                        TunnResult::WriteToNetwork(pkt) => {
                            let mut pkt_vec = pkt.to_vec();
                            inject_client_id(&mut pkt_vec, &self.client_id);
                            let more = drain_to_network(&mut tunn, &mut out_buf, &self.client_id);
                            drop(tunn);
                            let _ = self.sock.send(&pkt_vec).await;
                            for pkt in more {
                                let _ = self.sock.send(&pkt).await;
                            }
                            // Handshake response exchanged — session ready for data.
                            self.mark_established();
                            return Ok(start.elapsed());
                        }
                        TunnResult::WriteToTunnelV4(_, _) | TunnResult::WriteToTunnelV6(_, _) => {
                            drop(tunn);
                            self.mark_established();
                            return Ok(start.elapsed());
                        }
                        TunnResult::Err(e) => {
                            log::debug!("handshake decap: {e:?}");
                        }
                    }
                }
                _ = tokio::time::sleep(wait) => {}
            }
        }
    }

    pub async fn run(self, mut outbound_rx: mpsc::Receiver<Vec<u8>>) -> Result<()> {
        let sock_r = self.sock.clone();
        let sock_w = self.sock.clone();
        let sock_t = self.sock.clone();
        let tunn_r = self.tunn.clone();
        let tunn_w = self.tunn.clone();
        let tunn_t = self.tunn.clone();
        let inbound_tx = self.inbound_tx.clone();
        let obf_sent = self.obf_sent.clone();
        let aethernoize = self.aethernoize.clone();
        let client_id = self.client_id;
        let peer = self.peer;
        let established = self.established.clone();
        let established_notify = self.established_notify.clone();

        let mut recv_task = tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_PACKET];
            let mut tmp = vec![0u8; MAX_PACKET];
            loop {
                match sock_r.recv(&mut buf).await {
                    Ok(n) => {
                        strip_client_id(&mut buf[..n]);
                        let mut tunn = tunn_r.lock().await;
                        let mut out_buf = vec![0u8; MAX_PACKET];
                        match tunn.decapsulate(None, &buf[..n], &mut tmp) {
                            TunnResult::Done => {
                                let more = drain_to_network(&mut tunn, &mut out_buf, &client_id);
                                drop(tunn);
                                for pkt in more {
                                    let _ = sock_r.send(&pkt).await;
                                }
                            }
                            TunnResult::Err(e) => {
                                log::debug!("decapsulate error: {e:?}");
                            }
                            TunnResult::WriteToNetwork(pkt) => {
                                let mut pkt_vec = pkt.to_vec();
                                inject_client_id(&mut pkt_vec, &client_id);
                                let more = drain_to_network(&mut tunn, &mut out_buf, &client_id);
                                drop(tunn);
                                let _ = sock_r.send(&pkt_vec).await;
                                for pkt in more {
                                    let _ = sock_r.send(&pkt).await;
                                }
                                if !established.load(std::sync::atomic::Ordering::SeqCst) {
                                    established.store(true, std::sync::atomic::Ordering::SeqCst);
                                    established_notify.notify_waiters();
                                }
                            }
                            TunnResult::WriteToTunnelV4(pkt, _)
                            | TunnResult::WriteToTunnelV6(pkt, _) => {
                                let pkt_vec = pkt.to_vec();
                                // Also flush any pending network writes.
                                let more = drain_to_network(&mut tunn, &mut out_buf, &client_id);
                                drop(tunn);
                                for pkt in more {
                                    let _ = sock_r.send(&pkt).await;
                                }
                                if !established.load(std::sync::atomic::Ordering::SeqCst) {
                                    established.store(true, std::sync::atomic::Ordering::SeqCst);
                                    established_notify.notify_waiters();
                                }
                                if inbound_tx.send(pkt_vec).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        log::error!("recv error: {e}");
                        break;
                    }
                }
            }
        });

        let post_hs_done = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let post_hs_flag = post_hs_done.clone();
        let mut send_task = tokio::spawn(async move {
            let mut out_buf = vec![0u8; MAX_PACKET];
            while let Some(first) = outbound_rx.recv().await {
                let mut batch = Vec::with_capacity(32);
                batch.push(first);
                while batch.len() < 64 {
                    match outbound_rx.try_recv() {
                        Ok(p) => batch.push(p),
                        Err(_) => break,
                    }
                }

                let mut wire: Vec<Vec<u8>> = Vec::with_capacity(batch.len());
                {
                    let mut tunn = tunn_w.lock().await;
                    for ip_packet in batch {
                        wire.extend(encapsulate_all(
                            &mut tunn,
                            &ip_packet,
                            &mut out_buf,
                            &client_id,
                        ));
                    }
                }

                if !wire.is_empty() {
                    {
                        let mut sent = obf_sent.lock().await;
                        if !*sent && aethernoize.is_enabled() {
                            *sent = true;
                            drop(sent);
                            aethernoize::apply_obfuscation(&sock_w, peer, &aethernoize).await;
                        }
                    }
                    for pkt_vec in wire {
                        let _ = sock_w.send(&pkt_vec).await;
                    }
                    if aethernoize.jc_after_hs > 0
                        && !post_hs_flag.swap(true, std::sync::atomic::Ordering::SeqCst)
                    {
                        let sock_clone = sock_w.clone();
                        let cfg_clone = aethernoize.clone();
                        tokio::spawn(async move {
                            aethernoize::send_post_handshake_junk(&sock_clone, peer, &cfg_clone)
                                .await;
                        });
                    }
                }
            }
        });

        let mut timer_task = tokio::spawn(async move {
            let mut interval = tokio::time::interval(TIMER_TICK);
            loop {
                interval.tick().await;
                let mut tunn = tunn_t.lock().await;
                let mut tmp = vec![0u8; MAX_PACKET];
                if let TunnResult::WriteToNetwork(pkt) = tunn.update_timers(&mut tmp) {
                    let mut pkt_vec = pkt.to_vec();
                    inject_client_id(&mut pkt_vec, &client_id);
                    let more = drain_to_network(&mut tunn, &mut tmp, &client_id);
                    drop(tunn);
                    let _ = sock_t.send(&pkt_vec).await;
                    for pkt in more {
                        let _ = sock_t.send(&pkt).await;
                    }
                }
            }
        });

        tokio::select! {
            _ = &mut recv_task => log::info!("wireguard recv task ended"),
            _ = &mut send_task => log::info!("wireguard send task ended"),
            _ = &mut timer_task => log::info!("wireguard timer task ended"),
        }
        recv_task.abort();
        send_task.abort();
        timer_task.abort();
        let _ = recv_task.await;
        let _ = send_task.await;
        let _ = timer_task.await;

        Ok(())
    }
}

fn build_dns_query() -> Vec<u8> {
    let id: u16 = rand::random();
    let mut q = Vec::with_capacity(32);
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00]);
    q.extend_from_slice(&[0x00, 0x01]);
    q.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    for label in ["cloudflare", "com"] {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0x00);
    q.extend_from_slice(&[0x00, 0x01]);
    q.extend_from_slice(&[0x00, 0x01]);
    q
}

fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < header.len() {
        sum += u16::from_be_bytes([header[i], header[i + 1]]) as u32;
        i += 2;
    }
    if i < header.len() {
        sum += (header[i] as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn build_dataplane_probe(src: Ipv4Addr) -> Vec<u8> {
    let dns = build_dns_query();
    let udp_len = 8 + dns.len();
    let total_len = 20 + udp_len;
    let mut pkt = Vec::with_capacity(total_len);
    pkt.push(0x45);
    pkt.push(0x00);
    pkt.extend_from_slice(&(total_len as u16).to_be_bytes());
    let id: u16 = rand::random();
    pkt.extend_from_slice(&id.to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt.push(64);
    pkt.push(17);
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt.extend_from_slice(&src.octets());
    pkt.extend_from_slice(&Ipv4Addr::new(1, 1, 1, 1).octets());
    let csum = ipv4_checksum(&pkt[0..20]);
    pkt[10..12].copy_from_slice(&csum.to_be_bytes());
    let sport: u16 = rand::thread_rng().gen_range(20000..60000);
    pkt.extend_from_slice(&sport.to_be_bytes());
    pkt.extend_from_slice(&53u16.to_be_bytes());
    pkt.extend_from_slice(&(udp_len as u16).to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt.extend_from_slice(&dns);
    pkt
}

async fn send_dataplane_probe(
    sock: &UdpSocket,
    tunn: &mut Tunn,
    client_id: &[u8; 3],
    probe: &[u8],
    out_buf: &mut [u8],
) -> Result<()> {
    let wire = encapsulate_all(tunn, probe, out_buf, client_id);
    if wire.is_empty() {
        return Err(AetherError::Other("dataplane encap produced no packets".into()));
    }
    for pkt in wire {
        sock.send(&pkt).await?;
    }
    Ok(())
}

async fn verify_dataplane(
    sock: &UdpSocket,
    tunn: &mut Tunn,
    client_id: &[u8; 3],
    local_ipv4: Ipv4Addr,
    start: Instant,
    deadline: Instant,
) -> Result<Duration> {
    let probe = build_dataplane_probe(local_ipv4);
    let mut out_buf = vec![0u8; MAX_PACKET];
    let mut recv_buf = vec![0u8; MAX_PACKET];
    let mut tmp_buf = vec![0u8; MAX_PACKET];

    send_dataplane_probe(sock, tunn, client_id, &probe, &mut out_buf).await?;
    let mut resend_at = Instant::now() + Duration::from_millis(700);

    loop {
        let now = Instant::now();
        if now >= deadline {
            log::debug!("[wg] dataplane verify timed out");
            return Err(AetherError::Other("dataplane timeout".into()));
        }
        if now >= resend_at {
            let _ = send_dataplane_probe(sock, tunn, client_id, &probe, &mut out_buf).await;
            resend_at = now + Duration::from_millis(700);
        }
        let wait = deadline
            .saturating_duration_since(now)
            .min(resend_at.saturating_duration_since(now));

        tokio::select! {
            r = sock.recv(&mut recv_buf) => {
                let n = r?;
                strip_client_id(&mut recv_buf[..n]);
                match tunn.decapsulate(None, &recv_buf[..n], &mut tmp_buf) {
                    TunnResult::WriteToTunnelV4(_, _) | TunnResult::WriteToTunnelV6(_, _) => {
                        let elapsed = start.elapsed();
                        log::debug!("[wg] dataplane ok in {:?}", elapsed);
                        return Ok(elapsed);
                    }
                    TunnResult::WriteToNetwork(pkt) => {
                        let mut v = pkt.to_vec();
                        inject_client_id(&mut v, client_id);
                        let _ = sock.send(&v).await;
                        for pkt in drain_to_network(tunn, &mut out_buf, client_id) {
                            let _ = sock.send(&pkt).await;
                        }
                    }
                    TunnResult::Done => {
                        for pkt in drain_to_network(tunn, &mut out_buf, client_id) {
                            let _ = sock.send(&pkt).await;
                        }
                    }
                    _ => {}
                }
            }
            _ = tokio::time::sleep(wait) => {}
        }
    }
}

pub async fn verify_endpoint(
    peer: SocketAddr,
    private_key: [u8; 32],
    peer_public: [u8; 32],
    client_id: [u8; 3],
    local_ipv4: Ipv4Addr,
    aethernoize: &AetherNoizeConfig,
    timeout: Duration,
) -> Result<Duration> {
    let data_check = std::env::var("AETHER_WG_NO_DATA_CHECK").is_err();
    log::debug!(
        "[wg] verify {} obf={} data_check={}",
        peer,
        aethernoize.is_enabled(),
        data_check
    );

    let bind = if peer.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let sock = UdpSocket::bind(bind).await?;
    sock.connect(peer).await?;

    let start = Instant::now();
    let deadline = start + timeout;

    // Bound whole verify (including obfuscation) so concurrent hunts cannot hang.
    let result = tokio::time::timeout(timeout, async {
    if aethernoize.is_enabled() {
        aethernoize::apply_obfuscation(&sock, peer, aethernoize).await;
    }

    let local_secret = StaticSecret::from(private_key);
    let peer_pk = PublicKey::from(peer_public);

    let mut tunn = Tunn::new(local_secret, peer_pk, None, Some(25), 0, None)
        .map_err(|e| AetherError::Other(format!("tunn init: {e}")))?;

    let mut out_buf = vec![0u8; MAX_PACKET];
    let mut recv_buf = vec![0u8; MAX_PACKET];
    let mut tmp_buf = vec![0u8; MAX_PACKET];

    let wire = encapsulate_all(&mut tunn, &[], &mut out_buf, &client_id);
    if wire.is_empty() {
        return Err(AetherError::Other("handshake init failed".into()));
    }
    for pkt in wire {
        log::debug!("[wg] sending init {} bytes to {}", pkt.len(), peer);
        sock.send(&pkt).await?;
    }

    let mut attempts = 0;
    loop {
        if Instant::now() >= deadline {
            log::debug!("[wg] timeout after {} recv attempts", attempts);
            return Err(AetherError::Other("verify timeout".into()));
        }

        let remaining = deadline.saturating_duration_since(Instant::now()).max(Duration::from_millis(50));

        tokio::select! {
            r = sock.recv(&mut recv_buf) => {
                attempts += 1;
                let n = r?;
                log::debug!("[wg] recv {} bytes (attempt {})", n, attempts);
                strip_client_id(&mut recv_buf[..n]);

                match tunn.decapsulate(None, &recv_buf[..n], &mut tmp_buf) {
                    TunnResult::Done => {
                        for pkt in drain_to_network(&mut tunn, &mut out_buf, &client_id) {
                            let _ = sock.send(&pkt).await;
                        }
                        let elapsed = start.elapsed();
                        log::debug!("[wg] handshake done in {:?}", elapsed);
                        if data_check {
                            return verify_dataplane(&sock, &mut tunn, &client_id, local_ipv4, start, deadline).await;
                        }
                        return Ok(elapsed);
                    }
                    TunnResult::WriteToNetwork(pkt) => {
                        let mut pkt_vec = pkt.to_vec();
                        inject_client_id(&mut pkt_vec, &client_id);
                        log::debug!("[wg] sending response {} bytes", pkt_vec.len());
                        sock.send(&pkt_vec).await?;
                        for pkt in drain_to_network(&mut tunn, &mut out_buf, &client_id) {
                            let _ = sock.send(&pkt).await;
                        }
                        let elapsed = start.elapsed();
                        log::debug!("[wg] handshake success in {:?}", elapsed);
                        if data_check {
                            return verify_dataplane(&sock, &mut tunn, &client_id, local_ipv4, start, deadline).await;
                        }
                        return Ok(elapsed);
                    }
                    TunnResult::WriteToTunnelV4(_, _) | TunnResult::WriteToTunnelV6(_, _) => {
                        let elapsed = start.elapsed();
                        if data_check {
                            return Ok(elapsed);
                        }
                        return Ok(elapsed);
                    }
                    TunnResult::Err(e) => {
                        log::debug!("[wg] decap error: {:?}", e);
                    }
                }
            }
            _ = tokio::time::sleep(remaining) => {
                log::debug!("[wg] sleep timeout");
                return Err(AetherError::Other("verify timeout".into()));
            }
        }
    }
    })
    .await;

    match result {
        Ok(inner) => inner,
        Err(_) => Err(AetherError::Other("verify timeout".into())),
    }
}

// Shared edge pool with MASQUE (see scan_pool.rs).
pub use crate::scan_pool::{
    EDGE_CIDRS_V4 as WG_PREFIXES_V4, EDGE_CIDRS_V6 as WG_PREFIXES_V6, EDGE_PORTS as WG_PORTS,
    EDGE_SEEDS_V4 as WG_SEEDS_V4, EDGE_SEEDS_V6 as WG_SEEDS_V6,
};
