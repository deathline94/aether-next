use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Checksum, Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, Ipv4Address, Ipv6Address};
use tokio::sync::{mpsc, oneshot};

use crate::error::{AetherError, Result};

// Keep per-flow memory bounded. Large fixed buffers multiplied by browser connection
// counts caused multi-gigabyte growth and allocator aborts on desktop.
const TCP_BUF: usize = 512 * 1024;
const UDP_BUF: usize = 128 * 1024;
const UDP_META: usize = 128;
const APP_QUEUE: usize = 256;
const MAX_INGEST_PER_TICK: usize = 256;
const MAX_CMDS_PER_TICK: usize = 64;
const MAX_APPDATA_PER_TICK: usize = 64;
const MAX_RECV_CHUNKS: usize = 64;
const MAX_TCP_CONNECTIONS: usize = 512;
const MAX_UDP_CONNECTIONS: usize = 128;
const MAX_PENDING_PER_CONN: usize = 512 * 1024;

/// Upper bound on frames the device will queue for the tunnel.
///
/// Returning `None` from `transmit` is smoltcp's "device buffer full" signal
/// (`socket_egress` maps it to `EgressError::Exhausted => break`), and because
/// `emit()` runs before the TCP sequence state advances, the segment is retried
/// on the next poll rather than lost. Before this cap the queue was an
/// unbounded `VecDeque<Vec<u8>>`: a peer that advertises a window while the
/// tunnel queue is saturated grew memory until the allocator aborted.
const TX_RING: usize = 256;

/// Upper bound on frames the tunnel has pushed in that smoltcp has not polled
/// yet. Symmetric with TX_RING: the inbound side is attacker-influenced (the
/// peer decides how much comes back), so an unbounded `rx` let a fast peer grow
/// our memory while our poll loop was busy. Dropping here is safe — TCP/UDP
/// recover by retransmit, which is exactly what an oversize window would have
/// caused anyway once the socket buffer filled.
const RX_RING: usize = 512;

type OpenTcpResp = oneshot::Sender<std::result::Result<TcpConn, String>>;
type OpenUdpResp = oneshot::Sender<std::result::Result<UdpConn, String>>;

pub struct StackDevice {
    rx: VecDeque<Vec<u8>>,
    tx: VecDeque<Vec<u8>>,
    mtu: usize,
    /// Frames refused because the ring was full, so "backpressured" is
    /// distinguishable from "idle" in diagnostics instead of being invisible.
    pub tx_deferred: u64,
    /// Inbound frames dropped by the RX_RING admission cap (see `push_ingress`).
    pub rx_dropped: u64,
    /// Bytes currently queued for ingress; drives the soft byte admission budget.
    pub rx_bytes: usize,
}

impl StackDevice {
    fn new(mtu: usize) -> Self {
        Self {
            rx: VecDeque::new(),
            tx: VecDeque::new(),
            mtu,
            tx_deferred: 0,
            rx_dropped: 0,
            rx_bytes: 0,
        }
    }

    /// Admit one inbound frame, bounded by both frame count and bytes.
    ///
    /// Returns `false` when the frame was dropped. Silently accepting an
    /// unbounded queue turned a peer that floods us while our poll loop is busy
    /// into an allocator abort, so over the budget the frame is discarded and
    /// the count is surfaced instead — TCP/UDP retransmit is the intended
    /// recovery path for a full receiver, not memory exhaustion.
    fn push_ingress(&mut self, pkt: Vec<u8>) -> bool {
        const RX_BYTE_BUDGET: usize = 8 * 1024 * 1024;
        if self.rx.len() >= RX_RING || self.rx_bytes + pkt.len() > RX_BYTE_BUDGET {
            self.rx_dropped += 1;
            return false;
        }
        self.rx_bytes += pkt.len();
        self.rx.push_back(pkt);
        true
    }
}

pub struct StackRxToken(Vec<u8>);
pub struct StackTxToken<'a> {
    queue: &'a mut VecDeque<Vec<u8>>,
}

impl RxToken for StackRxToken {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

impl<'a> TxToken for StackTxToken<'a> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut buf = vec![0u8; len];
        let r = f(&mut buf);
        self.queue.push_back(buf);
        r
    }
}

impl Device for StackDevice {
    type RxToken<'a> = StackRxToken;
    type TxToken<'a> = StackTxToken<'a>;

    fn receive(&mut self, _t: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let pkt = self.rx.pop_front()?;
        self.rx_bytes = self.rx_bytes.saturating_sub(pkt.len());
        // The token paired with an ingress packet is deliberately *not* capped:
        // dropping an ACK is unsafe, because `ack_reply` updates remote_last_ack
        // eagerly and a lost reply is not regenerated until new data or a window
        // update arrives — whereas a refused egress segment is simply retried.
        Some((
            StackRxToken(pkt),
            StackTxToken {
                queue: &mut self.tx,
            },
        ))
    }

    fn transmit(&mut self, _t: Instant) -> Option<Self::TxToken<'_>> {
        if self.tx.len() >= TX_RING {
            self.tx_deferred += 1;
            return None;
        }
        Some(StackTxToken {
            queue: &mut self.tx,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps.checksum.ipv4 = Checksum::Tx;
        caps.checksum.tcp = Checksum::Tx;
        caps.checksum.udp = Checksum::Tx;
        caps
    }
}

pub enum Cmd {
    OpenTcp { dst: SocketAddr, resp: OpenTcpResp },
    OpenUdp { resp: OpenUdpResp },
    SetAddrs {
        v4: Option<(Ipv4Addr, u8)>,
        v6: Option<(Ipv6Addr, u8)>,
    },
}

pub enum DataIn {
    Tcp(usize, Vec<u8>),
    TcpClose(usize),
    Udp(usize, SocketAddr, Vec<u8>),
    UdpClose(usize),
}

pub struct TcpConn {
    pub id: usize,
    pub from_stack: mpsc::Receiver<Vec<u8>>,
    data_in: mpsc::Sender<DataIn>,
    dead: Arc<AtomicBool>,
}

impl TcpConn {
    pub async fn send(&self, data: Vec<u8>) -> Result<()> {
        check_live(&self.dead)?;
        self.data_in
            .send(DataIn::Tcp(self.id, data))
            .await
            .map_err(|_| AetherError::Other("netstack closed".into()))
    }

    pub fn into_split(self) -> (TcpSender, mpsc::Receiver<Vec<u8>>) {
        (
            TcpSender {
                id: self.id,
                data_in: self.data_in,
                dead: self.dead,
            },
            self.from_stack,
        )
    }
}

/// A write against a flow the stack has already discarded.
fn check_live(dead: &AtomicBool) -> Result<()> {
    if dead.load(Ordering::Relaxed) {
        return Err(AetherError::Other(
            "connection is closed; data was not written".into(),
        ));
    }
    Ok(())
}

pub struct TcpSender {
    id: usize,
    data_in: mpsc::Sender<DataIn>,
    dead: Arc<AtomicBool>,
}

impl Clone for TcpSender {
    fn clone(&self) -> Self {
        Self {
            id: self.id,
            data_in: self.data_in.clone(),
            dead: self.dead.clone(),
        }
    }
}

impl TcpSender {
    pub async fn send(&self, data: Vec<u8>) -> Result<()> {
        check_live(&self.dead)?;
        self.data_in
            .send(DataIn::Tcp(self.id, data))
            .await
            .map_err(|_| AetherError::Other("netstack closed".into()))
    }

    pub async fn close(&self) {
        let _ = self.data_in.send(DataIn::TcpClose(self.id)).await;
    }
}

pub struct UdpConn {
    pub id: usize,
    pub from_stack: mpsc::Receiver<(SocketAddr, Vec<u8>)>,
    data_in: mpsc::Sender<DataIn>,
}

impl UdpConn {
    pub fn into_split(self) -> (UdpSender, mpsc::Receiver<(SocketAddr, Vec<u8>)>) {
        (
            UdpSender::new(self.id, self.data_in),
            self.from_stack,
        )
    }
}

pub struct UdpSender {
    inner: Option<std::sync::Arc<UdpSenderShared>>,
}

struct UdpSenderShared {
    id: usize,
    data_in: mpsc::Sender<DataIn>,
}

impl Clone for UdpSender {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl UdpSender {
    fn new(id: usize, data_in: mpsc::Sender<DataIn>) -> Self {
        Self {
            inner: Some(std::sync::Arc::new(UdpSenderShared { id, data_in })),
        }
    }

    fn shared(&self) -> &UdpSenderShared {
        self.inner.as_ref().expect("UdpSender used after close")
    }

    pub async fn send_to(&self, dst: SocketAddr, data: Vec<u8>) -> Result<()> {
        let shared = self.shared();
        shared
            .data_in
            .send(DataIn::Udp(shared.id, dst, data))
            .await
            .map_err(|_| AetherError::Other("netstack closed".into()))
    }

    pub async fn close(&self) {
        let shared = self.shared();
        let _ = shared.data_in.send(DataIn::UdpClose(shared.id)).await;
    }
}

impl Drop for UdpSender {
    fn drop(&mut self) {
        // Safety net for the socket-leak class of bugs (H1): the netstack only
        // frees a UDP socket on an explicit UdpClose, so a sender dropped
        // without close() used to leak the socket + its buffers until the
        // MAX_UDP_CONNECTIONS cap permanently broke DNS/proxying. `try_send` so
        // drop never blocks; explicit close() calls remain authoritative.
        //
        // Taking the `Arc` out first makes this fire on the *last* handle only:
        // the SOCKS UDP resolver clones the sender, and closing per-clone tore
        // down an association that was still carrying traffic.
        let Some(shared) = self.inner.take() else { return };
        if std::sync::Arc::strong_count(&shared) != 1 {
            return;
        }
        let _ = shared.data_in.try_send(DataIn::UdpClose(shared.id));
    }
}

#[derive(Clone)]
pub struct StackHandle {
    cmd_tx: mpsc::Sender<Cmd>,
}

impl StackHandle {
    pub async fn open_tcp(&self, dst: SocketAddr) -> Result<TcpConn> {
        let (resp_tx, resp_rx) = oneshot::channel();
        self.cmd_tx
            .send(Cmd::OpenTcp { dst, resp: resp_tx })
            .await
            .map_err(|_| AetherError::Other("netstack closed".into()))?;
        resp_rx
            .await
            .map_err(|_| AetherError::Other("netstack dropped".into()))?
            .map_err(AetherError::Other)
    }

    pub async fn open_udp(&self) -> Result<UdpConn> {
        let (resp_tx, resp_rx) = oneshot::channel();
        self.cmd_tx
            .send(Cmd::OpenUdp { resp: resp_tx })
            .await
            .map_err(|_| AetherError::Other("netstack closed".into()))?;
        resp_rx
            .await
            .map_err(|_| AetherError::Other("netstack dropped".into()))?
            .map_err(AetherError::Other)
    }

    pub async fn set_addrs(
        &self,
        v4: Option<(Ipv4Addr, u8)>,
        v6: Option<(Ipv6Addr, u8)>,
    ) -> Result<()> {
        self.cmd_tx
            .send(Cmd::SetAddrs { v4, v6 })
            .await
            .map_err(|_| AetherError::Other("netstack closed".into()))
    }
}

struct TcpState {
    handle: SocketHandle,
    to_app: mpsc::Sender<Vec<u8>>,
    from_stack_rx: Option<mpsc::Receiver<Vec<u8>>>,
    connect_resp: Option<OpenTcpResp>,
    pending: Vec<u8>,
    established: bool,
    half_closed: bool,
    /// Set when the flow is finished from the app's point of view (dropped for
    /// exceeding `MAX_PENDING_PER_CONN`, aborted, or removed). `TcpSender::send`
    /// is otherwise an unacknowledged channel push, so a burst larger than the
    /// pending budget was reported as written and then thrown away — a
    /// truncated HTTP body or TLS record with no error anywhere.
    dead: Arc<AtomicBool>,
}

struct UdpState {
    handle: SocketHandle,
    to_app: mpsc::Sender<(SocketAddr, Vec<u8>)>,
}

pub struct NetStack {
    iface: Interface,
    device: StackDevice,
    sockets: SocketSet<'static>,
    tcp_conns: HashMap<usize, TcpState>,
    udp_conns: HashMap<usize, UdpState>,
    next_id: usize,
    next_port: u16,
    /// Odd step used to walk the ephemeral band (see `alloc_port`).
    port_stride: u16,
    data_in_tx: mpsc::Sender<DataIn>,
}

fn strip_cidr(s: &str) -> &str {
    match s.split_once('/') {
        Some((ip, _)) => ip,
        None => s,
    }
}

fn to_ip_address(ip: IpAddr) -> IpAddress {
    match ip {
        IpAddr::V4(v4) => IpAddress::Ipv4(v4),
        IpAddr::V6(v6) => IpAddress::Ipv6(v6),
    }
}

fn to_ip_endpoint(addr: SocketAddr) -> IpEndpoint {
    IpEndpoint::new(to_ip_address(addr.ip()), addr.port())
}

fn cidr_prefix(s: &str) -> Option<u8> {
    s.split_once('/').and_then(|(_, p)| p.parse().ok())
}

fn parse_v4(s: &str) -> Result<Option<(Ipv4Addr, u8)>> {
    if s.is_empty() {
        return Ok(None);
    }
    let ip: Ipv4Addr = strip_cidr(s)
        .parse()
        .map_err(|_| AetherError::Other(format!("bad ipv4 {s}")))?;
    Ok(Some((ip, cidr_prefix(s).unwrap_or(32))))
}

fn parse_v6(s: &str) -> Result<Option<(Ipv6Addr, u8)>> {
    if s.is_empty() {
        return Ok(None);
    }
    let ip: Ipv6Addr = strip_cidr(s)
        .parse()
        .map_err(|_| AetherError::Other(format!("bad ipv6 {s}")))?;
    Ok(Some((ip, cidr_prefix(s).unwrap_or(128))))
}

fn routable_prefix_v4(p: u8) -> u8 {
    if p >= 31 {
        24
    } else {
        p
    }
}

fn routable_prefix_v6(p: u8) -> u8 {
    if p >= 127 {
        64
    } else {
        p
    }
}

fn apply_addrs(
    iface: &mut Interface,
    v4: Option<(Ipv4Addr, u8)>,
    v6: Option<(Ipv6Addr, u8)>,
) {
    // Merge: when only one family is provided, keep the other family's current addrs.
    let mut keep_v4: Option<(Ipv4Addr, u8)> = None;
    let mut keep_v6: Option<(Ipv6Addr, u8)> = None;
    for cidr in iface.ip_addrs() {
        match cidr.address() {
            IpAddress::Ipv4(a) => keep_v4 = Some((a, cidr.prefix_len())),
            IpAddress::Ipv6(a) => keep_v6 = Some((a, cidr.prefix_len())),
        }
    }
    let next_v4 = v4.or(keep_v4);
    let next_v6 = v6.or(keep_v6);

    iface.update_ip_addrs(|addrs| {
        addrs.clear();
        if let Some((ip, p)) = next_v4 {
            let _ = addrs.push(IpCidr::new(IpAddress::Ipv4(ip), routable_prefix_v4(p)));
        }
        if let Some((ip, p)) = next_v6 {
            let _ = addrs.push(IpCidr::new(IpAddress::Ipv6(ip), routable_prefix_v6(p)));
        }
    });

    if let Some((ip, _)) = next_v4 {
        let o = ip.octets();
        let host = if o[3] == 1 { 2 } else { 1 };
        let gw = Ipv4Address::new(o[0], o[1], o[2], host);
        let _ = iface.routes_mut().add_default_ipv4_route(gw);
    }
    if let Some((ip, _)) = next_v6 {
        let mut o = ip.octets();
        o[15] = if o[15] == 1 { 2 } else { 1 };
        let _ = iface
            .routes_mut()
            .add_default_ipv6_route(Ipv6Address::from(o));
    }
}

fn endpoint_to_socketaddr(ep: IpEndpoint) -> SocketAddr {
    let ip = match ep.addr {
        IpAddress::Ipv4(v4) => IpAddr::V4(v4),
        IpAddress::Ipv6(v6) => IpAddr::V6(v6),
    };
    SocketAddr::new(ip, ep.port)
}

pub fn spawn(
    ipv4: &str,
    ipv6: &str,
    mtu: usize,
    inbound_rx: mpsc::Receiver<Vec<u8>>,
    outbound_tx: mpsc::Sender<Vec<u8>>,
) -> Result<StackHandle> {
    let mut device = StackDevice::new(mtu);

    let config = Config::new(HardwareAddress::Ip);
    let mut iface = Interface::new(config, &mut device, Instant::now());

    let v4 = parse_v4(ipv4)?;
    let v6 = parse_v6(ipv6)?;
    apply_addrs(&mut iface, v4, v6);

    let (cmd_tx, cmd_rx) = mpsc::channel(256);
    let (data_in_tx, data_in_rx) = mpsc::channel(APP_QUEUE);

    let stack = NetStack {
        iface,
        device,
        sockets: SocketSet::new(Vec::new()),
        tcp_conns: HashMap::new(),
        udp_conns: HashMap::new(),
        next_id: 1,
        next_port: port_seed().0,
        port_stride: port_seed().1,
        data_in_tx: data_in_tx.clone(),
    };

    tokio::spawn(run(stack, cmd_rx, data_in_rx, inbound_rx, outbound_tx));

    Ok(StackHandle { cmd_tx })
}

/// Ephemeral band.
///
/// Sequential allocation (49152, 49153, …) let an off-path attacker predict a
/// query's client port, leaving only the 16-bit DNS transaction ID to guess and
/// making retries free. 49152..=65535 spans exactly 2^14, so any odd stride is
/// coprime with it and visits the whole band before repeating.
const EPHEMERAL_BASE: u16 = 49152;
const EPHEMERAL_SPAN: u16 = 16384;

fn alloc_port(p: &mut u16, stride: u16) -> u16 {
    let port = *p;
    let next = port.wrapping_add(stride);
    // Only the `wrapping_add` overflow can leave the band, and 65536 is a
    // multiple of EPHEMERAL_SPAN, so the remap is an exact mod-band wrap: every
    // port in 49152..=65535 is visited before the cycle repeats.
    *p = if next < EPHEMERAL_BASE {
        EPHEMERAL_BASE + (next % EPHEMERAL_SPAN)
    } else {
        next
    };
    port
}

fn next_ephemeral(from: u16, stride: u16) -> u16 {
    let mut cursor = from;
    alloc_port(&mut cursor, stride);
    cursor
}

/// Random start plus an odd stride inside the ephemeral band.
fn seed_port_cursor() -> (u16, u16) {
    let start = EPHEMERAL_BASE + (rand::random::<u16>() % EPHEMERAL_SPAN);
    let stride = (((rand::random::<u16>() | 1) % (EPHEMERAL_SPAN - 1)) | 1).max(17);
    (start, stride)
}

/// One random seed shared by every stack in the process.
fn port_seed() -> (u16, u16) {
    static SEED: std::sync::OnceLock<(u16, u16)> = std::sync::OnceLock::new();
    *SEED.get_or_init(seed_port_cursor)
}

/// L-fix: pick the next ephemeral port that no live TCP/UDP socket is bound to.
/// The old wrap-around counter could hand a duplicate local port to a second
/// socket once ~16k flows opened, silently breaking both flows (responses became
/// ambiguous inside smoltcp).
fn alloc_unique_port(s: &NetStack) -> Option<u16> {
    let mut cursor = s.next_port;
    for _ in 0..16000 {
        let cand = alloc_port(&mut cursor, s.port_stride);
        let tcp_taken = s.tcp_conns.values().any(|st| {
            matches!(
                s.sockets.get::<tcp::Socket>(st.handle).local_endpoint(),
                Some(ep) if ep.port == cand
            )
        });
        if tcp_taken {
            continue;
        }
        let udp_taken = s
            .udp_conns
            .values()
            .any(|st| s.sockets.get::<udp::Socket>(st.handle).endpoint().port == cand);
        if udp_taken {
            continue;
        }
        return Some(cand);
    }
    None
}

async fn run(
    mut s: NetStack,
    mut cmd_rx: mpsc::Receiver<Cmd>,
    mut data_in_rx: mpsc::Receiver<DataIn>,
    mut inbound_rx: mpsc::Receiver<Vec<u8>>,
    outbound_tx: mpsc::Sender<Vec<u8>>,
) -> Result<()> {
    loop {
        let now = Instant::now();
        let poll_outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            s.iface.poll(now, &mut s.device, &mut s.sockets);
        }));
        if poll_outcome.is_err() {
            // L4 fix: don't silently swallow a smoltcp poll panic; surface it so the
            // recovery (dropping the in-flight rx/tx buffers) is visible in logs.
            log::error!(
                "[netstack] smoltcp poll panicked; dropping in-flight rx/tx buffers and continuing"
            );
            s.device.rx.clear();
            s.device.rx_bytes = 0;
            s.device.tx.clear();
        }
        for (name, svc) in [
            ("service_tcp", 0u8),
            ("service_udp", 1),
            ("flush_tx", 2),
        ] {
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| match svc {
                0 => {
                    service_tcp(&mut s);
                }
                1 => {
                    service_udp(&mut s);
                }
                _ => {
                    flush_tx(&mut s, &outbound_tx);
                }
            }));
            if outcome.is_err() {
                log::error!("[netstack] {name} panicked; dropping in-flight rx/tx buffers and continuing");
                s.device.rx.clear();
                s.device.rx_bytes = 0;
                s.device.tx.clear();
            }
        }

        let delay = s
            .iface
            .poll_delay(Instant::now(), &s.sockets)
            .map(|d| std::time::Duration::from_micros(d.total_micros()));

        tokio::select! {
            maybe = inbound_rx.recv() => {
                match maybe {
                    Some(pkt) => {
                        s.device.push_ingress(pkt);
                        drain_backlog(&mut s, &mut cmd_rx, &mut data_in_rx, &mut inbound_rx);
                    }
                    None => return Ok(()),
                }
            }

            maybe = cmd_rx.recv() => {
                match maybe {
                    Some(cmd) => {
                        guard_cmd(&mut s, cmd);
                        drain_backlog(&mut s, &mut cmd_rx, &mut data_in_rx, &mut inbound_rx);
                    }
                    None => return Ok(()),
                }
            }

            maybe = data_in_rx.recv() => {
                if let Some(d) = maybe {
                    guard_data(&mut s, d);
                    drain_backlog(&mut s, &mut cmd_rx, &mut data_in_rx, &mut inbound_rx);
                } else {
                    return Ok(());
                }
            }

            _ = sleep_opt(delay) => {}
        }
    }
}

/// Round-robin the channels' backlog after any wakeup.
///
/// Each source is capped per pass and every pass restarts from the top, so a
/// flood on one class (the peer pushing ingress at us, or a client blasting
/// writes) cannot starve the other two. Without this, a `biased;` select let
/// the always-ready inbound arm win every iteration: `open_tcp` from a new tab
/// then waits out the browser connection storm instead of the ~ms it should.
fn drain_backlog(
    s: &mut NetStack,
    cmd_rx: &mut mpsc::Receiver<Cmd>,
    data_in_rx: &mut mpsc::Receiver<DataIn>,
    inbound_rx: &mut mpsc::Receiver<Vec<u8>>,
) {
    let (mut ing, mut cm, mut ad) = (0usize, 0usize, 0usize);
    loop {
        let mut progressed = false;

        if ing < MAX_INGEST_PER_TICK {
            if let Ok(pkt) = inbound_rx.try_recv() {
                s.device.push_ingress(pkt);
                ing += 1;
                progressed = true;
            }
        }
        if cm < MAX_CMDS_PER_TICK {
            if let Ok(cmd) = cmd_rx.try_recv() {
                guard_cmd(s, cmd);
                cm += 1;
                progressed = true;
            }
        }
        if ad < MAX_APPDATA_PER_TICK {
            if let Ok(d) = data_in_rx.try_recv() {
                guard_data(s, d);
                ad += 1;
                progressed = true;
            }
        }
        if !progressed {
            return;
        }
    }
}

/// `handle_cmd` touches every socket handle the app knows about; a panic there
/// previously aborted the whole netstack task (and with it every tunnel)
/// because only `iface.poll` was wrapped. A dropped responder is a clean
/// `Err` at the caller, so containing here is strictly better than dying.
fn guard_cmd(s: &mut NetStack, cmd: Cmd) {
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        handle_cmd(s, cmd);
    }));
    if outcome.is_err() {
        log::error!("[netstack] handle_cmd panicked; dropping in-flight rx buffers and continuing");
        s.device.rx.clear();
        s.device.rx_bytes = 0;
    }
}

fn guard_data(s: &mut NetStack, d: DataIn) {
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        handle_data(s, d);
    }));
    if outcome.is_err() {
        log::error!("[netstack] handle_data panicked; dropping in-flight rx buffers and continuing");
        s.device.rx.clear();
        s.device.rx_bytes = 0;
    }
}

async fn sleep_opt(delay: Option<std::time::Duration>) {
    match delay {
        Some(d) => tokio::time::sleep(d).await,
        None => std::future::pending::<()>().await,
    }
}

fn handle_cmd(s: &mut NetStack, cmd: Cmd) {
    match cmd {
        Cmd::OpenTcp { dst, resp } => {
            if s.tcp_conns.len() >= MAX_TCP_CONNECTIONS {
                let _ = resp.send(Err("too many TCP connections".into()));
                return;
            }
            let rx_buf = tcp::SocketBuffer::new(vec![0u8; TCP_BUF]);
            let tx_buf = tcp::SocketBuffer::new(vec![0u8; TCP_BUF]);
            let mut socket = tcp::Socket::new(rx_buf, tx_buf);
            socket.set_nagle_enabled(false);
            // H2 fix: without a connect timeout a SYN to a black-holed address
            // sits in SynSent forever (smoltcp retransmits indefinitely), leaking
            // 1MB of buffers + a connection slot per attempt until
            // MAX_TCP_CONNECTIONS exhausts and the proxy dies permanently.
            // On expiry smoltcp aborts the socket -> State::Closed, which the
            // service loop already maps to "connection refused" for the caller.
            socket.set_timeout(Some(smoltcp::time::Duration::from_secs(10)));

            let local_port = match alloc_unique_port(s) {
                Some(p) => {
                    s.next_port = next_ephemeral(p, s.port_stride);
                    p
                }
                None => {
                    let _ = resp.send(Err("no free local ports".into()));
                    return;
                }
            };
            let remote = to_ip_endpoint(dst);

            if let Err(e) = socket.connect(s.iface.context(), remote, local_port) {
                let _ = resp.send(Err(format!("connect: {e:?}")));
                return;
            }

            let handle = s.sockets.add(socket);
            let id = s.next_id;
            s.next_id += 1;

            let (to_app_tx, to_app_rx) = mpsc::channel(APP_QUEUE);

            s.tcp_conns.insert(
                id,
                TcpState {
                    handle,
                    to_app: to_app_tx,
                    from_stack_rx: Some(to_app_rx),
                    connect_resp: Some(resp),
                    pending: Vec::new(),
                    established: false,
                    half_closed: false,
                    dead: Arc::new(AtomicBool::new(false)),
                },
            );
        }
        Cmd::OpenUdp { resp } => {
            if s.udp_conns.len() >= MAX_UDP_CONNECTIONS {
                let _ = resp.send(Err("too many UDP associations".into()));
                return;
            }
            let rx_meta = vec![udp::PacketMetadata::EMPTY; UDP_META];
            let tx_meta = vec![udp::PacketMetadata::EMPTY; UDP_META];
            let rx_buf = udp::PacketBuffer::new(rx_meta, vec![0u8; UDP_BUF]);
            let tx_buf = udp::PacketBuffer::new(tx_meta, vec![0u8; UDP_BUF]);
            let mut socket = udp::Socket::new(rx_buf, tx_buf);

            let local_port = match alloc_unique_port(s) {
                Some(p) => {
                    s.next_port = next_ephemeral(p, s.port_stride);
                    p
                }
                None => {
                    let _ = resp.send(Err("no free local ports".into()));
                    return;
                }
            };
            if let Err(e) = socket.bind(local_port) {
                let _ = resp.send(Err(format!("bind: {e:?}")));
                return;
            }

            let handle = s.sockets.add(socket);
            let id = s.next_id;
            s.next_id += 1;

            let (to_app_tx, to_app_rx) = mpsc::channel(APP_QUEUE);
            s.udp_conns.insert(id, UdpState { handle, to_app: to_app_tx });

            let conn = UdpConn {
                id,
                from_stack: to_app_rx,
                data_in: s.data_in_tx.clone(),
            };
            let _ = resp.send(Ok(conn));
        }
        Cmd::SetAddrs { v4, v6 } => {
            apply_addrs(&mut s.iface, v4, v6);
            log::info!("netstack addresses synchronized from edge capsule");
        }
    }
}

fn handle_data(s: &mut NetStack, d: DataIn) {
    match d {
        DataIn::Tcp(id, data) => {
            if let Some(st) = s.tcp_conns.get_mut(&id) {
                if st.pending.len().saturating_add(data.len()) > MAX_PENDING_PER_CONN {
                    log::warn!("netstack TCP {id} exceeded pending-data limit; closing");
                    st.half_closed = true;
                    st.dead.store(true, Ordering::Relaxed);
                } else {
                    st.pending.extend_from_slice(&data);
                }
            }
        }
        DataIn::TcpClose(id) => {
            if let Some(st) = s.tcp_conns.get_mut(&id) {
                st.half_closed = true;
            }
        }
        DataIn::Udp(id, dst, data) => {
            if let Some(st) = s.udp_conns.get(&id) {
                let sock = s.sockets.get_mut::<udp::Socket>(st.handle);
                let _ = sock.send_slice(&data, to_ip_endpoint(dst));
            }
        }
        DataIn::UdpClose(id) => {
            if let Some(st) = s.udp_conns.remove(&id) {
                s.sockets.remove(st.handle);
            }
        }
    }
}

fn service_tcp(s: &mut NetStack) {
    let ids: Vec<usize> = s.tcp_conns.keys().copied().collect();

    for id in ids {
        let handle = match s.tcp_conns.get(&id) {
            Some(st) => st.handle,
            None => continue,
        };

        let state = s.sockets.get_mut::<tcp::Socket>(handle).state();
        let data_in_tx = s.data_in_tx.clone();

        if !s.tcp_conns[&id].established && state == tcp::State::Established {
            // The 10 s timeout armed at connect is *also* smoltcp's inactivity
            // abort (`timed_out` compares remote_last_ts + timeout), so leaving
            // it armed killed every SSH / IMAP / long-poll / WebSocket / DB /
            // HTTP keep-alive session that went quiet for 10 s. Widen the abort
            // and start probing: a live idle peer's ACK refreshes
            // remote_last_ts, a dead peer stops answering and is reaped ~75 s.
            // `set_timeout(None)` was rejected — it leaves the stack unsupervised.
            {
                let sock = s.sockets.get_mut::<tcp::Socket>(handle);
                sock.set_timeout(Some(smoltcp::time::Duration::from_secs(75)));
                sock.set_keep_alive(Some(smoltcp::time::Duration::from_secs(15)));
            }
            if let Some(st) = s.tcp_conns.get_mut(&id) {
                st.established = true;
                if let (Some(resp), Some(rx)) = (st.connect_resp.take(), st.from_stack_rx.take()) {
                    let conn = TcpConn {
                        dead: s.tcp_conns[&id].dead.clone(),
                        id,
                        from_stack: rx,
                        data_in: data_in_tx.clone(),
                    };
                    let _ = resp.send(Ok(conn));
                }
            }
        }

        if !s.tcp_conns[&id].established
            && matches!(state, tcp::State::Closed | tcp::State::TimeWait)
        {
            if let Some(st) = s.tcp_conns.get_mut(&id) {
                if let Some(resp) = st.connect_resp.take() {
                    let _ = resp.send(Err("connection refused".into()));
                }
            }
            s.sockets.remove(handle);
            if let Some(st) = s.tcp_conns.remove(&id) {
                st.dead.store(true, Ordering::Relaxed);
            }
            continue;
        }

        {
            if let Some(st) = s.tcp_conns.get_mut(&id) {
                if !st.pending.is_empty() {
                    let socket = s.sockets.get_mut::<tcp::Socket>(handle);
                    if socket.can_send() {
                        let sent = socket.send_slice(&st.pending).unwrap_or(0);
                        if sent > 0 {
                            st.pending.drain(0..sent);
                        }
                    }
                }
            }
        }

        {
            let pending_empty = s.tcp_conns[&id].pending.is_empty();
            let half = s.tcp_conns[&id].half_closed;
            if half && pending_empty {
                s.sockets.get_mut::<tcp::Socket>(handle).close();
            }
        }

        // Critical: never `.await` on to_app here. Awaiting stalls the entire netstack
        // (including TCP ACK generation for other sockets) and kills download speed.
        // Leave unread bytes in smoltcp when the app channel is full — natural backpressure.
        let to_app = s.tcp_conns[&id].to_app.clone();
        if to_app.capacity() == 0 {
            continue;
        }
        let mut app_gone = false;
        {
            let socket = s.sockets.get_mut::<tcp::Socket>(handle);
            let mut n = 0;
            while socket.can_recv() && n < MAX_RECV_CHUNKS {
                if to_app.capacity() == 0 {
                    break;
                }
                match socket.recv(|buf| {
                    let v = buf.to_vec();
                    (v.len(), v)
                }) {
                    Ok(v) if !v.is_empty() => match to_app.try_send(v) {
                        Ok(()) => n += 1,
                        Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => break,
                        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                            app_gone = true;
                            break;
                        }
                    },
                    _ => break,
                }
            }
        }
        if app_gone {
            s.sockets.get_mut::<tcp::Socket>(handle).close();
        }

        let st_state = s.sockets.get_mut::<tcp::Socket>(handle).state();
        if matches!(st_state, tcp::State::CloseWait) {
            s.sockets.get_mut::<tcp::Socket>(handle).close();
        }
        if matches!(st_state, tcp::State::Closed) && s.tcp_conns[&id].established {
            s.sockets.remove(handle);
            if let Some(st) = s.tcp_conns.remove(&id) {
                st.dead.store(true, Ordering::Relaxed);
            }
        }
    }
}

fn service_udp(s: &mut NetStack) {
    let ids: Vec<usize> = s.udp_conns.keys().copied().collect();

    for id in ids {
        let handle = match s.udp_conns.get(&id) {
            Some(st) => st.handle,
            None => continue,
        };

        let to_app = s.udp_conns[&id].to_app.clone();
        if to_app.capacity() == 0 {
            continue;
        }
        {
            let socket = s.sockets.get_mut::<udp::Socket>(handle);
            let mut n = 0;
            while socket.can_recv() && n < MAX_RECV_CHUNKS && to_app.capacity() > 0 {
                match socket.recv() {
                    Ok((data, meta)) => {
                        let p = (endpoint_to_socketaddr(meta.endpoint), data.to_vec());
                        match to_app.try_send(p) {
                            Ok(()) => n += 1,
                            Err(_) => break,
                        }
                    }
                    Err(_) => break,
                }
            }
        }
    }
}

fn flush_tx(s: &mut NetStack, outbound_tx: &mpsc::Sender<Vec<u8>>) {
    // Strict FIFO. The previous version sent every frame <= 128 bytes ahead of
    // larger deferred ones so TCP ACKs could not starve — but size cannot
    // distinguish a pure ACK from a small PSH data segment (an SSH keystroke, a
    // short HTTP request), so a later small frame overtook an earlier 1448-byte
    // segment *on the same connection*: receiver reordering, duplicate ACKs and
    // spurious fast-retransmit / reorder-timeout. `specs/004` FR-001 was marked
    // fixed by a test using four identical 200-byte packets, which cannot
    // observe the inversion.
    //
    // ACK latency is already bounded structurally: `socket_egress` emits at most
    // one packet per socket per poll, and TX_RING caps how long a frame waits.
    while let Some(pkt) = s.device.tx.pop_front() {
        match outbound_tx.try_send(pkt) {
            Ok(()) => {}
            Err(tokio::sync::mpsc::error::TrySendError::Full(pkt)) => {
                // Head-of-queue restore, then stop: order is preserved and the
                // next poll retries the same frame.
                s.device.tx.push_front(pkt);
                return;
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => return,
        }
    }
}

#[cfg(test)]
mod tests {
    use tokio::sync::mpsc::error::TryRecvError;

    /// A discarded flow must stop acknowledging writes as if they were sent:
    /// an over-budget burst used to be dropped while `send()` still said `Ok`.
    #[tokio::test]
    async fn writing_to_a_dead_flow_reports_an_error() {
        let (tx, mut rx) = mpsc::channel(4);
        let dead = Arc::new(AtomicBool::new(false));
        let conn = TcpConn {
            id: 3,
            from_stack: mpsc::channel(1).1,
            data_in: tx,
            dead: dead.clone(),
        };
        let (sender, _rx) = conn.into_split();

        sender.send(vec![1]).await.expect("live flow accepts data");
        assert!(matches!(rx.recv().await, Some(DataIn::Tcp(3, _))));

        dead.store(true, Ordering::Relaxed);
        assert!(
            sender.send(vec![2]).await.is_err(),
            "a dead flow reported the write as successful"
        );
        assert!(matches!(rx.try_recv(), Err(TryRecvError::Empty)));
    }

    /// The resolver's clone of a UDP sender must not tear down the association
    /// it was cloned from: only the last handle may close it.
    #[tokio::test]
    async fn last_udp_sender_handle_closes_the_association() {
        let (tx, mut rx) = mpsc::channel(4);
        let sender = UdpSender::new(7, tx);
        let clone = sender.clone();
        drop(clone);
        assert!(
            matches!(rx.try_recv(), Err(TryRecvError::Empty)),
            "a cloned sender closed a live association"
        );
        drop(sender);
        assert!(matches!(rx.try_recv(), Ok(DataIn::UdpClose(7))));
    }

    use super::*;

    #[tokio::test]
    async fn netstack_queue_preserves_fifo_order_on_congestion() {
        // Channel with capacity 1 to simulate buffer backpressure
        let (tx, mut rx) = mpsc::channel(1);

        let mut device = StackDevice::new(1500);
        // Push 4 large packets (> 128 bytes) in known order
        let p1 = vec![1u8; 200];
        let p2 = vec![2u8; 200];
        let p3 = vec![3u8; 200];
        let p4 = vec![4u8; 200];

        device.tx.push_back(p1.clone());
        device.tx.push_back(p2.clone());
        device.tx.push_back(p3.clone());
        device.tx.push_back(p4.clone());

        let config = Config::new(HardwareAddress::Ip);
        let iface = Interface::new(config, &mut device, Instant::now());
        let (data_in_tx, _data_in_rx) = mpsc::channel(1);

        let mut stack = NetStack {
            iface,
            device,
            sockets: SocketSet::new(Vec::new()),
            tcp_conns: HashMap::new(),
            udp_conns: HashMap::new(),
            next_id: 1,
            next_port: port_seed().0,
            port_stride: port_seed().1,
            data_in_tx,
        };

        // First flush: tx has capacity 1, so p1 is sent, p2 encounters Full.
        // p2, p3, p4 must be re-queued in s.device.tx in EXACT order [p2, p3, p4].
        flush_tx(&mut stack, &tx);

        assert_eq!(rx.recv().await, Some(p1));
        assert_eq!(stack.device.tx.len(), 3);
        assert_eq!(stack.device.tx[0], p2);
        assert_eq!(stack.device.tx[1], p3);
        assert_eq!(stack.device.tx[2], p4);

        // Second flush: now channel is empty, p2 is sent, p3 hits full
        flush_tx(&mut stack, &tx);
        assert_eq!(rx.recv().await, Some(p2));
        assert_eq!(stack.device.tx.len(), 2);
        assert_eq!(stack.device.tx[0], p3);
        assert_eq!(stack.device.tx[1], p4);

        // Third flush
        flush_tx(&mut stack, &tx);
        assert_eq!(rx.recv().await, Some(p3));
        assert_eq!(stack.device.tx.len(), 1);
        assert_eq!(stack.device.tx[0], p4);

        // Fourth flush
        flush_tx(&mut stack, &tx);
        assert_eq!(rx.recv().await, Some(p4));
        assert!(stack.device.tx.is_empty());
    }

    /// The ACK-over-`specs/004` FR-001 fix was "verified" by a test that pushed
    /// four *identical-sized* packets — a shape the size-based reordering could
    /// not invert. Mixed sizes are what actually broke TCP.
    #[tokio::test]
    async fn fifo_survives_mixed_frame_sizes() {
        let (tx, mut rx) = mpsc::channel(1);
        let mut device = StackDevice::new(1500);

        // Two short frames interleave three full-MTU segments. Under the old
        // "send <=128B first" split, the 52B ACK overtook the pending 1448B
        // segment on the same connection.
        let frames: Vec<Vec<u8>> = vec![
            vec![0xAA; 1448],
            vec![0x02; 52],
            vec![0xBB; 1448],
            vec![0x03; 60],
            vec![0xCC; 1448],
        ];
        for f in &frames {
            device.tx.push_back(f.clone());
        }

        let config = Config::new(HardwareAddress::Ip);
        let iface = Interface::new(config, &mut device, Instant::now());
        let (data_in_tx, _data_in_rx) = mpsc::channel(1);
        let mut stack = NetStack {
            iface,
            device,
            sockets: SocketSet::new(Vec::new()),
            tcp_conns: HashMap::new(),
            udp_conns: HashMap::new(),
            next_id: 1,
            next_port: port_seed().0,
            port_stride: port_seed().1,
            data_in_tx,
        };

        let mut sent = Vec::new();
        for _ in 0..frames.len() {
            flush_tx(&mut stack, &tx);
            match rx.recv().await {
                Some(p) => sent.push(p),
                None => break,
            }
        }
        assert_eq!(
            sent.iter().map(|p| p.len()).collect::<Vec<_>>(),
            frames.iter().map(|p| p.len()).collect::<Vec<_>>(),
            "egress order must match ingress order regardless of frame size"
        );
        assert_eq!(sent, frames);
        assert!(stack.device.tx.is_empty());
    }

    /// The old ring was unbounded: a saturated tunnel plus a peer that kept
    /// advertising window turned memory growth into an allocator abort.
    #[test]
    fn transmit_ring_is_bounded_and_reports_backpressure() {
        let mut device = StackDevice::new(1500);
        let t = Instant::now();

        for i in 0..TX_RING * 3 {
            match device.transmit(t) {
                Some(tok) => tok.consume(64, |b| {
                    b[0] = (i & 0xff) as u8;
                }),
                None => break,
            }
        }

        assert_eq!(device.tx.len(), TX_RING, "ring must stop at TX_RING");
        assert!(
            device.tx_deferred > 0,
            "saturation must be observable, not indistinguishable from idle"
        );
        assert!(device.transmit(t).is_none());
    }

    /// Sequential ephemeral ports left DNS protected only by a 16-bit txid, and
    /// made a retry's source port free to guess.
    #[test]
    fn ephemeral_ports_are_scattered_and_cover_the_band() {
        let (mut cursor, stride) = seed_port_cursor();
        assert!(stride % 2 == 1, "stride must be odd to cover the band");
        assert!(stride >= 17);

        // alloc_port returns the *current* cursor, so the first value equals
        // the seed; start comparing from the second.
        let first = alloc_port(&mut cursor, stride);
        assert!((EPHEMERAL_BASE..=65535).contains(&first));

        let mut prev = first;
        let mut min_delta = u16::MAX;
        let mut seen = std::collections::HashSet::new();
        seen.insert(first);
        for _ in 0..(EPHEMERAL_SPAN - 1) {
            let port = alloc_port(&mut cursor, stride);
            assert!(
                (EPHEMERAL_BASE..=65535).contains(&port),
                "port {port} escaped the ephemeral band"
            );
            assert!(seen.insert(port), "cycle repeated after only {} ports", seen.len());
            min_delta = min_delta.min(port.wrapping_sub(prev));
            prev = port;
        }
        assert_eq!(seen.len(), EPHEMERAL_SPAN as usize, "did not cover the band");
        assert!(
            min_delta >= 17,
            "consecutive allocations differed by only {min_delta} — predictable"
        );
    }

    /// The inbound queue was unbounded and attacker-influenced: a peer that
    /// floods us while the poll loop is busy grew memory until the allocator
    /// aborted. Over the budget the frame must be dropped *and counted*.
    #[test]
    fn ingress_admission_is_bounded_and_counted() {
        let mut device = StackDevice::new(1500);
        let mut accepted = 0;
        for _ in 0..RX_RING * 2 {
            if device.push_ingress(vec![0u8; 1448]) {
                accepted += 1;
            }
        }
        assert_eq!(accepted, RX_RING, "admission ignored the frame cap");
        assert_eq!(device.rx.len(), RX_RING);
        assert_eq!(
            device.rx_dropped,
            (RX_RING * 2 - accepted) as u64,
            "drops must be visible, not silently swallowed"
        );

        // Draining frees the budget again.
        let token = device.receive(Instant::now()).map(|(r, _)| r);
        assert!(token.is_some());
        drop(token);
        assert!(device.push_ingress(vec![0u8; 64]));
    }
}
