use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Checksum, Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::{tcp, udp, AnySocket};
use smoltcp::time::{Duration, Instant};
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, Ipv4Address, Ipv6Address};
use tokio::sync::{mpsc, oneshot};

use crate::error::{AetherError, Result};

// Keep per-flow memory bounded. Large fixed buffers multiplied by browser connection
// counts caused multi-gigabyte growth and allocator aborts on desktop; the size of a
// new socket's buffers is now decided by the global admission budget below (T145).
const UDP_BUF: usize = 128 * 1024;
const UDP_META: usize = 128;
const APP_QUEUE: usize = 256;
/// Inbound frames copied out of the tunnel channel per wakeup.
///
/// This bounds the *handoff* from `inbound_rx` into `device.rx`; the ring itself
/// is separately capped at [`RX_RING`] frames / 8 MB by `push_ingress`, so the
/// channel can never be drained into an unbounded queue. It is deliberately
/// larger than [`MAX_INGRESS_PER_TICK`]: the two are different knobs, and the
/// one that matters for latency is the smaller.
const MAX_INGEST_PER_TICK: usize = 256;
const MAX_CMDS_PER_TICK: usize = 64;
/// App-side writes per pass. Higher than the command budget because one flow
/// bursts many writes per command it was opened with, but still bounded so a
/// single client blasting uploads cannot keep the loop away from `iface.poll`
/// (T147).
const MAX_APPDATA_PER_TICK: usize = 128;
const MAX_RECV_CHUNKS: usize = 64;
const MAX_PENDING_PER_CONN: usize = 512 * 1024;

/// Global admission budget for socket buffers (T145).
///
/// Buffers used to be allocated eagerly at a fixed size per socket, so the
/// advertised ceiling was `512 sockets x 2 x 1 MB` = 1 GB. That kills an 8 GB
/// laptop — and any Android device — long before `MAX_TCP_*` is a useful limit,
/// and it kills it in the allocator rather than in a refusal the client can see.
/// The budget is charged per socket and released with it, and it decides the
/// *size* of the next flow's buffers: a connection is degraded before it is
/// refused, and refused only once there is no pair left worth having.
const MEM_BUDGET_TOTAL: usize = 128 * 1024 * 1024;
/// While at least this much of the budget is still uncommitted a new flow gets
/// full-size buffers; below it, every flow gets the degraded pair.
const MEM_BUDGET_HEADROOM: usize = 16 * 1024 * 1024;
const TCP_RX_FULL: usize = 1024 * 1024;
const TCP_TX_FULL: usize = 256 * 1024;
const TCP_RX_LOW: usize = 128 * 1024;
const TCP_TX_LOW: usize = 64 * 1024;
/// The smallest TCP pair worth admitting: below this the socket cannot hold an
/// MSS in one direction and a window in the other, so the flow is refused
/// explicitly instead of silently crawling.
const TCP_MIN_PAIR: usize = TCP_RX_LOW + TCP_TX_LOW;
/// One UDP association's footprint: `UDP_BUF` in each direction, unchanged from
/// before the budget existed — datagrams are capped by the MTU, so shrinking the
/// buffer would only drop traffic rather than throttle it.
const UDP_PAIR: usize = UDP_BUF * 2;

/// The buffer pair a new TCP flow is granted for the memory already committed.
///
/// Pure — the tiers, the headroom rule and the refusal are all reachable from a
/// unit test without opening 512 sockets.
fn tcp_admission(reserved: usize) -> Option<(usize, usize)> {
    let free = MEM_BUDGET_TOTAL.saturating_sub(reserved);
    if free >= MEM_BUDGET_HEADROOM {
        Some((TCP_RX_FULL, TCP_TX_FULL))
    } else if free >= TCP_MIN_PAIR {
        Some((TCP_RX_LOW, TCP_TX_LOW))
    } else {
        None
    }
}

/// UDP is admitted whole or not at all; see [`tcp_admission`].
fn udp_admission(reserved: usize) -> Option<usize> {
    if MEM_BUDGET_TOTAL.saturating_sub(reserved) >= UDP_PAIR {
        Some(UDP_BUF)
    } else {
        None
    }
}

// Per-class socket budgets (T137/T149).
//
// Proxy traffic and the engine's own DNS lookups used to share one 128-entry
// pool, so a browser that opened every UDP association (trivial with WebRTC /
// QUIC) starved the resolver — and because every domain `CONNECT` is resolved
// through that same path, exhausting the UDP pool took down *all* proxying, not
// just UDP. Splitting the budget means the worst a client can do to name
// resolution is consume the proxy class, which the resolver cannot.
//
// The totals match the old single-pool caps, so per-flow memory is unchanged.
// They are public because the budgets are user-visible limits: the UI and the
// tests both need to say what "too many associations" means.
pub const MAX_UDP_PROXY: usize = 96;
pub const MAX_UDP_RESOLVER: usize = 32;
pub const MAX_TCP_PROXY: usize = 480;
pub const MAX_TCP_RESOLVER: usize = 32;

/// TCP inactivity abort while still connecting (H2): a SYN into a black hole
/// must not sit in `SynSent` forever holding 1 MB of buffers and a slot.
const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// TCP inactivity abort once Established.
///
/// smoltcp's `timed_out` is `timestamp >= remote_last_ts + timeout`
/// (`socket/tcp.rs:2118`), i.e. the *connect* timeout doubled as an idle killer
/// and cut every quiet SSH / IMAP / long-poll / WebSocket / keep-alive session
/// at 10 s. Widening alone would leave a dead peer unsupervised for minutes, so
/// it is paired with a real keep-alive below: 75 s > 4 x 15 s means four probes
/// go unanswered before a flow is reaped.
const TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(75);
/// Idle interval after which smoltcp emits a 1-byte probe at `seq - 1`
/// (`socket/tcp.rs:2449`); a live peer ACKs it, which refreshes
/// `remote_last_ts` and keeps the flow alive indefinitely.
const TCP_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);

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

/// Extra room past `TX_RING` for the transmit token paired with an ingress
/// frame.
///
/// `transmit()` refuses at `TX_RING` so bulk data cannot outrun the tunnel, but
/// a TCP *reply* must not be dropped: `ack_reply` moves `remote_last_ack`
/// forward eagerly and a lost ACK is not regenerated until new data or a window
/// update arrives. So the token `receive()` hands back may go a bounded distance
/// past the ring, which keeps the whole queue at `TX_RING + 32` frames maximum
/// and makes "the ring is full" observable instead of a growing `VecDeque`.
const TX_EGRESS_SLACK: usize = 32;

type OpenTcpResp = oneshot::Sender<std::result::Result<TcpConn, String>>;
type OpenUdpResp = oneshot::Sender<std::result::Result<UdpConn, String>>;

/// Which socket budget a flow draws from. See `MAX_*_PROXY` / `MAX_*_RESOLVER`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SocketClass {
    /// Client traffic relayed through the SOCKS / HTTP proxies.
    Proxy,
    /// The engine's own lookups, which must keep working while the proxy is at
    /// its limit.
    Resolver,
}

impl SocketClass {
    fn for_resolver(resolver: bool) -> Self {
        if resolver {
            SocketClass::Resolver
        } else {
            SocketClass::Proxy
        }
    }

    fn tcp_cap(self) -> usize {
        match self {
            SocketClass::Proxy => MAX_TCP_PROXY,
            SocketClass::Resolver => MAX_TCP_RESOLVER,
        }
    }

    fn udp_cap(self) -> usize {
        match self {
            SocketClass::Proxy => MAX_UDP_PROXY,
            SocketClass::Resolver => MAX_UDP_RESOLVER,
        }
    }

    fn label(self) -> &'static str {
        match self {
            SocketClass::Proxy => "proxy",
            SocketClass::Resolver => "resolver",
        }
    }
}

/// Ingress frames serviced per loop iteration before egress gets a pass.
///
/// This is the bound behind the "bounded ingress" claim in `c151591`: it caps
/// how many frames smoltcp will *process* per tick, and therefore how long one
/// tick can hold `poll_egress`, the socket services and `flush_tx` off. The
/// channel-to-ring handoff above (`MAX_INGEST_PER_TICK`) is a different, looser
/// limit — moving a `Vec<u8>` between two queues costs far less than running it
/// through the TCP state machine, which is why one is 256 and this is 32.
const MAX_INGRESS_PER_TICK: usize = 32;
/// Floor for the "nothing to wait for" case while frames are still queued.
const MIN_POLL_DELAY: std::time::Duration = std::time::Duration::from_micros(250);

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
    /// Hard ceiling for this token; `TX_RING` for bulk egress, `TX_RING +
    /// TX_EGRESS_SLACK` for the reply token paired with an ingress frame.
    cap: usize,
    deferred: &'a mut u64,
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
        // Past the cap the frame is dropped and *counted*. For bulk egress the
        // cap equals `TX_RING`, which `transmit()` already refuses up front, so
        // this arm is unreachable there; for the paired reply token it can only
        // be reached after `TX_EGRESS_SLACK` ACKs queued on top of a full ring —
        // a state where the tunnel is behind anyway and TCP recovers by
        // retransmit. The alternative was an unbounded queue.
        if self.queue.len() < self.cap {
            self.queue.push_back(buf);
        } else {
            *self.deferred += 1;
        }
        r
    }
}

impl Device for StackDevice {
    type RxToken<'a> = StackRxToken;
    type TxToken<'a> = StackTxToken<'a>;

    fn receive(&mut self, _t: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let pkt = self.rx.pop_front()?;
        self.rx_bytes = self.rx_bytes.saturating_sub(pkt.len());
        // The token paired with an ingress packet is deliberately *not* capped
        // at TX_RING: dropping an ACK is unsafe, because `ack_reply` updates
        // remote_last_ack eagerly and a lost reply is not regenerated until new
        // data or a window update arrives — whereas a refused egress segment is
        // simply retried. It is capped at TX_RING + TX_EGRESS_SLACK so a burst
        // of replies still cannot grow the queue without limit.
        Some((
            StackRxToken(pkt),
            StackTxToken {
                queue: &mut self.tx,
                cap: TX_RING + TX_EGRESS_SLACK,
                deferred: &mut self.tx_deferred,
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
            cap: TX_RING,
            deferred: &mut self.tx_deferred,
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
    /// Open a TCP flow to `dst`.
    ///
    /// `resolver` selects the socket budget (see `SocketClass`): internal name
    /// lookups must not compete with, and must not be starved by, client traffic.
    OpenTcp {
        dst: SocketAddr,
        resp: OpenTcpResp,
        resolver: bool,
    },
    OpenUdp {
        resp: OpenUdpResp,
        resolver: bool,
    },
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
    /// The netstack *task* itself, kept so a supervisor can tell "one command
    /// panicked and was contained" apart from "the task is gone". Only the
    /// latter is a restart condition; restarting the stack for a contained panic
    /// would kill every other flow on the tunnel (T148).
    task: Arc<tokio::task::JoinHandle<Result<()>>>,
}

impl StackHandle {
    pub async fn open_tcp(&self, dst: SocketAddr) -> Result<TcpConn> {
        self.open_tcp_class(dst, SocketClass::Proxy).await
    }

    /// Open a TCP flow against the resolver budget: a name lookup or a health
    /// probe must still get a socket when the proxy budget is full.
    pub async fn open_tcp_resolver(&self, dst: SocketAddr) -> Result<TcpConn> {
        self.open_tcp_class(dst, SocketClass::Resolver).await
    }

    async fn open_tcp_class(&self, dst: SocketAddr, class: SocketClass) -> Result<TcpConn> {
        let (resp_tx, resp_rx) = oneshot::channel();
        self.cmd_tx
            .send(Cmd::OpenTcp {
                dst,
                resp: resp_tx,
                resolver: class == SocketClass::Resolver,
            })
            .await
            .map_err(|_| AetherError::Other("netstack closed".into()))?;
        resp_rx
            .await
            .map_err(|_| AetherError::Other("netstack dropped".into()))?
            .map_err(AetherError::Other)
    }

    pub async fn open_udp(&self) -> Result<UdpConn> {
        self.open_udp_class(SocketClass::Proxy).await
    }

    /// Open a UDP association against the resolver budget (see
    /// `open_tcp_resolver`): this is what keeps `dns_resolve` working when a
    /// client has saturated its own association pool.
    pub async fn open_udp_resolver(&self) -> Result<UdpConn> {
        self.open_udp_class(SocketClass::Resolver).await
    }

    async fn open_udp_class(&self, class: SocketClass) -> Result<UdpConn> {
        let (resp_tx, resp_rx) = oneshot::channel();
        self.cmd_tx
            .send(Cmd::OpenUdp {
                resp: resp_tx,
                resolver: class == SocketClass::Resolver,
            })
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

    /// False only once the netstack task has actually returned — a contained
    /// panic inside `run` never finishes the task, so this cannot be used to
    /// justify tearing down live flows.
    pub fn task_alive(&self) -> bool {
        !self.task.is_finished()
    }
}

struct TcpState {
    handle: SocketHandle,
    /// Budget this flow was admitted against; see `SocketClass`.
    class: SocketClass,
    /// Buffer bytes this flow is charged to the global admission budget;
    /// released when the entry goes, whatever path removed it (T145).
    reserved: usize,
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
    /// Budget this association was admitted against; see `SocketClass`.
    class: SocketClass,
    /// Buffer bytes charged to the global admission budget (T145).
    reserved: usize,
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
    /// Buffer bytes currently committed to live sockets (T145); see
    /// [`tcp_admission`] for what a new flow may take from it.
    mem_reserved: usize,
    data_in_tx: mpsc::Sender<DataIn>,
}

/// Checked `tcp::Socket` access.
///
/// `SocketSet::get`/`get_mut` **panic** when a handle is stale or points at the
/// other socket type (`iface/socket_set.rs:98-130`), and a stale handle is an
/// ordinary outcome here: smoltcp retires sockets on its own timers while the
/// app-side entry still has a queued write or a pending connect reply. Every
/// access in this module therefore goes through these accessors and gets `None`,
/// so no code path depends on `catch_unwind` to stay alive.
fn with_tcp<'s, R>(
    sockets: &mut SocketSet<'s>,
    handle: SocketHandle,
    f: impl FnOnce(&mut tcp::Socket<'s>) -> R,
) -> Option<R> {
    for (h, sock) in sockets.iter_mut() {
        if h == handle {
            return tcp::Socket::downcast_mut(sock).map(f);
        }
    }
    None
}

/// Checked `udp::Socket` access; see [`with_tcp`].
fn with_udp<'s, R>(
    sockets: &mut SocketSet<'s>,
    handle: SocketHandle,
    f: impl FnOnce(&mut udp::Socket<'s>) -> R,
) -> Option<R> {
    for (h, sock) in sockets.iter_mut() {
        if h == handle {
            return udp::Socket::downcast_mut(sock).map(f);
        }
    }
    None
}

/// Remove a socket from the set, reporting whether one was there.
///
/// `SocketSet::remove` panics on a stale handle, and the close paths below run
/// from app-driven messages that can race smoltcp's own retirement of a socket.
fn remove_socket(sockets: &mut SocketSet<'_>, handle: SocketHandle) -> bool {
    if sockets.iter().any(|(h, _)| h == handle) {
        let _ = sockets.remove(handle);
        return true;
    }
    false
}

impl NetStack {
    /// Live TCP flows in one budget class.
    ///
    /// Counted from the maps rather than kept in a counter: an admit/remove pair
    /// that must stay balanced across five removal paths is exactly how the old
    /// single pool leaked slots, and `count()` over at most 512 entries is noise
    /// next to the 1 MB of buffers each admission allocates.
    fn tcp_in_class(&self, class: SocketClass) -> usize {
        self.tcp_conns.values().filter(|st| st.class == class).count()
    }

    /// Live UDP associations in one budget class; see [`Self::tcp_in_class`].
    fn udp_in_class(&self, class: SocketClass) -> usize {
        self.udp_conns.values().filter(|st| st.class == class).count()
    }
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

    // Monotonic clock for every timestamp handed to smoltcp; see `stack_now`.
    let clock_base = std::time::Instant::now();

    let config = Config::new(HardwareAddress::Ip);
    let mut iface = Interface::new(config, &mut device, stack_now(clock_base));

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
        mem_reserved: 0,
        data_in_tx: data_in_tx.clone(),
    };

    let task = tokio::spawn(run(
        stack,
        clock_base,
        cmd_rx,
        data_in_rx,
        inbound_rx,
        outbound_tx,
    ));

    Ok(StackHandle {
        cmd_tx,
        task: Arc::new(task),
    })
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

/// Every local port a live socket holds right now.
///
/// Read from the socket set in one pass instead of per candidate via
/// `sockets.get::<T>(handle)`: that lookup panics on a stale handle, and it ran
/// once per candidate port per live socket. A socket that is not bound yet has
/// no port to reserve, so the snapshot cannot be raced by our own admission.
fn live_local_ports(sockets: &SocketSet<'_>) -> HashSet<u16> {
    let mut ports = HashSet::new();
    for (_handle, sock) in sockets.iter() {
        if let Some(tcp_sock) = tcp::Socket::downcast(sock) {
            if let Some(ep) = tcp_sock.local_endpoint() {
                ports.insert(ep.port);
            }
        } else if let Some(udp_sock) = udp::Socket::downcast(sock) {
            let port = udp_sock.endpoint().port;
            if port != 0 {
                ports.insert(port);
            }
        }
    }
    ports
}

/// First port on the `start`/`stride` cycle that nothing is holding.
fn pick_free_port(taken: &HashSet<u16>, start: u16, stride: u16) -> Option<u16> {
    let mut cursor = start;
    for _ in 0..EPHEMERAL_SPAN {
        let cand = alloc_port(&mut cursor, stride);
        if !taken.contains(&cand) {
            return Some(cand);
        }
    }
    None
}

/// L-fix: pick the next ephemeral port that no live TCP/UDP socket is bound to.
/// The old wrap-around counter could hand a duplicate local port to a second
/// socket once ~16k flows opened, silently breaking both flows (responses became
/// ambiguous inside smoltcp).
fn alloc_unique_port(s: &NetStack) -> Option<u16> {
    pick_free_port(&live_local_ports(&s.sockets), s.next_port, s.port_stride)
}


/// Destinations the tunnel must never reach, whatever a web page asks for.
///
/// A local HTTP/SOCKS proxy is an amplification point: a browser can make it
/// connect anywhere, including the machine it runs on. That is how a proxy
/// becomes a loopback port scanner, a way to read the cloud instance metadata
/// service over `169.254.169.254`, and a route into carrier-grade-NAT
/// infrastructure. Checking here rather than in each proxy is deliberate: this
/// is the one place every tunnel flow passes through, and it sees the
/// *post-resolution* address, so a DNS record pointing at an internal host
/// cannot rebind past a name check.
pub fn forbidden_destination(ip: IpAddr) -> Option<&'static str> {
    let blocked_lan = crate::runtime_env::flag("AETHER_BLOCK_LAN_TARGETS");
    match ip {
        IpAddr::V4(v4) => forbidden_v4(v4, blocked_lan),
        IpAddr::V6(v6) => {
            if v6.is_loopback() {
                return Some("loopback (::1)");
            }
            if v6.is_unspecified() {
                return Some("unspecified (::)");
            }
            // A v6 literal can carry a v4 destination inside it. Routing sends
            // those to the same hosts, so every IPv4 rule has to be applied to
            // the embedded address: before this, `::ffff:169.254.169.254` read
            // the instance metadata service through the one check that claims
            // to be un-walk-aroundable.
            if let Some(inner) = embedded_ipv4(v6) {
                return forbidden_v4(inner, blocked_lan);
            }
            let f = v6.segments();
            if f[0] & 0xfe00 == 0xfc00 {
                Some("unique local (fc00::/7)")
            } else if f[0] & 0xffc0 == 0xfe80 {
                Some("link-local (fe80::/10)")
            } else if f[0] == 0x2001 && f[1] == 0 {
                // Teredo is a v4-relayed tunnel: every route through it ends at
                // an IPv4 literal embedded in the address, which is exactly what
                // the rules above exist to police. The server field straddles a
                // word boundary, so the prefix is refused whole.
                Some("teredo (2001:0::/32)")
            } else if f[0] == 0xff02 || v6.is_multicast() {
                Some("multicast")
            } else {
                None
            }
        }
    }
}

/// The IPv4 checks, shared by both families. See [`forbidden_destination`].
fn forbidden_v4(v4: Ipv4Addr, blocked_lan: bool) -> Option<&'static str> {
    let o = v4.octets();
    if v4.is_loopback() {
        Some("loopback")
    } else if o[0] == 0 {
        // 0.0.0.0/8: "this host", which routes to the local machine.
        Some("unspecified/this-network")
    } else if v4.is_link_local() || (o[0] == 169 && o[1] == 254) {
        Some("link-local (instance metadata)")
    } else if o[0] == 100 && o[1] >= 64 && o[1] <= 127 {
        Some("carrier-grade NAT (100.64.0.0/10)")
    } else if v4.is_multicast() {
        Some("multicast")
    } else if blocked_lan
        && (o[0] == 10
            || (o[0] == 172 && (16..=31).contains(&o[1]))
            || (o[0] == 192 && o[1] == 168))
    {
        Some("private (AETHER_BLOCK_LAN_TARGETS)")
    } else {
        None
    }
}

/// The IPv4 address a v6 literal is really addressed to, if it is one.
///
/// Covers the forms a resolver or a hand-written URL can legitimately produce:
/// IPv4-mapped (`::ffff:a.b.c.d`, what a dual-stack stack hands back for a v4
/// peer), the deprecated v4-compatible form (`::a.b.c.d`) and 6to4
/// (`2002:<v4>::/32`). `::` and `::1` are answered by the caller first, so
/// neither is mislabelled as a v4 address here.
fn embedded_ipv4(v6: Ipv6Addr) -> Option<Ipv4Addr> {
    if let Some(v4) = v6.to_ipv4_mapped() {
        return Some(v4);
    }
    let f = v6.segments();
    let from_words = |a: u16, b: u16| {
        Ipv4Addr::new((a >> 8) as u8, (a & 0xff) as u8, (b >> 8) as u8, (b & 0xff) as u8)
    };
    if f[..4].iter().all(|&w| w == 0) && (f[4] | f[5]) == 0 && (f[6] | f[7]) != 0 {
        // `::a.b.c.d` (deprecated v4-compatible) and `::ffff:a.b.c.d` (mapped).
        return Some(from_words(f[6], f[7]));
    }
    if f[0] == 0x2002 {
        // 6to4: 2002:<v4>::/32 carries the destination's own IPv4 in words 1-2.
        return Some(from_words(f[1], f[2]));
    }
    None
}

/// One reading of the stack's clock.
///
/// smoltcp's own `Instant::now()` is derived from `SystemTime` — a *wall* clock.
/// Every socket timer in smoltcp is an absolute `Instant`, so an NTP correction
/// or a manual date change shifted them all at once: a forward step aborted every
/// idle connection simultaneously, a backward one froze retransmit and the
/// keep-alive probes that detect a dead peer. `std::time::Instant` cannot go
/// backwards, so all timestamps given to smoltcp are measured from the instant
/// the stack task started instead. It is also what makes the socket state machine
/// testable against a simulated clock.
fn stack_now(base: std::time::Instant) -> Instant {
    let elapsed = std::time::Instant::now().saturating_duration_since(base);
    Instant::from_micros(i64::try_from(elapsed.as_micros()).unwrap_or(i64::MAX))
}

/// Arm the timers an established, possibly-long-lived flow needs.
///
/// Called exactly once, on the connect -> Established edge: the connect timeout
/// is also smoltcp's inactivity abort, so leaving it armed killed every session
/// that went quiet for 10 s. `set_timeout(None)` was rejected — it leaves the
/// stack unsupervised.
fn arm_idle_keepalive(sock: &mut tcp::Socket<'_>) {
    sock.set_timeout(Some(TCP_IDLE_TIMEOUT));
    sock.set_keep_alive(Some(TCP_KEEPALIVE_INTERVAL));
}

async fn run(
    mut s: NetStack,
    clock_base: std::time::Instant,
    mut cmd_rx: mpsc::Receiver<Cmd>,
    mut data_in_rx: mpsc::Receiver<DataIn>,
    mut inbound_rx: mpsc::Receiver<Vec<u8>>,
    outbound_tx: mpsc::Sender<Vec<u8>>,
) -> Result<()> {
    loop {
        let now = stack_now(clock_base);
        // Bounded interleave rather than one `iface.poll()`. A single poll drains
        // the whole device RX ring before it will service egress, so one client
        // blasting uploads held the loop away from every other flow's outbound
        // packet for the length of that burst. Ingress is capped per tick and
        // egress then gets its own pass.
        let poll_outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut ingressed = 0usize;
            while ingressed < MAX_INGRESS_PER_TICK {
                match s
                    .iface
                    .poll_ingress_single(now, &mut s.device, &mut s.sockets)
                {
                    smoltcp::iface::PollIngressSingleResult::None => break,
                    _ => ingressed += 1,
                }
            }
            s.iface.poll_egress(now, &mut s.device, &mut s.sockets);
        }));
        if poll_outcome.is_err() {
            // L4 fix: a smoltcp poll panic is surfaced, not swallowed. The
            // in-flight rx/tx buffers are deliberately *not* discarded here:
            // they hold packets the tunnel already paid to deliver, and
            // throwing them away turned one bad flow into a retransmit storm on
            // every other one. The ring caps and the checked socket accessors
            // make the panic path a no-op instead of a state corruption.
            log::error!("[netstack] smoltcp poll panicked; continuing with buffers retained");
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
                log::error!("[netstack] {name} panicked; continuing with buffers retained");
            }
        }

        let mut delay = s
            .iface
            .poll_delay(stack_now(clock_base), &s.sockets)
            .map(|d| std::time::Duration::from_micros(d.total_micros()));
        if delay.is_none() && (!s.device.rx.is_empty() || !s.device.tx.is_empty()) {
            // smoltcp says "act now" because a frame is queued on either side; we
            // just handed that work its bounded share, so wait long enough for
            // the select to mean something instead of spinning at 0. `tx` has to
            // be in this test: `flush_tx` returns early on a full tunnel queue
            // with no timer armed, and parking on `pending()` there meant queued
            // egress — including TCP ACKs — was never retried.
            delay = Some(MIN_POLL_DELAY);
        }

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

/// Which input a drain pass served next.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DrainSrc {
    Ingest,
    Cmd,
    Data,
}

/// Round-robin scheduler for one pass over the three input channels.
///
/// This is the command-starvation fix (T134). With `biased;` on the select, and
/// with the ingest branch draining a whole batch before any command was looked
/// at, a peer that kept frames arriving meant `Cmd::OpenTcp` waited behind
/// `MAX_INGEST_PER_TICK` frames *per wakeup* — a new tab's connect queued behind
/// the current download. Serving at most one item per source and then advancing
/// the cursor means a concurrently-submitted command is reached on the *second*
/// step of the first pass no matter how much ingress is pending, while the
/// per-source caps still bound how long one pass can hold the loop.
#[derive(Clone, Copy, Debug, Default)]
struct DrainState {
    served: [usize; 3],
    cursor: usize,
}

impl DrainState {
    const CAPS: [usize; 3] = [
        MAX_INGEST_PER_TICK,
        MAX_CMDS_PER_TICK,
        MAX_APPDATA_PER_TICK,
    ];

    /// Pick the next source with work left, or `None` to end the pass.
    fn next(&mut self, ready: [bool; 3]) -> Option<DrainSrc> {
        for step in 0..3 {
            let idx = (self.cursor + step) % 3;
            if !ready[idx] || self.served[idx] >= Self::CAPS[idx] {
                continue;
            }
            self.served[idx] += 1;
            // Next pass starts after the source just served, so a source that is
            // always ready cannot occupy the head of the rotation.
            self.cursor = (idx + 1) % 3;
            return match idx {
                0 => Some(DrainSrc::Ingest),
                1 => Some(DrainSrc::Cmd),
                _ => Some(DrainSrc::Data),
            };
        }
        None
    }
}

/// Round-robin the channels' backlog after any wakeup.
///
/// Each source is capped per pass and every step rotates, so a flood on one
/// class (the peer pushing ingress at us, or a client blasting writes) cannot
/// starve the other two.
fn drain_backlog(
    s: &mut NetStack,
    cmd_rx: &mut mpsc::Receiver<Cmd>,
    data_in_rx: &mut mpsc::Receiver<DataIn>,
    inbound_rx: &mut mpsc::Receiver<Vec<u8>>,
) {
    let mut state = DrainState::default();
    loop {
        let ready = [
            !inbound_rx.is_empty(),
            !cmd_rx.is_empty(),
            !data_in_rx.is_empty(),
        ];
        match state.next(ready) {
            None => return,
            Some(DrainSrc::Ingest) => {
                if let Ok(pkt) = inbound_rx.try_recv() {
                    s.device.push_ingress(pkt);
                }
            }
            Some(DrainSrc::Cmd) => {
                if let Ok(cmd) = cmd_rx.try_recv() {
                    guard_cmd(s, cmd);
                }
            }
            Some(DrainSrc::Data) => {
                if let Ok(d) = data_in_rx.try_recv() {
                    guard_data(s, d);
                }
            }
        }
    }
}

/// `handle_cmd` touches every socket handle the app knows about; a panic there
/// previously aborted the whole netstack task (and with it every tunnel)
/// because only `iface.poll` was wrapped. A dropped responder is a clean
/// `Err` at the caller, so containing here is strictly better than dying.
///
/// Recovery does *not* discard the rx/tx queues: those are packets the tunnel
/// already paid to deliver, and the checked `with_tcp`/`with_udp` accessors mean
/// a stale handle can no longer panic in the first place.
fn guard_cmd(s: &mut NetStack, cmd: Cmd) {
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        handle_cmd(s, cmd);
    }));
    if outcome.is_err() {
        log::error!("[netstack] handle_cmd panicked; command dropped, buffers retained");
    }
}

fn guard_data(s: &mut NetStack, d: DataIn) {
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        handle_data(s, d);
    }));
    if outcome.is_err() {
        log::error!("[netstack] handle_data panicked; write dropped, buffers retained");
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
        Cmd::OpenTcp { dst, resp, resolver } => {
            let class = SocketClass::for_resolver(resolver);
            // Post-resolution choke point (T157): `dst` is an address here, not a
            // name, so this is the one check a DNS rebinding cannot walk around.
            if let Some(reason) = forbidden_destination(dst.ip()) {
                let _ = resp.send(Err(format!("destination {dst} is not reachable through the tunnel: {reason}")));
                return;
            }
            if s.tcp_in_class(class) >= class.tcp_cap() {
                // The class goes in *parentheses*: `session::local_stack_broken`
                // matches the literal "too many TCP connections" to tell a local
                // refusal apart from a refusal that came back through the tunnel,
                // and rewording the prefix would silently turn that readiness
                // gate back into a false positive.
                let label = class.label();
                let _ = resp.send(Err(format!("too many TCP connections ({label})")));
                return;
            }
            let (rx_cap, tx_cap) = match tcp_admission(s.mem_reserved) {
                Some(pair) => pair,
                None => {
                    // Same prefix as the class refusal above: `session::local_stack_broken`
                    // matches "too many TCP connections" to tell a local refusal apart
                    // from one that came back through the tunnel.
                    let label = class.label();
                    let _ = resp.send(Err(format!(
                        "too many TCP connections ({label}): memory admission budget is full"
                    )));
                    return;
                }
            };
            let rx_buf = tcp::SocketBuffer::new(vec![0u8; rx_cap]);
            let tx_buf = tcp::SocketBuffer::new(vec![0u8; tx_cap]);
            let mut socket = tcp::Socket::new(rx_buf, tx_buf);
            socket.set_nagle_enabled(false);
            // H2 fix: without a connect timeout a SYN to a black-holed address
            // sits in SynSent forever (smoltcp retransmits indefinitely), leaking
            // 1MB of buffers + a connection slot per attempt until the TCP budget
            // exhausts and the proxy dies permanently.
            // On expiry smoltcp aborts the socket -> State::Closed, which the
            // service loop already maps to "connection refused" for the caller.
            // This is only the *connect* budget: `service_tcp` re-arms a longer
            // timeout plus a keep-alive on the Established edge, because smoltcp
            // reads this same field as an inactivity abort (see T131).
            socket.set_timeout(Some(TCP_CONNECT_TIMEOUT));

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
            // Charged only once the socket is in the set: the refusals above drop
            // the buffers they allocated, so an attempted connect costs nothing.
            let reserved = rx_cap + tx_cap;
            s.mem_reserved += reserved;

            let (to_app_tx, to_app_rx) = mpsc::channel(APP_QUEUE);

            s.tcp_conns.insert(
                id,
                TcpState {
                    handle,
                    class,
                    reserved,
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
        Cmd::OpenUdp { resp, resolver } => {
            let class = SocketClass::for_resolver(resolver);
            if s.udp_in_class(class) >= class.udp_cap() {
                let label = class.label();
                let _ = resp.send(Err(format!("too many UDP associations ({label})")));
                return;
            }
            let cap = match udp_admission(s.mem_reserved) {
                Some(cap) => cap,
                None => {
                    let label = class.label();
                    let _ = resp.send(Err(format!(
                        "too many UDP associations ({label}): memory admission budget is full"
                    )));
                    return;
                }
            };
            let rx_meta = vec![udp::PacketMetadata::EMPTY; UDP_META];
            let tx_meta = vec![udp::PacketMetadata::EMPTY; UDP_META];
            let rx_buf = udp::PacketBuffer::new(rx_meta, vec![0u8; cap]);
            let tx_buf = udp::PacketBuffer::new(tx_meta, vec![0u8; cap]);
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
            let reserved = cap * 2;
            s.mem_reserved += reserved;

            let (to_app_tx, to_app_rx) = mpsc::channel(APP_QUEUE);
            s.udp_conns.insert(
                id,
                UdpState {
                    handle,
                    class,
                    reserved,
                    to_app: to_app_tx,
                },
            );

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
            if let Some(reason) = forbidden_destination(dst.ip()) {
                log::debug!("netstack: dropped UDP to {dst} ({reason})");
                return;
            }
            let Some(handle) = s.udp_conns.get(&id).map(|st| st.handle) else {
                return;
            };
            // Checked access: a sender racing its own `UdpClose`, or an
            // association retired by the pool, used to panic here.
            with_udp(&mut s.sockets, handle, |sock| {
                let _ = sock.send_slice(&data, to_ip_endpoint(dst));
            });
        }
        DataIn::UdpClose(id) => {
            if let Some(st) = s.udp_conns.remove(&id) {
                s.mem_reserved = s.mem_reserved.saturating_sub(st.reserved);
                remove_socket(&mut s.sockets, st.handle);
            }
        }
    }
}

/// Retire the app-side state of a TCP flow, answering a connect that never
/// completed with `reason` if one is pending.
fn retire_tcp(s: &mut NetStack, id: usize, reason: Option<&str>) {
    if let Some(st) = s.tcp_conns.get_mut(&id) {
        if let Some(resp) = st.connect_resp.take() {
            match reason {
                Some(msg) => {
                    let _ = resp.send(Err(msg.to_string()));
                }
                None => drop(resp),
            }
        }
    }
    if let Some(st) = s.tcp_conns.remove(&id) {
        st.dead.store(true, Ordering::Relaxed);
        // One release per admission, wherever the flow was dropped from the map
        // (T145): a budget that only ever grows is a permanent outage with a
        // nicer name.
        s.mem_reserved = s.mem_reserved.saturating_sub(st.reserved);
    }
}

/// What one egress attempt did with a flow's queued bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Egress {
    /// The socket took `n` bytes; the remainder waits for the next poll.
    Accepted(usize),
    /// The socket cannot take data in its current state, so nothing it still
    /// holds is ever going to leave.
    Dead,
}

/// Tear down a flow whose app-side half is gone.
///
/// `close()` on its own is not enough: from `Established` it only moves the
/// socket to `FinWait1`, which is reclaimed once the *peer* answers — against a
/// dead or silent peer the flow then sat there holding its buffer pair (up to
/// 1.3 MB) and a proxy slot for the full 75 s idle timeout, which is the exact
/// failure this function exists to remove. The socket is dropped in the same
/// breath as the app-side entry, so no handle is orphaned in the `SocketSet`
/// and no inbound segment can find it afterwards.
fn abandon_tcp(s: &mut NetStack, id: usize, handle: SocketHandle, established: bool) {
    with_tcp(&mut s.sockets, handle, |sock| sock.abort());
    remove_socket(&mut s.sockets, handle);
    // An established flow's caller already has its `TcpConn`; one that never
    // finished handshaking still has a `connect` waiting, and it must be
    // answered rather than left to hang.
    let reason = if established {
        None
    } else {
        Some("connection abandoned before it completed")
    };
    retire_tcp(s, id, reason);
}

fn service_tcp(s: &mut NetStack) {
    let ids: Vec<usize> = s.tcp_conns.keys().copied().collect();

    for id in ids {
        let Some((handle, was_established)) = s.tcp_conns.get(&id).map(|st| (st.handle, st.established))
        else {
            continue;
        };

        // Every access below goes through `with_tcp`: smoltcp's `get`/`get_mut`
        // panic on a stale handle, and a socket can be retired while its
        // app-side entry still has a queued write or an unanswered connect.
        let Some(state) = with_tcp(&mut s.sockets, handle, |sock| sock.state()) else {
            retire_tcp(s, id, Some("connection lost"));
            continue;
        };
        let data_in_tx = s.data_in_tx.clone();

        // Set on the connect -> Established edge when the accepted flow has
        // nowhere to go: the caller stopped waiting (aborted tab, client cancel)
        // between the SYN and the handshake completing.
        let mut orphaned = false;
        if !was_established && state == tcp::State::Established {
            with_tcp(&mut s.sockets, handle, arm_idle_keepalive);
            if let Some(st) = s.tcp_conns.get_mut(&id) {
                st.established = true;
                if let (Some(resp), Some(rx)) = (st.connect_resp.take(), st.from_stack_rx.take()) {
                    let conn = TcpConn {
                        dead: st.dead.clone(),
                        id,
                        from_stack: rx,
                        data_in: data_in_tx.clone(),
                    };
                    orphaned = resp.send(Ok(conn)).is_err();
                }
            }
        }
        if orphaned {
            abandon_tcp(s, id, handle, true);
            continue;
        }

        if !was_established && matches!(state, tcp::State::Closed | tcp::State::TimeWait) {
            retire_tcp(s, id, Some("connection refused"));
            remove_socket(&mut s.sockets, handle);
            continue;
        }

        if let Some(st) = s.tcp_conns.get_mut(&id) {
            if !st.pending.is_empty() {
                let pending = std::mem::take(&mut st.pending);
                // `send_slice` reports two very different things as the same `0`:
                // a full transmit buffer (retry next poll, nothing is lost) and a
                // socket that cannot accept data in its current state (these bytes
                // can never leave). The old `.unwrap_or(0)` conflated them, so a
                // half-closed flow re-queued its backlog every tick until the
                // pending cap killed it — after holding 512 KB of it for free.
                let outcome = with_tcp(&mut s.sockets, handle, |sock| {
                    match sock.send_slice(&pending) {
                        Ok(n) => Egress::Accepted(n),
                        Err(tcp::SendError::InvalidState) => Egress::Dead,
                    }
                })
                .unwrap_or(Egress::Dead);
                match outcome {
                    Egress::Accepted(n) if n > 0 => st.pending.extend_from_slice(&pending[n..]),
                    Egress::Accepted(_) => st.pending = pending,
                    Egress::Dead => {
                        log::debug!(
                            "netstack TCP {id}: socket cannot accept {} queued byte(s)",
                            pending.len()
                        );
                        st.half_closed = true;
                        st.dead.store(true, Ordering::Relaxed);
                    }
                }
            }
        }

        let close_now = s
            .tcp_conns
            .get(&id)
            .map(|st| st.half_closed && st.pending.is_empty())
            .unwrap_or(false);
        if close_now {
            with_tcp(&mut s.sockets, handle, |sock| sock.close());
        }

        // Critical: never `.await` on to_app here. Awaiting stalls the entire netstack
        // (including TCP ACK generation for other sockets) and kills download speed.
        // Leave unread bytes in smoltcp when the app channel is full — natural backpressure.
        let to_app = match s.tcp_conns.get(&id) {
            Some(st) => st.to_app.clone(),
            None => continue,
        };
        let established = s
            .tcp_conns
            .get(&id)
            .map(|st| st.established)
            .unwrap_or(false);
        if to_app.capacity() == 0 {
            // A full channel means "the reader is slow", and the bytes stay in
            // smoltcp; a *closed* one means nobody will ever read again. The
            // unqualified `continue` skipped the closed check below, so an
            // abandoned flow stayed open — holding its buffer pair and a proxy
            // slot — until the 75 s idle timeout.
            if to_app.is_closed() {
                abandon_tcp(s, id, handle, established);
            }
            continue;
        }
        let app_gone = with_tcp(&mut s.sockets, handle, |socket| {
            let mut n = 0;
            let mut gone = false;
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
                            gone = true;
                            break;
                        }
                    },
                    _ => break,
                }
            }
            gone
        })
        .unwrap_or(false);
        if app_gone {
            abandon_tcp(s, id, handle, established);
            continue;
        }

        let st_state = with_tcp(&mut s.sockets, handle, |sock| sock.state()).unwrap_or(tcp::State::Closed);
        if matches!(st_state, tcp::State::CloseWait) {
            with_tcp(&mut s.sockets, handle, |sock| sock.close());
        }
        if matches!(st_state, tcp::State::Closed) && established {
            remove_socket(&mut s.sockets, handle);
            retire_tcp(s, id, None);
        }
    }
}

fn service_udp(s: &mut NetStack) {
    let ids: Vec<usize> = s.udp_conns.keys().copied().collect();

    for id in ids {
        let Some((handle, to_app)) = s
            .udp_conns
            .get(&id)
            .map(|st| (st.handle, st.to_app.clone()))
        else {
            continue;
        };
        if to_app.capacity() == 0 {
            continue;
        }
        // Checked access; see `with_tcp`. An association closed by its sender's
        // `Drop` between the handle being read and the socket being polled was a
        // panic here.
        with_udp(&mut s.sockets, handle, |socket| {
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
        });
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
    #[test]
    fn tunnel_destinations_are_confined_to_routable_space() {
        let v4 = |a, b, c, d| IpAddr::V4(Ipv4Addr::new(a, b, c, d));
        for (addr, why) in [
            (v4(127, 0, 0, 1), "loopback"),
            (v4(0, 0, 0, 0), "unspecified/this-network"),
            (v4(169, 254, 169, 254), "link-local (instance metadata)"),
            (v4(100, 64, 0, 1), "carrier-grade NAT (100.64.0.0/10)"),
            (v4(224, 0, 0, 1), "multicast"),
            (IpAddr::V6(Ipv6Addr::LOCALHOST), "loopback (::1)"),
            (IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1)), "unique local (fc00::/7)"),
            (IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)), "link-local (fe80::/10)"),
        ] {
            assert_eq!(forbidden_destination(addr), Some(why), "{addr}");
        }
        for addr in [v4(93, 184, 216, 34), v4(10, 0, 0, 5), IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0, 1))] {
            assert_eq!(forbidden_destination(addr), None, "{addr} must be reachable");
        }
    }

    /// The same destination written in IPv6 form must be refused for the same
    /// reason. `::ffff:x` is what a dual-stack resolver returns for an IPv4
    /// record, so an un-de-mapped v6 check is not a narrower rule — it is a
    /// bypass of the whole function, and this is the choke point a DNS rebinding
    /// cannot walk around.
    #[test]
    fn ipv4_targets_in_ipv6_form_are_refused_too() {
        let mapped = |a, b, c, d| {
            IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, (a << 8 | b) as u16, (c << 8 | d) as u16))
        };
        let v4 = |a, b, c, d| IpAddr::V4(Ipv4Addr::new(a, b, c, d));
        for (a, b, c, d, why) in [
            (127, 0, 0, 1, "loopback"),
            (169, 254, 169, 254, "link-local (instance metadata)"),
            (100, 64, 0, 1, "carrier-grade NAT (100.64.0.0/10)"),
            (224, 0, 0, 1, "multicast"),
            (0, 0, 0, 0, "unspecified/this-network"),
        ] {
            assert_eq!(
                forbidden_destination(v4(a, b, c, d)),
                Some(why),
                "v4 spelling of {a}.{b}.{c}.{d}"
            );
            assert_eq!(
                forbidden_destination(mapped(a, b, c, d)),
                Some(why),
                "v4-mapped spelling of {a}.{b}.{c}.{d} walked through the choke point"
            );
        }

        // Deprecated v4-compatible form, and a routable host in both spellings.
        assert_eq!(
            forbidden_destination(IpAddr::V6(Ipv6Addr::new(
                0, 0, 0, 0, 0, 0, 0xa9fe, 0xa9fe
            ))),
            Some("link-local (instance metadata)"),
            "::169.254.169.254"
        );
        assert_eq!(
            forbidden_destination(IpAddr::V6(Ipv6Addr::new(
                0x2002, 0xa9fe, 0xa9fe, 0, 0, 0, 0, 0
            ))),
            Some("link-local (instance metadata)"),
            "6to4 2002:169.254.169.254"
        );
        assert_eq!(
            forbidden_destination(IpAddr::V6(Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 1))),
            Some("teredo (2001:0::/32)")
        );
        assert_eq!(
            forbidden_destination(IpAddr::V6(Ipv6Addr::UNSPECIFIED)),
            Some("unspecified (::)")
        );
        assert_eq!(
            forbidden_destination(IpAddr::V6(Ipv6Addr::new(
                0x2606, 0x4700, 0, 0, 0, 0xffff, 0x5db8, 0xd822
            ))),
            None,
            "a mapped *routable* v6 address must still work"
        );
    }

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
            mem_reserved: 0,
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
            mem_reserved: 0,
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

    /// An idle **Established** flow must survive 60 s of silence.
    ///
    /// The 10 s timeout armed at connect is *also* smoltcp's inactivity abort
    /// (`timed_out` is `now >= remote_last_ts + timeout`), so the connect-timeout
    /// fix silently became an idle killer for every SSH / IMAP / long-poll /
    /// WebSocket / database session that went quiet.
    ///
    /// This drives the real smoltcp state machine: two interfaces cross-connected
    /// through their `StackDevice`s, a **simulated** clock, and zero inbound
    /// frames after the handshake. It asserts both halves of the requirement —
    /// the flow is still `Established` after 60 s, *and* at least one egress
    /// frame went out in that window, which is what distinguishes a quiet peer
    /// from a dead one.
    #[test]
    fn idle_established_survives() {
        let t0 = Instant::from_millis(1_000);
        let mut dev_c = StackDevice::new(1500);
        let mut dev_s = StackDevice::new(1500);
        let mut if_c = Interface::new(Config::new(HardwareAddress::Ip), &mut dev_c, t0);
        let mut if_s = Interface::new(Config::new(HardwareAddress::Ip), &mut dev_s, t0);
        if_c.update_ip_addrs(|addrs| {
            let _ = addrs.push(IpCidr::new(IpAddress::Ipv4(Ipv4Addr::new(10, 0, 0, 2)), 24));
        });
        if_s.update_ip_addrs(|addrs| {
            let _ = addrs.push(IpCidr::new(IpAddress::Ipv4(Ipv4Addr::new(10, 0, 0, 1)), 24));
        });

        let mut set_c: SocketSet<'static> = SocketSet::new(Vec::new());
        let mut set_s: SocketSet<'static> = SocketSet::new(Vec::new());
        let buf = || tcp::SocketBuffer::new(vec![0u8; 8192]);

        let mut client = tcp::Socket::new(buf(), buf());
        // The production connect policy, then the production Established policy.
        client.set_timeout(Some(TCP_CONNECT_TIMEOUT));
        let server_ep = IpEndpoint::new(IpAddress::Ipv4(Ipv4Addr::new(10, 0, 0, 1)), 443);
        client
            .connect(if_c.context(), server_ep, 40000u16)
            .expect("connect accepted");
        let ch = set_c.add(client);

        let mut server = tcp::Socket::new(buf(), buf());
        server.listen(443u16).expect("listen");
        let sh = set_s.add(server);

        for _ in 0..8 {
            if_c.poll(t0, &mut dev_c, &mut set_c);
            move_frames(&mut dev_c, &mut dev_s);
            if_s.poll(t0, &mut dev_s, &mut set_s);
            move_frames(&mut dev_s, &mut dev_c);
            if with_tcp(&mut set_c, ch, |sock| sock.state()) == Some(tcp::State::Established) {
                break;
            }
        }
        assert_eq!(
            with_tcp(&mut set_c, ch, |sock| sock.state()),
            Some(tcp::State::Established),
            "the mock handshake never completed, so this test would prove nothing"
        );
        assert_eq!(
            with_tcp(&mut set_s, sh, |sock| sock.state()),
            Some(tcp::State::Established),
            "the listening half never came up"
        );

        with_tcp(&mut set_c, ch, arm_idle_keepalive);
        dev_c.tx.clear();

        let mut probes = 0usize;
        let mut t = t0;
        for step in 1..=12usize {
            t = Instant::from_millis(t.total_millis() + 5_000);
            assert!(dev_c.rx.is_empty(), "the peer was meant to stay silent");
            if_c.poll(t, &mut dev_c, &mut set_c);
            probes += dev_c.tx.len();
            dev_c.tx.clear();
            let quiet_for = step * 5;
            assert_eq!(
                with_tcp(&mut set_c, ch, |sock| sock.state()),
                Some(tcp::State::Established),
                "idle Established socket died after {quiet_for} s of silence"
            );
        }
        assert!(
            probes > 0,
            "60 s of silence produced no keep-alive frame: a crashed peer would never be reaped"
        );
        // The other half of the bug: the connect timeout really is the short one,
        // so a socket that never had its timers revised would have died here.
        assert!(TCP_CONNECT_TIMEOUT < TCP_IDLE_TIMEOUT);
        assert!(TCP_IDLE_TIMEOUT.total_millis() > 60_000);
        assert!(TCP_IDLE_TIMEOUT.total_millis() > 4 * TCP_KEEPALIVE_INTERVAL.total_millis());
    }

    /// The tx ring must be bounded by the ring, not by available RAM (T133).
    ///
    /// `outbound_tx` saturation is the interesting case: smoltcp keeps polling
    /// and keeps producing while nothing drains, and an unbounded queue there
    /// ended in an allocator abort.
    #[test]
    fn tx_ring_is_bounded() {
        let mut device = StackDevice::new(1500);
        let t = Instant::from_millis(1);

        // Bulk egress: the producer never stops, the drain never runs.
        for _ in 0..TX_RING * 8 {
            if let Some(tok) = device.transmit(t) {
                tok.consume(1448, |b| b[0] = 0xAA);
            }
        }
        assert_eq!(
            device.tx.len(),
            TX_RING,
            "bulk egress grew past the ring while the tunnel was not draining"
        );
        assert!(
            device.tx_deferred > 0,
            "saturation must be counted, not silently dropped"
        );
        let deferred_at_ring = device.tx_deferred;

        // The ACK path: the token paired with an ingress frame is allowed past
        // the ring (a lost reply is not regenerated) but only by the documented
        // slack, so the queue still cannot grow without limit.
        for _ in 0..RX_RING * 4 {
            let _ = device.push_ingress(vec![0u8; 64]);
        }
        for _ in 0..RX_RING * 4 {
            match device.receive(t) {
                Some((rx, tok)) => {
                    rx.consume(|pkt| pkt.len());
                    tok.consume(64, |_| ());
                }
                None => break,
            }
        }
        assert!(
            device.tx.len() <= TX_RING + TX_EGRESS_SLACK,
            "reply frames grew the queue past TX_RING + TX_EGRESS_SLACK: {}",
            device.tx.len()
        );
        assert!(
            device.tx.len() > TX_RING,
            "the reply token was capped at TX_RING, which is the ACK-loss bug"
        );
        assert!(device.tx_deferred > deferred_at_ring);
    }

    /// A command submitted while the peer is flooding us must be reached in a
    /// bounded number of steps (T134).
    #[test]
    fn cmd_not_starved_by_inbound() {
        // Five full ingest batches queued behind one `Cmd::OpenTcp`.
        let mut queued_ingest = MAX_INGEST_PER_TICK * 5;
        let mut queued_cmd = 1usize;
        let mut state = DrainState::default();
        let mut steps = 0usize;
        while queued_cmd > 0 {
            let ready = [queued_ingest > 0, queued_cmd > 0, false];
            match state.next(ready) {
                None => break,
                Some(DrainSrc::Ingest) => queued_ingest -= 1,
                Some(DrainSrc::Cmd) => queued_cmd -= 1,
                Some(DrainSrc::Data) => {}
            }
            steps += 1;
            assert!(steps <= 10, "a concurrently submitted command took {steps} drain steps");
        }
        assert_eq!(queued_cmd, 0, "OpenTcp was starved by the ingest backlog");
        assert!(
            queued_ingest > 0,
            "the drain ran the ingest queue dry instead of rotating"
        );

        // One pass is still bounded, so a permanently-ready channel cannot make
        // the loop spin forever without polling the stack.
        let mut state = DrainState::default();
        let mut ingested = 0usize;
        for _ in 0..1_000 {
            match state.next([true, false, false]) {
                Some(DrainSrc::Ingest) => ingested += 1,
                Some(_) => unreachable!("nothing else was ready"),
                None => break,
            }
        }
        assert_eq!(ingested, MAX_INGEST_PER_TICK, "one pass ignored the ingest cap");
    }

    /// Deliver every frame one device queued into the other's ingress ring.
    fn move_frames(from: &mut StackDevice, to: &mut StackDevice) {
        while let Some(pkt) = from.tx.pop_front() {
            to.push_ingress(pkt);
        }
    }

    /// An in-process stack with a routable address and no peer: the same
    /// harness the FIFO tests build by hand, shared.
    fn empty_stack() -> NetStack {
        let mut device = StackDevice::new(1500);
        let config = Config::new(HardwareAddress::Ip);
        let mut iface = Interface::new(config, &mut device, Instant::from_millis(0));
        apply_addrs(&mut iface, Some((Ipv4Addr::new(10, 0, 0, 2), 24)), None);
        let (data_in_tx, _data_in_rx) = mpsc::channel(1);
        NetStack {
            iface,
            device,
            sockets: SocketSet::new(Vec::new()),
            tcp_conns: HashMap::new(),
            udp_conns: HashMap::new(),
            next_id: 1,
            next_port: port_seed().0,
            port_stride: port_seed().1,
            mem_reserved: 0,
            data_in_tx,
        }
    }

    /// True when `Cmd::OpenUdp` was admitted, judged by the pool it joined.
    fn admitted_udp(stack: &mut NetStack, resolver: bool) -> bool {
        let before = stack.udp_conns.len();
        let (tx, _rx) = oneshot::channel();
        handle_cmd(stack, Cmd::OpenUdp { resp: tx, resolver });
        stack.udp_conns.len() > before
    }

    /// True when `Cmd::OpenTcp` was admitted to a socket, judged the same way.
    fn admitted_tcp(stack: &mut NetStack, dst: SocketAddr, resolver: bool) -> bool {
        let before = stack.tcp_conns.len();
        let (tx, _rx) = oneshot::channel();
        handle_cmd(stack, Cmd::OpenTcp { dst, resp: tx, resolver });
        stack.tcp_conns.len() > before
    }

    /// A handle that no longer names a socket must not take the netstack down
    /// (T135/T148), and recovering from one must not throw away the packets
    /// behind it.
    #[test]
    fn stale_handle_does_not_panic() {
        let dst: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 443);
        let mut stack = empty_stack();

        let mut sock = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0u8; 1024]),
            tcp::SocketBuffer::new(vec![0u8; 1024]),
        );
        sock.connect(stack.iface.context(), to_ip_endpoint(dst), 40001u16)
            .expect("connect accepted");
        let handle = stack.sockets.add(sock);
        let (to_app, _to_app_rx) = mpsc::channel(4);
        let dead = Arc::new(AtomicBool::new(false));
        stack.tcp_conns.insert(
            7,
            TcpState {
                handle,
                class: SocketClass::Proxy,
                reserved: 0,
                to_app,
                from_stack_rx: None,
                connect_resp: None,
                pending: Vec::new(),
                established: true,
                half_closed: false,
                dead: dead.clone(),
            },
        );

        let mut usock = udp::Socket::new(
            udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 4], vec![0u8; 512]),
            udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 4], vec![0u8; 512]),
        );
        usock.bind(40002u16).expect("bind");
        let uhandle = stack.sockets.add(usock);
        let (uto_app, _uto_app_rx) = mpsc::channel(4);
        stack.udp_conns.insert(
            9,
            UdpState {
                handle: uhandle,
                class: SocketClass::Proxy,
                reserved: 0,
                to_app: uto_app,
            },
        );

        // Both sockets disappear underneath the app-side entries — smoltcp
        // retiring them on its own timers, or a close racing the service loop.
        assert!(remove_socket(&mut stack.sockets, handle));
        assert!(remove_socket(&mut stack.sockets, uhandle));
        assert!(!remove_socket(&mut stack.sockets, uhandle), "double remove reported success");

        // Buffered traffic that must survive.
        stack.device.push_ingress(vec![0u8; 64]);
        stack.device.tx.push_back(vec![9u8; 1448]);

        guard_data(&mut stack, DataIn::Tcp(7, b"hi".to_vec()));
        guard_data(&mut stack, DataIn::Udp(9, dst, b"ping".to_vec()));
        guard_data(&mut stack, DataIn::UdpClose(9));
        guard_data(&mut stack, DataIn::UdpClose(9));
        service_udp(&mut stack);
        service_tcp(&mut stack);

        assert!(
            stack.tcp_conns.is_empty(),
            "the flow was not retired, so its slot and buffers leaked"
        );
        assert!(stack.udp_conns.is_empty());
        assert!(
            dead.load(Ordering::Relaxed),
            "a retired flow still acknowledges writes as sent"
        );
        assert_eq!(
            stack.device.rx.len(),
            1,
            "recovery discarded a good inbound packet"
        );
        assert_eq!(stack.device.rx_bytes, 64);
        assert_eq!(
            stack.device.tx.len(),
            1,
            "recovery discarded a good outbound frame"
        );
        assert!(!stack.sockets.iter().any(|(h, _)| h == handle));

        // And the stack keeps admitting connections afterwards.
        assert!(
            admitted_tcp(&mut stack, dst, false),
            "the next open_tcp did not succeed"
        );
    }

    /// Proxy traffic must not be able to take name resolution down with it
    /// (T137/T149).
    #[test]
    fn proxy_saturation_leaves_the_resolver_budget_intact() {
        let dst: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 443);
        let mut stack = empty_stack();

        let mut proxy = 0usize;
        while admitted_udp(&mut stack, false) {
            proxy += 1;
        }
        assert_eq!(proxy, MAX_UDP_PROXY, "the proxy UDP budget moved");
        assert_eq!(stack.udp_in_class(SocketClass::Proxy), MAX_UDP_PROXY);
        assert_eq!(stack.udp_in_class(SocketClass::Resolver), 0);

        let mut resolver = 0usize;
        while admitted_udp(&mut stack, true) {
            resolver += 1;
        }
        assert_eq!(
            resolver, MAX_UDP_RESOLVER,
            "DNS was starved by proxy associations instead of getting its own budget"
        );

        // The TCP classes are separate too (a saturated proxy must not be able
        // to block the resolver's own connects), and the split preserves the old
        // overall ceiling so per-flow memory is unchanged.
        assert!(admitted_tcp(&mut stack, dst, false));
        assert!(admitted_tcp(&mut stack, dst, true));
        assert_eq!(stack.tcp_in_class(SocketClass::Proxy), 1);
        assert_eq!(stack.tcp_in_class(SocketClass::Resolver), 1);
        assert_eq!(
            SocketClass::Proxy.tcp_cap() + SocketClass::Resolver.tcp_cap(),
            512
        );
        assert_eq!(
            SocketClass::Proxy.udp_cap() + SocketClass::Resolver.udp_cap(),
            128
        );
    }

    /// `forbidden_destination` is the single choke point every flow passes, and
    /// a refusal is answered to the caller rather than dropped on the floor.
    #[test]
    fn loopback_and_metadata_targets_are_refused_at_admission() {
        let mut stack = empty_stack();
        let (tx, rx) = oneshot::channel();
        handle_cmd(
            &mut stack,
            Cmd::OpenTcp {
                dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 1337),
                resp: tx,
                resolver: false,
            },
        );
        let refusal = rx
            .blocking_recv()
            .expect("a refusal is replied to, not silently dropped");
        let msg = match refusal {
            Err(msg) => msg,
            Ok(_) => panic!("loopback was admitted through the tunnel"),
        };
        assert!(msg.contains("loopback"), "unexpected refusal: {msg}");
        assert!(stack.tcp_conns.is_empty(), "a refused connect took a slot");
    }
}
