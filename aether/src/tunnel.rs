//! Shared IP-packet channel pair used by all tunnel transports.
//!
//! MASQUE (quic/masque_h2) and WireGuard both move raw IP bytes over the same shape:
//! app/netstack ──outbound──► tunnel ──inbound──► app/netstack
use std::net::IpAddr;
use tokio::sync::mpsc;

pub const NET_QUEUE: usize = 2048;

/// App-facing half: write outbound IP packets, read inbound.
pub struct Channels {
    pub outbound_tx: mpsc::Sender<Vec<u8>>,
    pub inbound_rx: mpsc::Receiver<Vec<u8>>,
}

/// Tunnel-facing half: read outbound, write inbound.
pub struct Internals {
    pub outbound_rx: mpsc::Receiver<Vec<u8>>,
    pub inbound_tx: mpsc::Sender<Vec<u8>>,
}

pub fn channels() -> (Channels, Internals) {
    let (outbound_tx, outbound_rx) = packet_channels();
    let (inbound_tx, inbound_rx) = packet_channels();
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

/// Create a single bidirectional packet channel pair (sender, receiver).
/// Used by transports that compose their own channel sets (e.g. QUIC adds a
/// control channel on top).
pub fn packet_channels() -> (mpsc::Sender<Vec<u8>>, mpsc::Receiver<Vec<u8>>) {
    mpsc::channel(NET_QUEUE)
}

/// A CONNECT-IP address as the tunnel carries it: an address family byte plus
/// 4 or 16 bytes.
///
/// Lived twice, byte-identical, in `quic.rs` (the H3 datagram path) and
/// `masque_h2.rs` (the capsule path) - the pair this module exists to keep
/// common. Two copies of an address parser is how one transport starts accepting
/// an encoding the other rejects.
pub(crate) fn bytes_to_ip(version: u8, bytes: &[u8]) -> Option<IpAddr> {
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

/// Owns a spawned task and aborts it when the guard goes out of scope.
///
/// A `JoinHandle` that nobody keeps is a detached future: it survives every
/// failure path of the function that spawned it, so an abandoned transport, H2
/// connection driver or forwarder keeps its socket open and keeps using it — one
/// leaked connection per retry, forever. Wrapping the handle here makes all of
/// them unwind: `?`, an early `return`, and even a wrapping `timeout()` that
/// drops the future mid-await, since the guard is a local of that future.
///
/// Three transports hand-rolled this (`session.rs`'s `AbortOnDrop`,
/// `tunnelping.rs`'s `AbortGuard`, `quic.rs`'s `ReaderGuard`) and a fourth
/// (`masque_h2.rs`) spawned its driver with no guard at all, which is the leak
/// this exists to close. It lives in this module rather than a new `task.rs`
/// because a new module means editing `lib.rs`, and CI's formatting ratchet
/// (`ci.yml`, `fmt`) recurses from every touched file into its submodules — a
/// commit that touches `lib.rs` is red until the whole tree is rustfmt-clean.
pub(crate) struct AbortOnDrop<T>(pub(crate) tokio::task::JoinHandle<T>);

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl<T> AbortOnDrop<T> {
    /// Resolve when the wrapped task does, without consuming the guard — a
    /// supervision `select!` needs to await the task while every other exit path
    /// still has to abort it. A guard nobody can wait on is how a dead inner
    /// tunnel turned into a hung session.
    pub(crate) async fn done(&mut self) -> std::result::Result<T, tokio::task::JoinError> {
        (&mut self.0).await
    }
}
