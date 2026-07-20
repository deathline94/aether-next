//! Shared IP-packet channel pair used by all tunnel transports.
//!
//! MASQUE (quic/masque_h2) and WireGuard both move raw IP bytes over the same shape:
//! app/netstack ──outbound──► tunnel ──inbound──► app/netstack
use tokio::sync::mpsc;

const NET_QUEUE: usize = 2048;

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
    let (outbound_tx, outbound_rx) = mpsc::channel(NET_QUEUE);
    let (inbound_tx, inbound_rx) = mpsc::channel(NET_QUEUE);
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

/// Marker for transport kind — used by session events / logging.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportKind {
    MasqueH3,
    MasqueH2,
    WireGuard,
    Gool,
}

impl TransportKind {
    pub fn as_str(self) -> &'static str {
        match self {
            TransportKind::MasqueH3 => "h3",
            TransportKind::MasqueH2 => "h2",
            TransportKind::WireGuard => "wireguard",
            TransportKind::Gool => "gool",
        }
    }
}
