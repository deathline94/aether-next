//! Routing plane: either the userspace proxy stack or WinTUN, never both.
use crate::error::Result;
use crate::netstack;
use std::net::SocketAddr;
use tokio::sync::mpsc;

pub enum TunGuard {
    /// Held only for its `Drop`, which tears down the WinTUN adapter and routes
    /// on disconnect; the handle itself is never read.
    #[cfg(windows)]
    Windows(#[allow(dead_code)] crate::tun_win::TunHandle),
}

/// Spawn exactly one IP consumer. Feeding decrypted packets to both WinTUN and
/// smoltcp makes two TCP/IP stacks claim the same address and can generate RSTs.
pub async fn spawn(
    ipv4: &str,
    ipv6: &str,
    peer: SocketAddr,
    mtu: usize,
    inbound_rx: mpsc::Receiver<Vec<u8>>,
    outbound_tx: mpsc::Sender<Vec<u8>>,
) -> Result<(Option<netstack::StackHandle>, Option<TunGuard>)> {
    #[cfg(windows)]
    if crate::tun_win::enabled() {
        let tun = crate::tun_win::spawn(ipv4, peer, mtu, inbound_rx, outbound_tx).await?;
        log::info!("[+] TUN mode enabled (exclusive WinTUN routing, MTU={mtu})");
        crate::session_event::emit(crate::session_event::SessionEvent::TunReady);
        return Ok((None, Some(TunGuard::Windows(tun))));
    }

    let _ = peer;
    log::info!("[+] userspace proxy netstack MTU={mtu}");
    let stack = netstack::spawn(ipv4, ipv6, mtu, inbound_rx, outbound_tx)?;
    Ok((Some(stack), None))
}
