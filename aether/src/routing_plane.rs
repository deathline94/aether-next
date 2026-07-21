//! Routing plane: either the userspace proxy stack or WinTUN, never both.
use std::net::SocketAddr;
use tokio::sync::mpsc;
use crate::error::Result;
use crate::netstack;


pub fn tunnel_mtu() -> usize { crate::mtu::current() }

pub enum TunGuard {
    #[cfg(windows)]
    Windows(crate::tun_win::TunHandle),
}

/// Spawn exactly one IP consumer. Feeding decrypted packets to both WinTUN and
/// smoltcp makes two TCP/IP stacks claim the same address and can generate RSTs.
pub async fn spawn(
    ipv4: &str,
    ipv6: &str,
    peer: SocketAddr,
    inbound_rx: mpsc::Receiver<Vec<u8>>,
    outbound_tx: mpsc::Sender<Vec<u8>>,
) -> Result<(Option<netstack::StackHandle>, Option<TunGuard>)> {
    let mtu = tunnel_mtu();

    #[cfg(windows)]
    if crate::tun_win::enabled() {
        let tun = crate::tun_win::spawn(ipv4, peer, inbound_rx, outbound_tx).await?;
        log::info!("[+] TUN mode enabled (exclusive WinTUN routing, MTU={mtu})");
        crate::session_event::emit(crate::session_event::SessionEvent::TunReady);
        return Ok((None, Some(TunGuard::Windows(tun))));
    }

    let _ = peer;
    log::info!("[+] userspace proxy netstack MTU={mtu}");
    let stack = netstack::spawn(ipv4, ipv6, mtu, inbound_rx, outbound_tx)?;
    Ok((Some(stack), None))
}
