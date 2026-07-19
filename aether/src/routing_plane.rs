//! Routing plane: userspace netstack ± optional WinTUN full-system path.
use std::net::SocketAddr;

use tokio::sync::mpsc;

use crate::error::Result;
use crate::netstack;
use crate::session_event::{self, SessionEvent};

pub fn tunnel_mtu() -> usize {
    crate::mtu::current()
}

pub enum TunGuard {
    #[cfg(windows)]
    Windows(crate::tun_win::TunHandle),
}

/// Spawn netstack and optionally bridge WinTUN when `AETHER_TUN` is set.
pub async fn spawn(
    ipv4: &str,
    ipv6: &str,
    peer: SocketAddr,
    inbound_rx: mpsc::Receiver<Vec<u8>>,
    outbound_tx: mpsc::Sender<Vec<u8>>,
) -> Result<(netstack::StackHandle, Option<TunGuard>)> {
    let mtu = tunnel_mtu();
    log::info!("[+] netstack MTU={mtu}");

    #[cfg(windows)]
    if crate::tun_win::enabled() {
        return spawn_with_tun(ipv4, ipv6, peer, inbound_rx, outbound_tx).await;
    }
    let _ = peer; // used on Windows TUN path only

    let stack = netstack::spawn(ipv4, ipv6, mtu, inbound_rx, outbound_tx)?;
    Ok((stack, None))
}

#[cfg(windows)]
async fn spawn_with_tun(
    ipv4: &str,
    ipv6: &str,
    peer: SocketAddr,
    inbound_rx: mpsc::Receiver<Vec<u8>>,
    outbound_tx: mpsc::Sender<Vec<u8>>,
) -> Result<(netstack::StackHandle, Option<TunGuard>)> {
    // Large queues: full-system TUN is bursty; 1k slots blackhole under load.
    const Q: usize = 16_384;
    let (app_out_tx, mut app_out_rx) = mpsc::channel::<Vec<u8>>(Q);
    let (tun_out_tx, mut tun_out_rx) = mpsc::channel::<Vec<u8>>(Q);
    let merge_tx = outbound_tx.clone();
    // Prefer TUN-originated packets (kernel traffic) over SOCKS netstack under contention.
    tokio::spawn(async move {
        loop {
            tokio::select! {
                biased;
                p = tun_out_rx.recv() => {
                    match p {
                        Some(pkt) => { if merge_tx.send(pkt).await.is_err() { break; } }
                        None => break,
                    }
                }
                p = app_out_rx.recv() => {
                    match p {
                        Some(pkt) => { if merge_tx.send(pkt).await.is_err() { break; } }
                        None => break,
                    }
                }
            }
        }
    });

    let (app_in_tx, app_in_rx) = mpsc::channel::<Vec<u8>>(Q);
    let (tun_in_tx, tun_in_rx) = mpsc::channel::<Vec<u8>>(Q);
    // Never block tunnel decrypt on a full netstack queue — that froze TUN TX before.
    tokio::spawn(async move {
        let mut inbound_rx = inbound_rx;
        while let Some(pkt) = inbound_rx.recv().await {
            // TUN first (full-system path).
            match tun_in_tx.try_send(pkt.clone()) {
                Ok(()) => {}
                Err(tokio::sync::mpsc::error::TrySendError::Full(p)) => {
                    // Drop oldest pressure: await briefly for TUN only.
                    if tun_in_tx.send(p).await.is_err() {
                        break;
                    }
                }
                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => break,
            }
            // SOCKS/local stack is best-effort under TUN mode.
            let _ = app_in_tx.try_send(pkt);
        }
    });

    let mtu = tunnel_mtu();
    let stack = netstack::spawn(ipv4, ipv6, mtu, app_in_rx, app_out_tx)?;
    let tun = crate::tun_win::spawn(ipv4, peer, tun_in_rx, tun_out_tx).await?;
    log::info!("[+] TUN mode enabled (WinTUN full-system routing)");
    // Emit only after WinTUN session + routes are installed (spawn fails closed otherwise).
    session_event::emit(SessionEvent::TunReady);
    Ok((stack, Some(TunGuard::Windows(tun))))
}
