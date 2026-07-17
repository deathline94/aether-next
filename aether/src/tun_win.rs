use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use wintun_bindings::{Adapter, Session, MAX_RING_CAPACITY};

use crate::error::{AetherError, Result};

const ADAPTER_NAME: &str = "Aether";
const TUNNEL_TYPE: &str = "Aether";

pub fn enabled() -> bool {
    match std::env::var("AETHER_TUN") {
        Ok(v) => {
            let v = v.trim().to_lowercase();
            v == "1" || v == "true" || v == "yes" || v == "on"
        }
        Err(_) => false,
    }
}

fn find_wintun_dll() -> Result<PathBuf> {
    if let Ok(p) = std::env::var("AETHER_WINTUN") {
        let path = PathBuf::from(p);
        if path.exists() {
            return Ok(path);
        }
    }
    let beside = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("wintun.dll")));
    if let Some(path) = beside {
        if path.exists() {
            return Ok(path);
        }
    }
    let cwd = PathBuf::from("wintun.dll");
    if cwd.exists() {
        return Ok(cwd);
    }
    Err(AetherError::Other(
        "wintun.dll not found (set AETHER_WINTUN or place next to aether.exe)".into(),
    ))
}

fn run_cmd(program: &str, args: &[&str]) -> Result<String> {
    let out = Command::new(program)
        .args(args)
        .output()
        .map_err(|e| AetherError::Other(format!("{program} failed: {e}")))?;
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    if !out.status.success() {
        return Err(AetherError::Other(format!(
            "{program} {:?}: {} {}",
            args, stdout, stderr
        )));
    }
    Ok(stdout)
}

fn parse_v4(s: &str) -> Result<Ipv4Addr> {
    let ip = s.split('/').next().unwrap_or(s);
    ip.parse()
        .map_err(|_| AetherError::Other(format!("bad ipv4 {s}")))
}

fn default_gateway() -> Result<(String, Ipv4Addr)> {
    let out = run_cmd("route", &["print", "0.0.0.0"])?;
    for line in out.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() >= 5 && cols[0] == "0.0.0.0" && cols[1] == "0.0.0.0" {
            let gw: Ipv4Addr = cols[2]
                .parse()
                .map_err(|_| AetherError::Other("bad default gateway".into()))?;
            if !gw.is_unspecified() {
                return Ok((cols[3].to_string(), gw));
            }
        }
    }
    Err(AetherError::Other("default gateway not found".into()))
}

fn configure_adapter_ip(name: &str, ipv4: Ipv4Addr) -> Result<()> {
    let _ = run_cmd(
        "netsh",
        &[
            "interface",
            "ip",
            "set",
            "address",
            &format!("name={name}"),
            "static",
            &ipv4.to_string(),
            "255.255.255.255",
        ],
    );
    let _ = run_cmd(
        "netsh",
        &[
            "interface",
            "ip",
            "set",
            "dns",
            &format!("name={name}"),
            "static",
            "1.1.1.1",
            "primary",
        ],
    );
    // Kernel TCP path: raise adapter MTU to match tunnel MTU (default 1280, up to 1400).
    let mtu = crate::mtu::current().clamp(1280, 1400);
    let _ = run_cmd(
        "netsh",
        &[
            "interface",
            "ipv4",
            "set",
            "subinterface",
            name,
            &format!("mtu={mtu}"),
            "store=active",
        ],
    );
    // Prefer TUN for default traffic (lower metric wins on Windows).
    let _ = run_cmd(
        "netsh",
        &[
            "interface",
            "ip",
            "set",
            "interface",
            name,
            "metric=1",
        ],
    );
    log::info!("[tun] adapter {name} mtu={mtu} metric=1 (OS/kernel TCP stack)");
    Ok(())
}

fn install_routes(peer: SocketAddr, ipv4: Ipv4Addr) -> Result<Vec<String>> {
    let mut installed = Vec::new();
    let peer_ip = match peer.ip() {
        IpAddr::V4(v4) => v4,
        IpAddr::V6(_) => {
            return Err(AetherError::Other(
                "TUN mode currently requires IPv4 peer".into(),
            ))
        }
    };
    let (_iface, gw) = default_gateway()?;

    // Keep path to edge peer on physical gateway.
    let peer_s = peer_ip.to_string();
    let gw_s = gw.to_string();
    run_cmd(
        "route",
        &["add", &peer_s, "mask", "255.255.255.255", &gw_s, "metric", "5"],
    )?;
    installed.push(peer_s);

    // Split default route via TUN IP (avoids replacing system default entirely).
    for dest in ["0.0.0.0", "128.0.0.0"] {
        let mask = "128.0.0.0";
        let via = ipv4.to_string();
        let _ = run_cmd(
            "route",
            &["add", dest, "mask", mask, &via, "metric", "5"],
        );
        installed.push(format!("{dest}/{mask}"));
    }
    Ok(installed)
}

fn remove_routes(peer: SocketAddr) {
    if let IpAddr::V4(v4) = peer.ip() {
        let _ = run_cmd("route", &["delete", &v4.to_string()]);
    }
    let _ = run_cmd("route", &["delete", "0.0.0.0", "mask", "128.0.0.0"]);
    let _ = run_cmd("route", &["delete", "128.0.0.0", "mask", "128.0.0.0"]);
}

pub struct TunHandle {
    _adapter: Arc<Adapter>,
    session: Arc<Session>,
    peer: SocketAddr,
}

impl Drop for TunHandle {
    fn drop(&mut self) {
        remove_routes(self.peer);
        let _ = self.session.shutdown();
        log::info!("[tun] cleaned routes and session");
    }
}

pub async fn spawn(
    ipv4_cidr: &str,
    peer: SocketAddr,
    inbound_rx: mpsc::Receiver<Vec<u8>>,
    outbound_tx: mpsc::Sender<Vec<u8>>,
) -> Result<TunHandle> {
    let dll = find_wintun_dll()?;
    log::info!("[tun] loading {}", dll.display());
    let wintun = unsafe { wintun_bindings::load_from_path(&dll) }
        .map_err(|e| AetherError::Other(format!("load wintun: {e}")))?;

    let adapter = match Adapter::open(&wintun, ADAPTER_NAME) {
        Ok(a) => a,
        Err(_) => Adapter::create(&wintun, ADAPTER_NAME, TUNNEL_TYPE, None)
            .map_err(|e| AetherError::Other(format!("create adapter: {e}")))?,
    };

    let ipv4 = parse_v4(ipv4_cidr)?;
    // Wait briefly for adapter to appear in Windows.
    tokio::time::sleep(Duration::from_millis(300)).await;
    configure_adapter_ip(ADAPTER_NAME, ipv4)?;
    let _ = install_routes(peer, ipv4)?;
    log::info!("[tun] adapter {ADAPTER_NAME} up {ipv4}/32 peer exclude {}", peer.ip());

    let session = adapter
        .start_session(MAX_RING_CAPACITY)
        .map_err(|e| AetherError::Other(format!("start session: {e}")))?;

    // High-throughput path: dedicated OS thread reads WinTUN ring (kernel packets)
    // and feeds the userspace tunnel encryptor. App TCP lives in the Windows stack.
    let session_r = session.clone();
    let out_tx = outbound_tx;
    std::thread::Builder::new()
        .name("aether-tun-rx".into())
        .spawn(move || {
            loop {
                match session_r.receive_blocking() {
                    Ok(pkt) => {
                        let data = pkt.bytes().to_vec();
                        if out_tx.blocking_send(data).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        })
        .map_err(|e| AetherError::Other(format!("tun rx thread: {e}")))?;

    // Kernel TX path: dedicated thread drains inbound packets without
    // per-packet spawn_blocking overhead (was a major TUN speed limit).
    let session_w = session.clone();
    std::thread::Builder::new()
        .name("aether-tun-tx".into())
        .spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build();
            let Ok(rt) = rt else { return };
            rt.block_on(async move {
                let mut inbound_rx = inbound_rx;
                while let Some(first) = inbound_rx.recv().await {
                    let mut batch = vec![first];
                    while batch.len() < 64 {
                        match inbound_rx.try_recv() {
                            Ok(p) => batch.push(p),
                            Err(_) => break,
                        }
                    }
                    let session = session_w.clone();
                    let _ = tokio::task::spawn_blocking(move || {
                        for pkt in batch {
                            if pkt.is_empty() || pkt.len() > u16::MAX as usize {
                                continue;
                            }
                            if let Ok(mut packet) = session.allocate_send_packet(pkt.len() as u16) {
                                packet.bytes_mut()[..pkt.len()].copy_from_slice(&pkt);
                                session.send_packet(packet);
                            }
                        }
                    })
                    .await;
                }
            });
        })
        .map_err(|e| AetherError::Other(format!("tun tx thread: {e}")))?;

    log::info!("[tun] bridge active (kernel TCP / WinTUN high-throughput path)");
    Ok(TunHandle {
        _adapter: adapter,
        session,
        peer,
    })
}
