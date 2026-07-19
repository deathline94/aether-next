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
    // Point-to-point /32; gateway=none so Windows treats it as a tunnel NIC.
    run_cmd(
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
            "none",
        ],
    )?;
    // Point DNS at the tunnel so name lookups leave via TUN (not physical NIC).
    run_cmd(
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
    )?;
    let _ = run_cmd(
        "netsh",
        &[
            "interface",
            "ip",
            "add",
            "dns",
            &format!("name={name}"),
            "1.0.0.1",
            "index=2",
        ],
    );
    // Kernel TCP path: raise adapter MTU to match tunnel MTU (default 1280, up to 1400).
    let mtu = crate::mtu::current().clamp(1280, 1400);
    run_cmd(
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
    )?;
    // Prefer TUN for default traffic (lower metric wins on Windows).
    run_cmd(
        "netsh",
        &["interface", "ip", "set", "interface", name, "metric=1"],
    )?;
    // Ensure adapter is up (orphaned adapters can sit Disabled).
    let _ = run_cmd(
        "powershell",
        &[
            "-NoProfile",
            "-Command",
            &format!("Enable-NetAdapter -Name '{name}' -Confirm:$false -ErrorAction SilentlyContinue"),
        ],
    );
    log::info!("[tun] adapter {name} mtu={mtu} metric=1 (OS/kernel TCP stack)");
    Ok(())
}

fn interface_index(name: &str) -> Result<u32> {
    let out = run_cmd(
        "powershell",
        &[
            "-NoProfile",
            "-Command",
            &format!(
                "(Get-NetAdapter -Name '{name}' -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty ifIndex)"
            ),
        ],
    )?;
    let idx = out
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .and_then(|l| l.parse::<u32>().ok())
        .ok_or_else(|| AetherError::Other(format!("could not resolve ifIndex for {name}")))?;
    Ok(idx)
}

fn install_routes(peer: SocketAddr, ipv4: Ipv4Addr) -> Result<Ipv4Addr> {
    let peer_ip = match peer.ip() {
        IpAddr::V4(v4) => v4,
        IpAddr::V6(_) => {
            return Err(AetherError::Other(
                "TUN mode currently requires IPv4 peer".into(),
            ))
        }
    };
    let (_iface, gw) = default_gateway()?;
    let if_index = interface_index(ADAPTER_NAME)?;

    // Keep path to edge peer on physical gateway (not via TUN).
    let peer_s = peer_ip.to_string();
    let gw_s = gw.to_string();
    run_cmd(
        "route",
        &[
            "add",
            &peer_s,
            "mask",
            "255.255.255.255",
            &gw_s,
            "metric",
            "1",
        ],
    )?;

    // Split default via TUN: next-hop MUST be the TUN interface IP (not 0.0.0.0).
    // On-link 0.0.0.0 next-hop often installs but never carries traffic on WinTUN.
    let ifs = if_index.to_string();
    let via = ipv4.to_string();
    for dest in ["0.0.0.0", "128.0.0.0"] {
        let mask = "128.0.0.0";
        // Prefer delete-then-add so restarts don't leave stale/conflicting routes.
        let _ = run_cmd("route", &["delete", dest, "mask", mask]);
        if let Err(error) = run_cmd(
            "route",
            &[
                "add",
                dest,
                "mask",
                mask,
                &via,
                "metric",
                "1",
                "IF",
                &ifs,
            ],
        ) {
            remove_routes(peer, ipv4, gw);
            return Err(error);
        }
    }
    log::info!(
        "[tun] routes installed: peer exclude via {gw_s}, split-default {via} IF={if_index}"
    );
    Ok(gw)
}

fn remove_routes(peer: SocketAddr, ipv4: Ipv4Addr, gateway: Ipv4Addr) {
    if let IpAddr::V4(v4) = peer.ip() {
        let gateway = gateway.to_string();
        let _ = run_cmd(
            "route",
            &[
                "delete",
                &v4.to_string(),
                "mask",
                "255.255.255.255",
                &gateway,
            ],
        );
    }
    let via = ipv4.to_string();
    let _ = run_cmd("route", &["delete", "0.0.0.0", "mask", "128.0.0.0", &via]);
    let _ = run_cmd("route", &["delete", "128.0.0.0", "mask", "128.0.0.0", &via]);
    // Fallback if Windows stored route without matching via string.
    let _ = run_cmd("route", &["delete", "0.0.0.0", "mask", "128.0.0.0"]);
    let _ = run_cmd("route", &["delete", "128.0.0.0", "mask", "128.0.0.0"]);
}

fn route_state_path() -> Option<PathBuf> {
    let dir = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("TEMP").map(PathBuf::from))?;
    Some(dir.join("AetherNext").join("tun-routes.json"))
}

#[derive(serde::Serialize, serde::Deserialize)]
struct RouteState {
    peer: String,
    ipv4: String,
    gateway: String,
    /// Process id that installed routes (stale if dead).
    pid: u32,
}

fn persist_routes(peer: SocketAddr, ipv4: Ipv4Addr, gateway: Ipv4Addr) {
    let Some(path) = route_state_path() else {
        return;
    };
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let state = RouteState {
        peer: peer.ip().to_string(),
        ipv4: ipv4.to_string(),
        gateway: gateway.to_string(),
        pid: std::process::id(),
    };
    if let Ok(body) = serde_json::to_vec_pretty(&state) {
        let tmp = path.with_extension("json.tmp");
        if std::fs::write(&tmp, body).is_ok() {
            let _ = std::fs::rename(tmp, path);
        }
    }
}

fn clear_persisted_routes() {
    if let Some(path) = route_state_path() {
        let _ = std::fs::remove_file(path);
    }
}

/// Remove routes left by a crashed previous engine process.
pub fn recover_stale_routes() {
    let Some(path) = route_state_path() else {
        return;
    };
    let Ok(bytes) = std::fs::read(&path) else {
        return;
    };
    let Ok(state) = serde_json::from_slice::<RouteState>(&bytes) else {
        let _ = std::fs::remove_file(&path);
        return;
    };
    // If installer process still lives, leave routes alone (another instance).
    if state.pid != 0 && process_alive(state.pid) {
        return;
    }
    let peer_ip = state.peer.parse::<IpAddr>().ok();
    let ipv4 = state.ipv4.parse::<Ipv4Addr>().ok();
    let gateway = state.gateway.parse::<Ipv4Addr>().ok();
    if let (Some(IpAddr::V4(peer_ip)), Some(ipv4), Some(gateway)) = (peer_ip, ipv4, gateway) {
        log::warn!("[tun] recovering stale routes from previous session");
        remove_routes(SocketAddr::new(IpAddr::V4(peer_ip), 0), ipv4, gateway);
    }
    let _ = std::fs::remove_file(path);
}

fn process_alive(pid: u32) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // tasklist is slow; use OpenProcess via wmic-less approach: try kill with signal 0 equivalent.
        // On Windows, OpenProcess + GetExitCodeProcess would need FFI; use `tasklist /FI PID eq`.
        let out = Command::new("tasklist")
            .args(["/FI", &format!("PID eq {pid}"), "/NH"])
            .creation_flags(0x08000000)
            .output();
        match out {
            Ok(o) => {
                let s = String::from_utf8_lossy(&o.stdout);
                s.contains(&pid.to_string())
            }
            Err(_) => false,
        }
    }
    #[cfg(not(windows))]
    {
        let _ = pid;
        false
    }
}

pub struct TunHandle {
    _adapter: Arc<Adapter>,
    session: Arc<Session>,
    peer: SocketAddr,
    ipv4: Ipv4Addr,
    gateway: Ipv4Addr,
}

impl Drop for TunHandle {
    fn drop(&mut self) {
        remove_routes(self.peer, self.ipv4, self.gateway);
        clear_persisted_routes();
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

    // Prefer existing adapter; create if missing. Orphaned "Aether 1" names are cleaned by WinTun.
    let adapter = match Adapter::open(&wintun, ADAPTER_NAME) {
        Ok(a) => {
            log::info!("[tun] opened existing adapter {ADAPTER_NAME}");
            a
        }
        Err(e) => {
            log::info!("[tun] open {ADAPTER_NAME}: {e}; creating");
            Adapter::create(&wintun, ADAPTER_NAME, TUNNEL_TYPE, None)
                .map_err(|e| AetherError::Other(format!("create adapter: {e}")))?
        }
    };

    let ipv4 = parse_v4(ipv4_cidr)?;
    // Wait briefly for adapter to appear in Windows.
    tokio::time::sleep(Duration::from_millis(300)).await;
    configure_adapter_ip(ADAPTER_NAME, ipv4)?;

    let session = adapter
        .start_session(MAX_RING_CAPACITY)
        .map_err(|e| AetherError::Other(format!("start session: {e}")))?;
    recover_stale_routes();
    let gateway = match install_routes(peer, ipv4) {
        Ok(gateway) => {
            persist_routes(peer, ipv4, gateway);
            gateway
        }
        Err(error) => {
            let _ = session.shutdown();
            return Err(error);
        }
    };

    // Build handle first so Drop cleans routes/session if thread spawn fails.
    let handle = TunHandle {
        _adapter: adapter,
        session: session.clone(),
        peer,
        ipv4,
        gateway,
    };

    // High-throughput path: dedicated OS thread reads WinTUN ring (kernel packets)
    // and feeds the userspace tunnel encryptor. App TCP lives in the Windows stack.
    let session_r = session.clone();
    let out_tx = outbound_tx;
    std::thread::Builder::new()
        .name("aether-tun-rx".into())
        .spawn(move || {
            let mut n: u64 = 0;
            while let Ok(pkt) = session_r.receive_blocking() {
                let data = pkt.bytes().to_vec();
                if data.is_empty() {
                    continue;
                }
                n += 1;
                if n == 1 || n % 5000 == 0 {
                    log::info!("[tun] rx from kernel packets={n} last_len={}", data.len());
                }
                if out_tx.blocking_send(data).is_err() {
                    break;
                }
            }
            log::info!("[tun] rx thread exit after {n} packets");
        })
        .map_err(|e| AetherError::Other(format!("tun rx thread: {e}")))?;

    // Kernel TX path: write decrypted tunnel packets into WinTUN for the OS stack.
    let session_w = session;
    std::thread::Builder::new()
        .name("aether-tun-tx".into())
        .spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build();
            let Ok(rt) = rt else { return };
            rt.block_on(async move {
                let mut inbound_rx = inbound_rx;
                let mut n: u64 = 0;
                while let Some(first) = inbound_rx.recv().await {
                    let mut batch = vec![first];
                    while batch.len() < 64 {
                        match inbound_rx.try_recv() {
                            Ok(p) => batch.push(p),
                            Err(_) => break,
                        }
                    }
                    let session = session_w.clone();
                    let batch_len = batch.len();
                    let wrote = tokio::task::spawn_blocking(move || {
                        let mut ok = 0u32;
                        for pkt in batch {
                            if pkt.is_empty() || pkt.len() > u16::MAX as usize {
                                continue;
                            }
                            if let Ok(mut packet) = session.allocate_send_packet(pkt.len() as u16) {
                                packet.bytes_mut()[..pkt.len()].copy_from_slice(&pkt);
                                session.send_packet(packet);
                                ok += 1;
                            }
                        }
                        ok
                    })
                    .await
                    .unwrap_or(0);
                    n += wrote as u64;
                    if n <= batch_len as u64 || n % 5000 == 0 {
                        log::info!("[tun] tx to kernel packets={n} batch={batch_len}");
                    }
                }
                log::info!("[tun] tx thread exit after {n} packets");
            });
        })
        .map_err(|e| AetherError::Other(format!("tun tx thread: {e}")))?;

    log::info!(
        "[tun] adapter {ADAPTER_NAME} up {ipv4}/32 peer exclude {}",
        peer.ip()
    );
    log::info!("[tun] bridge active (kernel TCP / WinTUN high-throughput path)");
    Ok(handle)
}
