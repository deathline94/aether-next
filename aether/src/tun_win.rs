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
    match crate::runtime_env::var("AETHER_TUN") {
        Some(v) => {
            let v = v.trim().to_lowercase();
            v == "1" || v == "true" || v == "yes" || v == "on"
        }
        None => false,
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

/// Defense-in-depth: reject any interpolated value that could break out of a
/// single-quoted PowerShell string literal (L1 fix). Inputs here are typed IPs
/// and a constant adapter name, so this should never fire in practice; it guards
/// against future call sites passing attacker-influenced strings into scripts.
fn ps_literal_is_safe(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, ' ' | '-' | '_' | '.' | ':'))
}

fn parse_v4(s: &str) -> Result<Ipv4Addr> {
    let ip = s.split('/').next().unwrap_or(s);
    ip.parse()
        .map_err(|_| AetherError::Other(format!("bad ipv4 {s}")))
}

fn default_gateway() -> Result<(u32, Ipv4Addr)> {
    let script = r#"
$ErrorActionPreference = 'Stop'
$best = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' |
  Where-Object { $_.NextHop -ne '0.0.0.0' -and $_.InterfaceAlias -ne 'Aether' } |
  ForEach-Object {
    $ifm = (Get-NetIPInterface -AddressFamily IPv4 -InterfaceIndex $_.InterfaceIndex).InterfaceMetric
    [PSCustomObject]@{ InterfaceIndex=$_.InterfaceIndex; NextHop=$_.NextHop; TotalMetric=($_.RouteMetric + $ifm) }
  } | Sort-Object TotalMetric | Select-Object -First 1
if (-not $best) { throw 'physical default gateway not found' }
Write-Output ($best.InterfaceIndex.ToString() + '|' + $best.NextHop)
"#;
    let out = ps(script)?;
    let line = out.lines().map(str::trim).find(|line| line.contains('|'))
        .ok_or_else(|| AetherError::Other("bad default gateway output".into()))?;
    let (idx, gateway) = line.split_once('|')
        .ok_or_else(|| AetherError::Other("bad default gateway output".into()))?;
    let idx = idx.trim().parse::<u32>()
        .map_err(|_| AetherError::Other("bad default interface index".into()))?;
    let gateway = gateway.trim().parse::<Ipv4Addr>()
        .map_err(|_| AetherError::Other("bad default gateway".into()))?;
    Ok((idx, gateway))
}

fn ps(cmd: &str) -> Result<String> {
    run_cmd(
        "powershell",
        &["-NoProfile", "-NonInteractive", "-Command", cmd],
    )
}

fn configure_adapter_ip(name: &str, ipv4: Ipv4Addr) -> Result<()> {
    if !ps_literal_is_safe(name) {
        return Err(AetherError::Other(format!("unsafe adapter name: {name:?}")));
    }
    // WireGuard-style: /32 on tunnel NIC, no gateway, low metric, DNS via tunnel.
    let mtu = crate::mtu::current().clamp(1280, 1400);
    let ip = ipv4.to_string();
    // Enable + purge old IPv4 config, then set address/DNS/MTU/metric in one shot.
    // Also disable IPv6 on the adapter to prevent router advertisements from overriding.
    let script = format!(
        r#"
$ErrorActionPreference = 'Stop'
$n = '{name}'
Enable-NetAdapter -Name $n -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
Disable-NetAdapterBinding -Name $n -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue | Out-Null
Get-NetIPAddress -InterfaceAlias $n -AddressFamily IPv4 -ErrorAction SilentlyContinue |
  Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
Get-NetRoute -InterfaceAlias $n -ErrorAction SilentlyContinue |
  Where-Object {{ $_.DestinationPrefix -ne '255.255.255.255/32' }} |
  Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
New-NetIPAddress -InterfaceAlias $n -IPAddress '{ip}' -PrefixLength 32 -PolicyStore ActiveStore | Out-Null
Set-DnsClientServerAddress -InterfaceAlias $n -ServerAddresses @('1.1.1.1','1.0.0.1')
Set-NetIPInterface -InterfaceAlias $n -InterfaceMetric 1 -NlMtuBytes {mtu} -ErrorAction SilentlyContinue
Write-Output 'ok'
"#
    );
    match ps(&script) {
        Ok(out) => log::info!("[tun] adapter {name} configured via NetIP ({})", out.trim()),
        Err(e) => {
            // Fallback to netsh if NetCmdlets fail.
            log::warn!("[tun] NetIP configure failed ({e}); trying netsh");
            run_cmd(
                "netsh",
                &[
                    "interface",
                    "ip",
                    "set",
                    "address",
                    &format!("name={name}"),
                    "static",
                    &ip,
                    "255.255.255.255",
                    "none",
                ],
            )?;
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
                    "ipv4",
                    "set",
                    "subinterface",
                    name,
                    &format!("mtu={mtu}"),
                    "store=active",
                ],
            );
            let _ = run_cmd(
                "netsh",
                &["interface", "ip", "set", "interface", name, "metric=1"],
            );
        }
    }
    log::info!("[tun] adapter {name} mtu={mtu} metric=1 ip={ip}/32");
    Ok(())
}

fn interface_index(name: &str) -> Result<u32> {
    if !ps_literal_is_safe(name) {
        return Err(AetherError::Other(format!("unsafe adapter name: {name:?}")));
    }
    let out = ps(&format!(
        "(Get-NetAdapter -Name '{name}' -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty ifIndex)"
    ))?;
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
    let (physical_if_index, gw) = default_gateway()?;
    let if_index = interface_index(ADAPTER_NAME)?;
    let peer_s = peer_ip.to_string();
    let gw_s = gw.to_string();
    let via = ipv4.to_string();

    // WireGuard-Windows style: on-link split default on tunnel IF (NextHop 0.0.0.0),
    // plus host route for edge peer via physical gateway. Prefer New-NetRoute.
    let script = format!(
        r#"
$ErrorActionPreference = 'Stop'
$tunIf = {if_index}
$peer = '{peer_s}/32'
$gw = '{gw_s}'
$via = '{via}'
$physIf = {physical_if_index}
# Drop stale split defaults
foreach ($p in @('0.0.0.0/1','128.0.0.0/1','::/1','8000::/1')) {{
  Get-NetRoute -DestinationPrefix $p -ErrorAction SilentlyContinue |
    Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
}}
# Peer exclude: force edge traffic out physical gateway
Get-NetRoute -DestinationPrefix $peer -ErrorAction SilentlyContinue |
  Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
# Pin the outer transport to the selected physical interface.
New-NetRoute -DestinationPrefix $peer -InterfaceIndex $physIf -NextHop $gw -RouteMetric 0 -PolicyStore ActiveStore -ErrorAction Stop | Out-Null
# Split default ON-LINK on WinTUN (this is what WireGuard uses)
foreach ($p in @('0.0.0.0/1','128.0.0.0/1')) {{
  New-NetRoute -DestinationPrefix $p -InterfaceIndex $tunIf -NextHop '0.0.0.0' -RouteMetric 0 -PolicyStore ActiveStore -ErrorAction Stop | Out-Null
  if (-not (Get-NetRoute -DestinationPrefix $p -InterfaceIndex $tunIf -ErrorAction SilentlyContinue)) {{
    # Fallback: next-hop = tunnel IP + IF
    $dest = $p.Split('/')[0]
    $mask = if ($p -like '0.0.0.0/*') {{ '128.0.0.0' }} else {{ '128.0.0.0' }}
    route add $dest mask $mask $via metric 1 IF $tunIf | Out-Null
  }}
}}
# IPv6 stays disabled until this TUN path supports it.
# Verify
$v = @(Get-NetRoute -InterfaceIndex $tunIf -ErrorAction SilentlyContinue |
  Where-Object {{ $_.DestinationPrefix -in @('0.0.0.0/1','128.0.0.0/1') }} |
  Select-Object -ExpandProperty DestinationPrefix)
$peerOk = Get-NetRoute -DestinationPrefix $peer -InterfaceIndex $physIf -ErrorAction SilentlyContinue
if ($v.Count -lt 2 -or -not $peerOk) {{ throw 'route verification failed' }}
Write-Output ('ok tunIf=' + $tunIf + ' physIf=' + $physIf + ' routes=' + ($v -join ','))
"#
    );
    match ps(&script) {
        Ok(out) => {
            let t = out.trim();
            if t.contains("WARN") {
                log::warn!("[tun] route install warning: {t}");
            } else {
                log::info!("[tun] routes installed: peer exclude via {gw_s}, {t}");
            }
        }
        Err(e) => {
            log::warn!("[tun] New-NetRoute failed ({e}); falling back to route.exe");
            let ifs = if_index.to_string();
            let _ = run_cmd(
                "route",
                &["add", &peer_s, "mask", "255.255.255.255", &gw_s, "metric", "1"],
            );
            for dest in ["0.0.0.0", "128.0.0.0"] {
                let _ = run_cmd("route", &["delete", dest, "mask", "128.0.0.0"]);
                run_cmd(
                    "route",
                    &["add", dest, "mask", "128.0.0.0", &via, "metric", "1", "IF", &ifs],
                )?;
            }
            log::info!(
                "[tun] routes installed (route.exe): peer via {gw_s}, split-default {via} IF={if_index}"
            );
        }
    }
    Ok(gw)
}

fn remove_routes(peer: SocketAddr, ipv4: Ipv4Addr, gateway: Ipv4Addr) {
    let _ = ipv4;
    let peer_s = match peer.ip() {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(_) => return,
    };
    let gw_s = gateway.to_string();
    let script = format!(
        r#"
foreach ($p in @('0.0.0.0/1','128.0.0.0/1','::/1','8000::/1','{peer_s}/32')) {{
  Get-NetRoute -DestinationPrefix $p -ErrorAction SilentlyContinue |
    Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
}}
route delete {peer_s} mask 255.255.255.255 {gw_s} 2>$null
route delete 0.0.0.0 mask 128.0.0.0 2>$null
route delete 128.0.0.0 mask 128.0.0.0 2>$null
"#
    );
    let _ = ps(&script);
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
            // Never block kernel packet reading: use try_send, drop on backpressure.
            while let Ok(pkt) = session_r.receive_blocking() {
                let data = pkt.bytes().to_vec();
                if data.is_empty() {
                    continue;
                }
                n += 1;
                if n == 1 || n % 5000 == 0 {
                    log::info!("[tun] rx from kernel packets={n} last_len={}", data.len());
                }
                match out_tx.try_send(data) {
                    Ok(_) => {}
                    Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => break,
                    Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {} // drop to keep WinTUN ring moving
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
                            // WinTUN expects raw IP packets. Ensure version is 4 (no ethernet header).
                            if pkt[0] >> 4 == 4 {
                                if let Ok(mut packet) = session.allocate_send_packet(pkt.len() as u16) {
                                    packet.bytes_mut()[..pkt.len()].copy_from_slice(&pkt);
                                    session.send_packet(packet);
                                    ok += 1;
                                }
                            } else if pkt[0] >> 4 == 6 {
                                // Drop IPv6 — tunnel is currently IPv4 only.
                            } else {
                                // Sometimes Netstack adds ethernet header? Strip it if so.
                                if pkt.len() > 14 && pkt[14] >> 4 == 4 {
                                    let ip_len = pkt.len() - 14;
                                    if let Ok(mut packet) = session.allocate_send_packet(ip_len as u16) {
                                        packet.bytes_mut()[..ip_len].copy_from_slice(&pkt[14..]);
                                        session.send_packet(packet);
                                        ok += 1;
                                    }
                                }
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
