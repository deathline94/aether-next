use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use wintun_bindings::{Adapter, Session, MAX_RING_CAPACITY};

use crate::error::{AetherError, Result};
use crate::route_repair::{RouteIntent, RouteJournal, ScopeKind};

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
    if let Some(p) = crate::runtime_env::var("AETHER_WINTUN") {
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

fn configure_adapter_ip(name: &str, ipv4: Ipv4Addr, mtu: usize) -> Result<()> {
    if !ps_literal_is_safe(name) {
        return Err(AetherError::Other(format!("unsafe adapter name: {name:?}")));
    }
    // WireGuard-style: /32 on tunnel NIC, no gateway, low metric, DNS via tunnel.
    // MTU is threaded in from the tunnel runner (the H3 data plane caps it to 1280
    // to fit QUIC DATAGRAMs) instead of read from a global, so a concurrent
    // scan/tunnel in the same process cannot clobber it.
    let mtu = mtu.clamp(1280, 1400);
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

/// Build the intent journal for the routes this function is about to create.
///
/// Written and flushed to disk **before** the first mutation, so a process that
/// dies mid-install leaves a replayable record instead of a half-configured host
/// with no note of what it touched.
fn plan_journal(
    peer_ip: Ipv4Addr,
    ipv4: Ipv4Addr,
    gateway: Ipv4Addr,
    tun_if: u32,
    phys_if: u32,
) -> RouteJournal {
    let mut entries = Vec::new();
    for dest in crate::route_repair::SPLIT_DEFAULTS_V4 {
        let (destination, mask) = dest.split_once('/').unwrap_or((dest, "0"));
        entries.push(RouteIntent {
            destination: destination.into(),
            mask: crate::route_repair::prefix_len_to_mask(
                mask.parse::<u32>().unwrap_or(0)
            ),
            // On-link on the tunnel interface, WireGuard-style.
            next_hop: "0.0.0.0".into(),
            if_index: tun_if,
            family: 2,
        });
    }
    entries.push(RouteIntent {
        destination: peer_ip.to_string(),
        mask: "255.255.255.255".into(),
        next_hop: gateway.to_string(),
        if_index: phys_if,
        family: 2,
    });
    RouteJournal {
        version: crate::route_repair::JOURNAL_VERSION,
        created_unix: crate::trust::now_unix(),
        creator_pid: std::process::id(),
        tun_alias: ADAPTER_NAME.into(),
        tun_if_index: tun_if,
        phys_if_index: phys_if,
        gateway: gateway.to_string(),
        tunnel_ipv4: ipv4.to_string(),
        peer_ipv4: peer_ip.to_string(),
        entries,
        // Captured by configure_adapter_ip's caller on a future pass; the
        // reset path today restores to Automatic/empty, which is the safe
        // default for an adapter this process created.
        before: None,
    }
}

fn install_routes(peer: SocketAddr, ipv4: Ipv4Addr) -> Result<RouteJournal> {
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

    // Journal first, fail closed: an install we cannot record is an install we
    // cannot undo, and undoing is the whole point.
    let mut journal = plan_journal(peer_ip, ipv4, gw, if_index, physical_if_index);
    if let Some(path) = crate::route_repair::journal_path() {
        crate::route_repair::write_journal(&path, &journal)
            .map_err(|e| AetherError::Other(format!("refusing to mutate routes: {e}")))?;
    }

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
# Drop stale split defaults on our tunnel interface only
foreach ($p in @('0.0.0.0/1','128.0.0.0/1','::/1','8000::/1')) {{
  Get-NetRoute -DestinationPrefix $p -InterfaceIndex $tunIf -ErrorAction SilentlyContinue |
    Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
}}
# Peer exclude: force edge traffic out physical gateway
Get-NetRoute -DestinationPrefix $peer -InterfaceIndex $physIf -ErrorAction SilentlyContinue |
  Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
$added = @()
try {{
  # Pin the outer transport to the selected physical interface.
  New-NetRoute -DestinationPrefix $peer -InterfaceIndex $physIf -NextHop $gw -RouteMetric 0 -PolicyStore ActiveStore -ErrorAction Stop | Out-Null
  $added += [PSCustomObject]@{{ DestinationPrefix = $peer; InterfaceIndex = $physIf }}
  # Split default ON-LINK on WinTUN (this is what WireGuard uses)
  foreach ($p in @('0.0.0.0/1','128.0.0.0/1')) {{
    New-NetRoute -DestinationPrefix $p -InterfaceIndex $tunIf -NextHop '0.0.0.0' -RouteMetric 0 -PolicyStore ActiveStore -ErrorAction Stop | Out-Null
    $added += [PSCustomObject]@{{ DestinationPrefix = $p; InterfaceIndex = $tunIf }}
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
}} catch {{
  foreach ($r in $added) {{
    Remove-NetRoute -DestinationPrefix $r.DestinationPrefix -InterfaceIndex $r.InterfaceIndex -Confirm:$false -ErrorAction SilentlyContinue
  }}
  throw
}}
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
            let phys_s = physical_if_index.to_string();
            // 1. Mandatory peer escape route pinned to physical interface
            if let Err(err) = run_cmd(
                "route",
                &["add", &peer_s, "mask", "255.255.255.255", &gw_s, "metric", "1", "IF", &phys_s],
            ) {
                clear_journal();
                return Err(AetherError::Other(format!(
                    "failed to install physical peer escape route: {err}"
                )));
            }

            // 2. Transactional split-default installation with rollback on failure
            let mut installed_splits = Vec::new();
            for dest in ["0.0.0.0", "128.0.0.0"] {
                let _ = run_cmd("route", &["delete", dest, "mask", "128.0.0.0", "IF", &ifs]);
                if let Err(add_err) = run_cmd(
                    "route",
                    &["add", dest, "mask", "128.0.0.0", &via, "metric", "1", "IF", &ifs],
                ) {
                    log::error!("[tun] failed to add split route {dest} ({add_err}); rolling back routes");
                    for installed in installed_splits {
                        let _ = run_cmd("route", &["delete", installed, "mask", "128.0.0.0", "IF", &ifs]);
                    }
                    let _ = run_cmd("route", &["delete", &peer_s, "mask", "255.255.255.255", "IF", &phys_s]);
                    clear_journal();
                    return Err(add_err);
                }
                installed_splits.push(dest);
            }
            // route.exe installs the split defaults *via the tunnel address*, not
            // on-link. The journal must describe what actually exists, or a later
            // next-hop-scoped removal would match nothing and leave the routes in
            // place forever.
            for entry in &mut journal.entries {
                if entry.next_hop == "0.0.0.0" {
                    entry.next_hop = via.clone();
                }
            }
            if let Some(path) = crate::route_repair::journal_path() {
                if let Err(err) = crate::route_repair::write_journal(&path, &journal) {
                    log::error!("[tun] installed routes but the journal is stale: {err}");
                }
            }
            log::info!(
                "[tun] routes installed (route.exe): peer via {gw_s} IF={physical_if_index}, split-default {via} IF={if_index}"
            );
        }
    }
    Ok(journal)
}

/// Remove exactly the routes the journal says we created, and nothing else.
///
/// Every deletion is scoped by a recorded interface index or, failing that, by
/// our own next-hop address; where neither is known the plan refuses. The
/// previous code fell back to removing `0.0.0.0/1` and `128.0.0.0/1` from
/// *every* interface whenever the recorded indexes were 0 — which is the exact
/// prefix pair OpenVPN/Cisco/AnyConnect use for split tunnelling, so a legacy or
/// truncated state file let an Aether disconnect take down an unrelated VPN.
fn remove_routes(journal: &RouteJournal) {
    let plan = journal.removal_plan();
    if plan.is_empty() {
        log::warn!("[tun] no removal plan for this journal; leaving routes untouched");
        return;
    }
    let mut script = String::from("$ErrorActionPreference = 'SilentlyContinue'\n");
    let mut issued = 0usize;
    let mut refused = 0usize;
    for p in plan {
        let Some(cidr) = crate::route_repair::as_cidr(&p.destination, &p.mask) else {
            log::error!(
                "[tun] cannot express {}/{:?} as a prefix; refusing this removal",
                p.destination, p.mask
            );
            refused += 1;
            continue;
        };
        match &p.scope {
            ScopeKind::Interface { if_index } => {
                script.push_str(&format!(
                    "Get-NetRoute -DestinationPrefix '{cidr}' -InterfaceIndex {if_index} -ErrorAction SilentlyContinue |\n  Where-Object {{ $_.InterfaceIndex -eq {if_index} }} |\n  Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue\n"
                ));
                issued += 1;
            }
            ScopeKind::NextHop { next_hop } if ps_literal_is_safe(next_hop) => {
                script.push_str(&format!(
                    "Get-NetRoute -DestinationPrefix '{cidr}' -ErrorAction SilentlyContinue |\n  Where-Object {{ $_.NextHop -eq '{next_hop}' }} |\n  Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue\n"
                ));
                issued += 1;
            }
            ScopeKind::NextHop { next_hop } => {
                log::error!("[tun] refusing removal for {cidr}: rejected next-hop {next_hop:?}");
                refused += 1;
            }
            ScopeKind::Refused { why } => {
                log::error!("[tun] refusing to remove {cidr}: {why}");
                refused += 1;
            }
        }
    }
    if issued > 0 {
        // One shell spawn for the whole plan, not one per prefix: the teardown
        // has to fit inside the supervisor's grace window or it never runs.
        if let Err(e) = ps(&script) {
            log::error!("[tun] route removal reported an error: {e}");
        }
    }
    log::info!(
        "[tun] route removal: {} scoped deletion(s) issued, {} refused",
        issued,
        refused
    );
}

/// M1 fix (continued): undo what configure_adapter_ip set on the tunnel NIC —
/// pinned DNS servers (1.1.1.1/1.0.0.1) and InterfaceMetric=1 used to persist
/// after disconnect/crash while the adapter lingered, degrading or breaking name
/// resolution via a now-dead path. Called on drop and on stale-state recovery.
fn reset_adapter_config(name: &str) {
    if !ps_literal_is_safe(name) {
        log::error!("[tun] refusing to reset adapter config for unsafe alias {name:?}");
        return;
    }
    let script = format!(
        r#"
Set-DnsClientServerAddress -InterfaceAlias '{name}' -ResetServerAddresses -ErrorAction SilentlyContinue
Set-NetIPInterface -InterfaceAlias '{name}' -AutomaticMetric Enabled -ErrorAction SilentlyContinue
"#
    );
    // Teardown failures used to be discarded with `let _ =`, so a host left with
    // a dead NIC's pinned resolver looked like a clean disconnect.
    if let Err(e) = ps(&script) {
        log::error!("[tun] adapter {name} reset failed: {e}");
    }
}

fn clear_journal() {
    if let Some(path) = crate::route_repair::journal_path() {
        if let Err(e) = std::fs::remove_file(&path) {
            if e.kind() != std::io::ErrorKind::NotFound {
                log::error!("[tun] could not clear journal {}: {e}", path.display());
            }
        }
    }
    // The pre-journal file name, cleaned up so an upgrade cannot leave a second
    // stale record that a future reader might trust over the journal.
    if let Some(legacy) = legacy_state_path() {
        let _ = std::fs::remove_file(legacy);
    }
}

fn legacy_state_path() -> Option<PathBuf> {
    let dir = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("TEMP").map(PathBuf::from))?;
    Some(dir.join("AetherNext").join("tun-routes.json"))
}

/// Upgrade the pre-journal `tun-routes.json` into a journal.
///
/// The legacy record carries the tunnel address, so removal can still be
/// next-hop scoped even when its interface indexes are zero — which is exactly
/// the case that used to trigger global prefix deletion.
fn journal_from_legacy(state: &serde_json::Value) -> Option<RouteJournal> {
    let g = |k: &str| state.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
    let u = |k: &str| state.get(k).and_then(|v| v.as_u64()).map(|v| v as u32).unwrap_or(0);
    let tunnel_ipv4 = g("ipv4");
    let peer_ipv4 = g("peer");
    if tunnel_ipv4.is_empty() && peer_ipv4.is_empty() {
        return None;
    }
    let tun_if = u("tun_if");
    let phys_if = u("phys_if");
    let mut entries = Vec::new();
    for dest in crate::route_repair::SPLIT_DEFAULTS_V4 {
        let (destination, mask) = dest.split_once('/').unwrap_or((dest, "0"));
        entries.push(RouteIntent {
            destination: destination.into(),
            mask: crate::route_repair::prefix_len_to_mask(mask.parse::<u32>().unwrap_or(0)),
            next_hop: if tun_if != 0 { "0.0.0.0".into() } else { tunnel_ipv4.clone() },
            if_index: tun_if,
            family: 2,
        });
    }
    if !peer_ipv4.is_empty() {
        entries.push(RouteIntent {
            destination: peer_ipv4.clone(),
            mask: "255.255.255.255".into(),
            next_hop: g("gateway"),
            if_index: phys_if,
            family: 2,
        });
    }
    Some(RouteJournal {
        version: crate::route_repair::JOURNAL_VERSION,
        created_unix: 0,
        creator_pid: u("pid"),
        tun_alias: ADAPTER_NAME.into(),
        tun_if_index: tun_if,
        phys_if_index: phys_if,
        gateway: g("gateway"),
        tunnel_ipv4,
        peer_ipv4,
        entries,
        before: None,
    })
}

/// Remove routes left by a crashed previous engine process.
pub fn recover_stale_routes() {
    let mut handled = false;
    if let Some(path) = crate::route_repair::journal_path() {
        match RouteJournal::load_opt(&path) {
            Ok(Some(journal)) => {
                let alive = journal.creator_pid != 0 && process_alive(journal.creator_pid);
                if alive {
                    log::info!(
                        "[tun] routes owned by live pid {}; leaving them alone",
                        journal.creator_pid
                    );
                    return;
                }
                if journal.creator_pid != 0 {
                    log::warn!(
                        "[tun] recovering stale routes from dead pid {}",
                        journal.creator_pid
                    );
                    remove_routes(&journal);
                    reset_adapter_config(ADAPTER_NAME);
                    handled = true;
                }
                let _ = std::fs::remove_file(&path);
            }
            Ok(None) => {}
            Err(e) => log::error!("[tun] journal unreadable, cannot verify host state: {e}"),
        }
    }
    // Pre-journal state file from an older build.
    if let Some(legacy) = legacy_state_path() {
        if let Ok(raw) = std::fs::read(&legacy) {
            if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&raw) {
                if let Some(journal) = journal_from_legacy(&v) {
                    if journal.is_abandoned(process_alive(journal.creator_pid)) {
                        log::warn!(
                            "[tun] recovering legacy routes from dead pid {}",
                            journal.creator_pid
                        );
                        remove_routes(&journal);
                        reset_adapter_config(ADAPTER_NAME);
                        handled = true;
                    }
                }
            }
            let _ = std::fs::remove_file(&legacy);
        }
    }
    if handled {
        log::info!("[tun] stale route recovery complete");
    }
}

/// Is this pid ours, right now?
///
/// Exact field match. The shipped version asked `tasklist` for the pid and then
/// substring-searched the whole output, so pid `4` matched the working-set and
/// session columns of unrelated rows: a long-dead holder looked alive, stale
/// routes were never cleaned, and the machine stayed black-holed.
fn process_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    use std::os::windows::process::CommandExt;
    let out = Command::new("tasklist")
        .args([
            "/FI",
            &format!("PID eq {pid}"),
            "/NH",
            "/FO",
            "CSV",
        ])
        .creation_flags(0x08000000)
        .output();
    let Ok(o) = out else {
        log::warn!("[tun] liveness probe for pid {pid} failed to run; assuming dead");
        return false;
    };
    if !o.status.success() {
        log::warn!(
            "[tun] liveness probe for pid {pid} exited {}: assuming dead",
            o.status.code().unwrap_or(-1)
        );
        return false;
    }
    for line in String::from_utf8_lossy(&o.stdout).lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("INFO:") {
            continue;
        }
        // CSV row: "image.exe","pid","session name",...
        if let Some(field) = line.split(',').nth(1) {
            if field.trim_matches('"').parse::<u32>() == Ok(pid) {
                return true;
            }
        }
    }
    false
}


pub struct TunHandle {
    _adapter: Arc<Adapter>,
    session: Arc<Session>,
    journal: RouteJournal,
}

impl Drop for TunHandle {
    fn drop(&mut self) {
        remove_routes(&self.journal);
        clear_journal();
        // Restore adapter DNS + metric so the lingering NIC cannot keep
        // hijacking name resolution after disconnect.
        reset_adapter_config(ADAPTER_NAME);
        let _ = self.session.shutdown();
        log::info!("[tun] cleaned routes, adapter config, and session");
    }
}

pub async fn spawn(
    ipv4_cidr: &str,
    peer: SocketAddr,
    mtu: usize,
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
    configure_adapter_ip(ADAPTER_NAME, ipv4, mtu)?;

    let session = adapter
        .start_session(MAX_RING_CAPACITY)
        .map_err(|e| AetherError::Other(format!("start session: {e}")))?;
    recover_stale_routes();
    let journal = match install_routes(peer, ipv4) {
        Ok(journal) => journal,
        Err(error) => {
            let _ = session.shutdown();
            return Err(error);
        }
    };

    // Build handle first so Drop cleans routes/session if thread spawn fails.
    let handle = TunHandle {
        _adapter: adapter,
        session: session.clone(),
        journal,
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
                if n == 1 || n.is_multiple_of(5000) {
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
                                // L7 fix: require the actual IPv4 ethertype (0x0800) at
                                // bytes 12-13, not just "byte 14 looks like version 4" —
                                // the old heuristic could forward ARP/garbage frames
                                // whose 15th byte happened to start with 0x4.
                                if pkt.len() > 14
                                    && pkt[12] == 0x08
                                    && pkt[13] == 0x00
                                    && pkt[14] >> 4 == 4
                                {
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
                    if n <= batch_len as u64 || n.is_multiple_of(5000) {
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
