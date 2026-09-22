use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use wintun_bindings::{Adapter, Session, MAX_RING_CAPACITY};

use crate::error::{AetherError, Result};
use crate::route_repair::{
    self, powershell_script, ps_literal_is_safe, JournalOwner, Liveness, MutationVerdict,
    OwnershipRecord, RouteIntent, RouteJournal,
};

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

/// Roots the driver may be loaded from: the directory holding `aether.exe`, and
/// its parent (the packaged layout puts binaries under `install-dir/resources`).
/// Same pair the shell uses for its own allow-list, so the two ends cannot drift.
fn wintun_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if let Some(dir) = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
    {
        let canon = dir.canonicalize().unwrap_or(dir.clone());
        roots.push(canon.clone());
        if let Some(parent) = canon.parent() {
            roots.push(parent.to_path_buf());
        }
    }
    roots
}

/// Accept `raw` only if it resolves to a plain `wintun.dll` inside one of
/// [`wintun_roots`]. Canonicalising *before* the comparison is the point: a
/// `..\`-laden or symlinked path is judged by where it ends up, not how it reads.
fn inside_allowed_root(raw: &str) -> Option<PathBuf> {
    let path = PathBuf::from(raw);
    if !path
        .file_name()
        .and_then(|n| n.to_str())?
        .eq_ignore_ascii_case("wintun.dll")
    {
        return None;
    }
    let canon = path.canonicalize().ok()?;
    if !canon.is_file() {
        return None;
    }
    wintun_roots()
        .into_iter()
        .find(|r| canon.starts_with(r))
        .map(|_| canon)
}

fn find_wintun_dll() -> Result<PathBuf> {
    // Handed over by the parent that already Authenticode-verified this exact
    // file, before it launched us elevated.
    if let Some(p) = crate::keyhandoff::wintun_dll_path() {
        let s = p.to_string_lossy();
        return inside_allowed_root(&s).ok_or_else(|| {
            AetherError::Other(format!(
                "wintun path from the parent ({s}) is not a plain wintun.dll inside the install \
                 directory; refusing to load a driver from anywhere else"
            ))
        });
    }
    // No handoff (CLI, or a shell that did not opt in): only the copy sitting
    // next to the executable. The former `AETHER_WINTUN` environment read and the
    // relative `./wintun.dll` probe are gone — the first let anything that could
    // set the child's environment point the elevated engine at its own DLL, and
    // the second made the *working directory* a component of the trust decision,
    // which is exactly how a `LoadLibrary` hijack becomes a token escalation.
    let beside = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("wintun.dll")));
    if let Some(path) = beside.as_ref().and_then(|p| p.canonicalize().ok()) {
        if path.is_file() {
            return Ok(path);
        }
    }
    Err(AetherError::Other(
        "wintun.dll not found beside aether.exe, and the parent handed over no path".into(),
    ))
}

fn run_cmd(program: &str, args: &[&str]) -> Result<String> {
    // Never by name: this process runs elevated, and the default search order
    // includes the current directory.
    let exe = crate::win_exec::system_exe(program)?;
    let out = Command::new(&exe)
        .args(args)
        .output()
        .map_err(|e| AetherError::Other(format!("{} failed: {e}", exe.display())))?;
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

// Defense-in-depth for interpolated values now lives with the renderer that
// consumes it (`route_repair::ps_literal_is_safe`), so a command string cannot
// be built by one rule and checked by another.

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
    let line = out
        .lines()
        .map(str::trim)
        .find(|line| line.contains('|'))
        .ok_or_else(|| AetherError::Other("bad default gateway output".into()))?;
    let (idx, gateway) = line
        .split_once('|')
        .ok_or_else(|| AetherError::Other("bad default gateway output".into()))?;
    let idx = idx
        .trim()
        .parse::<u32>()
        .map_err(|_| AetherError::Other("bad default interface index".into()))?;
    let gateway = gateway
        .trim()
        .parse::<Ipv4Addr>()
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
    //
    // `mtu` is the value the **data plane** was told to use: the session caps it
    // (H3 DATAGRAMs get 1280, `mtu::resolve_mtu` the per-protocol answer) and
    // threads it here so the adapter cannot disagree with the stack feeding it.
    // The old `clamp(1280, 1400)` broke that on the way *up*: a legal
    // `AETHER_MTU=1200` (see `mtu::env_override`) arrived as 1200 and left as
    // 1280, i.e. the host was configured to emit frames the tunnel then dropped.
    // Nothing is raised above what was threaded; 576 is the IPv4 floor (IPv6 is
    // disabled on this adapter two lines below, so the 1280 v6 floor does not
    // apply) and 1400 is the largest value this path ever asks the adapter for.
    const ADAPTER_MIN_MTU: usize = 576;
    const ADAPTER_MAX_MTU: usize = 1400;
    let mtu = mtu.clamp(ADAPTER_MIN_MTU, ADAPTER_MAX_MTU);
    let ip = ipv4.to_string();
    // Each entry is an `Ipv4Addr` rendered by `to_string`, so the literals below
    // cannot be steered by configuration.
    let resolvers = crate::socks::dns_servers_for_adapter(&crate::socks::configured_dns_servers());
    let dns_literal = resolvers
        .iter()
        .map(|s| format!("'{s}'"))
        .collect::<Vec<_>>()
        .join(",");
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
Set-DnsClientServerAddress -InterfaceAlias $n -ServerAddresses @({dns_literal})
Set-NetIPInterface -InterfaceAlias $n -InterfaceMetric 1 -NlMtuBytes {mtu}
# Read the value back instead of assuming it: a mtu the host refused to take is
# the one failure mode that turns the tunnel into a silent blackhole, and the log
# line below has to describe the adapter, not the request.
$applied = (Get-NetIPInterface -InterfaceAlias $n -AddressFamily IPv4).NlMtuBytes
Write-Output ('ok mtu-requested={mtu} mtu-applied=' + $applied)
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
            let mut dns_args: Vec<String> = vec![
                "interface".into(),
                "ip".into(),
                "set".into(),
                "dns".into(),
                format!("name={name}"),
                "static".into(),
                resolvers[0].to_string(),
                "primary".into(),
            ];
            run_cmd(
                "netsh",
                &dns_args.iter().map(String::as_str).collect::<Vec<_>>(),
            )?;
            if let Some(second) = resolvers.get(1) {
                // `add dns` appends the secondary; `set dns` above replaced the list.
                dns_args[3] = "add".into();
                dns_args[7] = second.to_string();
                run_cmd(
                    "netsh",
                    &dns_args.iter().map(String::as_str).collect::<Vec<_>>(),
                )?;
            }
            if let Err(e) = run_cmd(
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
            ) {
                // Fail the bring-up rather than come up wrong: the adapter keeps
                // its own MTU here, which on the H3 path means full-size inner
                // packets that the data plane then throws away. A tunnel that
                // works for small requests and blackholes everything else is
                // worse than one that says it did not start.
                return Err(AetherError::Other(format!(
                    "cannot set the {name} adapter MTU to {mtu}: {e}"
                )));
            }
            if let Err(e) = run_cmd(
                "netsh",
                &["interface", "ip", "set", "interface", name, "metric=1"],
            ) {
                // Not fatal — the explicit split-default routes carry the
                // traffic — but a higher interface metric means Windows may
                // prefer the physical adapter for anything the journal does not
                // name, and that has to be visible.
                log::error!("[tun] could not set interface metric=1 on {name}: {e}");
            }
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
            mask: crate::route_repair::prefix_len_to_mask(mask.parse::<u32>().unwrap_or(0)),
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
        // T036: the pid alone is not an owner — pids get reused, and a reused pid
        // is how a fresh instance inherits a dead one's claim on the table. The
        // boot id is what makes the pair meaningful.
        boot_id: crate::route_repair::boot_id(),
        tun_alias: ADAPTER_NAME.into(),
        tun_if_index: tun_if,
        phys_if_index: phys_if,
        gateway: gateway.to_string(),
        tunnel_ipv4: ipv4.to_string(),
        peer_ipv4: peer_ip.to_string(),
        entries,
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
    // One host mutation per moment, across processes. Two sessions each install
    // the same split-default prefixes, so the second must not be allowed to
    // describe those prefixes as its own: the lock serialises the act of
    // installing, and `refuse_if_another_instance_holds_a_journal` (T036) makes a
    // live journal by another owner a refusal rather than a takeover.
    let _mutation =
        crate::host_lock::HostMutationGuard::acquire(crate::host_lock::ACQUIRE_TIMEOUT)?;
    let (physical_if_index, gw) = default_gateway()?;
    let if_index = interface_index(ADAPTER_NAME)?;
    let peer_s = peer_ip.to_string();
    let gw_s = gw.to_string();
    let via = ipv4.to_string();

    // Journal first, fail closed: an install we cannot record is an install we
    // cannot undo, and undoing is the whole point.
    //
    // T036 — before the journal is written, ask whether another instance already
    // owns this interface's record. The single shared journal used to make a
    // second engine overwrite the first one's, after which whichever teardown ran
    // last deleted prefixes the *other* process still believed it held.
    let me = route_repair::current_owner();
    refuse_if_another_instance_holds_a_journal(if_index, &me)?;
    let mut journal = plan_journal(peer_ip, ipv4, gw, if_index, physical_if_index);
    let journal_path = route_repair::journal_path_for(&me).ok_or_else(|| {
        AetherError::Other("refusing to mutate routes: no per-owner journal path".into())
    })?;
    route_repair::write_journal(&journal_path, &journal)
        .map_err(|e| AetherError::Other(format!("refusing to mutate routes: {e}")))?;

    // T044 — the backstop block, see `route_repair::ROUTE_BACKSTOP_LIFETIME`. It
    // is applied inside its own `try`, so a host whose NetTCPIP cmdlets do not
    // take a lifetime still gets its routes installed: the backstop degrades, the
    // connection does not.
    let backstop = route_repair::lifetime_refresh_commands(&journal);
    let backstop_block = if backstop.is_empty() {
        "Write-Output 'backstop=no-scoped-entries'".to_string()
    } else {
        let mut block = String::from("try {\n");
        for command in &backstop {
            block.push_str(command);
            block.push('\n');
        }
        block.push_str(
            "  Write-Output 'backstop=armed'\n} catch { Write-Output 'backstop=unsupported' }",
        );
        block
    };

    // Never a bare `route` inside the script: PowerShell resolves a tool name
    // through PATH *and the process current directory*, which is the search
    // order `win_exec` exists to take out of the picture for an elevated
    // process. The absolute System32 path is the same one `run_cmd` uses.
    let route_exe = match crate::win_exec::system_exe("route") {
        Ok(p) => format!("& '{}'", p.to_string_lossy().replace('\'', "''")),
        Err(e) => {
            // The NetTCPIP cmdlets are still the primary path; only the
            // in-script fallback needs route.exe. Naming the refusal keeps the
            // script from silently going looking for the tool somewhere else.
            log::warn!(
                "[tun] route.exe could not be resolved ({e}); the in-script fallback is disabled"
            );
            "throw 'route.exe unresolvable'".to_string()
        }
    };
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
      {route_exe} add $dest mask $mask $via metric 1 IF $tunIf | Out-Null
    }}
  }}
  # IPv6 stays disabled until this TUN path supports it.
  # Verify
  $v = @(Get-NetRoute -InterfaceIndex $tunIf -ErrorAction SilentlyContinue |
    Where-Object {{ $_.DestinationPrefix -in @('0.0.0.0/1','128.0.0.0/1') }} |
    Select-Object -ExpandProperty DestinationPrefix)
  $peerOk = Get-NetRoute -DestinationPrefix $peer -InterfaceIndex $physIf -ErrorAction SilentlyContinue
  if ($v.Count -lt 2 -or -not $peerOk) {{ throw 'route verification failed' }}
  {backstop_block}
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
                &[
                    "add",
                    &peer_s,
                    "mask",
                    "255.255.255.255",
                    &gw_s,
                    "metric",
                    "1",
                    "IF",
                    &phys_s,
                ],
            ) {
                clear_journal_at(&journal_path);
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
                    &[
                        "add",
                        dest,
                        "mask",
                        "128.0.0.0",
                        &via,
                        "metric",
                        "1",
                        "IF",
                        &ifs,
                    ],
                ) {
                    log::error!(
                        "[tun] failed to add split route {dest} ({add_err}); rolling back routes"
                    );
                    for installed in installed_splits {
                        let _ = run_cmd(
                            "route",
                            &["delete", installed, "mask", "128.0.0.0", "IF", &ifs],
                        );
                    }
                    let _ = run_cmd(
                        "route",
                        &["delete", &peer_s, "mask", "255.255.255.255", "IF", &phys_s],
                    );
                    clear_journal_at(&journal_path);
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
            if let Err(err) = route_repair::write_journal(&journal_path, &journal) {
                log::error!("[tun] installed routes but the journal is stale: {err}");
            }
            // `route.exe` has no seconds-granularity lifetime (its `-age` is in
            // minutes and only feeds the automatic-metric calculation), so a host
            // that lands here has no T044 backstop: a killed process is cleaned by
            // the journal replay at the next start instead.
            log::warn!(
                "[tun] route lifetime backstop not available on the route.exe path; \
                 cleanup relies on the journal replay"
            );
            log::info!(
                "[tun] routes installed (route.exe): peer via {gw_s} IF={physical_if_index}, split-default {via} IF={if_index}"
            );
        }
    }
    Ok(journal)
}

/// T036 — another instance's journal blocks us, and that is the whole answer.
fn refuse_if_another_instance_holds_a_journal(if_index: u32, me: &JournalOwner) -> Result<()> {
    let records: Vec<OwnershipRecord> =
        route_repair::scan_journals(route_repair::boot_id(), process_liveness)
            .into_iter()
            .map(|stale| OwnershipRecord {
                owner: route_repair::owner_of(&stale.journal),
                tun_if_index: stale.journal.tun_if_index,
                holder: stale.holder,
            })
            .collect();
    match route_repair::decide_owner_exclusivity(&records, me, if_index) {
        MutationVerdict::Proceed => Ok(()),
        MutationVerdict::Refuse { why, owner } => Err(AetherError::Other(format!(
            "{why} (pid {} from boot {:#x}); refusing to install routes a second instance would later delete",
            owner.creator_pid, owner.boot_id
        ))),
    }
}

/// Remove exactly the routes the journal says we created, and nothing else.
///
/// Every deletion is scoped by a recorded interface index or, failing that, by
/// our own next-hop address; where neither is known the plan refuses. The
/// previous code fell back to removing `0.0.0.0/1` and `128.0.0.0/1` from
/// *every* interface whenever the recorded indexes were 0 — which is the exact
/// prefix pair OpenVPN/Cisco/AnyConnect use for split tunnelling, so a legacy or
/// truncated state file let an Aether disconnect take down an unrelated VPN.
/// Take the host-mutation lock for one removal, or decline to remove.
///
/// Declining is not a shrug: the journal stays on disk with our pid in it, and the
/// next start's stale-route replay (or `--repair-routes`) takes the routes down
/// once that pid is demonstrably gone. Removing them *unguarded* is what this lock
/// exists to prevent — a second session mid-install owns the same prefixes, so an
/// unguarded delete would take down routes that are no longer only ours, and the
/// machine would lose its tunnel with one still reporting connected.
fn remove_routes(journal: &RouteJournal) {
    let _mutation = match crate::host_lock::HostMutationGuard::acquire(
        crate::host_lock::ACQUIRE_TIMEOUT,
    ) {
        Ok(guard) => guard,
        Err(e) => {
            log::error!(
                "[tun] routes left installed: {e}. The journal is kept so the next Aether start                  replays the removal; run `aether --repair-routes` to do it now."
            );
            return;
        }
    };
    remove_routes_locked(journal);
}

/// Remove this journal's routes while holding the host-mutation lock.
///
/// Callers that already hold it (the stale-route replay) use this directly;
/// anything else goes through [`remove_routes`], which takes the lock first. The
/// split exists because the lock is not re-entrant, and a nested acquire would
/// fail and silently skip the removal.
///
/// T032: the route deletions *and* the adapter reset are rendered into one
/// script, so a teardown is a single `powershell.exe` cold start instead of two
/// (previously three, with `route.exe` after them, which is why it overran the
/// supervisor's grace window and never ran at all). Nothing here shells out per
/// prefix.
fn remove_routes_locked(journal: &RouteJournal) {
    let plan = route_repair::teardown_plan(journal, ADAPTER_NAME);
    if plan.commands.is_empty() {
        log::warn!("[tun] nothing removable in this journal and no safe adapter alias; leaving host state untouched");
        return;
    }
    if plan.removals == 0 {
        log::warn!(
            "[tun] no scoped removal for this journal ({} refused); the adapter reset still runs",
            plan.refused
        );
    }
    if let Err(e) = ps(&powershell_script(&plan.commands)) {
        log::error!("[tun] teardown reported an error: {e}");
    }
    log::info!(
        "[tun] teardown: {} scoped deletion(s) issued, {} refused, adapter reset folded in, one shell spawn",
        plan.removals,
        plan.refused
    );
}

/// Unlink **this** owner's journal, plus the pre-journal state file.
///
/// T036: it takes a path. Clearing "the journal" without saying whose was how a
/// second instance erased the record the first one needed to clean up after
/// itself.
fn clear_journal_at(path: &std::path::Path) {
    route_repair::remove_journal_file(path);
    // The pre-journal file name, cleaned up so an upgrade cannot leave a second
    // stale record that a future reader might trust over the journal.
    if let Some(legacy) = legacy_state_path() {
        route_repair::remove_journal_file(&legacy);
    }
}

fn legacy_state_path() -> Option<PathBuf> {
    Some(route_repair::state_dir()?.join("tun-routes.json"))
}

/// Upgrade the pre-journal `tun-routes.json` into a journal.
///
/// The legacy record carries the tunnel address, so removal can still be
/// next-hop scoped even when its interface indexes are zero — which is exactly
/// the case that used to trigger global prefix deletion.
fn journal_from_legacy(state: &serde_json::Value) -> Option<RouteJournal> {
    let g = |k: &str| {
        state
            .get(k)
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string()
    };
    let u = |k: &str| {
        state
            .get(k)
            .and_then(|v| v.as_u64())
            .map(|v| v as u32)
            .unwrap_or(0)
    };
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
            next_hop: if tun_if != 0 {
                "0.0.0.0".into()
            } else {
                tunnel_ipv4.clone()
            },
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
        // A pre-journal file has no boot identity, so it can never be matched to
        // "this process, this boot": `decide_replay` still needs a live-holder
        // probe for it, and `decide_owner_exclusivity` treats it as a foreign
        // owner rather than as ours.
        boot_id: 0,
        tun_alias: ADAPTER_NAME.into(),
        tun_if_index: tun_if,
        phys_if_index: phys_if,
        gateway: g("gateway"),
        tunnel_ipv4,
        peer_ipv4,
        entries,
    })
}

/// Remove routes left by a crashed previous engine process.
///
/// T033: reachable from anywhere — the engine calls it at its own startup, before
/// any session runs (`cli::run`), and `route_repair::repair_host_state_now` is the
/// name a shell can call without entering TUN mode. It is safe to call at any
/// moment because every journal it can act on has to pass
/// [`route_repair::decide_replay`] first, which refuses to touch anything whose
/// holder is alive or whose liveness could not be established.
pub fn recover_stale_routes() {
    // The replay is a host mutation like any other. Holding the lock here also
    // means `remove_routes_locked` below is called with it already taken.
    let Ok(_mutation) =
        crate::host_lock::HostMutationGuard::acquire(crate::host_lock::ACQUIRE_TIMEOUT)
    else {
        log::info!("[tun] another session owns host mutation; skipping the stale-route replay");
        return;
    };
    // Every journal on disk — this one, every other owner's, and the legacy single
    // file. `remove_routes_locked` already folds the adapter reset into the same
    // script, so recovery needs no separate reset call.
    let handled =
        route_repair::replay_abandoned_journals(process_liveness, &|journal: &RouteJournal| {
            remove_routes_locked(journal);
        });
    if recover_legacy_state_file() {
        log::info!("[tun] recovered routes recorded by a pre-journal build");
    }
    if handled > 0 {
        log::info!("[tun] stale route recovery complete: {handled} journal(s) replayed");
    }
}

/// The `tun-routes.json` a build from before the journal left behind.
fn recover_legacy_state_file() -> bool {
    let Some(legacy) = legacy_state_path() else {
        return false;
    };
    let Ok(raw) = std::fs::read(&legacy) else {
        return false;
    };
    let journal = serde_json::from_slice::<serde_json::Value>(&raw)
        .ok()
        .and_then(|v| journal_from_legacy(&v));
    let mut removed = false;
    let mut keep_for_later = false;
    if let Some(journal) = journal {
        let holder = combine(process_liveness(journal.creator_pid), &journal);
        match route_repair::decide_replay(
            &journal,
            holder,
            std::process::id(),
            route_repair::boot_id(),
        ) {
            route_repair::Replay::Remove => {
                log::warn!(
                    "[tun] recovering legacy routes from dead pid {}",
                    journal.creator_pid
                );
                remove_routes_locked(&journal);
                removed = true;
            }
            route_repair::Replay::LeaveAlone(why) => {
                log::info!("[tun] leaving the pre-journal record alone: {why}");
                // The holder may be live: the file is that session's only record,
                // and deleting it would strand its routes with nothing to replay.
                keep_for_later = journal.creator_pid != 0;
            }
        }
    }
    if !keep_for_later {
        // Unreadable as a journal, or already acted on: it has no further use, and
        // leaving it would let a future build re-derive a journal from state it
        // never verified.
        route_repair::remove_journal_file(&legacy);
    }
    removed
}

/// Liveness folded with "was this written before the current boot".
fn combine(probe: Liveness, journal: &RouteJournal) -> Liveness {
    route_repair::combine_liveness(journal.created_unix, route_repair::boot_id(), probe)
}

/// Is this pid running?
///
/// T035. The shipped version substring-searched `tasklist`'s whole output, so pid
/// `4` matched the working-set and session columns of unrelated rows: a long-dead
/// holder looked alive forever and its routes were never cleaned. Two exact
/// mechanisms replace it, and neither can guess:
///
/// 1. `OpenProcess` + `GetExitCodeProcess`, which identifies a process by handle,
///    not by text; and
/// 2. `tasklist /FI "PID eq <pid>" /FO CSV /NH`, parsed by
///    [`route_repair::liveness_from_tasklist`] against the PID column only.
///
/// Access denied on the first is `Alive` (the process exists, it is someone
/// else's); a probe that could not be performed at all is `Unknown`, which no
/// caller may read as permission to delete.
fn process_liveness(pid: u32) -> Liveness {
    if pid == 0 {
        return Liveness::Unknown;
    }
    match handle_liveness(pid) {
        Liveness::Unknown => tasklist_liveness(pid),
        decided => decided,
    }
}

/// The kernel's own answer, for the common case where it has one.
fn handle_liveness(pid: u32) -> Liveness {
    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, ERROR_ACCESS_DENIED};
    use windows_sys::Win32::System::Threading::{
        GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };
    // The exit code a running process reports; `windows-sys` does not export it.
    const STILL_ACTIVE: u32 = 259;
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle.is_null() {
        // Only "it exists but is not ours" is evidence of life. Anything else —
        // including a privilege-restricted token that refuses the query — is not.
        return if unsafe { GetLastError() } == ERROR_ACCESS_DENIED {
            Liveness::Alive
        } else {
            Liveness::Unknown
        };
    }
    let mut code = 0u32;
    let queried = unsafe { GetExitCodeProcess(handle, &mut code) };
    unsafe { CloseHandle(handle) };
    if queried == 0 {
        return Liveness::Unknown;
    }
    if code == STILL_ACTIVE {
        Liveness::Alive
    } else {
        // A pid whose only remaining state is its exit code is not running.
        Liveness::Dead
    }
}

/// Fallback probe, for when the handle query cannot answer.
fn tasklist_liveness(pid: u32) -> Liveness {
    use std::os::windows::process::CommandExt;
    let filter = format!("PID eq {pid}");
    let exe = match crate::win_exec::system_exe("tasklist") {
        Ok(p) => p,
        Err(e) => {
            log::warn!("[tun] liveness probe for pid {pid} cannot be resolved ({e}); unknown");
            return Liveness::Unknown;
        }
    };
    let out = Command::new(exe)
        .args(["/FI", &filter, "/NH", "/FO", "CSV"])
        .creation_flags(0x08000000)
        .output();
    let Ok(o) = out else {
        log::warn!("[tun] liveness probe for pid {pid} failed to run; unknown");
        return Liveness::Unknown;
    };
    if !o.status.success() {
        log::warn!(
            "[tun] liveness probe for pid {pid} exited {}; unknown",
            o.status.code().unwrap_or(-1)
        );
        return Liveness::Unknown;
    }
    route_repair::liveness_from_tasklist(&String::from_utf8_lossy(&o.stdout), pid)
}

/// T044 — re-arm the route lifetime every [`route_repair::ROUTE_BACKSTOP_REFRESH_INTERVAL`]
/// while this tunnel is up.
///
/// This is a backstop and nothing else. The primary teardown is `Drop`/journal
/// replay; a live session re-arming a 90 s lifetime simply means the entry cannot
/// outlive the process that made it when that process is killed hard. Skipping a
/// round is not an error — one missed refresh still leaves 60 s of margin.
fn spawn_route_lifetime_refresher(journal: RouteJournal) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(route_repair::ROUTE_BACKSTOP_REFRESH_INTERVAL).await;
            let journal = journal.clone();
            // The refresh launches a process; it must not run on an async thread.
            if tokio::task::spawn_blocking(move || rearm_route_lifetime(&journal))
                .await
                .is_err()
            {
                log::warn!("[tun] route lifetime refresh could not run; the loop is done");
                return;
            }
        }
    })
}

fn rearm_route_lifetime(journal: &RouteJournal) {
    let commands = route_repair::lifetime_refresh_commands(journal);
    if commands.is_empty() {
        return;
    }
    // A refresh is a host mutation like any other: if another session is
    // mid-install, decline this round rather than race it.
    let Ok(_mutation) = crate::host_lock::HostMutationGuard::acquire(Duration::from_millis(500))
    else {
        log::debug!("[tun] host mutation is busy; skipping this lifetime refresh");
        return;
    };
    if let Err(e) = ps(&powershell_script(&commands)) {
        log::debug!("[tun] route lifetime refresh reported: {e}");
    }
}

pub struct TunHandle {
    _adapter: Arc<Adapter>,
    session: Arc<Session>,
    journal: RouteJournal,
    journal_path: PathBuf,
    /// T044 — the refresh task that keeps the 90 s backstop armed. Aborted in
    /// `Drop`, *before* the routes themselves are removed.
    refresh: Option<tokio::task::JoinHandle<()>>,
}

impl Drop for TunHandle {
    fn drop(&mut self) {
        // Stop re-arming first, or a refresh could land after the deletion.
        if let Some(task) = self.refresh.take() {
            task.abort();
        }
        remove_routes(&self.journal);
        clear_journal_at(&self.journal_path);
        // Closing the session is the step that releases the adapter. When it
        // fails the adapter stays claimed by a process that is already gone, and
        // the next start inherits a device nobody can open — so the failure is
        // named, and the "all cleaned" line is not printed over it.
        match self.session.shutdown() {
            Ok(()) => log::info!("[tun] cleaned routes, adapter config, and session"),
            Err(e) => log::error!(
                "[tun] routes and journal cleaned, but the wintun session could not be shut \
                 down: {e}; the adapter may stay claimed until the next start"
            ),
        }
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
    // Reclaim a crashed predecessor's routes *before* this adapter is configured.
    // The plan `recover_stale_routes` executes folds in
    // `Set-DnsClientServerAddress -ResetServerAddresses` for this very alias (see
    // `route_repair::teardown_plan`), so running it after `configure_adapter_ip`
    // wiped the resolvers that call had just pinned: DNS leaked to the physical
    // adapter while the tunnel still reported itself ready.
    recover_stale_routes();
    configure_adapter_ip(ADAPTER_NAME, ipv4, mtu)?;

    let session = adapter
        .start_session(MAX_RING_CAPACITY)
        .map_err(|e| AetherError::Other(format!("start session: {e}")))?;
    let journal = match install_routes(peer, ipv4) {
        Ok(journal) => journal,
        Err(error) => {
            // The routes did not go in, so the adapter is ours to give back; a
            // failed shutdown here leaks the device, which the next start then
            // cannot raise. Say so rather than returning only the route error.
            if let Err(e) = session.shutdown() {
                log::error!("[tun] route install failed and the wintun session stayed open: {e}");
            }
            return Err(error);
        }
    };

    // Build handle first so Drop cleans routes/session if thread spawn fails.
    let journal_path = route_repair::journal_path_for(&route_repair::owner_of(&journal))
        .ok_or_else(|| {
            if let Err(e) = session.shutdown() {
                log::error!(
                    "[tun] no journal path for the routes just installed and the wintun \
                     session stayed open: {e}"
                );
            }
            AetherError::Other("no per-owner journal path for the routes just installed".into())
        })?;
    let handle = TunHandle {
        _adapter: adapter,
        session: session.clone(),
        journal,
        journal_path,
        refresh: None,
    };
    // T044 — keep the backstop armed for as long as this handle lives. See
    // `route_repair::ROUTE_BACKSTOP_LIFETIME`: this is *not* the teardown path, it
    // is what stops a killed process from black-holing the machine until the next
    // start replays the journal.
    let mut handle = handle;
    handle.refresh = Some(spawn_route_lifetime_refresher(handle.journal.clone()));

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
            let Ok(rt) = rt else {
                // This used to be a bare `return`, which is how "connected, nothing
                // loads" happened: the adapter is up and the routes are installed by
                // now, so every external signal says ready while the tunnel→kernel
                // direction is dead. Returning also drops the captured session, which
                // releases the ring; the important part is that the reason is logged.
                log::error!(
                    "[tun] cannot build the kernel-TX runtime; packets the tunnel \
                     receives cannot be delivered to the OS, and the session is ending"
                );
                return;
            };
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
                                if let Ok(mut packet) =
                                    session.allocate_send_packet(pkt.len() as u16)
                                {
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
                                    if let Ok(mut packet) =
                                        session.allocate_send_packet(ip_len as u16)
                                    {
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

#[cfg(test)]
mod wintun_resolution_tests {
    use super::*;

    /// `AETHER_WINTUN` used to be read in the elevated child, so anything able to
    /// set that variable chose which DLL a process with administrator rights would
    /// `LoadLibrary`. A marker file proves the difference between "did not load it"
    /// and "loaded it and reported a problem".
    #[test]
    fn an_environment_variable_cannot_name_the_driver() {
        let dir = std::env::temp_dir().join(format!("aether_wintun_env_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let evil = dir.join("wintun.dll");
        std::fs::write(&evil, b"MZ not a driver").unwrap();

        // The variable is no longer consulted at all, so even a perfectly shaped
        // candidate outside the install roots cannot be selected by it.
        crate::runtime_env::set("AETHER_WINTUN", &evil.to_string_lossy());
        let resolved = find_wintun_dll();
        crate::runtime_env::remove("AETHER_WINTUN");

        if let Ok(path) = resolved {
            // Compare canonical forms: on Windows a raw temp path and its
            // canonicalised version differ textually (8.3 short names), and a test
            // that compares strings would pass while the engine loaded the plant.
            assert!(
                path.canonicalize().ok().as_ref() != Some(&evil.canonicalize().unwrap()),
                "the engine resolved the driver from an environment variable"
            );
        }
        assert_eq!(
            std::fs::read(&evil).unwrap(),
            b"MZ not a driver",
            "resolution must not read from or write to the candidate"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn only_a_plain_wintun_dll_inside_the_install_roots_is_accepted() {
        let dir = std::env::temp_dir().join(format!("aether_wintun_root_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let good = dir.join("wintun.dll");
        std::fs::write(&good, b"MZ").unwrap();
        assert!(
            inside_allowed_root(&good.to_string_lossy()).is_none(),
            "a temp directory is not one of the install roots"
        );

        // Right name, wrong shape: a differently named file is not the driver even
        // if it sits where the driver lives.
        let misnamed = dir.join("not-wintun.dll");
        std::fs::write(&misnamed, b"MZ").unwrap();
        assert!(inside_allowed_root(&misnamed.to_string_lossy()).is_none());

        // A path that walks out of the roots is judged where it lands, not as it
        // reads - `..` in a path is not a way back in.
        let escape = format!("{}", dir.join("..").join("..").display());
        assert!(inside_allowed_root(&escape).is_none());

        // Nothing on disk at all.
        assert!(inside_allowed_root("").is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_beside_exe_candidate_is_the_only_fallback() {
        // With no handoff and no environment variable, resolution can only be the
        // copy next to the executable (or an error): the CWD-relative probe is gone,
        // because a working directory is not a trust boundary.
        let exe_dir = std::env::current_exe()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();
        let candidate = exe_dir.join("wintun.dll");
        match find_wintun_dll() {
            Ok(path) => assert!(
                path == candidate.canonicalize().unwrap(),
                "resolution reached for something other than the beside-exe copy: {path:?}"
            ),
            Err(e) => {
                let msg = e.to_string();
                assert!(msg.contains("beside aether.exe"), "{msg}");
                assert!(
                    !msg.contains("set AETHER_WINTUN"),
                    "the error still advertises the removed environment override: {msg}"
                );
            }
        }
    }
}
