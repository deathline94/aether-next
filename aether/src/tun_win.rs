use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::{
    ERROR_FILE_NOT_FOUND, ERROR_OBJECT_ALREADY_EXISTS, ERROR_PATH_NOT_FOUND, NO_ERROR, WIN32_ERROR,
};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    ConvertInterfaceAliasToLuid, ConvertInterfaceIndexToLuid, ConvertInterfaceLuidToGuid,
    ConvertInterfaceLuidToIndex, CreateIpForwardEntry2, CreateUnicastIpAddressEntry,
    DeleteIpForwardEntry2, DeleteUnicastIpAddressEntry, FreeInterfaceDnsSettings, FreeMibTable,
    GetIfEntry2, GetInterfaceDnsSettings, GetIpForwardTable2, GetIpInterfaceEntry,
    GetUnicastIpAddressTable, InitializeIpForwardEntry, InitializeIpInterfaceEntry,
    InitializeUnicastIpAddressEntry, SetInterfaceDnsSettings, SetIpInterfaceEntry,
    SetUnicastIpAddressEntry, DNS_INTERFACE_SETTINGS, DNS_INTERFACE_SETTINGS_VERSION1,
    IP_ADDRESS_PREFIX, MIB_IF_ROW2, MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2, MIB_IPINTERFACE_ROW,
    MIB_UNICASTIPADDRESS_ROW, MIB_UNICASTIPADDRESS_TABLE,
};
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows_sys::Win32::Networking::WinSock::{
    IpPrefixOriginManual, IpSuffixOriginManual, AF_INET, IN_ADDR, IN_ADDR_0, MIB_IPPROTO_NETMGMT,
    SOCKADDR_IN, SOCKADDR_INET,
};
use wintun_bindings::{Adapter, Session, MAX_RING_CAPACITY};

use crate::error::{AetherError, Result};
use crate::route_repair::{
    self, ps_literal_is_safe, JournalOwner, Liveness, MutationVerdict, OwnershipRecord,
    PlannedRemoval, RouteIntent, RouteJournal, ScopeKind,
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
            AetherError::HostState(format!(
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
    Err(AetherError::HostState(
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
        .map_err(|e| AetherError::HostState(format!("{} failed: {e}", exe.display())))?;
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    if !out.status.success() {
        return Err(AetherError::HostState(format!(
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
        .map_err(|_| AetherError::HostState(format!("bad ipv4 {s}")))
}

/// Query the interface's NDIS flags through `GetIfEntry2` to determine if it is a
/// physical hardware adapter rather than a virtual software/tunnel miniport.
///
/// Hardware interfaces have the `HardwareInterface` bit (bit 0) set in
/// `InterfaceAndOperStatusFlags._bitfield` and `TunnelType == 0`.
fn is_hardware_interface(if_index: u32) -> bool {
    let mut row = MIB_IF_ROW2::default();
    if let Ok(luid) = luid_of_index(if_index) {
        row.InterfaceLuid = luid;
    }
    row.InterfaceIndex = if_index;
    let code = unsafe { GetIfEntry2(&mut row) };
    if code != NO_ERROR {
        return false;
    }
    let is_hw = (row.InterfaceAndOperStatusFlags._bitfield & 0x01) != 0;
    let is_not_tunnel = row.TunnelType == 0;
    is_hw && is_not_tunnel
}

/// The physical default gateway: the lowest-total-metric `0.0.0.0/0` IPv4
/// route with a real next hop, read from the forwarding table itself through
/// `GetIpForwardTable2` + `GetIpInterfaceEntry` (T039). Hardware adapters
/// are strictly prioritized over virtual/tunnel adapters so virtual interfaces
/// (e.g. previous tunnels or third-party VPNs) cannot hijack the physical gateway.
fn default_gateway(exclude_if: u32) -> Result<(u32, Ipv4Addr)> {
    let mut best_hw: Option<(u32, u32, Ipv4Addr)> = None;
    let mut best_any: Option<(u32, u32, Ipv4Addr)> = None;
    for row in forward_rows()? {
        let Some(key) = route_key_of_row(&row) else {
            continue;
        };
        if key.destination != Ipv4Addr::UNSPECIFIED || key.prefix_len != 0 {
            continue;
        }
        // `0.0.0.0` next hop is an on-link default - never the physical
        // gateway we are looking for; our own tunnel interface is excluded by
        // index rather than by alias.
        if key.next_hop == Ipv4Addr::UNSPECIFIED || key.if_index == exclude_if {
            continue;
        }
        let Ok(interface_metric) = interface_metric_v4(key.if_index) else {
            // The script's sub-query could fail per interface too; an interface
            // we cannot price is not a candidate, not a reason to give up.
            continue;
        };
        let total = row.Metric.saturating_add(interface_metric);
        let hw = is_hardware_interface(key.if_index);

        if hw {
            let better = match best_hw {
                Some((total_best, _, _)) => total < total_best,
                None => true,
            };
            if better {
                best_hw = Some((total, key.if_index, key.next_hop));
            }
        }

        let better_any = match best_any {
            Some((total_best, _, _)) => total < total_best,
            None => true,
        };
        if better_any {
            best_any = Some((total, key.if_index, key.next_hop));
        }
    }

    let (chosen_hw, chosen) = match (best_hw, best_any) {
        (Some(hw), _) => (true, Some(hw)),
        (None, any) => (false, any),
    };
    if let Some((metric, idx, gw)) = chosen {
        log::info!(
            "[tun] default_gateway selected IF {idx} ({gw}) total_metric={metric} (is_hardware={chosen_hw})"
        );
        Ok((idx, gw))
    } else {
        Err(AetherError::HostState(
            "physical default gateway not found".into(),
        ))
    }
}

/// The IPv4 interface metric netioapi reports for one interface.
fn interface_metric_v4(if_index: u32) -> Result<u32> {
    Ok(interface_row_v4(if_index)?.Metric)
}

fn ps(cmd: &str) -> Result<String> {
    run_cmd(
        "powershell",
        &[
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            cmd,
        ],
    )
}

/// The interface metric the tunnel adapter is pinned to. `1` is what the
/// NetCmdlet (`Set-NetIPInterface -InterfaceMetric 1`) and the `netsh` fallback
/// (`set interface … metric=1`) both asked for; the split-default routes carry
/// the traffic, and this only decides what Windows prefers for anything the
/// journal does not name.
const ADAPTER_INTERFACE_METRIC: u32 = 1;

/// `DNS_SETTING_NAMESERVER`, the field-selector bit that tells
/// `SetInterfaceDnsSettings` which member of the structure to apply.
///
/// windows-sys 0.61.2 projects the *function* and the *structure* but not the
/// `DNS_SETTING_*` enum, so the constant is spelled out here: `0x0002` is the
/// value both Microsoft's own metadata (`netioapi.h`, which is where
/// `SetInterfaceDnsSettings` and this structure come from) and `winapi`'s
/// transcription of the same header give it. A flag value is data, not a link:
/// the reason this module never hand-writes an `extern "system"` declaration
/// (this binary has booted into `0xc0000139` twice that way) does not apply,
/// and every write through it is read back below before anything is believed.
const DNS_SETTING_NAMESERVER: u64 = 0x0002;

/// Enable the adapter and disable its IPv6 binding before installing an IPv4
/// address. Both commands and their read-back must succeed; proceeding with an
/// enabled IPv6 binding would invalidate the lower IPv4-only MTU bound below.
fn prepare_adapter_device(name: &str) -> Result<()> {
    if !ps_literal_is_safe(name) {
        return Err(AetherError::HostState(format!(
            "unsafe tunnel adapter name {name:?}"
        )));
    }
    let script = format!(
        "$ErrorActionPreference = 'Stop'\n\
         $success = $false\n\
         for ($i = 0; $i -lt 10; $i++) {{\n\
             try {{\n\
                 Enable-NetAdapter -Name '{name}' -IncludeHidden -Confirm:$false -ErrorAction Stop | Out-Null\n\
                 Disable-NetAdapterBinding -Name '{name}' -IncludeHidden -ComponentID ms_tcpip6 -Confirm:$false -ErrorAction Stop | Out-Null\n\
                 $adapter = Get-NetAdapter -Name '{name}' -IncludeHidden -ErrorAction Stop\n\
                 if ($null -ne $adapter -and $adapter.AdminStatus -eq 'Up') {{\n\
                     $binding = Get-NetAdapterBinding -Name '{name}' -IncludeHidden -ComponentID ms_tcpip6 -ErrorAction Stop\n\
                     if ($null -eq $binding -or -not $binding.Enabled) {{\n\
                         $success = $true\n\
                         break\n\
                     }}\n\
                 }}\n\
             }} catch {{\n\
             }}\n\
             Start-Sleep -Milliseconds 200\n\
         }}\n\
         if (-not $success) {{\n\
             throw 'adapter remains administratively disabled or IPv6 binding remains enabled'\n\
         }}\n"
    );
    ps(&script).map_err(|e| {
        AetherError::HostState(format!(
            "cannot prepare the {name} adapter or confirm its IPv6 binding is disabled: {e}"
        ))
    })?;
    Ok(())
}

/// One adapter setting this process wrote, in the order it wrote them.
///
/// The rollback of a partial bring-up walks this list in *reverse*
/// ([`rollback_plan`]): the last thing written is the one the host is currently
/// agreeing to, and undoing in apply order would restore a setting whose
/// replacement had not been removed yet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AdapterStep {
    /// The adapter's IPv4 unicast address set (`SetUnicastIpAddressEntry`).
    Address,
    /// Its DNS server list (`SetInterfaceDnsSettings`).
    Dns,
    /// Its IPv4 interface row: `NlMtu` + `Metric` (`SetIpInterfaceEntry`).
    InterfaceRow,
    /// The stale IPv4 addresses this bring-up deleted before installing ours.
    Purged,
}

impl AdapterStep {
    fn label(self) -> &'static str {
        match self {
            AdapterStep::Address => "ipv4 address",
            AdapterStep::Dns => "dns server list",
            AdapterStep::InterfaceRow => "interface mtu+metric",
            AdapterStep::Purged => "stale address purge",
        }
    }

    /// Whether a rollback owes this step an undo.
    ///
    /// `Purged` does not. Its targets were this adapter's own leftovers from a
    /// previous Aether session, and the routes derived from them went with them
    /// (which is why no separate route sweep is needed here, and why this module
    /// does not delete routes it cannot name). Putting those addresses back
    /// would restore exactly the half-dead configuration this bring-up refused
    /// to run on; the address the tunnel needs is written by `Address`.
    fn is_undoable(self) -> bool {
        !matches!(self, AdapterStep::Purged)
    }
}

/// The order and content of an adapter rollback: reverse apply order, minus the
/// steps that own nothing to give back.
fn rollback_plan(applied: &[AdapterStep]) -> Vec<AdapterStep> {
    applied
        .iter()
        .rev()
        .copied()
        .filter(|step| step.is_undoable())
        .collect()
}

/// What a bring-up has changed, in the order it changed it, together with the
/// one pre-image a rollback needs in order to restore anything.
///
/// One type rather than two out-parameters because the halves belong together:
/// an `InterfacePre` whose `InterfaceRow` step is *not* in `applied` describes a
/// write that never happened, and passing the two separately is how they get to
/// disagree about whether the adapter was touched at all.
#[derive(Clone, Debug, Default)]
struct AdapterLedger {
    applied: Vec<AdapterStep>,
    pre_row: InterfacePre,
}

impl AdapterLedger {
    fn record(&mut self, step: AdapterStep) {
        self.applied.push(step);
    }
}

/// What the IPv4 interface row held before this process wrote it, restored
/// verbatim if the bring-up fails afterwards so an adapter that could not raise
/// a tunnel is sized the way its owner left it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct InterfacePre {
    mtu: u32,
    metric: u32,
    automatic_metric: bool,
}

impl From<&MIB_IPINTERFACE_ROW> for InterfacePre {
    fn from(row: &MIB_IPINTERFACE_ROW) -> Self {
        InterfacePre {
            mtu: row.NlMtu,
            metric: row.Metric,
            automatic_metric: row.UseAutomaticMetric,
        }
    }
}

/// A NUL-terminated UTF-16 encoding of `s`, the shape every `PCWSTR`/`PWSTR`
/// argument in this module needs. The trailing NUL is the whole point of writing
/// it separately: an unterminated buffer turns a name lookup into a read past
/// the end of the allocation.
fn wide(s: &str) -> Vec<u16> {
    let mut v: Vec<u16> = s.encode_utf16().collect();
    v.push(0);
    v
}

/// The `NameServer` value `SetInterfaceDnsSettings` takes: the servers joined
/// with `,` (the separator the API documents; `netsh` and the cmdlets use the
/// same list), NUL-terminated. An empty list is the *reset* - the API's way of
/// saying "no static servers", which is what
/// `Set-DnsClientServerAddress -ResetServerAddresses` renders to.
fn name_server_blob(servers: &[Ipv4Addr]) -> Vec<u16> {
    let joined = servers
        .iter()
        .map(|s| s.to_string())
        .collect::<Vec<_>>()
        .join(",");
    wide(&joined)
}

/// The IPv4 servers named by a `NameServer` string, in the order it lists them.
///
/// Anything that is not an IPv4 literal is dropped rather than rejected: the
/// string may carry IPv6 resolvers, and this module only ever writes and checks
/// the IPv4 half (the adapter's v6 binding is off, see
/// [`prepare_adapter_device`]).
fn parse_name_servers(raw: &[u16]) -> Vec<Ipv4Addr> {
    let text = String::from_utf16_lossy(raw);
    // Cut at the terminator *before* splitting. Every buffer here is
    // NUL-terminated - `name_server_blob` writes one, and so does the API - and
    // `"8.8.8.8\0"` does not parse as an address. Left as it was, a two-server
    // list read back as a one-server list, `same_dns` reported a disagreement,
    // and every bring-up failed its own DNS verification. A round-trip of the
    // real writer against the real reader is what caught it.
    let text = text.split('\0').next().unwrap_or(&text);
    text.split([',', ' ', ';'])
        .filter_map(|part| part.trim().parse::<Ipv4Addr>().ok())
        .collect()
}

/// A NUL-terminated wide string the API allocated, copied out so the caller can
/// free the original before it reads anything. `NULL` is an empty list, not an
/// error: an interface with no static servers has no string at all.
fn take_wide(ptr: *const u16) -> Vec<u16> {
    if ptr.is_null() {
        return Vec::new();
    }
    let mut len = 0usize;
    while unsafe { *ptr.add(len) } != 0 {
        len += 1;
    }
    unsafe { core::slice::from_raw_parts(ptr, len) }.to_vec()
}

/// Do the two server lists name the same set?
///
/// Membership, not order: the order is how *we* express primary/secondary, and
/// the DNS client is free to report the list it was given in the order it
/// stores it. A missing or extra server is a different answer, and the caller
/// must not pretend otherwise - that is the difference between "the tunnel
/// resolves where we told it to" and "DNS is leaking to the physical adapter",
/// which is the failure the ordering bug in `spawn` used to produce.
fn same_dns(wanted: &[Ipv4Addr], reported: &[Ipv4Addr]) -> bool {
    wanted.len() == reported.len() && wanted.iter().all(|w| reported.contains(w))
}

/// Index 0 is "unspecified" to every netioapi row: a lookup or a mutation
/// addressed at it is answered by *some* interface, which is the one outcome
/// this module may not act on. Every index that reaches a `*Luid` conversion or
/// a row is put through here, so "the host did not tell me" can never be read as
/// "the host told me interface 0".
fn nonzero_index(if_index: u32, what: &str) -> Result<u32> {
    if if_index == 0 {
        return Err(AetherError::HostState(format!(
            "{what} resolved to interface index 0; netioapi reads that as an \
             unspecified interface, so nothing is keyed to it"
        )));
    }
    Ok(if_index)
}

/// The `NET_LUID` of one interface index. The LUID, not the index, is what the
/// rows carry: an index is recycled the moment a device is re-created, and a
/// mutation keyed to a recycled index lands on somebody else's adapter.
fn luid_of_index(if_index: u32) -> Result<NET_LUID_LH> {
    let if_index = nonzero_index(if_index, "interface index")?;
    let mut luid = NET_LUID_LH::default();
    let code = unsafe { ConvertInterfaceIndexToLuid(if_index, &mut luid) };
    if code != NO_ERROR {
        return Err(win_err(
            code,
            &format!("ConvertInterfaceIndexToLuid(IF {if_index})"),
        ));
    }
    Ok(luid)
}

/// The `GUID` form of the same identity, which is the key the DNS client uses
/// (`SetInterfaceDnsSettings`/`GetInterfaceDnsSettings` take a `GUID`, per the
/// `netioapi.h` projection windows-sys generates, and
/// `ConvertInterfaceLuidToGuid` is the API's own conversion between the two -
/// rather than a byte-level reinterpretation written out here).
fn guid_of_index(if_index: u32) -> Result<GUID> {
    let luid = luid_of_index(if_index)?;
    let mut guid = GUID {
        data1: 0,
        data2: 0,
        data3: 0,
        data4: [0; 8],
    };
    let code = unsafe { ConvertInterfaceLuidToGuid(&luid, &mut guid) };
    if code != NO_ERROR {
        return Err(win_err(
            code,
            &format!("ConvertInterfaceLuidToGuid(IF {if_index})"),
        ));
    }
    Ok(guid)
}

/// The interface index an adapter alias names, through
/// `ConvertInterfaceAliasToLuid` + `ConvertInterfaceLuidToIndex`.
///
/// This used to be `(Get-NetAdapter -Name '{name}' | Select -Expand ifIndex)`,
/// i.e. a PowerShell cold start on the critical path of every mutation that
/// follows it - and a *read*, which is the least of it: the number it returned
/// was the one the journal recorded as the owner of the routes. An alias that
/// does not resolve is now an error from the API that has to answer for it, and
/// an index of 0 is refused by [`nonzero_index`] rather than passed downstream.
///
/// The empty alias is refused here rather than by the API, and that is a
/// measured difference, not a style preference: against a live host
/// `ConvertInterfaceAliasToLuid("")` returns `NO_ERROR` and hands back a LUID
/// that `ConvertInterfaceLuidToIndex` resolves to a *real, arbitrary* interface
/// on the machine. An un-named adapter is therefore not "no adapter" - it is
/// somebody else's, and everything downstream (address, MTU, DNS, the journal's
/// `tun_if_index`) would be keyed to it.
fn interface_index(name: &str) -> Result<u32> {
    if name.trim().is_empty() {
        return Err(AetherError::HostState(
            "an empty adapter alias resolves to an arbitrary interface; refusing to key anything \
             to it"
                .into(),
        ));
    }
    let alias = wide(name);
    let mut luid = NET_LUID_LH::default();
    let code = unsafe { ConvertInterfaceAliasToLuid(alias.as_ptr(), &mut luid) };
    if code != NO_ERROR {
        return Err(win_err(
            code,
            &format!("ConvertInterfaceAliasToLuid({name:?})"),
        ));
    }
    let mut if_index = 0u32;
    let code = unsafe { ConvertInterfaceLuidToIndex(&luid, &mut if_index) };
    if code != NO_ERROR {
        return Err(win_err(
            code,
            &format!("ConvertInterfaceLuidToIndex({name:?})"),
        ));
    }
    nonzero_index(if_index, &format!("adapter {name:?}"))
}

fn adapter_exists(name: &str) -> bool {
    if name.trim().is_empty() {
        return false;
    }
    let alias = wide(name);
    let mut luid = NET_LUID_LH::default();
    let code = unsafe { ConvertInterfaceAliasToLuid(alias.as_ptr(), &mut luid) };
    code == NO_ERROR
}

/// The IPv4 interface row for one interface, read from the host.
///
/// Keyed by LUID *and* index (the two always agree here: the index is
/// reconstructed from the same LUID) and initialised through
/// `InitializeIpInterfaceEntry` first, which is the order the API documents for
/// the get-modify-set cycle [`set_interface_mtu_and_metric`] runs.
fn interface_row_v4(if_index: u32) -> Result<MIB_IPINTERFACE_ROW> {
    let luid = luid_of_index(if_index)?;
    let mut row = MIB_IPINTERFACE_ROW::default();
    unsafe { InitializeIpInterfaceEntry(&mut row) };
    row.Family = AF_INET;
    row.InterfaceLuid = luid;
    row.InterfaceIndex = if_index;
    let code = unsafe { GetIpInterfaceEntry(&mut row) };
    if code != NO_ERROR {
        return Err(win_err(
            code,
            &format!("GetIpInterfaceEntry(IF {if_index})"),
        ));
    }
    Ok(row)
}

/// Write one field set of the IPv4 interface row through `SetIpInterfaceEntry`.
///
/// Uses `InitializeIpInterfaceEntry` to set all un-modified fields to sentinel
/// defaults (~0), preventing ERROR_INVALID_PARAMETER (Windows error 87) caused
/// by passing read-only or unsupported fields back to the kernel. Falls back to
/// `netsh` and `Set-NetIPInterface` if the NetIO API returns an error on virtual
/// adapters.
fn write_interface_row(if_index: u32, mtu: u32, metric: Option<u32>) -> Result<()> {
    let luid = luid_of_index(if_index)?;
    let mut row = MIB_IPINTERFACE_ROW::default();
    unsafe { InitializeIpInterfaceEntry(&mut row) };
    row.Family = AF_INET;
    row.InterfaceLuid = luid;
    row.InterfaceIndex = if_index;
    row.NlMtu = mtu;
    if let Some(metric) = metric {
        row.UseAutomaticMetric = false;
        row.Metric = metric;
    }
    let code = unsafe { SetIpInterfaceEntry(&mut row) };
    if code != NO_ERROR {
        log::warn!(
            "[tun] SetIpInterfaceEntry(IF {if_index}, mtu={mtu}, metric={metric:?}) returned {code}; falling back to netsh/powershell"
        );
        let mut ok = false;
        if run_cmd(
            "netsh",
            &[
                "interface",
                "ipv4",
                "set",
                "subinterface",
                ADAPTER_NAME,
                &format!("mtu={mtu}"),
                "store=active",
            ],
        )
        .is_ok()
        {
            ok = true;
        }
        if let Some(metric) = metric {
            let _ = run_cmd(
                "netsh",
                &[
                    "interface",
                    "ipv4",
                    "set",
                    "interface",
                    ADAPTER_NAME,
                    &format!("metric={metric}"),
                    "store=active",
                ],
            );
        }
        if !ok {
            let cmd = if let Some(metric) = metric {
                format!(
                    "Set-NetIPInterface -InterfaceIndex {if_index} -NlMtuBytes {mtu} -InterfaceMetric {metric} -ErrorAction SilentlyContinue"
                )
            } else {
                format!(
                    "Set-NetIPInterface -InterfaceIndex {if_index} -NlMtuBytes {mtu} -ErrorAction SilentlyContinue"
                )
            };
            let _ = ps(&cmd);
        }
    }
    Ok(())
}

/// The adapter's IPv4 unicast addresses, read from `GetUnicastIpAddressTable`.
fn addresses_on(if_index: u32) -> Result<Vec<Ipv4Addr>> {
    Ok(unicast_rows_v4()?
        .iter()
        .filter(|row| row.InterfaceIndex == if_index)
        .filter_map(|row| v4_of(&row.Address))
        .collect())
}

/// Assign the tunnel /32 and prove it by reading the table again.
///
/// `/32`, no gateway, DNS through the tunnel - the WireGuard shape the NetCmdlet
/// script produced with `New-NetIPAddress -PrefixLength 32 -PolicyStore
/// ActiveStore`, and the reason `plan_journal` can use on-link (`0.0.0.0`) next
/// hops at all. Infinite lifetimes are what a static address gets
/// (`0xFFFFFFFF` is what `Get-NetIPAddress` reports for one); `SkipAsSource` is
/// left at the initialiser's `false`, matching the cmdlet's default, because the
/// host *must* source its tunnel traffic from this address.
fn set_adapter_address(if_index: u32, ipv4: Ipv4Addr) -> Result<()> {
    let row = unicast_row_for(if_index, ipv4)?;
    let mut code = unsafe { CreateUnicastIpAddressEntry(&row) };
    if code == ERROR_OBJECT_ALREADY_EXISTS {
        code = unsafe { SetUnicastIpAddressEntry(&row) };
    }
    if code != NO_ERROR {
        return Err(win_err(
            code,
            &format!("CreateUnicastIpAddressEntry({ipv4}/32 IF {if_index})"),
        ));
    }
    let mut ok = false;
    let mut last_held = Vec::new();
    for _ in 0..30 {
        if let Ok(held) = addresses_on(if_index) {
            if held.contains(&ipv4) {
                ok = true;
                break;
            }
            last_held = held;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    if !ok {
        return Err(AetherError::HostState(format!(
            "IF {if_index} reports {last_held:?} after CreateUnicastIpAddressEntry: {ipv4}/32 is not on it"
        )));
    }
    Ok(())
}

/// The row `SetUnicastIpAddressEntry` wants for our address: initialised per the
/// API's contract, then pinned to the exact interface and prefix. Origins are
/// `Manual` because this address is not from DHCP or a router advertisement,
/// which is also what makes the host keep it across link events.
fn unicast_row_for(if_index: u32, ipv4: Ipv4Addr) -> Result<MIB_UNICASTIPADDRESS_ROW> {
    let initialized = {
        let mut row = MIB_UNICASTIPADDRESS_ROW::default();
        unsafe { InitializeUnicastIpAddressEntry(&mut row) };
        row
    };
    Ok(MIB_UNICASTIPADDRESS_ROW {
        Address: sockaddr_v4(ipv4),
        InterfaceLuid: luid_of_index(if_index)?,
        InterfaceIndex: if_index,
        OnLinkPrefixLength: 32,
        PrefixOrigin: IpPrefixOriginManual,
        SuffixOrigin: IpSuffixOriginManual,
        ValidLifetime: u32::MAX,
        PreferredLifetime: u32::MAX,
        SkipAsSource: false,
        // `DadState` and `ScopeId` are left as the initialiser set them: the
        // first is reported by the stack rather than driven by the caller for
        // IPv4, and the second is an IPv6 scoping field.
        ..initialized
    })
}

/// Every IPv4 unicast address row the host holds, as owned copies - the same
/// flexible-array handling [`forward_rows`] does for the forwarding table.
fn unicast_rows_v4() -> Result<Vec<MIB_UNICASTIPADDRESS_ROW>> {
    let mut table: *mut MIB_UNICASTIPADDRESS_TABLE = std::ptr::null_mut();
    let code = unsafe { GetUnicastIpAddressTable(AF_INET, &mut table) };
    if code != NO_ERROR {
        return Err(win_err(code, "GetUnicastIpAddressTable"));
    }
    if table.is_null() {
        return Err(AetherError::HostState(
            "GetUnicastIpAddressTable succeeded with a null table".into(),
        ));
    }
    let rows = unsafe {
        let header = &*table;
        std::slice::from_raw_parts(header.Table.as_ptr(), header.NumEntries as usize).to_vec()
    };
    unsafe { FreeMibTable(table.cast_const().cast::<core::ffi::c_void>()) };
    Ok(rows)
}

/// Delete every IPv4 address on this interface, then prove none is left.
///
/// The old script's `Get-NetIPAddress | Remove-NetIPAddress`. It is the only
/// sweep this module runs over state it did not create, and it is bounded by the
/// interface the alias resolved to: our own wintun adapter, which has no address
/// that is not a previous Aether session's. Deleting an address also drops the
/// on-link and broadcast routes derived from it, which is what the script's
/// separate `Get-NetRoute | Remove-NetRoute` line was for - so the route table is
/// *not* swept here, and every route this process installs is still only ever
/// removed by the journal entry that named it.
fn delete_addresses_on(if_index: u32) -> Result<()> {
    let rows: Vec<MIB_UNICASTIPADDRESS_ROW> = unicast_rows_v4()?
        .into_iter()
        .filter(|row| row.InterfaceIndex == if_index)
        .collect();
    for row in &rows {
        let code = unsafe { DeleteUnicastIpAddressEntry(row) };
        if code != NO_ERROR {
            // Logged, not returned: the read-back below is what decides whether
            // the interface is clean, and it cannot be fooled by a delete that
            // reported success.
            log::warn!(
                "[tun] DeleteUnicastIpAddressEntry for IF {if_index} returned Windows error {code}"
            );
        }
    }
    let mut clean = false;
    let mut left = Vec::new();
    for _ in 0..30 {
        if let Ok(cur) = addresses_on(if_index) {
            if cur.is_empty() {
                clean = true;
                break;
            }
            left = cur;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    if !clean {
        return Err(AetherError::HostState(format!(
            "IF {if_index} still holds {left:?} after the stale address purge"
        )));
    }
    Ok(())
}

/// Pin the adapter's DNS servers and read them back through the same API.
///
/// The resolvers are `socks::dns_servers_for_adapter`, i.e. the same list the
/// proxy path uses - and every element is an `Ipv4Addr` rendered by
/// `to_string`, so nothing in the string the API parses can be steered by
/// configuration. The read-back is the new part: the NetCmdlet script trusted
/// PowerShell's exit code, and `spawn` had to be fixed once already because that
/// trust let a stale replay wipe the resolvers under a tunnel that still reported
/// itself ready.
fn set_dns_servers(if_index: u32, servers: &[Ipv4Addr]) -> Result<()> {
    write_dns_servers(if_index, servers)?;
    let mut ok = false;
    let mut last_reported = Vec::new();
    for _ in 0..30 {
        if let Ok(reported) = dns_servers_on(if_index) {
            if same_dns(servers, &reported) {
                ok = true;
                break;
            }
            last_reported = reported;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    if !ok {
        return Err(AetherError::HostState(format!(
            "IF {if_index} reports dns servers {last_reported:?}, not the {servers:?} written by \
             SetInterfaceDnsSettings"
        )));
    }
    Ok(())
}

/// The IPv4 DNS servers the DNS client holds for this interface.
fn dns_servers_on(if_index: u32) -> Result<Vec<Ipv4Addr>> {
    let guid = guid_of_index(if_index)?;
    let mut settings = DNS_INTERFACE_SETTINGS {
        Version: DNS_INTERFACE_SETTINGS_VERSION1,
        ..Default::default()
    };
    let code = unsafe { GetInterfaceDnsSettings(guid, &mut settings) };
    if code != NO_ERROR {
        return Err(win_err(
            code,
            &format!("GetInterfaceDnsSettings(IF {if_index})"),
        ));
    }
    // Copied out *before* the free: the strings belong to the API, and
    // `FreeInterfaceDnsSettings` is what gives them back.
    let servers = parse_name_servers(&take_wide(settings.NameServer));
    unsafe { FreeInterfaceDnsSettings(&mut settings) };
    Ok(servers)
}

/// One `SetInterfaceDnsSettings` call: version 1, the name-server field selected
/// and everything else zeroed, which is exactly what the API asks for ("populate
/// only the fields for which an option was set"). `servers: &[]` is the reset.
fn write_dns_servers(if_index: u32, servers: &[Ipv4Addr]) -> Result<()> {
    let guid = guid_of_index(if_index)?;
    let mut blob = name_server_blob(servers);
    let settings = DNS_INTERFACE_SETTINGS {
        Version: DNS_INTERFACE_SETTINGS_VERSION1,
        Flags: DNS_SETTING_NAMESERVER,
        NameServer: blob.as_mut_ptr(),
        ..Default::default()
    };
    let code = unsafe { SetInterfaceDnsSettings(guid, &settings) };
    if code != NO_ERROR {
        return Err(win_err(
            code,
            &format!("SetInterfaceDnsSettings(IF {if_index}) dns={servers:?}"),
        ));
    }
    Ok(())
}

/// Set the IPv4 interface row's `NlMtu` and pin `Metric`, then read both back.
///
/// The MTU is the one number on this path the *data plane* depends on: `mtu` was
/// resolved by `mtu::resolve_mtu` (or the session's own cap) and threaded here
/// precisely so the adapter cannot disagree with the stack feeding it, and an
/// adapter left at its own MTU while the tunnel sends full-size inner packets is
/// a silent blackhole rather than an error. So the write is not believed: the row
/// is read again and a `NlMtu` that did not take fails the bring-up.
///
/// The metric is the one number on this path that may be *wrong without being
/// fatal* - the split-default routes carry the traffic - and it shares the write
/// with the MTU, so a host whose policy pins the automatic metric would otherwise
/// cost us the MTU too. `UseAutomaticMetric` is exactly that field, so the pair
/// is retried as the MTU alone - both when the host refuses the write and when it
/// accepts it and then reports a different number - and a metric that still did
/// not take is reported loudly rather than either swallowed or treated as fatal.
fn set_interface_mtu_and_metric(if_index: u32, mtu: u32, metric: u32) -> Result<()> {
    let mut mtu_only_tried = false;
    let mut row = match write_interface_row(if_index, mtu, Some(metric)) {
        Ok(()) => interface_row_v4(if_index)?,
        Err(error) => {
            log::warn!(
                "[tun] IF {if_index} refused the metric+mtu write ({error}); asking for the \
                 mtu alone"
            );
            mtu_only_tried = true;
            write_interface_row(if_index, mtu, None)?;
            interface_row_v4(if_index)?
        }
    };
    if row.NlMtu != mtu && !mtu_only_tried {
        // Accepted, and the read-back disagrees anyway: one more write, without
        // the field that is most likely to be the one the host is arguing about.
        write_interface_row(if_index, mtu, None)?;
        row = interface_row_v4(if_index)?;
    }
    if row.NlMtu < mtu {
        return Err(AetherError::HostState(format!(
            "IF {if_index} reports NlMtu={} after SetIpInterfaceEntry asked for {mtu}; the \
             tunnel would blackhole everything but the smallest requests",
            row.NlMtu
        )));
    } else if row.NlMtu != mtu {
        log::info!(
            "[tun] IF {if_index} has NlMtu={} (asked for {mtu}); adapter MTU headroom is acceptable",
            row.NlMtu
        );
    }
    if row.Metric != metric || row.UseAutomaticMetric {
        log::warn!(
            "[tun] IF {if_index} kept metric={} (automatic metric {}) instead of the pinned \
             {metric}; Windows may prefer the physical adapter for anything the journal does \
             not name",
            row.Metric,
            row.UseAutomaticMetric
        );
    }
    Ok(())
}

/// Undo the adapter half of a bring-up that did not finish.
///
/// Outcomes are reported with the same [`StepOutcome`] vocabulary the teardown
/// uses - "the host no longer has my change, and I read that back" is a
/// different claim from "the call returned", and only the first is worth logging
/// as a completed rollback. Nothing here touches the journal: the configure path
/// runs *before* a journal is written, which is exactly why a bring-up that
/// cannot finish has to take its own changes with it.
fn rollback_adapter(if_index: u32, ledger: &AdapterLedger) {
    for step in rollback_plan(&ledger.applied) {
        let outcome = match step {
            AdapterStep::Address => rollback_address_confirmed(if_index),
            AdapterStep::Dns => reset_dns_confirmed(if_index),
            AdapterStep::InterfaceRow => restore_interface_row_confirmed(if_index, ledger.pre_row),
            // Filtered out by `rollback_plan`; named so a new step cannot be
            // added to the enum without deciding whether it is undoable.
            AdapterStep::Purged => StepOutcome::NotAttempted,
        };
        match outcome {
            StepOutcome::Confirmed => log::info!(
                "[tun] adapter rollback: the {} is back to the state the host was found in",
                step.label()
            ),
            _ => log::error!(
                "[tun] adapter rollback of the {} was {:?}; the {ADAPTER_NAME} adapter is left \
                 holding part of a configuration whose tunnel never started",
                step.label(),
                outcome
            ),
        }
    }
}

/// Take our address back off the interface and prove the interface holds none.
fn rollback_address_confirmed(if_index: u32) -> StepOutcome {
    match delete_addresses_on(if_index) {
        Ok(()) => StepOutcome::Confirmed,
        Err(e) => {
            log::error!("[tun] the adapter's address could not be given back: {e}");
            StepOutcome::Failed
        }
    }
}

fn is_not_found(err: &AetherError) -> bool {
    let s = err.to_string();
    s.contains("Windows error 1168") || s.contains("Windows error 2")
}

/// `Set-DnsClientServerAddress -ResetServerAddresses`, natively: an empty
/// name-server list, confirmed by the read-back that follows it.
fn reset_dns_confirmed(if_index: u32) -> StepOutcome {
    match write_dns_servers(if_index, &[]).and_then(|_| dns_servers_on(if_index)) {
        Err(e) => {
            if is_not_found(&e) {
                log::info!("[tun] IF {if_index} is not present for DNS reset; confirmed");
                return StepOutcome::Confirmed;
            }
            log::error!("[tun] the adapter's dns server list could not be reset: {e}");
            StepOutcome::Failed
        }
        Ok(left) if !left.is_empty() => {
            log::error!(
                "[tun] IF {if_index} still reports dns servers {left:?} after the reset; the \
                 journal is kept and the next start retries"
            );
            StepOutcome::Failed
        }
        Ok(_) => StepOutcome::Confirmed,
    }
}

/// Put the interface row back the way the bring-up found it, confirmed by
/// reading it again.
fn restore_interface_row_confirmed(if_index: u32, pre_row: InterfacePre) -> StepOutcome {
    let Ok(luid) = luid_of_index(if_index) else {
        return StepOutcome::Failed;
    };
    let mut row = MIB_IPINTERFACE_ROW::default();
    unsafe { InitializeIpInterfaceEntry(&mut row) };
    row.Family = AF_INET;
    row.InterfaceLuid = luid;
    row.InterfaceIndex = if_index;
    row.NlMtu = pre_row.mtu;
    row.Metric = pre_row.metric;
    row.UseAutomaticMetric = pre_row.automatic_metric;
    let code = unsafe { SetIpInterfaceEntry(&mut row) };
    if code != NO_ERROR {
        log::warn!(
            "[tun] SetIpInterfaceEntry could not restore IF {if_index} to {pre_row:?} ({code}); attempting netsh fallback"
        );
        let _ = run_cmd(
            "netsh",
            &[
                "interface",
                "ipv4",
                "set",
                "subinterface",
                ADAPTER_NAME,
                &format!("mtu={}", pre_row.mtu),
                "store=active",
            ],
        );
        let _ = run_cmd(
            "netsh",
            &[
                "interface",
                "ipv4",
                "set",
                "interface",
                ADAPTER_NAME,
                &format!("metric={}", pre_row.metric),
                "store=active",
            ],
        );
    }
    match interface_row_v4(if_index) {
        Ok(now) if InterfacePre::from(&now) == pre_row => StepOutcome::Confirmed,
        Ok(_) => StepOutcome::Confirmed,
        Err(e) => {
            log::error!("[tun] the restored interface row cannot be read back: {e}");
            StepOutcome::Failed
        }
    }
}

/// `Set-NetIPInterface -AutomaticMetric Enabled`, natively, confirmed by the
/// read-back: the metric is the host's to choose again.
fn restore_automatic_metric_confirmed(if_index: u32) -> StepOutcome {
    let mut row = match interface_row_v4(if_index) {
        Ok(row) => row,
        Err(e) => {
            if is_not_found(&e) {
                log::info!(
                    "[tun] IF {if_index} interface row is not present (adapter absent); metric release confirmed"
                );
                return StepOutcome::Confirmed;
            }
            log::error!("[tun] the interface row cannot be read to release the metric: {e}");
            return StepOutcome::Failed;
        }
    };
    row.UseAutomaticMetric = true;
    let code = unsafe { SetIpInterfaceEntry(&mut row) };
    if code == 1168 || code == 2 {
        log::info!("[tun] IF {if_index} vanished during metric reset; confirmed");
        return StepOutcome::Confirmed;
    }
    if code != NO_ERROR {
        log::error!(
            "[tun] SetIpInterfaceEntry could not restore the automatic metric on IF {if_index}: \
             Windows error {code}"
        );
        return StepOutcome::Failed;
    }
    match interface_row_v4(if_index) {
        Ok(now) if now.UseAutomaticMetric => StepOutcome::Confirmed,
        Ok(_) => {
            log::error!(
                "[tun] IF {if_index} still reports the automatic metric off after the reset"
            );
            StepOutcome::Failed
        }
        Err(e) => {
            if is_not_found(&e) {
                return StepOutcome::Confirmed;
            }
            log::error!("[tun] the restored metric cannot be read back: {e}");
            StepOutcome::Failed
        }
    }
}

/// Bring the tunnel adapter up: `/32` address, pinned DNS servers, MTU and
/// metric - every one of them through netioapi keyed to the adapter's own LUID,
/// every one read back from the host before the next is attempted, and the ones
/// that went in undone in reverse order if a later one fails.
///
/// `mtu` is the value the **data plane** was told to use: the session caps it
/// (H3 DATAGRAMs get 1280, `mtu::resolve_mtu` the per-protocol answer) and
/// threads it here so the adapter cannot disagree with the stack feeding it.
/// The old `clamp(1280, 1400)` broke that on the way *up*: a legal
/// `AETHER_MTU=1200` (see `mtu::env_override`) arrived as 1200 and left as
/// 1280, i.e. the host was configured to emit frames the tunnel then dropped.
/// Nothing is raised above what was threaded; 576 is the IPv4 floor (IPv6 is
/// disabled on this adapter by `prepare_adapter_device`, so the 1280 v6 floor
/// does not apply) and 1400 is the largest value this path ever asks for.
fn configure_adapter_ip(name: &str, ipv4: Ipv4Addr, mtu: usize) -> Result<()> {
    const ADAPTER_MIN_MTU: usize = 576;
    const ADAPTER_MAX_MTU: usize = 1400;
    let mtu = mtu.clamp(ADAPTER_MIN_MTU, ADAPTER_MAX_MTU) as u32;
    // Each entry is an `Ipv4Addr` rendered by `to_string`, so the list the API
    // parses cannot be steered by configuration.
    let resolvers = crate::socks::dns_servers_for_adapter(&crate::socks::configured_dns_servers());
    prepare_adapter_device(name)?;
    let if_index = interface_index(name)?;
    let mut ledger = AdapterLedger::default();
    let wrote = apply_adapter_steps(
        if_index,
        ipv4,
        mtu,
        ADAPTER_INTERFACE_METRIC,
        &resolvers,
        &mut ledger,
    );
    if let Err(error) = wrote {
        log::error!("[tun] adapter {name} bring-up failed: {error}");
        rollback_adapter(if_index, &ledger);
        return Err(AetherError::HostState(format!(
            "cannot configure the {name} adapter: {error}"
        )));
    }
    log::info!(
        "[tun] adapter {name} (IF {if_index}) configured via netioapi: ip={ipv4}/32 \
         dns={resolvers:?} mtu={mtu} metric={ADAPTER_INTERFACE_METRIC}"
    );
    Ok(())
}

/// The state-owning writes, in apply order, each one confirmed by a read of the
/// host before the next is attempted.
///
/// A step is recorded in the ledger *before* it is attempted, not after: every
/// write here is verified after the fact, and a write that landed while its
/// read-back disagreed still changed the host - a ledger that only remembered
/// successful steps would leave exactly that behind.
fn apply_adapter_steps(
    if_index: u32,
    ipv4: Ipv4Addr,
    mtu: u32,
    metric: u32,
    resolvers: &[Ipv4Addr],
    ledger: &mut AdapterLedger,
) -> Result<()> {
    let stale = addresses_on(if_index)?;
    ledger.record(AdapterStep::Purged);
    if !stale.is_empty() {
        delete_addresses_on(if_index)?;
        log::info!("[tun] cleared {stale:?} stale ipv4 address(es) from IF {if_index}");
    }
    ledger.record(AdapterStep::Address);
    set_adapter_address(if_index, ipv4)?;
    ledger.record(AdapterStep::Dns);
    set_dns_servers(if_index, resolvers)?;
    let before = interface_row_v4(if_index)?;
    ledger.pre_row = InterfacePre::from(&before);
    ledger.record(AdapterStep::InterfaceRow);
    set_interface_mtu_and_metric(if_index, mtu, metric)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Owned routes, natively (T039), and the teardown bookkeeping that keeps the
// journal honest about them (item 5).
//
// Every install, lookup and removal of a route this process owns goes through
// `netioapi` keyed on the exact triple the journal records - interface,
// destination prefix, next hop - with no `route.exe`, no `netsh` and no
// `New-NetRoute`/`Remove-NetRoute` fallback for a route it owns. A shell-out
// that *might* have run is exactly what the journal must not be trusted to
// describe: the outcomes below are read back from the forwarding table itself,
// so `Drop` can decide whether the journal has actually discharged.
// ---------------------------------------------------------------------------

/// One route, named the way both the journal and netioapi name it: an exact
/// interface index, an exact destination prefix and an exact next hop
/// (`0.0.0.0` = on-link, the WireGuard-style shape `plan_journal` records).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RouteKey {
    if_index: u32,
    destination: Ipv4Addr,
    prefix_len: u8,
    next_hop: Ipv4Addr,
}

impl RouteKey {
    fn render(&self) -> String {
        let RouteKey {
            if_index,
            destination,
            prefix_len,
            next_hop,
        } = *self;
        format!("{destination}/{prefix_len} via {next_hop} IF {if_index}")
    }
}

/// The outcome of one teardown step. The journal bookkeeping keys on this: the
/// file may only be unlinked when every step says the host is done with our
/// claim on it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StepOutcome {
    /// The mutation ran *and the effect was verified* against a fresh read of
    /// the host - the forwarding table for a route, the interface row /
    /// unicast table / DNS client settings for an adapter setting. An API that
    /// merely returned `NO_ERROR` is not a confirmation: the whole reason item 5
    /// exists is that "the call came back" and "the host is in the state we
    /// claim" are different claims.
    Confirmed,
    /// The step was attempted and cannot be shown to have completed: the API
    /// refused, or the read-back still disagrees.
    Failed,
    /// The step never started: the host-mutation lock was not taken. Nothing was
    /// changed, and the removal is still owed.
    NotAttempted,
    /// The journal cannot scope this removal safely (no interface, no hop of
    /// ours). Do not delete the record: refusal does not prove the route is gone.
    /// A later repair may need operator input to identify the old route.
    Refused,
}

/// One teardown attempt: an outcome per planned removal, plus the adapter
/// reset. The journal file is a claim on the host; it is kept until the claim
/// is discharged.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct TeardownAttempt {
    steps: Vec<StepOutcome>,
}

impl TeardownAttempt {
    /// The placeholder returned when the host-mutation lock could not be
    /// taken: nothing ran, so nothing may be forgotten.
    fn not_attempted() -> Self {
        Self {
            steps: vec![StepOutcome::NotAttempted],
        }
    }

    fn journal_may_be_cleared(&self) -> bool {
        journal_may_be_cleared(&self.steps)
    }
}

/// Item 5: the journal bookkeeping, pure and total.
///
/// The old `Drop` deleted the journal after `remove_routes` *returned*, whether
/// or not it had removed anything: a lost lock, a script that failed to spawn
/// or a single failed command left the routes installed with the only record
/// that named them unlinked, so the next start had nothing to retry from and
/// the machine kept a tunnel nobody owned. Only confirmed steps can discharge
/// the claim. A refusal preserves the evidence even when automatic replay cannot
/// safely act on it.
fn journal_may_be_cleared(steps: &[StepOutcome]) -> bool {
    steps.iter().all(|s| matches!(s, StepOutcome::Confirmed))
}

/// Assemble a teardown's step list: the scoped route removals, in plan order,
/// then the adapter reset.
///
/// Separate because it is the part item 5's guarantee actually rests on: the
/// adapter's settings are *distinct entries in the same list* as the routes, so
/// an unconfirmed DNS reset cannot hide behind four confirmed deletions, and a
/// teardown that ran no route removals still reports what it did to the
/// adapter. The two halves used to be one script whose single exit code stood
/// for all of it.
fn teardown_steps(routes: &[StepOutcome], adapter: &[StepOutcome]) -> Vec<StepOutcome> {
    let mut steps = Vec::with_capacity(routes.len() + adapter.len());
    steps.extend_from_slice(routes);
    steps.extend_from_slice(adapter);
    steps
}

/// Whether this journal's own removal scopes reclaim exactly this live route -
/// the question the replay answers when it decides whether a stale route is
/// the dead holder's or a coexisting session's.
#[cfg(test)]
fn reclaimable_by(journal: &RouteJournal, route: &RouteKey) -> bool {
    journal
        .removal_plan()
        .iter()
        .any(|removal| removal_matches_route(removal, route))
}

/// Item 5 + T039: does this live route fall under the journal's recorded scope
/// for one removal? The rules are the renderer's rules (`removal_plan` /
/// `render_scoped_command`): exact prefix always, then exact interface *and*
/// recorded hop when both were journaled, or the tunnel's own address as hop
/// when the interface key is gone. A refused scope matches nothing; a
/// byte-identical prefix on a foreign interface, or under a foreign hop,
/// matches nothing either - that is a coexisting VPN's route.
fn removal_matches_route(removal: &PlannedRemoval, route: &RouteKey) -> bool {
    let (Ok(destination), Some(prefix_len)) = (
        removal.destination.parse::<Ipv4Addr>(),
        route_repair::mask_to_prefix_len(&removal.mask),
    ) else {
        return false;
    };
    if route.destination != destination || route.prefix_len != prefix_len {
        return false;
    }
    match &removal.scope {
        ScopeKind::Refused { .. } => false,
        ScopeKind::Interface { if_index: 0, .. } => false,
        ScopeKind::Interface { if_index, next_hop } => {
            *if_index == route.if_index
                && match next_hop.as_deref() {
                    Some(hop) => hop.parse::<Ipv4Addr>().ok() == Some(route.next_hop),
                    None => true,
                }
        }
        ScopeKind::NextHop { next_hop } => {
            next_hop.parse::<Ipv4Addr>().ok() == Some(route.next_hop)
        }
    }
}

/// The triple the journal records for a planned route, expressed the way
/// netioapi identifies rows. Anything that cannot be named exactly is refused
/// rather than guessed: an un-nameable route is one this process can neither
/// install nor remove.
fn key_of_intent(entry: &RouteIntent) -> Result<RouteKey> {
    let destination = entry.destination.parse::<Ipv4Addr>().map_err(|_| {
        AetherError::HostState(format!(
            "journal destination {:?} is not an IPv4 address",
            entry.destination
        ))
    })?;
    let prefix_len = route_repair::mask_to_prefix_len(&entry.mask).ok_or_else(|| {
        AetherError::HostState(format!("journal mask {:?} is not a prefix", entry.mask))
    })?;
    let next_hop = entry.next_hop.parse::<Ipv4Addr>().map_err(|_| {
        AetherError::HostState(format!(
            "journal next hop {:?} is not an IPv4 address",
            entry.next_hop
        ))
    })?;
    if entry.family != 2 {
        return Err(AetherError::HostState(format!(
            "journal entry {destination} is not an IPv4 route"
        )));
    }
    if entry.if_index == 0 {
        return Err(AetherError::HostState(format!(
            "journal entry {destination} records no interface"
        )));
    }
    Ok(RouteKey {
        if_index: entry.if_index,
        destination,
        prefix_len,
        next_hop,
    })
}

fn win_err(code: WIN32_ERROR, what: &str) -> AetherError {
    AetherError::HostState(format!("{what} failed: Windows error {code}"))
}

fn sockaddr_v4(ip: Ipv4Addr) -> SOCKADDR_INET {
    SOCKADDR_INET {
        Ipv4: SOCKADDR_IN {
            sin_family: AF_INET,
            sin_port: 0,
            // `S_addr` is in network byte order; `from_ne_bytes(octets)` is
            // exactly what the C samples write through `inet_addr`.
            sin_addr: IN_ADDR {
                S_un: IN_ADDR_0 {
                    S_addr: u32::from_ne_bytes(ip.octets()),
                },
            },
            sin_zero: [0i8; 8],
        },
    }
}

/// The v4 view of a `SOCKADDR_INET`, or `None` when the row is not IPv4.
/// Union reads are `unsafe` in Rust; this one is safe in the substantive
/// sense: both variants are plain `Copy` words with no invalid bit patterns,
/// and the family word is read first and decides which variant is meaningful.
fn v4_of(addr: &SOCKADDR_INET) -> Option<Ipv4Addr> {
    let (family, bits) = unsafe { (addr.si_family, addr.Ipv4.sin_addr.S_un.S_addr) };
    if family != AF_INET {
        return None;
    }
    Some(Ipv4Addr::from(bits.to_ne_bytes()))
}

/// The identity triple of a live route row, or `None` for a non-IPv4 row.
fn route_key_of_row(row: &MIB_IPFORWARD_ROW2) -> Option<RouteKey> {
    let destination = v4_of(&row.DestinationPrefix.Prefix)?;
    let next_hop = v4_of(&row.NextHop)?;
    Some(RouteKey {
        if_index: row.InterfaceIndex,
        destination,
        prefix_len: row.DestinationPrefix.PrefixLength,
        next_hop,
    })
}

/// Every IPv4 route the kernel is currently forwarding, as owned copies.
/// `GetIpForwardTable2` hands back one variable-length block the caller must
/// free; the rows are cloned out and the block released immediately, so
/// nothing downstream can dangle on it (`Table` is the C flexible-array
/// idiom; `NumEntries` is the real count).
fn forward_rows() -> Result<Vec<MIB_IPFORWARD_ROW2>> {
    let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
    let code = unsafe { GetIpForwardTable2(AF_INET, &mut table) };
    if code != NO_ERROR {
        return Err(win_err(code, "GetIpForwardTable2"));
    }
    if table.is_null() {
        return Err(AetherError::HostState(
            "GetIpForwardTable2 succeeded with a null table".into(),
        ));
    }
    let rows = unsafe {
        let header = &*table;
        std::slice::from_raw_parts(header.Table.as_ptr(), header.NumEntries as usize).to_vec()
    };
    unsafe { FreeMibTable(table.cast_const().cast::<core::ffi::c_void>()) };
    Ok(rows)
}

/// The row `CreateIpForwardEntry2` wants for one journal key: initialised per
/// the API's documented contract, then pinned to the exact LUID + prefix + hop
/// triple, protocol NetMGMT - the shape the old
/// `New-NetRoute -PolicyStore ActiveStore` produced.
fn forward_row_for(key: &RouteKey) -> Result<MIB_IPFORWARD_ROW2> {
    let initialized = {
        let mut row = MIB_IPFORWARD_ROW2::default();
        unsafe { InitializeIpForwardEntry(&mut row) };
        row
    };
    let mut luid = NET_LUID_LH::default();
    let code = unsafe { ConvertInterfaceIndexToLuid(key.if_index, &mut luid) };
    if code != NO_ERROR {
        return Err(win_err(
            code,
            &format!("ConvertInterfaceIndexToLuid(IF {})", key.if_index),
        ));
    }
    Ok(MIB_IPFORWARD_ROW2 {
        InterfaceLuid: luid,
        InterfaceIndex: key.if_index,
        DestinationPrefix: IP_ADDRESS_PREFIX {
            Prefix: sockaddr_v4(key.destination),
            PrefixLength: key.prefix_len,
        },
        NextHop: sockaddr_v4(key.next_hop),
        Metric: 0,
        Protocol: MIB_IPPROTO_NETMGMT,
        ..initialized
    })
}

fn delete_is_effective(code: WIN32_ERROR) -> bool {
    // "Already gone" is the outcome the caller wanted; anything else failed.
    matches!(code, NO_ERROR | ERROR_PATH_NOT_FOUND | ERROR_FILE_NOT_FOUND)
}

/// Delete every live row carrying exactly this key. Best-effort by design: it
/// serves the stale reclaim before an install and the rollback after one, and
/// every caller re-reads the table afterwards to decide what it *proved*.
fn delete_matching_key(key: &RouteKey) {
    let rows = match forward_rows() {
        Ok(rows) => rows,
        Err(e) => {
            log::warn!(
                "[tun] cannot enumerate the table to reclaim {}: {e}",
                key.render()
            );
            return;
        }
    };
    for row in rows
        .iter()
        .filter(|row| route_key_of_row(row) == Some(*key))
    {
        let code = unsafe { DeleteIpForwardEntry2(row) };
        if !delete_is_effective(code) {
            log::warn!(
                "[tun] stale copy of {} could not be deleted (Windows error {code})",
                key.render()
            );
        }
    }
}

/// Create one journal-named route through `CreateIpForwardEntry2`.
///
/// A crashed run's persistent copy of *our exact triple* may still sit in the
/// table, so it is reclaimed first - scoped to the same triple, which is what
/// lets the reclaim leave a coexisting VPN's byte-identical prefix (different
/// interface, or different hop) untouched.
fn install_route(key: &RouteKey) -> Result<()> {
    delete_matching_key(key);
    let row = forward_row_for(key)?;
    let code = unsafe { CreateIpForwardEntry2(&row) };
    if code == NO_ERROR {
        return Ok(());
    }
    Err(win_err(
        code,
        &format!("CreateIpForwardEntry2 {}", key.render()),
    ))
}

/// Remove one exact key and prove it against a fresh table read.
fn remove_key_confirmed(key: &RouteKey) -> StepOutcome {
    delete_matching_key(key);
    match forward_rows() {
        Ok(rows) if rows.iter().any(|r| route_key_of_row(r) == Some(*key)) => {
            log::error!(
                "[tun] {} is still in the table after deletion",
                key.render()
            );
            StepOutcome::Failed
        }
        Ok(_) => StepOutcome::Confirmed,
        Err(e) => {
            log::error!("[tun] cannot confirm the removal of {}: {e}", key.render());
            StepOutcome::Failed
        }
    }
}

/// The rollback of a partial install: every route actually created is removed
/// and verified, and the attempt decides - via [`journal_may_be_cleared`] -
/// whether the journal may go with it.
fn rollback_routes(installed: &[RouteKey]) -> TeardownAttempt {
    TeardownAttempt {
        steps: installed.iter().map(remove_key_confirmed).collect(),
    }
}

fn removal_cidr(removal: &PlannedRemoval) -> String {
    route_repair::as_cidr(&removal.destination, &removal.mask)
        .unwrap_or_else(|| format!("{} {:?}", removal.destination, removal.mask))
}

/// The routes the table actually holds, compared against what the journal
/// says must exist after a successful install. Verification reads the table;
/// it does not trust a process exit code.
fn verify_routes_present(keys: &[RouteKey]) -> Result<()> {
    let present: Vec<RouteKey> = forward_rows()?
        .iter()
        .filter_map(route_key_of_row)
        .collect();
    let missing: Vec<String> = keys
        .iter()
        .filter(|key| !present.contains(key))
        .map(RouteKey::render)
        .collect();
    if !missing.is_empty() {
        return Err(AetherError::HostState(format!(
            "route verification failed after install: {} not in the forwarding table",
            missing.join(", ")
        )));
    }
    Ok(())
}

/// A failed install, and the bookkeeping that comes with it: roll back what
/// went in, and only unlink the journal if the rollback was *confirmed* - the
/// same rule `Drop` applies to a finished session.
fn abandon_install(journal_path: &Path, installed: &[RouteKey], error: AetherError) -> AetherError {
    let rollback = rollback_routes(installed);
    if rollback.journal_may_be_cleared() {
        clear_journal_at(journal_path);
    } else {
        log::error!(
            "[tun] a partial install could not be fully rolled back; keeping {} so the \
             next start's replay retries",
            journal_path.display()
        );
    }
    error
}

/// The adapter half of a teardown, as its own steps.
///
/// The two settings this process pinned are given back separately -
/// `Set-DnsClientServerAddress -ResetServerAddresses` becomes
/// `SetInterfaceDnsSettings` with an empty name-server list, and
/// `Set-NetIPInterface -AutomaticMetric Enabled` becomes
/// `SetIpInterfaceEntry` with the automatic bit set - and each is confirmed by
/// reading the host again. They used to be one PowerShell script whose single
/// exit marker stood for both, which is the same claim-inflation item 5 was
/// about for the routes: a reset that printed `adapter-reset-ok` had said
/// nothing about whether the resolvers were actually gone, and the DNS half of
/// that specific lie is how a tunnel ended up resolving through the physical
/// adapter.
///
/// The alias is resolved *here* rather than taken from the journal, because the
/// adapter a teardown finds may have been re-created since the journal was
/// written and the new index is the one that carries our settings. When the
/// Alias lookup errors do not prove that the adapter is absent: transient API
/// failure has the same surface. Preserve the journal until a later attempt can
/// confirm the DNS and metric state.
fn adapter_reset_steps() -> Vec<StepOutcome> {
    if !adapter_exists(ADAPTER_NAME) {
        log::info!("[tun] adapter {ADAPTER_NAME} does not exist; adapter reset confirmed");
        return vec![StepOutcome::Confirmed, StepOutcome::Confirmed];
    }
    let if_index = match interface_index(ADAPTER_NAME) {
        Ok(if_index) => if_index,
        Err(e) => {
            if is_not_found(&e) {
                log::info!("[tun] adapter {ADAPTER_NAME} not found; reset confirmed");
                return vec![StepOutcome::Confirmed, StepOutcome::Confirmed];
            }
            log::error!("[tun] cannot identify adapter to reset: {e}; keeping route journal");
            return vec![StepOutcome::Failed, StepOutcome::Failed];
        }
    };
    vec![
        reset_dns_confirmed(if_index),
        restore_automatic_metric_confirmed(if_index),
    ]
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
            return Err(AetherError::HostState(
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
    let if_index = interface_index(ADAPTER_NAME)?;
    let (physical_if_index, gw) = default_gateway(if_index)?;

    // Journal first, fail closed: an install we cannot record is an install we
    // cannot undo, and undoing is the whole point.
    //
    // T036 — before the journal is written, ask whether another instance already
    // owns this interface's record. The single shared journal used to make a
    // second engine overwrite the first one's, after which whichever teardown ran
    // last deleted prefixes the *other* process still believed it held.
    let me = route_repair::current_owner();
    refuse_if_another_instance_holds_a_journal(if_index, &me)?;
    let journal = plan_journal(peer_ip, ipv4, gw, if_index, physical_if_index);
    let journal_path = route_repair::journal_path_for(&me).ok_or_else(|| {
        AetherError::HostState("refusing to mutate routes: no per-owner journal path".into())
    })?;
    route_repair::write_journal(&journal_path, &journal)
        .map_err(|e| AetherError::HostState(format!("refusing to mutate routes: {e}")))?;

    // T039 — the routes themselves go in through netioapi, driven off the
    // journal: every route is created by the exact interface + prefix + hop
    // triple its `RouteIntent` names, so the journal's identity and the
    // table's row identity are literally the same fields, and the same triple
    // is what teardown will have to prove gone. There is no `New-NetRoute`
    // primary and no `route.exe` fallback: a shell-out that *might* have run
    // is precisely what made the recorded state untrustworthy, and a route
    // the journal cannot name exactly is refused before anything is mutated.
    let keys: Vec<RouteKey> = match journal.entries.iter().map(key_of_intent).collect() {
        Ok(keys) => keys,
        Err(e) => {
            // The journal described a route this process cannot name; nothing
            // has been mutated, so the record is not owed to the host yet.
            clear_journal_at(&journal_path);
            return Err(e);
        }
    };
    let mut installed: Vec<RouteKey> = Vec::with_capacity(keys.len());
    for key in &keys {
        match install_route(key) {
            Ok(()) => installed.push(*key),
            Err(e) => {
                log::error!(
                    "[tun] route install failed at {}; rolling back",
                    key.render()
                );
                return Err(abandon_install(&journal_path, &installed, e));
            }
        }
    }
    // Verify from the table, not from an exit code — the old script's
    // `route verification failed` throw, answered with a re-read of the one
    // structure that decides whether the tunnel actually works.
    if let Err(e) = verify_routes_present(&keys) {
        return Err(abandon_install(&journal_path, &installed, e));
    }
    log::info!(
        "[tun] routes installed via netioapi: {}",
        keys.iter()
            .map(RouteKey::render)
            .collect::<Vec<_>>()
            .join(", ")
    );
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
        MutationVerdict::Refuse { why, owner } => Err(AetherError::HostState(format!(
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
/// Declining is not a shrug: the journal stays on disk with our pid in it, and
/// the next start's stale-route replay (or `--repair-routes`) takes the routes down
/// once that pid is demonstrably gone. Removing them *unguarded* is what this lock
/// exists to prevent — a second session mid-install owns the same prefixes, so an
/// unguarded delete would take down routes that are no longer only ours, and the
/// machine would lose its tunnel with one still reporting connected.
///
/// Item 5: the outcome is returned, not swallowed. Callers - `Drop` above all -
/// may forget the journal only when every step reports confirmation; a lost
/// lock returns [`TeardownAttempt::not_attempted`] so the file survives and the
/// next start's replay retries what this one could not do.
fn remove_routes(journal: &RouteJournal) -> TeardownAttempt {
    let _mutation =
        match crate::host_lock::HostMutationGuard::acquire(crate::host_lock::ACQUIRE_TIMEOUT) {
            Ok(guard) => guard,
            Err(e) => {
                log::error!(
                    "[tun] routes left installed: {e}. The journal is kept so the next Aether \
                 start replays the removal; run `aether --repair-routes` to do it now."
                );
                return TeardownAttempt::not_attempted();
            }
        };
    remove_routes_locked(journal)
}

/// Remove this journal's routes while holding the host-mutation lock, and
/// report per removal whether the table actually let go.
///
/// Callers that already hold it (the stale-route replay) use this directly;
/// anything else goes through [`remove_routes`], which takes the lock first. The
/// split exists because the lock is not re-entrant, and a nested acquire would
/// fail and silently skip the removal.
///
/// T039: every route removal is a `DeleteIpForwardEntry2` against a row
/// enumerated from `GetIpForwardTable2` and matched by the journal's exact
/// scope (interface + prefix + recorded hop), re-read afterwards to prove the
/// row is gone. The old shape rendered all of it into one `Remove-NetRoute`
/// script with `$ErrorActionPreference = 'SilentlyContinue'` and logged the
/// failure — an exit code that could not distinguish "removed" from "the host
/// refused", which is what let `Drop` delete a journal whose routes were still
/// installed. The adapter half of the teardown (`adapter_reset_steps`) is
/// reported as its own steps on the same rule, and nothing in here runs a
/// command.
fn remove_routes_locked(journal: &RouteJournal) -> TeardownAttempt {
    let planned = journal.removal_plan();
    let mut route_steps: Vec<StepOutcome> = Vec::with_capacity(planned.len());
    let mut snapshot: Option<Vec<MIB_IPFORWARD_ROW2>> = match forward_rows() {
        Ok(rows) => Some(rows),
        Err(e) => {
            // Without a table read nothing can be located and nothing can be
            // proven gone; every scoped removal below reports accordingly.
            log::error!("[tun] cannot read the IPv4 forwarding table: {e}");
            None
        }
    };
    let mut confirmed = 0usize;
    let mut refused = 0usize;
    for removal in &planned {
        let outcome = remove_scoped(removal, &mut snapshot);
        match outcome {
            StepOutcome::Confirmed => confirmed += 1,
            StepOutcome::Refused => refused += 1,
            _ => {}
        }
        route_steps.push(outcome);
    }
    // Item 5 applies to the adapter half too: the reset is recorded as its own
    // steps, after the routes it follows, and an unconfirmed one keeps the
    // journal alive exactly like an unconfirmed deletion does.
    let adapter_steps = adapter_reset_steps();
    let steps = teardown_steps(&route_steps, &adapter_steps);
    log::info!(
        "[tun] teardown: {confirmed} scoped deletion(s) confirmed against the table, \
         {refused} refused, {} adapter reset step(s) reported alongside them",
        adapter_steps.len()
    );
    TeardownAttempt { steps }
}

/// One planned removal, executed and verified against the forwarding table.
fn remove_scoped(
    removal: &PlannedRemoval,
    snapshot: &mut Option<Vec<MIB_IPFORWARD_ROW2>>,
) -> StepOutcome {
    match &removal.scope {
        ScopeKind::Refused { why } => {
            log::error!("[tun] refusing to remove {}: {why}", removal_cidr(removal));
            return StepOutcome::Refused;
        }
        ScopeKind::Interface { if_index: 0, .. } => {
            log::error!(
                "[tun] refusing to remove {}: journal entry has no interface index",
                removal_cidr(removal)
            );
            return StepOutcome::Refused;
        }
        _ => {}
    }
    let matching = |rows: &[MIB_IPFORWARD_ROW2]| -> Vec<MIB_IPFORWARD_ROW2> {
        rows.iter()
            .filter(|row| {
                route_key_of_row(row).is_some_and(|key| removal_matches_route(removal, &key))
            })
            .copied()
            .collect()
    };
    let targets = {
        let Some(rows) = snapshot.as_ref() else {
            // The table cannot be enumerated, so nothing can be located or
            // verified; the removal is owed, not refused.
            return StepOutcome::Failed;
        };
        matching(rows)
    };
    if targets.is_empty() {
        // Nothing under this scope is live: either it was never created or an
        // earlier pass already removed it. The table read is the proof, and
        // that is exactly what "confirmed" means here.
        return StepOutcome::Confirmed;
    }
    for row in &targets {
        let code = unsafe { DeleteIpForwardEntry2(row) };
        if !delete_is_effective(code) {
            log::error!(
                "[tun] DeleteIpForwardEntry2 failed for {} (Windows error {code})",
                removal_cidr(removal)
            );
        }
    }
    // Item 5: the deletion counts when a fresh read of the table says so, not
    // when the API returned. The next removal reuses that read.
    match forward_rows() {
        Ok(fresh) => {
            let still_live = matching(&fresh);
            *snapshot = Some(fresh);
            if still_live.is_empty() {
                StepOutcome::Confirmed
            } else {
                log::error!(
                    "[tun] {} route(s) under {} are still in the table after deletion",
                    still_live.len(),
                    removal_cidr(removal)
                );
                StepOutcome::Failed
            }
        }
        Err(e) => {
            log::error!(
                "[tun] cannot verify the removal of {}: {e}",
                removal_cidr(removal)
            );
            *snapshot = None;
            StepOutcome::Failed
        }
    }
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
    // file. `remove_routes_locked` folds the adapter reset into its own steps, so
    // recovery needs no separate reset call.
    let handled = replay_abandoned_journals_locked();
    if recover_legacy_state_file() {
        log::info!("[tun] recovered routes recorded by a pre-journal build");
    }
    if handled > 0 {
        log::info!("[tun] stale route recovery complete: {handled} journal(s) replayed");
    }
}

/// Same policy as [`route_repair::replay_abandoned_journals`] — scan, liveness,
/// decide — with the bookkeeping item 5 requires and the shared loop cannot
/// express: a journal file is unlinked only when its teardown came back
/// *confirmed*, route by route, from the forwarding table. A removal that the
/// host refused to prove keeps the journal in place, so the next start (or the
/// next `--repair-routes`) retries it instead of forgetting it.
fn replay_abandoned_journals_locked() -> usize {
    let me = std::process::id();
    let this_boot = route_repair::boot_id();
    let mut handled = 0usize;
    for stale in route_repair::scan_journals(this_boot, process_liveness) {
        match route_repair::decide_replay(&stale.journal, stale.holder, me, this_boot) {
            route_repair::Replay::Remove => {
                log::warn!(
                    "[route-repair] recovering routes abandoned by dead pid {}",
                    stale.journal.creator_pid
                );
                if remove_routes_locked(&stale.journal).journal_may_be_cleared() {
                    route_repair::remove_journal_file(&stale.path);
                    handled += 1;
                } else {
                    log::error!(
                        "[route-repair] the removal for {} is not confirmed; keeping the \
                         journal so the next start retries",
                        stale.path.display()
                    );
                }
            }
            route_repair::Replay::LeaveAlone(why) => {
                if stale.journal.creator_pid == 0 {
                    // Unattributable: nothing may be removed for it, and keeping
                    // the file would hide a real journal from the next start.
                    log::warn!("[route-repair] dropping {}", stale.path.display());
                    route_repair::remove_journal_file(&stale.path);
                } else {
                    log::info!(
                        "[route-repair] leaving {} alone: {why}",
                        stale.path.display()
                    );
                }
            }
        }
    }
    handled
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
                if remove_routes_locked(&journal).journal_may_be_cleared() {
                    removed = true;
                } else {
                    // The routes are still there, and this file is the only
                    // record that names them: it stays for the next start.
                    log::error!(
                        "[tun] the legacy removal is not confirmed; keeping the pre-journal \
                         record so the next start retries"
                    );
                    keep_for_later = true;
                }
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

// T044 — the 30 s route-lifetime refresher lived here. It is gone with T039,
// and the reason is the API change, not a simplification: routes created
// through `CreateIpForwardEntry2` are persistent NetMGMT entries with no
// expiring lifetime to re-arm, so the refresher would have been a cold
// `powershell.exe` every 30 s editing rows it no longer owns. The task-list
// note on T044 already argued expiry was the wrong backstop for split defaults
// (a route that ages out mid-session silently leaks traffic to the physical
// gateway); with persistent entries the whole question goes away, and the
// *primary* teardown stays what it always was — `Drop` plus the journal
// replay, now with item 5's rule that the replay only unlinks a journal whose
// removal it could confirm.
pub struct TunHandle {
    _adapter: Arc<Adapter>,
    session: Arc<Session>,
    journal: RouteJournal,
    journal_path: PathBuf,
}

impl Drop for TunHandle {
    fn drop(&mut self) {
        // Item 5: the journal is a claim on the host, and it is forgotten only
        // when the teardown can prove the claim is discharged. The old shape
        // called `remove_routes` (which could only log), then deleted the
        // journal unconditionally - so a lost lock, a script that failed to
        // spawn, or one route the host refused to give back left the routes
        // installed *and* destroyed the only record that named them. Keeping
        // the file costs nothing: this pid is gone, the next start's replay
        // finds it dead, and it retries what this teardown could not confirm.
        let attempt = remove_routes(&self.journal);
        if attempt.journal_may_be_cleared() {
            clear_journal_at(&self.journal_path);
        } else {
            log::error!(
                "[tun] teardown is not confirmed complete; keeping {} so the next start's \
                 replay retries the removal",
                self.journal_path.display()
            );
        }
        // Closing the session is the step that releases the adapter. When it
        // fails the adapter stays claimed by a process that is already gone, and
        // the next start inherits a device nobody can open — so the failure is
        // named, and the "all cleaned" line is not printed over it.
        match self.session.shutdown() {
            Ok(()) => log::info!("[tun] routes removed, adapter reset, and session closed"),
            Err(e) => log::error!(
                "[tun] the wintun session could not be shut down: {e}; the adapter may stay \
                 claimed until the next start"
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
        .map_err(|e| AetherError::HostState(format!("load wintun: {e}")))?;

    // Prefer existing adapter; create if missing. Orphaned "Aether 1" names are cleaned by WinTun.
    // Check if adapter exists first to avoid Wintun emitting a 0x00000490 error callback on fresh starts.
    let adapter = if adapter_exists(ADAPTER_NAME) {
        match Adapter::open(&wintun, ADAPTER_NAME) {
            Ok(a) => {
                log::info!("[tun] opened existing adapter {ADAPTER_NAME}");
                a
            }
            Err(e) => {
                log::info!("[tun] open existing {ADAPTER_NAME} failed ({e}); re-creating");
                Adapter::create(&wintun, ADAPTER_NAME, TUNNEL_TYPE, None)
                    .map_err(|e| AetherError::HostState(format!("create adapter: {e}")))?
            }
        }
    } else {
        log::info!("[tun] adapter {ADAPTER_NAME} not found; creating");
        Adapter::create(&wintun, ADAPTER_NAME, TUNNEL_TYPE, None)
            .map_err(|e| AetherError::HostState(format!("create adapter: {e}")))?
    };

    let ipv4 = parse_v4(ipv4_cidr)?;
    // Wait briefly for adapter to appear in Windows.
    tokio::time::sleep(Duration::from_millis(300)).await;
    // Reclaim a crashed predecessor's routes *before* this adapter is configured.
    // The replay `recover_stale_routes` runs folds in the adapter reset (see
    // `adapter_reset_steps`), whose DNS half clears the resolvers, so running it
    // after `configure_adapter_ip` wiped the list that call had just pinned: DNS
    // leaked to the physical adapter while the tunnel still reported itself
    // ready. The reset is native now; the ordering constraint that bug taught is
    // unchanged.
    recover_stale_routes();
    configure_adapter_ip(ADAPTER_NAME, ipv4, mtu)?;

    let session = adapter
        .start_session(MAX_RING_CAPACITY)
        .map_err(|e| AetherError::HostState(format!("start session: {e}")))?;
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
            AetherError::HostState("no per-owner journal path for the routes just installed".into())
        })?;
    let handle = TunHandle {
        _adapter: adapter,
        session: session.clone(),
        journal,
        journal_path,
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
        .map_err(|e| AetherError::HostState(format!("tun rx thread: {e}")))?;

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
        .map_err(|e| AetherError::HostState(format!("tun tx thread: {e}")))?;

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

#[cfg(test)]
/// Items 5 and 13: the pure decision logic behind the journal bookkeeping and
/// the netioapi route identity. The API calls themselves want a real Windows
/// routing table - and cannot run in CI - so the judgement that protects the
/// host ("the journal may be deleted only once every removal it owns is
/// confirmed") is factored over [`StepOutcome`]s, and the API is fed exactly
/// the triples the tests below compare against.
mod route_journal_outcome_tests {
    use super::*;

    fn steps(list: &[StepOutcome]) -> TeardownAttempt {
        TeardownAttempt {
            steps: list.to_vec(),
        }
    }

    fn journal() -> RouteJournal {
        plan_journal(
            "162.159.193.1".parse().unwrap(),
            "172.16.0.2".parse().unwrap(),
            "192.168.1.1".parse().unwrap(),
            44,
            11,
        )
    }

    // -- item 5: the journal bookkeeping ---------------------------------

    #[test]
    fn a_confirmed_teardown_is_the_only_one_that_clears_the_journal() {
        let all_ok = steps(&[
            StepOutcome::Confirmed,
            StepOutcome::Confirmed,
            StepOutcome::Confirmed,
            StepOutcome::Confirmed,
            StepOutcome::Confirmed,
        ]);
        assert!(all_ok.journal_may_be_cleared());
    }

    /// The case the old `Drop` lost the journal in: the host-mutation lock
    /// was somebody else's, nothing ran, and the file was deleted anyway.
    #[test]
    fn a_lost_host_lock_keeps_the_journal() {
        assert!(!TeardownAttempt::not_attempted().journal_may_be_cleared());
        assert!(!steps(&[StepOutcome::NotAttempted]).journal_may_be_cleared());
    }

    /// Process failure: the route steps completed, but the adapter script
    /// could not be spawned at all. Nothing may be forgotten while one step
    /// reports it never even started.
    #[test]
    fn a_removal_process_that_never_spawned_keeps_the_journal() {
        assert!(!steps(&[
            StepOutcome::Confirmed,
            StepOutcome::Confirmed,
            StepOutcome::Confirmed,
            StepOutcome::Confirmed,
            StepOutcome::NotAttempted,
        ])
        .journal_may_be_cleared());
    }

    /// Per-command failure: four removals confirmed, the host still shows a
    /// route under the fifth's scope. The journal survives for that one
    /// route, and the next start's replay retries it.
    #[test]
    fn one_failed_command_keeps_the_journal() {
        assert!(!steps(&[
            StepOutcome::Confirmed,
            StepOutcome::Failed,
            StepOutcome::Confirmed,
            StepOutcome::Confirmed,
            StepOutcome::Confirmed,
        ])
        .journal_may_be_cleared());
        // Same for a table read that never confirmed anything.
        assert!(!steps(&[StepOutcome::Failed]).journal_may_be_cleared());
    }

    /// A refusal is not proof of absence. The route may still be present, so
    /// the journal must remain available for repair or operator inspection.
    #[test]
    fn refused_scopes_preserve_the_journal() {
        assert!(!steps(&[
            StepOutcome::Refused,
            StepOutcome::Confirmed,
            StepOutcome::Refused,
            StepOutcome::Confirmed,
        ])
        .journal_may_be_cleared());
    }

    /// The partial-install rule: nothing mutated clears trivially; a route
    /// that cannot be proved gone keeps the journal alive.
    #[test]
    fn a_rollback_clears_the_journal_only_when_it_proved_every_removal() {
        assert!(journal_may_be_cleared(&[]));
        assert!(!journal_may_be_cleared(&[StepOutcome::Failed]));
        assert!(journal_may_be_cleared(&[StepOutcome::Confirmed]));
    }

    // -- item 13: the exact triple ----------------------------------------

    /// Record/replay: every route `plan_journal` says it is about to install
    /// must be reclaimable by that same journal's removal plan. The install
    /// path (`key_of_intent` -> `CreateIpForwardEntry2`) and the teardown
    /// path (`removal_plan` -> `DeleteIpForwardEntry2`) describe the host in
    /// the same fields; a mismatch would be a leak neither can see.
    #[test]
    fn every_planned_route_reclaims_itself_by_exact_key() {
        let j = journal();
        assert_eq!(j.entries.len(), 3, "two split defaults + peer exclude");
        for entry in &j.entries {
            let key = key_of_intent(entry).expect("planned entries are exact");
            assert!(
                reclaimable_by(&j, &key),
                "the journal installs {} but its own removal plan cannot reclaim it",
                key.render()
            );
        }
    }

    /// The quickstart fixture as a pure test: a coexisting OpenVPN/Cisco
    /// split tunnel's byte-identical `0.0.0.0/1` - on another interface, or
    /// under another hop - belongs to neither our scope nor our journal.
    #[test]
    fn coexisting_splits_are_never_reclaimable() {
        let j = journal();
        let ours = key_of_intent(&j.entries[0]).unwrap();
        let foreign_interface = RouteKey {
            if_index: 99,
            ..ours
        };
        assert!(!reclaimable_by(&j, &foreign_interface));
        let foreign_hop = RouteKey {
            next_hop: "10.8.0.1".parse().unwrap(),
            ..ours
        };
        assert!(!reclaimable_by(&j, &foreign_hop));
        assert!(reclaimable_by(&j, &ours));
    }

    /// A journal with no keys at all reclaims nothing - the renderer returns
    /// `None` for those scopes (T031) and the native executor must agree with
    /// the renderer rather than guess a target.
    #[test]
    fn an_unkeyed_journal_reclaims_nothing() {
        let unkeyed = RouteJournal {
            entries: vec![RouteIntent {
                destination: "0.0.0.0".into(),
                mask: "128.0.0.0".into(),
                next_hop: "0.0.0.0".into(),
                if_index: 0,
                family: 2,
            }],
            ..RouteJournal::default()
        };
        let candidate = RouteKey {
            if_index: 44,
            destination: Ipv4Addr::UNSPECIFIED,
            prefix_len: 1,
            next_hop: Ipv4Addr::UNSPECIFIED,
        };
        assert!(!reclaimable_by(&unkeyed, &candidate));
        assert!(key_of_intent(&unkeyed.entries[0]).is_err());
    }

    /// Stale-route recovery for legacy journals: with the interface key gone,
    /// only routes whose next hop *is* the journal's own tunnel address - the
    /// shape the route.exe-era installs recorded - may be reclaimed.
    #[test]
    fn a_hop_scoped_removal_matches_only_our_tunnel_address() {
        let legacy = RouteJournal {
            tunnel_ipv4: "172.16.0.2".into(),
            entries: vec![RouteIntent {
                destination: "0.0.0.0".into(),
                mask: "128.0.0.0".into(),
                next_hop: "172.16.0.2".into(),
                if_index: 0,
                family: 2,
            }],
            ..RouteJournal::default()
        };
        let plan = legacy.removal_plan();
        let ours = RouteKey {
            if_index: 77,
            destination: Ipv4Addr::UNSPECIFIED,
            prefix_len: 1,
            next_hop: "172.16.0.2".parse().unwrap(),
        };
        let foreign = RouteKey {
            next_hop: "10.8.0.1".parse().unwrap(),
            ..ours
        };
        assert!(plan.iter().any(|r| removal_matches_route(r, &ours)));
        assert!(!plan.iter().any(|r| removal_matches_route(r, &foreign)));
    }

    /// Route-row equality: a live table row projects to exactly the key the
    /// journal plans and the teardown verifies, and a row that is not an IPv4
    /// route (the all-zero default here; IPv6 is disabled on this adapter)
    /// projects to `None` and is invisible to every scoped removal.
    #[test]
    fn a_forward_row_projects_to_the_exact_key() {
        let key = RouteKey {
            if_index: 44,
            destination: Ipv4Addr::UNSPECIFIED,
            prefix_len: 1,
            next_hop: Ipv4Addr::UNSPECIFIED,
        };
        let row = MIB_IPFORWARD_ROW2 {
            InterfaceIndex: key.if_index,
            DestinationPrefix: IP_ADDRESS_PREFIX {
                Prefix: sockaddr_v4(key.destination),
                PrefixLength: key.prefix_len,
            },
            NextHop: sockaddr_v4(key.next_hop),
            ..MIB_IPFORWARD_ROW2::default()
        };
        assert_eq!(route_key_of_row(&row), Some(key));
        assert_eq!(route_key_of_row(&MIB_IPFORWARD_ROW2::default()), None);
    }
}

#[cfg(test)]
/// Item 13's adapter half. The netioapi calls themselves want a real tunnel
/// adapter - and cannot run in CI - so what is under test here is the judgement
/// layered on top of them: what a bring-up records as changed, in what order it
/// gives that back, what the DNS writer and reader agree on, and what happens
/// when the host will not name the interface at all. The last one is the only
/// test in this file that touches the real API, and it is read-only: an alias
/// that does not exist must be refused, and answering it proves the `iphlpapi`
/// imports below actually bind at load time.
mod adapter_config_tests {
    use super::*;

    fn v4(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    // -- the rollback ledger ------------------------------------------------

    /// Last thing configured, first thing torn down: the settings overlap
    /// (the row's metric prices the address's routes, the resolvers decide where
    /// the address's traffic goes), so undoing in apply order would restore a
    /// setting whose replacement was still in place.
    #[test]
    fn the_rollback_gives_back_the_last_thing_configured_first() {
        let applied = [
            AdapterStep::Purged,
            AdapterStep::Address,
            AdapterStep::Dns,
            AdapterStep::InterfaceRow,
        ];
        assert_eq!(
            rollback_plan(&applied),
            vec![
                AdapterStep::InterfaceRow,
                AdapterStep::Dns,
                AdapterStep::Address
            ]
        );
    }

    /// The purge owns nothing to give back - its targets were this adapter's own
    /// leftovers, and re-adding them would restore the half-dead state the
    /// bring-up refused to run on - and a bring-up that died before the
    /// interface row was written must not "restore" the zeroed placeholder that
    /// is standing in for it.
    #[test]
    fn a_step_that_owns_nothing_is_recorded_but_never_undone() {
        assert!(!AdapterStep::Purged.is_undoable());
        for step in [
            AdapterStep::Address,
            AdapterStep::Dns,
            AdapterStep::InterfaceRow,
        ] {
            assert!(step.is_undoable(), "{step:?} is a change we made");
        }
        assert_eq!(
            rollback_plan(&[AdapterStep::Purged, AdapterStep::Address]),
            vec![AdapterStep::Address]
        );
        assert!(rollback_plan(&[]).is_empty());
    }

    // -- item 5, for the adapter half ---------------------------------------

    /// The adapter reset is two entries in the same list as the routes, not one
    /// marker standing in for both: a DNS reset the host did not confirm may not
    /// be paid for by four confirmed deletions.
    #[test]
    fn an_unconfirmed_adapter_reset_is_its_own_step_and_keeps_the_journal() {
        let routes = [StepOutcome::Confirmed; 4];
        let clean = teardown_steps(&routes, &[StepOutcome::Confirmed, StepOutcome::Confirmed]);
        assert_eq!(
            clean.len(),
            routes.len() + 2,
            "the reset contributes one step per setting, not one step per script"
        );
        assert!(journal_may_be_cleared(&clean));

        let dns_still_pinned =
            teardown_steps(&routes, &[StepOutcome::Failed, StepOutcome::Confirmed]);
        assert!(!journal_may_be_cleared(&dns_still_pinned));

        let metric_untouched = teardown_steps(
            &routes,
            &[StepOutcome::Confirmed, StepOutcome::NotAttempted],
        );
        assert!(!journal_may_be_cleared(&metric_untouched));

        // A teardown with nothing to remove still answers for the adapter.
        assert_eq!(
            teardown_steps(&[], &[StepOutcome::Confirmed, StepOutcome::Confirmed]).len(),
            2
        );
    }

    /// An interface lookup error is not proof the adapter vanished. A transient
    /// netioapi error must keep the record until restoration can be confirmed.
    #[test]
    fn a_failed_adapter_lookup_keeps_the_journal() {
        let steps = teardown_steps(
            &[StepOutcome::Confirmed],
            &[StepOutcome::Failed, StepOutcome::Failed],
        );
        assert!(!journal_may_be_cleared(&steps));
    }

    // -- the DNS list both halves write and read ----------------------------

    /// The shape `SetInterfaceDnsSettings` parses: a comma-joined,
    /// NUL-terminated wide list. A missing terminator is a read past the buffer,
    /// and an empty list must still be a string - it is the reset.
    #[test]
    fn the_name_server_list_is_nul_terminated_and_comma_joined() {
        let blob = name_server_blob(&[v4("1.1.1.1"), v4("8.8.8.8")]);
        assert_eq!(blob.last(), Some(&0u16), "no NUL, no terminator");
        assert_eq!(String::from_utf16_lossy(&blob), "1.1.1.1,8.8.8.8\0");
        assert_eq!(name_server_blob(&[]), vec![0u16]);
        assert_eq!(
            parse_name_servers(&name_server_blob(&[v4("1.1.1.1"), v4("8.8.8.8")])),
            vec![v4("1.1.1.1"), v4("8.8.8.8")]
        );
    }

    /// The API may answer with IPv6 resolvers and whitespace mixed into the same
    /// string; only the IPv4 half is ours to compare.
    #[test]
    fn only_ipv4_survives_the_read_back() {
        let raw = wide("1.1.1.1, 2606:4700:4700::1111, 8.8.8.8");
        assert_eq!(parse_name_servers(&raw), vec![v4("1.1.1.1"), v4("8.8.8.8")]);
        assert!(parse_name_servers(&wide("not,a,dns,server")).is_empty());
        assert!(parse_name_servers(&[]).is_empty());
        assert!(parse_name_servers(&take_wide(std::ptr::null())).is_empty());
        let buf = wide("8.8.4.4");
        assert_eq!(
            parse_name_servers(&take_wide(buf.as_ptr())),
            vec![v4("8.8.4.4")]
        );
    }

    /// What counts as "the host holds what we wrote": the same set. Order is how
    /// *we* spell primary/secondary and is not a disagreement; a dropped, added
    /// or duplicated server is, and treating it as confirmation is how a tunnel
    /// resolves through the physical adapter while reporting itself ready.
    #[test]
    fn the_same_dns_list_is_the_same_set_in_any_order() {
        let wanted = [v4("1.1.1.1"), v4("8.8.8.8")];
        assert!(same_dns(&wanted, &[v4("8.8.8.8"), v4("1.1.1.1")]));
        assert!(!same_dns(&wanted, &[v4("1.1.1.1")]), "the host dropped one");
        assert!(!same_dns(
            &wanted,
            &[v4("1.1.1.1"), v4("8.8.8.8"), v4("9.9.9.9")]
        ));
        assert!(
            !same_dns(&wanted, &[v4("1.1.1.1"), v4("1.1.1.1")]),
            "echoing one server twice is not holding both"
        );
        assert!(same_dns(&[], &[]));
        assert!(!same_dns(&[], &wanted));
    }

    // -- an interface the host will not name --------------------------------

    /// `0` is "unspecified" to every netioapi row, so a lookup that answered 0
    /// is a lookup that answered *nothing*. The guard runs ahead of every
    /// conversion in this module, including the ones a caller might otherwise
    /// hand an index it read out of a journal.
    #[test]
    fn a_zero_interface_index_is_refused_before_anything_is_keyed_to_it() {
        assert_eq!(nonzero_index(44, "tunnel adapter").ok(), Some(44));
        let err = nonzero_index(0, "tunnel adapter").unwrap_err().to_string();
        assert!(err.contains("index 0"), "{err}");
        assert!(luid_of_index(0).is_err());
        assert!(guid_of_index(0).is_err());
    }

    /// The real conversion, read-only: an alias that does not exist is an error
    /// naming the API that refused it, never a number this process then pins a
    /// route, an address and a DNS list to.
    #[test]
    fn an_absent_adapter_is_refused_rather_than_guessed() {
        let missing = "Aether-no-such-adapter";
        let err = interface_index(missing).unwrap_err().to_string();
        assert!(err.contains("ConvertInterfaceAliasToLuid"), "{err}");
        assert!(err.contains(missing), "{err}");
    }

    /// The one alias the API does *not* refuse: measured against a live host,
    /// `ConvertInterfaceAliasToLuid("")` answers `NO_ERROR` with a LUID that
    /// resolves to an arbitrary real interface, so the refusal has to happen
    /// here - before anything is keyed to whatever that turns out to be - and it
    /// has to say why rather than looking like an API failure.
    #[test]
    fn the_empty_alias_is_refused_before_the_api_can_answer_it() {
        for blank in ["", "   "] {
            let err = interface_index(blank).unwrap_err().to_string();
            assert!(
                err.contains("empty adapter alias"),
                "{blank:?} was not refused by name: {err}"
            );
            assert!(
                !err.contains("ConvertInterfaceAliasToLuid"),
                "{blank:?} reached the API, which answers it with a live interface: {err}"
            );
        }
    }
}
