# Contract: Host Network State (Routes, Adapter, System Proxy)

**Feature**: `015-full-audit-remediation` | Applies to: `aether/src/tun_win.rs`, new `aether/src/route_repair.rs`, `apps/desktop/src-tauri/src/lib.rs`

## Invariants

**INV-1** No route, adapter DNS/metric or proxy setting is removed or altered outside what Aether created, under any state of its own bookkeeping.
**INV-2** Every host mutation has a journal entry written **before** the mutation, replayable, and idempotent.
**INV-3** Repair runs unconditionally at startup in **every** routing mode, before any connection attempt. Today `recover_stale_routes()` is reachable only from `tun_win::spawn`, so proxy-only users and uninstalls never repair — while the failure it must repair is a full IPv4 blackhole.
**INV-4** Teardown completes within a bounded, measurable budget and never depends on a destructor running inside a grace window. `Drop`-only cleanup + `child.kill()` after 5 s is exactly how routes stay pointed at a dead adapter.
**INV-5** Every cleanup failure is reported at `error!` + event; no cleanup call site uses `let _ =`.
**INV-6** The host's pre-Aether state is recoverable even when Aether's own recovery artifacts are lost, deleted by AV, or corrupt.

## Ownership and mechanism

| Concern | Contract |
|---|---|
| Who mutates | The **GUI** (already elevated in TUN mode). The elevated child receives configuration over stdin and does not own host state. |
| How | `netioapi` FFI: `CreateIpForwardEntry2` / `DeleteIpForwardEntry2` / `GetIpForwardTable2`; adapter config via `SetIpInterfaceEntry` / `SetDnsServerSettings` — **no** `powershell.exe`, `route.exe`, `netsh`, `ipconfig`. |
| Identity of a route | `InterfaceLuid` + `DestinationPrefix` + `NextHop` (Microsoft documents `ifIndex` as non-persistent), with `Protocol == MIB_IPPROTO_NETMGMT`. |
| Backstop | 90 s `ValidLifetime` lease refreshed every 30 s — a backstop, never the primary mechanism. |
| Pre-kill signal | Engine waits on a duplicated parent process handle and tears down before `kill()`. |

## RouteJournal schema

```json
{ "version": 1, "created_at": 0, "creator_pid": 0, "creator_process_start_time": 0,
  "tun_luid": "", "tun_alias": "", "tun_if_index": 0,
  "phys_luid": "", "gateway": "", "peer_host": "",
  "entries": [ { "prefix": "", "next_hop": "", "family": 2, "proto": "netmgmt", "valid_lifetime_s": 90 } ],
  "before": { "adapter_dns": [], "interface_metric": 0, "peer_route_present": false } }
```

## Deletion scoping rules

| Journal state | Permitted removal |
|---|---|
| Identifiers present | Removal by LUID + prefix + next-hop. |
| Identifiers absent/zero | **Only** prefixes whose next-hop equals the recorded tunnel address. |
| Never | Unscoped prefix deletion. `Get-NetRoute -DestinationPrefix '0.0.0.0/1' \| Remove-NetRoute` with no `Where-Object` is the current code path when indexes are 0 — it deletes a coexisting VPN's split-default routes. |

## Single-instance rule

A per-instance named mutex guards host mutation. Substring PID liveness checks (`s.contains(&pid.to_string())`) are prohibited: "4" matches inside memory and session columns, so a dead holder looks alive and a second instance's cleanup deletes the first instance's routes.

## Adapter rules

- DNS servers come from `configured_dns_servers()`, the same source the proxy path uses. Today TUN hardcodes `1.1.1.1`/`1.0.0.1`, so `AETHER_DNS` is honoured on one path and ignored on the other.
- `InterfaceMetric` is restored from `before.interface_metric`, never reset to a default.
- IPv4-only vs dual-stack is decided once, in one place.

## Proxy contract

| Rule | Detail |
|---|---|
| Snapshot all five values | `ProxyEnable`, `ProxyServer`, `ProxyOverride`, `AutoConfigURL`, per-connection `INTERNET_PER_CONN_PROXY_PAC`. Hard-fail reads — no `.unwrap_or(0)`, which today silently records "was disabled" when the registry read failed. |
| Order | journal → verify write → enable → refresh → … → restore → verify → delete journal. |
| Propagation | `InternetSetOptionW(INTERNET_OPTION_SETTINGS_CHANGED)` then `(INTERNET_OPTION_REFRESH)` after **both** directions. |
| Durability | Journal mirrored to `HKCU\Software\AetherNext\ProxyJournal`. |
| Orphan sweep | `ProxyEnable == 1 && ProxyServer == 127.0.0.1:<our port>` with no journal ⇒ clear + log. Runs on every startup. |
| Coherence | While connected, a 30 s check re-asserts or reports if a third party changed the setting. |
| Uninstall / mode switch | Reversal reachable from `--repair-proxy` and the uninstaller, not only from a proxy-mode session. |

## wintun.dll

| Rule | Detail |
|---|---|
| Resolution | Supplied by the verified parent as an absolute canonicalised path over stdin. No `AETHER_WINTUN` env read; no CWD-relative fallback (both exist today at `tun_win.rs:25-47`, in an **elevated** process). |
| Search order | `SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)` at startup; `LoadLibraryExW(LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR \| LOAD_LIBRARY_SEARCH_SYSTEM32)`. |
| Verify before load | Pinned SHA-256 + publisher `WireGuard LLC` via the `wintun` crate's `verify_binary_signature` feature (no `DllMain` execution before verification). |
| GUI side | Mandatory, not `if let Some(wintun) = wintun_path()` — the check is currently skipped precisely when the packaged DLL is missing. |

## Elevated spawn boundary

Keep "GUI is elevated" for TUN. A `Start-Process -Verb RunAs` child crosses a token boundary and escapes the GUI's kill-on-close job object, orphaning an elevated engine with the system proxy ON. A SYSTEM service over a SID-restricted named pipe is the accepted phase-2 alternative, not a phase-1 requirement.

## Verification

| Test | Falsifies |
|---|---|
| Decoy `0.0.0.0/1` on interface B, Aether's journal LUIDs zeroed, disconnect | INV-1 — decoy must survive. Today it is deleted. |
| `taskkill /F` the engine mid-session, start Aether in **proxy-only** mode, then check the table | INV-3, INV-4 — repair must fire without ever entering TUN. |
| Remove `powershell.exe` from `PATH`, time teardown | INV-4 — must be < 500 ms; today it exceeds the 5 s grace. |
| Truncate `tun-routes.json` to `{}` | INV-2 — treated as absent, repaired, not fatal. |
| `ProxyEnable=1` + our listener, delete the journal, restart | INV-6 — orphan sweep clears it. |
| `AETHER_WINTUN=<trojan>` then connect | wintun rule — connect fails **and** `DllMain` never executes. |
| Read-only registry (simulated failure) then enable | INV-5 — `error!` + event, not a discarded `let _ =`. |
