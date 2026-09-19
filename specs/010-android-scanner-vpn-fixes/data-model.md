# Data Model: Android Scanner Gateway Display & VPN Tunnel Leak Fixes

**Feature**: [`specs/010-android-scanner-vpn-fixes`](../spec.md)
**Date**: 2026-09-18

---

## 1. Discovered Gateway Presentation Entity

### `DiscoveredGatewayItem`
Represents an edge gateway discovered by the scanner and displayed to the user in the scanner results list.

| Field | Type | Description | Validation / Constraints |
|:------|:-----|:------------|:-------------------------|
| `addr` | `string` | IP address and port formatted as `host:port` (e.g. `162.159.198.1:4500` or `[2606:4700:d0::a29f:c001]:4500`) | Non-empty string. Formatted with `tabular-nums` and `white-space: nowrap`. Must never wrap character-by-character. |
| `protocol` | `string` | Tunnel protocol name (e.g. `masque`, `wg`, `gool`) | Displayed in uppercase (`MASQUE H3`, `WIREGUARD`, etc.). Rendered as a compact badge. |
| `rtt` | `string` | Formatted round-trip latency string (e.g. `626ms`, `48ms`) | Monospace numeric text. |
| `rttMs` | `number` | Numeric round-trip latency in milliseconds | $\ge 0$. Determines tier classification. |
| `tierClass` | `string` | CSS class for latency badge coloring | One of: `rtt-ultra-green` ($< 80\text{ms}$), `rtt-optimal-cyan` ($< 160\text{ms}$), `rtt-acceptable-amber` ($< 300\text{ms}$), `rtt-high-coral` ($\ge 300\text{ms}$). |
| `badgeText` | `string` | Tooltip / accessibility description | e.g. `Optimal response time`, `High latency`. |

---

## 2. Android VPN Configuration & Routing Entity

### `VpnTunnelConfig`
Configuration applied to Android `android.net.VpnService.Builder` to instantiate the virtual network interface (`tun0`).

| Field | Type | Default Value | Description |
|:------|:-----|:--------------|:------------|
| `sessionName` | `string` | `"Aether Next"` | System notification session label. |
| `mtu` | `number` | `1280` | IPv6 minimum standard MTU, preventing packet fragmentation over cellular and WAN tunnels. |
| `blocking` | `boolean` | `false` | Asynchronous non-blocking file descriptor mode. |
| `tunAddrV4` | `string` | `"198.18.0.1"` | Local IPv4 address assigned to the TUN interface. |
| `tunPrefixV4` | `number` | `24` | Local IPv4 subnet prefix (`198.18.0.0/24`). |
| `tunAddrV6` | `string` | `"fd00:ae::1"` | Unique local IPv6 address assigned to the TUN interface. |
| `tunPrefixV6` | `number` | `64` | Local IPv6 subnet prefix (`fd00:ae::/64`). |
| `dnsServers` | `string[]` | `["198.18.0.2", "1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"]` | Configured DNS servers for system and app lookups, supporting DoT validation on port 853. |
| `routesV4` | `[string, number][]` | `[["0.0.0.0", 0], ["198.18.0.0", 15]]` | Default IPv4 internet route and RFC 2544 benchmark space covering fake-IP mapped routes. |
| `routesV6` | `[string, number][]` | `[["::", 0]]` | Default IPv6 route capturing all device IPv6 packets. |
| `disallowedApps` | `string[]` | `[packageName]` | App package excluded from the VPN interface to allow engine sockets to connect to edge IPs without looping. |

---

## 3. hev-socks5-tunnel Configuration Entity

### `HevTunnelConfig`
YAML configuration written to `noBackupFilesDir/hev-socks5-tunnel.yml` and ingested by `libhev-socks5-tunnel.so`.

```yaml
tunnel:
  mtu: 1280
  ipv4: '198.18.0.1'
  ipv6: 'fd00:ae::1'
  icmp: 'drop'

socks5:
  port: <socksPort>
  address: '127.0.0.1'
  udp: 'udp'

mapdns:
  address: '198.18.0.2'
  port: 53
  network: '198.19.0.0'
  netmask: '255.255.0.0'
  cache-size: 10000

misc:
  task-stack-size: 81920
  connect-timeout: 10000
  log-level: 'warn'
```

### Constraints & Invariants
1. `mapdns.network` (`198.19.0.0/16`) **MUST NOT** overlap with `tunnel.ipv4` (`198.18.0.1`) or `mapdns.address` (`198.18.0.2`).
2. `tunnel.ipv6` **MUST** match `VpnTunnelConfig.tunAddrV6`.
3. `socks5.udp` **MUST** remain `'udp'` to leverage standard SOCKS5 UDP ASSOCIATE for low-latency datagram forwarding.

---

## 4. State Lifecycle & Transitions

```
 [ Idle / Disconnected ]
          │
          ▼ User taps "Connect" or "Connect Direct"
 [ Connecting: Engine Starting & Probing ]
          │
          ▼ Aether local SOCKS5 proxy listening (127.0.0.1:socksPort)
 [ VPN Establishing: AetherVpnService ]
          │ ──► Builder sets TUN routes (0.0.0.0/0, ::/0, 198.18.0.0/15)
          │ ──► Builder sets DNS (198.18.0.2, 1.1.1.1, 8.8.8.8, 2606:4700:4700::1111)
          │ ──► Hev config generated with 198.19.0.0/16 fake-IP pool and IPv6 enabled
          │ ──► TProxyStartService(configPath, established.fd)
          ▼
 [ Active: All Device Traffic Encapsulated ]
          │
          ▼ User taps "Disconnect" or Engine Exits
 [ Tearing Down: TProxyStopService + tun.close() ]
          ▼
 [ Idle / Disconnected ]
```
