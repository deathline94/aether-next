# Data Model: Android Cellular Full-Tunnel Protection

## Entities & Configuration Models

### 1. `VpnNetworkConfig`
Represents the virtual network interface parameters passed to Android `VpnService.Builder`.

| Field | Type | Value | Rationale |
| :--- | :--- | :--- | :--- |
| `session` | String | `"Aether Next"` | User-visible VPN session name. |
| `mtu` | Int | `1280` | IPv6 minimum MTU; prevents fragmentation on cellular carriers. |
| `blocking` | Boolean | `false` | Non-blocking file descriptor for epoll/event loop in tun2socks. |
| `ipv4Address` | String | `"198.18.0.1"` | Host TUN IP (RFC 2544 benchmark subnet). |
| `ipv4Prefix` | Int | `24` | Subnet mask ensuring `198.18.0.2` is in local on-link subnet. |
| `ipv4Routes` | List<Route> | `[("0.0.0.0", 0), ("198.18.0.0", 15)]` | Default route capturing all IPv4; explicit subnet covering fake IPs. |
| `ipv6Address` | String | `"fd00:ae::1"` | Unique Local Address (ULA) host IP. |
| `ipv6Prefix` | Int | `128` | Point-to-point host prefix (avoids erroneous subnet broadcasts). |
| `ipv6Routes` | List<Route> | `[("::", 0)]` | Default route capturing all IPv6 to prevent carrier bypass. |
| `dnsServers` | List<String> | `["198.18.0.2"]` | **Only** the local `mapdns` resolver. No external DNS servers. |
| `metered` | Boolean | `false` | Instructs Android not to apply metered network restrictions to the tunnel. |
| `disallowedApps` | List<String> | `[packageName]` | Excludes Aether itself to prevent upstream socket recursion. |

---

### 2. `HevTunnelConfig`
Represents the configuration YAML written to `noBackupFilesDir/hev-socks5-tunnel.yml`.

```yaml
tunnel:
  mtu: 1280
  ipv4: 198.18.0.1
  ipv6: 'fd00:ae::1'
  icmp: 'reject'        # Fast ECONNREFUSED for IPv6 / unmapped destinations
socks5:
  port: <socksPort>
  address: 127.0.0.1
  udp: 'udp'
mapdns:
  address: 198.18.0.2
  port: 53
  network: 198.19.0.0   # RFC 2544 benchmark range isolated from TUN_ADDR
  netmask: 255.255.0.0
  cache-size: 10000
misc:
  task-stack-size: 81920
  connect-timeout: 5000 # Reduced from 10000ms for faster failover
  log-level: warn
```

---

### 3. `UnderlyingNetworkState`
Tracks physical network transitions to maintain seamless encapsulation without leaks.

| State | Trigger | Action |
| :--- | :--- | :--- |
| `INITIAL` | `establishTun()` | Register `ConnectivityManager.NetworkCallback`. |
| `CONNECTED_CELLULAR` | `onAvailable(network)` (Cellular) | Call `setUnderlyingNetworks(arrayOf(network))`. |
| `CONNECTED_WIFI` | `onAvailable(network)` (Wi-Fi) | Call `setUnderlyingNetworks(arrayOf(network))`. |
| `HANDOVER` | Active network transitions | Update `setUnderlyingNetworks` to new active network in real-time. |
| `DISCONNECTED` | `stopTunnel()` | Unregister `NetworkCallback`. Reset underlying networks. |
