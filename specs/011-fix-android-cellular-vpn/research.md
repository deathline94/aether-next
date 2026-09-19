# Research: Android Cellular Full-Tunnel Protection & IPv6 Leak Prevention

## Background & Problem Statement
On Android devices, activating the Aether VPN over Wi-Fi successfully routes 100% of device traffic through the secure tunnel (Cloudflare MASQUE/WARP). However, when operating on mobile data (cellular LTE/5G), device traffic bypasses the VPN tunnel and connects directly from the mobile carrier's public IP address, despite `VpnService` displaying an active VPN status (key icon in the status bar).

---

## Findings & Root Cause Analysis

### 1. Dual-Stack IPv6 Carrier Leakage
- **Wi-Fi Environment**: Residential and enterprise Wi-Fi networks in almost all user environments allocate private IPv4 addresses (`192.168.x.x` / `10.x.x.x`) without native IPv6 connectivity. All application traffic is IPv4 (`0.0.0.0/0`), which routes cleanly into `tun0` -> `hev-socks5-tunnel` -> `127.0.0.1:socksPort` -> Cloudflare MASQUE.
- **Cellular Environment**: Modern mobile network operators (T-Mobile, Jio, Verizon, Irancell, MCI, etc.) allocate native public IPv6 prefixes (`/64`) to the cellular radio interface (`rmnet_data0`).
- **The Core Breakage**:
  1. In `AetherVpnService.kt`, external DNS resolvers were registered with `VpnService.Builder`:
     ```kotlin
     .addDnsServer(MAPPED_DNS) // 198.18.0.2
     .addDnsServer("1.1.1.1")
     .addDnsServer("8.8.8.8")
     .addDnsServer("2606:4700:4700::1111")
     ```
  2. Because `1.1.1.1` and `2606:4700:4700::1111` were advertised, Android's system resolver (`netd`) sent DNS queries directly to these external IPs instead of using `MAPPED_DNS` (`198.18.0.2`).
  3. External resolvers return real public IP addresses, including `AAAA` (IPv6) records, rather than `hev-socks5-tunnel`'s fake IPs from `198.19.0.0/16`.
  4. Modern dual-stack applications (browsers, messaging apps) prefer IPv6 via Happy Eyeballs v2 (RFC 8305). When an app initiates an IPv6 connection to a real destination address (e.g. `[2600:1901:...]:443`), the packet enters `tun0` via `addRoute("::", 0)`.
  5. `hev-socks5-tunnel` forwards the request as SOCKS5 `CONNECT` with `ATYP_V6` to `aether` engine.
  6. In `aether`, Cloudflare MASQUE CONNECT-IP only assigns an IPv4 address (`172.16.0.2/32`) via the `ADDRESS_ASSIGN` capsule; no IPv6 address is assigned for MASQUE egress. Furthermore, `netstack.rs` creates a synthetic default IPv6 gateway (`o[15] = 1`) which has no neighbor router (NDP fails).
  7. SOCKS5 `handle_connect` waits 20 seconds before timing out. Because `hev-socks5-tunnel.yml` had `icmp: 'drop'`, the IPv6 packets were silently discarded.
  8. When Android detects that the default VPN network times out or fails on IPv6, Android's `ConnectivityService` and multi-network routing falls back to the native cellular connection (`rmnet_data0`), causing application traffic to bypass the VPN and connect directly over the carrier network.

---

## Technical Decisions & Rationale

### Decision 1: Isolate DNS to `MAPPED_DNS` Only
- **Decision**: Configure `VpnService.Builder` with **only** `MAPPED_DNS` (`198.18.0.2`). Remove `1.1.1.1`, `8.8.8.8`, and `2606:4700:4700::1111` from the VPN interface.
- **Rationale**:
  - `hev-socks5-tunnel`'s `mapdns` engine listens exclusively on `198.18.0.2:53`.
  - When an app queries `A` (IPv4), `mapdns` returns synthetic fake IPs in `198.19.0.0/16`. When the app connects to that fake IP, `hev-socks5-tunnel` translates it back to the domain name and issues a domain-based SOCKS5 `CONNECT` through the tunnel.
  - When an app queries `AAAA` (IPv6), `mapdns` immediately returns `NODATA` (0 answers).
  - Because `NODATA` is returned instantly, applications (Happy Eyeballs) know immediately that the destination has no IPv6 address and fall back to IPv4 in 0ms without waiting.
  - No external DNS leak occurs to the carrier network.
- **Alternatives Considered**:
  - *Keep external DNS*: Caused Android `netd` to query `1.1.1.1:853` (DoT) and `2606:4700:4700::1111:53`, receiving public IPv6 IPs that trigger failed IPv6 connections and cellular bypass.

### Decision 2: IPv6 Blackholing with Fast Rejection
- **Decision**: Maintain `addAddress(TUN_ADDR_V6, 128)` and `addRoute("::", 0)` on the TUN interface, but configure `hev-socks5-tunnel.yml` with `icmp: 'reject'` (or ensure immediate TCP RST / ICMPv6 Destination Unreachable).
- **Rationale**:
  - `addRoute("::", 0)` traps all raw IPv6 traffic into the TUN interface so that literal IPv6 connections cannot escape to `rmnet_data0`.
  - Using prefix `128` (host address) matches the standard Android point-to-point TUN interface convention.
  - `icmp: 'reject'` immediately returns ICMPv6 Port Unreachable / TCP RST if an app attempts an IPv6 connection, signaling `ECONNREFUSED` in 0ms rather than hanging for 20 seconds.
- **Alternatives Considered**:
  - *Omit `addRoute("::", 0)`*: Leaving IPv6 unrouted would allow all IPv6 traffic to route directly through the carrier interface (`rmnet_data0`), leaking user identity.
  - *`icmp: 'drop'`*: Silently dropping causes 20-second connection timeouts that trigger Android's cellular failover mechanism.

### Decision 3: Dynamic Underlying Network Tracking
- **Decision**: Register a `ConnectivityManager.NetworkCallback` in `AetherVpnService` to listen for network availability and capabilities (Wi-Fi, Cellular) and dynamically pass the active underlying network to `setUnderlyingNetworks(arrayOf(network))`.
- **Rationale**:
  - Passing `null` tells Android to use system defaults, but when switching between Wi-Fi and cellular, Android's `ConnectivityService` can fail to transfer VPN sockets cleanly.
  - Explicitly updating `setUnderlyingNetworks(networks)` informs Android that the cellular interface is strictly the underlying transport for the VPN, preventing the OS from offering it as an unrouted general internet connection to applications.
- **Alternatives Considered**:
  - *Leaving `setUnderlyingNetworks(null)` static*: Does not handle network handover or multi-network cellular isolation reliably.

### Decision 4: SOCKS5 Fast Failure for IPv6 Destinations
- **Decision**: In `aether/src/socks.rs`, when a client requests a connection to an `ATYP_V6` target and the netstack does not have a confirmed IPv6 gateway, fail the connection immediately with `REP_GENERAL` or `REP_NOT_SUPPORTED` instead of waiting for the 20-second connection timeout.
- **Rationale**:
  - Prevents the 20-second timeout inside the proxy worker thread.
  - SOCKS5 client (`hev-socks5-tunnel`) immediately tears down the flow and returns TCP RST to the application.
