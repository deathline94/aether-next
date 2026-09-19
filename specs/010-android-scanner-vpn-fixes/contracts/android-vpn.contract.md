# Contract: Android VpnService & hev-socks5-tunnel Integration

**Feature**: [`specs/010-android-scanner-vpn-fixes`](../spec.md)
**Date**: 2026-09-18

---

## 1. Scope
Defines the technical contract between Android's `VpnService` network builder and `hev-socks5-tunnel` configuration to guarantee full device traffic routing without leaks or interface collisions.

---

## 2. VpnService Interface Contract

### Interface Addressing
- `IPv4`: `198.18.0.1` / 24 (`198.18.0.0/24`)
- `IPv6`: `fd00:ae::1` / 64 (`fd00:ae::/64`)

### Routing Table
- `0.0.0.0` / 0 (all IPv4 internet traffic)
- `198.18.0.0` / 15 (RFC 2544 benchmark range covering `198.18.0.0/16` and `198.19.0.0/16`)
- `::` / 0 (all IPv6 internet traffic)

### DNS Server Declarations
1. `198.18.0.2`: Local synthetic fake-IP resolver on port 53.
2. `1.1.1.1`: Primary public resolver for DoT (port 853) probe validation and fallback resolution.
3. `8.8.8.8`: Secondary public resolver for DoT (port 853) probe validation.
4. `2606:4700:4700::1111`: Primary IPv6 resolver.

### Package Exclusions
- `packageName`: `app.aethernext` MUST be added via `addDisallowedApplication` to ensure the core engine and its child processes bypass `tun0` and can reach remote edge servers over the physical carrier network.

---

## 3. hev-socks5-tunnel Contract

### Configuration Schema (`hev-socks5-tunnel.yml`)
```yaml
tunnel:
  mtu: 1280
  ipv4: 198.18.0.1
  ipv6: 'fd00:ae::1'
  icmp: 'drop'

socks5:
  port: <socksPort>
  address: 127.0.0.1
  udp: 'udp'

mapdns:
  address: 198.18.0.2
  port: 53
  network: 198.19.0.0
  netmask: 255.255.0.0
  cache-size: 10000

misc:
  task-stack-size: 81920
  connect-timeout: 10000
  log-level: warn
```

### Invariants
1. `mapdns.network` MUST be `198.19.0.0` with `255.255.0.0` so allocated fake IPs (`198.19.x.x`) do not collide with `198.18.0.1` (TUN interface) or `198.18.0.2` (DNS resolver).
2. `tunnel.ipv6` MUST be declared so `hev` forwards IPv6 packets over SOCKS5.
3. `socks5.udp` MUST be `'udp'` for UDP ASSOCIATE datagram forwarding.
