# Contract: Android VpnService & tun2socks Integration

## 1. VpnService Routing Contract

### Interface Definition
The virtual network interface must adhere to the following contract during construction:

```kotlin
val builder = Builder()
    .setSession("Aether Next")
    .setMtu(1280)
    .setBlocking(false)
    .addAddress("198.18.0.1", 24)
    .addRoute("0.0.0.0", 0)
    .addRoute("198.18.0.0", 15)
    .addAddress("fd00:ae::1", 128)
    .addRoute("::", 0)
    .addDnsServer("198.18.0.2")
    .addDisallowedApplication(packageName)
```

### Invariants
1. **Single Resolver Rule**: Exactly one DNS server (`198.18.0.2`) MUST be added to the builder. No external DNS servers (such as `1.1.1.1`, `8.8.8.8`, or `2606:4700:4700::1111`) may be added.
2. **Dual-Stack Trapping**: Both `0.0.0.0/0` and `::/0` MUST be routed into the interface. Under no circumstances may `::/0` be omitted, as omission permits immediate carrier IPv6 leakage.
3. **Prefix Discipline**: The IPv6 address `fd00:ae::1` MUST use prefix length `128` to define a single point-to-point host interface.
4. **Self-Exclusion**: The application package name MUST be disallowed from the VPN interface to allow the upstream engine process to bind to physical network sockets.

---

## 2. tun2socks (hev) Contract

### Configuration Schema
```yaml
tunnel:
  mtu: 1280
  ipv4: 198.18.0.1
  ipv6: 'fd00:ae::1'
  icmp: 'reject'
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
```

### Invariants
1. `mapdns.address` MUST match the DNS server advertised to Android (`198.18.0.2`).
2. `mapdns.network` MUST NOT overlap with `tunnel.ipv4` or `mapdns.address` (using RFC 2544 benchmark space `198.19.0.0/16`).
3. `icmp` MUST be set to `reject` to signal fast socket failure (`ECONNREFUSED` / TCP RST) for unsupported traffic, preventing application stalls.

---

## 3. Network Lifecycle Contract

### Dynamic Underlying Networks
```kotlin
connectivityManager.registerDefaultNetworkCallback(object : ConnectivityManager.NetworkCallback() {
    override fun onAvailable(network: Network) {
        setUnderlyingNetworks(arrayOf(network))
    }
    override fun onLost(network: Network) {
        setUnderlyingNetworks(null)
    }
})
```
- Active network transitions between Wi-Fi and Cellular update `setUnderlyingNetworks` in real-time, preventing Android multi-networking from creating direct carrier bypass paths.
