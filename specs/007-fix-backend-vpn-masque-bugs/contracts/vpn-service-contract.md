# Android VpnService Interface Contract

## 1. Network Configuration Specification

```kotlin
val builder = Builder()
    .setSession("Aether Next")
    .setMtu(1280)
    .setBlocking(false)
    // 198.18.0.1/24 ensures 198.18.0.2 is an on-link subnet peer for DnsManager
    .addAddress("198.18.0.1", 24)
    .addDnsServer("198.18.0.2")
    // Capture full default IPv4 space
    .addRoute("0.0.0.0", 0)
    // Capture mapped DNS benchmark space explicitly
    .addRoute("198.18.0.0", 15)
    // Blackhole IPv6 to prevent ISP IPv6 bypass leaks
    .addAddress("fd00:ae::1", 128)
    .addRoute("::", 0)

// Exclude our own package so outbound QUIC/UDP from engine is not looped back
builder.addDisallowedApplication(packageName)

val pfd = builder.establish()
// Set underlying network explicitly to route all other apps through VPN
if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP_MR1) {
    setUnderlyingNetworks(null)
}
```

## 2. Invariants
- `TUN_ADDR`: MUST be `198.18.0.1` with prefix `<= 24`.
- `MAPPED_DNS`: MUST be `198.18.0.2`.
- `mapdns` network in `hev-socks5-tunnel.yml`: MUST be `198.18.0.0` with netmask `255.255.0.0`.
- All external applications (browsers, apps) are routed into TUN, resolved to `198.18.x.x`, and handled by `hev-socks5-tunnel` -> local SOCKS5 proxy -> Cloudflare edge tunnel.
