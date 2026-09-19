# Phase 1 Data Model: Backend & Technical Bug Fixes

## 1. Android Hev Tunnel Configuration (`HevConfig`)

The YAML data structure written to `noBackupFilesDir/hev-socks5-tunnel.yml` and passed to native `TProxyStartService`:

```yaml
tunnel:
  mtu: 1280
  ipv4: 198.18.0.1
  icmp: 'drop'
socks5:
  port: <socks_port>
  address: 127.0.0.1
  udp: 'udp'
mapdns:
  address: 198.18.0.2
  port: 53
  network: 198.18.0.0
  netmask: 255.255.0.0
  cache-size: 10000
misc:
  task-stack-size: 81920
  connect-timeout: 10000
  log-level: warn
```

### Field Definitions:
- `tunnel.ipv4`: `198.18.0.1` — local TUN interface endpoint.
- `socks5.port`: Port passed from `SettingsStore` (default `1819`).
- `mapdns.address`: `198.18.0.2` — virtual DNS resolver endpoint on the TUN interface.
- `mapdns.network` & `mapdns.netmask`: `198.18.0.0` / `255.255.0.0` (`/16`) — RFC 2544 benchmark unicast network. When external apps query domain names, `mapdns` assigns temporary IPs within this range, which the Linux kernel routes cleanly to TUN.

---

## 2. Upstream Synchronized Network Pools (`NetworkPools`)

### MASQUE Pools (`aether/src/prober.rs`, `aether/src/consts.rs`):
- `MASQUE_CIDRS_V4`: 14 `/24` subnets (162.159.192.0/24 through 162.159.198.0/24, 172.65.251.0/24, 188.114.96.0/24-99.0/24, 162.159.36.0/24, 162.159.46.0/24).
- `MASQUE_SEEDS`: 8 known-good Cloudflare Anycast seed IPs.
- `MASQUE_PORTS`: `[443, 500, 1701, 4500, 4443, 8443, 8095]`.
- `MASQUE_CIDRS_V6`: 3 `/48` subnets.
- `MASQUE_SEEDS_V6`: 4 IPv6 seeds.

### WireGuard Pools (`aether/src/wireguard.rs`):
- `WG_PREFIXES_V4`: 7 `/24` subnets (162.159.192.0/24, 162.159.195.0/24, 188.114.96-99.0/24, 162.159.193.0/24).
- `WG_SEEDS_V4`: 5 IPv4 seeds.
- `WG_PORTS`: 54 standard WireGuard Anycast ports.
- `WG_PREFIXES_V6`: 3 subnets.
- `WG_SEEDS_V6`: 4 IPv6 seeds.

---

## 3. SPKI Pin Verification (`SpkiPinConfig`)

### Certificate Pin Set (`consts::MASQUE_PINS`):
- Array of SHA-256 SPKI 32-byte digests:
  1. `eb591b36ab26ba617e98371918c10bcdeae3742db6e76543f94be524dce1d555` (masque.cloudflareclient.com self-signed)
  2. `3fbb1d7452d32b3881eb4b5d48421445b6b9d8f5225959f033532d502637b040` (cloudflareaccess.com GTS WE1)
- **Log Level**:
  - `log::debug!` on non-match during candidate discovery.
  - SslVerifyError::Invalid(SslAlert::CERTIFICATE_UNKNOWN) returned to BoringSSL context.

---

## 4. Scan Card Layout Model (`ScanCardState`)

### Component Markup (`ActivityTab.tsx`):
```html
<div className="scan-card tactical-scan-card">
  <div className="scan-card-header">
    <div className="scan-title">
      <Sparkles className="spin-icon" />
      <strong>Active Engine Scan (BALANCED)</strong>
      <span className="phase-pill">Probing Pool</span>
    </div>
    <div className="scan-badges">
      <span className="badge concurrency">16 workers</span>
      <span className="badge working">0 working</span>
      <span className="badge rtt">best 42ms</span>
    </div>
  </div>
  <div className="scan-progress-bar-bg">
    <div className="scan-progress-bar-fill" />
  </div>
  <div className="scan-card-footer">
    <small className="tabular-nums">Probed 100 / 350 candidates</small>
    <small className="tabular-nums">28%</small>
  </div>
</div>
```
