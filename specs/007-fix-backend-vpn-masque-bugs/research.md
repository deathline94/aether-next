# Phase 0 Research: Backend & Technical Bug Fixes

## 1. Upstream IP/Port Pool Synchronization

### Context & Findings
- **Upstream Repository**: [`CluvexStudio/Aether`](https://github.com/CluvexStudio/Aether).
- Upstream specifies all Cloudflare Anycast address pools, seeds, and ports across three files:
  - `aether/src/consts.rs`: Base endpoints and pins.
  - `aether/src/prober.rs`: MASQUE CIDRs, seeds, and ports.
  - `aether/src/wireguard.rs`: WireGuard CIDRs, seeds, and ports.
- In our local codebase, foreign `8.x.x.x` subnets (Level3/Google CDN ranges like `8.34.146.0/24`, `8.39.214.0/24`) were added. These IPs do not run Cloudflare edge software, and probing them yields 100% timeouts.

### Upstream Standard Definitions to Sync:
```rust
// MASQUE IPv4 CIDRs (14 total)
pub const MASQUE_CIDRS_V4: &[&str] = &[
    "162.159.196.0/24",
    "162.159.195.0/24",
    "162.159.192.0/24",
    "162.159.193.0/24",
    "162.159.204.0/24",
    "162.159.197.0/24",
    "162.159.198.0/24",
    "172.65.251.0/24",
    "188.114.96.0/24",
    "188.114.97.0/24",
    "188.114.98.0/24",
    "188.114.99.0/24",
    "162.159.36.0/24",
    "162.159.46.0/24",
];

// MASQUE IPv4 Seeds (8 total)
pub const MASQUE_SEEDS: &[&str] = &[
    "162.159.196.1",
    "162.159.195.1",
    "162.159.192.1",
    "162.159.197.3",
    "162.159.197.1",
    "162.159.198.2",
    "162.159.198.1",
    "162.159.193.1",
];

// MASQUE Ports (7 total)
pub const MASQUE_PORTS: &[u16] = &[443, 500, 1701, 4500, 4443, 8443, 8095];

// WireGuard IPv4 Prefixes (7 total)
pub const WG_PREFIXES_V4: &[&str] = &[
    "162.159.192.0/24",
    "162.159.195.0/24",
    "188.114.96.0/24",
    "188.114.97.0/24",
    "188.114.98.0/24",
    "188.114.99.0/24",
    "162.159.193.0/24",
];

// WireGuard Seeds (5 total)
pub const WG_SEEDS_V4: &[&str] = &[
    "162.159.192.1",
    "162.159.195.1",
    "188.114.96.1",
    "188.114.97.1",
    "162.159.193.1",
];

// WireGuard Ports (54 total)
pub const WG_PORTS: &[u16] = &[
    2408, 500, 1701, 4500, 854, 859, 864, 878, 880, 890, 891, 894, 903, 908, 928, 934, 939, 942,
    943, 945, 946, 955, 968, 987, 988, 1002, 1010, 1014, 1018, 1070, 1074, 1180, 1387, 1843, 2371,
    2506, 3138, 3476, 3581, 3854, 4177, 4198, 4233, 5279, 5956, 7103, 7152, 7156, 7281, 7559, 8319,
    8742, 8854, 8886,
];
```

---

## 2. MASQUE H3 Candidate Probing Strategy

### Problem
Why does MASQUE H3 only accept 2 or 3 IPs while the prober generated over 12,000 candidates?
1. **Infrastructure Reality**: Cloudflare's general CDN IPs (hundreds of thousands of anycast IPs) only serve reverse-proxy web traffic (`GET /`). Only the dedicated WARP Anycast edge VIPs (the seeds, e.g. `162.159.198.2`) accept QUIC extended CONNECT (`cf-connect-ip`).
2. **Local Multiplier Bug**: In local `prober.rs`, every single host across 21 subnets was multiplied by 8 different ports. This generated `14 * 254 * 8 + ... = 12,363` candidate pairs.
3. **Upstream Solution**: Upstream `build_candidates()` tests the high-value seed VIPs on all ports first, and tests sampled CIDR hosts on port 443 only. This ensures fast convergence on working gateways within seconds, rather than churning through 12,000 dead IPs.

---

## 3. SPKI Pin Verification & Diagnostic Demotion

### Problem
`[tls] SPKI pin mismatch: [19, ce, e4, 42, 63, 3f, 9b, 40] — refusing connection` was filling the activity logs.
- When the scanner probes random IPs across Cloudflare's CIDRs, edge servers without MASQUE termination return default Cloudflare CDN certificates.
- The SPKI hash of those default certificates is `19 ce e4 42 63 3f 9b 40 ...`.
- In `aether/src/tls.rs`, this was logged at `log::warn!`, which immediately sent it to the user's GUI activity window.
- In upstream `CluvexStudio/Aether:aether/src/tls.rs`:
  ```rust
  log::debug!("tls pin: server cert SPKI hash {:02x?} does not match any pinned hash", hash);
  return Err(SslVerifyError::Invalid(boring::ssl::SslAlert::CERTIFICATE_UNKNOWN));
  ```
- Upstream logs this at `debug!` so that failed candidate probes are silently skipped during scanning, while preventing MITM on actual tunnel establishment.

---

## 4. Activity Tab Top Scan Banner Layout Bug

### Problem
In `ActivityTab.tsx`, the top scan card was missing CSS declarations for its flex containers and child spans:
- `.scan-card-header`: was rendered as a block without flex or space-between.
- `.scan-title`: lacked `gap`, causing the mode and phase pill to touch (`(BALANCED)Probing Pool`).
- `.scan-badges`: lacked `gap` and `.badge` styling, causing badges to concatenate (`16 workers0 working`).
- `.scan-card-footer`: `<small>` elements were inline without `justify-content: space-between` (`candidates1%`).

### Solution
Add comprehensive CSS rules in `apps/desktop/src/App.css` and `apps/android/src/App.css` for:
- `.scan-card-header`, `.scan-title`, `.scan-badges`, `.scan-card-footer`
- `.phase-pill`, `.badge`, `.badge.concurrency`, `.badge.working`, `.badge.rtt`

---

## 5. Android VpnService Full-Device Traffic Capture

### Problem
The Android app connected to the engine and VpnService started, but all device traffic continued outside the tunnel.

### Root Causes
1. **Unreachable Fake DNS Subnet**:
   - `AetherVpnService` set `.addAddress("198.18.0.1", 32)` and `.addDnsServer("198.18.0.2")`.
   - With prefix `/32`, `198.18.0.2` is not in the interface subnet. Android `DnsManager` rejects it as an unreachable on-link server and falls back to physical cellular/Wi-Fi DNS.
   - **Fix**: Use `.addAddress("198.18.0.1", 24)` or `.addRoute("198.18.0.0", 15)`.
2. **Invalid Class E IP Range in `mapdns`**:
   - `writeHevConfig` configured `mapdns.network: 240.0.0.0` with `netmask: 240.0.0.0`.
   - `240.0.0.0/4` is Class E reserved. Linux kernel socket `connect()` to `240.x.x.x` returns `EINVAL` ("Network is unreachable").
   - **Fix**: Configure `mapdns.network: 198.18.0.0` and `netmask: 255.255.0.0` (RFC 2544 benchmark unicast space, matching `hev-socks5-tunnel` standard).
3. **Missing System Default Network Override**:
   - Missing `setUnderlyingNetworks(null)` allowed Android `ConnectivityManager` to leave the physical Wi-Fi/Cellular network as the active default route for apps.
   - **Fix**: Call `setUnderlyingNetworks(null)` on the VpnService builder / instance.
4. **Disallowed Application Clarification**:
   - `addDisallowedApplication(packageName)` correctly prevents `app.aethernext` (the engine process) from looping its own outbound UDP packets into the TUN.
   - External apps (Chrome, etc.) are routed into the TUN, resolved via mapped DNS (`198.18.x.x`), and forwarded through `hev-socks5-tunnel` to the local SOCKS proxy (`127.0.0.1:socksPort`).
