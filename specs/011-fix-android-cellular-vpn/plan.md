# Implementation Plan: Full Tunnel Protection on Android Cellular Networks

**Branch**: `011-fix-android-cellular-vpn` | **Date**: 2026-09-19 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `specs/011-fix-android-cellular-vpn/spec.md`

## Summary

Resolve the Android cellular data VPN bypass where device traffic circumvents the secure tunnel and connects directly via the carrier IP. The root cause is a dual-stack IPv6 and DNS misconfiguration: advertising external DNS servers (`1.1.1.1`, `8.8.8.8`, `2606:4700:4700::1111`) bypassed the local `mapdns` resolver on `198.18.0.2`, returning real IPv6 addresses that failed across the upstream tunnel, prompting Android's multi-network resolver to fall back to the direct cellular radio interface (`rmnet_data0`).

The technical fix entails:
1. Configuring `VpnService.Builder` to advertise **strictly** `198.18.0.2` (`MAPPED_DNS`) so all domain lookups are intercepted by `mapdns` (which synthesizes fake IPv4 addresses from `198.19.0.0/16` and returns `NODATA` for `AAAA`).
2. Setting IPv6 address prefix length to `128` (`addAddress("fd00:ae::1", 128)`) with `addRoute("::", 0)` to trap any raw IPv6 packets.
3. Switching `hev-socks5-tunnel.yml` from `icmp: 'drop'` to `icmp: 'reject'` to signal immediate `ECONNREFUSED` / TCP RST for unrouteable traffic, enabling instant Happy Eyeballs v2 fallback to IPv4.
4. Implementing dynamic underlying network tracking via `ConnectivityManager.NetworkCallback` to register cellular and Wi-Fi transitions in real-time with `setUnderlyingNetworks()`.
5. Enhancing `aether` engine SOCKS5 server to return immediate refusal on `ATYP_V6` when the upstream stack lacks an IPv6 egress route, eliminating 20-second connection stalls.

## Technical Context

**Language/Version**: Kotlin 1.9+, Java 17, Android SDK 24–34; Rust 1.80+ (embedded engine).

**Primary Dependencies**: Android `VpnService`, `hev-socks5-tunnel` (native tun2socks), `smoltcp`, `tokio`.

**Storage**: N/A (runtime YAML configurations in `noBackupFilesDir`).

**Testing**: Gradle Android compilation (`./gradlew assembleRelease`), local unit/integration tests, physical device leak test validation (`ipinfo.io`, `test-ipv6.com`, `dnsleaktest.com`).

**Target Platform**: Android 7.0+ (API 24 to 34), tested on Android 13/14/15.

**Project Type**: Android application (`apps/android`) with native JNI and Rust engine binary.

**Performance Goals**: 0ms IPv6 fallback (instant Happy Eyeballs transition), zero connection hang, <3s Wi-Fi/cellular network handover.

**Constraints**: Zero data packet leakage to mobile carrier interface; identical security posture across Wi-Fi and mobile data.

**Scale/Scope**: Android VPN service networking (`apps/android/android/app/src/main/java/app/aethernext/AetherVpnService.kt`) and SOCKS5 fast-fail handling (`aether/src/socks.rs`).

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

- Principle I (Library-First / Clean Boundaries): PASS — Modifies only Android platform routing and upstream SOCKS handler without disturbing core MASQUE protocol implementation.
- Principle II (Zero Leakage): PASS — Traps both IPv4 and IPv6 on `tun0` while eliminating external DNS bypass.
- Principle III (Simplicity & Robustness): PASS — Uses proven Android VpnService patterns and `mapdns` single-resolver architecture.

## Project Structure

### Documentation (this feature)

```text
specs/011-fix-android-cellular-vpn/
├── spec.md              # Feature specification
├── plan.md              # Implementation plan (this file)
├── research.md          # Phase 0 research & root cause analysis
├── data-model.md        # Phase 1 entities & configuration models
├── quickstart.md        # Phase 1 verification & test guide
└── contracts/           # Phase 1 interface contracts
    └── vpn-service-contract.md
```

### Source Code (repository root)

```text
apps/android/android/app/src/main/java/app/aethernext/
└── AetherVpnService.kt  # Routing, DNS configuration, and NetworkCallback

aether/src/
└── socks.rs             # Fast-fail SOCKS5 handling for IPv6 without upstream route
```

**Structure Decision**: Confined directly to Android platform routing (`AetherVpnService.kt`) and fast-rejection support in the SOCKS5 proxy layer (`socks.rs`).

## Complexity Tracking

*No constitutional violations; no additional complexity introduced.*
