# Implementation Plan: Backend & Technical Bug Fixes (MASQUE H3 Pool, SPKI Pins, Android VPN Traffic, IP/Port Sync, Activity Header Spacing)

**Branch**: `007-fix-backend-vpn-masque-bugs` | **Date**: 2026-09-18 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `specs/007-fix-backend-vpn-masque-bugs/spec.md`

## Summary

This plan addresses five core backend and technical issues across Desktop and Android:
1. **IP & Port Pool Synchronization**: Aligns `aether/src/prober.rs`, `consts.rs`, and `wireguard.rs` with upstream `CluvexStudio/Aether`, purging non-Cloudflare `8.x.x.x` CIDRs.
2. **MASQUE H3 Prober Candidate Strategy**: Replaces the combinatorial multiplier with the upstream candidate strategy (testing seed VIPs on all ports first, and sampling CIDRs on port 443 only), reducing candidates from 12,000+ futile attempts to fast, high-yield gateway targets.
3. **SPKI Pin Warning Demotion**: Replaces `log::warn!` in `aether/src/tls.rs` with `log::debug!` on candidate probe mismatch, matching upstream and eliminating false-positive terminal spam.
4. **Activity Tab Banner UI Spacing**: Adds flexbox layout, element spacing, and badge styling in `App.css` for `.scan-card-header`, `.scan-title`, `.scan-badges`, and `.scan-card-footer`.
5. **Android VpnService Full-Device Traffic Capture**: Adjusts `AetherVpnService.kt` to allocate a valid `/24` subnet on `198.18.0.1`, switches `mapdns` from Class E (`240.0.0.0/4`) to benchmark unicast (`198.18.0.0/16`), and calls `setUnderlyingNetworks(null)` to route all external application traffic into the tunnel.

---

## Technical Context

**Language/Version**: Rust 1.80+ (Engine), Kotlin / Android SDK 26-35 (Mobile Host), TypeScript 5.8+ / React 19 (Desktop & Android UI)  
**Primary Dependencies**: `quiche`, `boring`, `tokio`, `boringtun`, `socket2`, `lucide-react`, `libhev-socks5-tunnel.so`  
**Target Platform**: Windows 10/11 x64, Android (arm64-v8a, armeabi-v7a, x86_64)  
**Project Type**: Multi-platform VPN & Proxy Engine with native Android and Tauri desktop frontends  
**Performance Goals**: Standalone edge scans discover valid gateways in < 5s; zero DNS/traffic bypass on Android VPN  
**Constraints**: Keep all existing Tauri IPC bridges, native Android bridge methods, and UI hooks strictly backward-compatible.

---

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

- **Principle 1 (Library-First)**: Passed. Rust engine changes remain encapsulated within `aether/src/`.
- **Principle 2 (Observability)**: Passed. Debug-level logging preserves troubleshooting capability while keeping user-facing logs clean.
- **Principle 3 (Simplicity & YAGNI)**: Passed. No unnecessary abstractions; synchronizes directly with upstream standard.

---

## Project Structure

### Documentation (this feature)

```text
specs/007-fix-backend-vpn-masque-bugs/
├── spec.md              # Feature specification
├── plan.md              # This plan
├── research.md          # Phase 0 technical research
├── data-model.md        # Phase 1 data & configuration model
├── quickstart.md        # Phase 1 verification guide
├── contracts/           # Phase 1 interface contracts
│   ├── vpn-service-contract.md
│   └── activity-banner-contract.md
└── checklists/
    └── requirements.md  # Spec quality validation checklist
```

### Source Code Paths

```text
aether/
├── src/
│   ├── consts.rs        # Upstream MASQUE_PINS, CDN_ANYCAST_POOL
│   ├── prober.rs        # Upstream MASQUE_CIDRS_V4, SEEDS, PORTS, candidate builder
│   ├── tls.rs           # SPKI verification log level (warn -> debug)
│   └── wireguard.rs     # Upstream WG_PREFIXES_V4, SEEDS, WG_PORTS

apps/android/
├── android/app/src/main/java/app/aethernext/
│   └── AetherVpnService.kt # TUN subnet, mapdns unicast range, setUnderlyingNetworks
├── src/
│   └── App.css          # Scan banner spacing, badges, and footer alignment

apps/desktop/
└── src/
    └── App.css          # Scan banner spacing, badges, and footer alignment
```

---

## Implementation Steps (Phase 2 Preparation)

1. **Rust Engine Synchronization (`aether/`)**:
   - Update `aether/src/consts.rs` and `aether/src/prober.rs` with upstream MASQUE CIDRs, seeds, and ports; drop all `8.x.x.x` addresses.
   - Refactor candidate generator in `aether/src/prober.rs` to prioritize seed VIPs across all ports, then sample CIDRs on primary port.
   - Update `aether/src/wireguard.rs` with upstream `WG_PREFIXES_V4`, `WG_SEEDS_V4`, and 54-port `WG_PORTS`.
   - Update `aether/src/tls.rs` to log SPKI mismatches at `debug` instead of `warn`.
   - Run `cargo test` in `aether` to confirm test suite integrity.

2. **Android VpnService Traffic Routing (`apps/android/android`)**:
   - In `AetherVpnService.kt`:
     - Change `.addAddress(TUN_ADDR, 32)` to `.addAddress(TUN_ADDR, 24)`.
     - Add `.addRoute("198.18.0.0", 15)`.
     - In `writeHevConfig`: change `network: 240.0.0.0` and `netmask: 240.0.0.0` to `network: 198.18.0.0` and `netmask: 255.255.0.0`.
     - Add `setUnderlyingNetworks(null)` call on Android 5.1+.

3. **Activity Tab UI Layout & Spacing (`apps/desktop/` & `apps/android/`)**:
   - In `apps/desktop/src/App.css` and `apps/android/src/App.css`:
     - Add styling for `.scan-card-header`, `.scan-title`, `.scan-badges`, `.scan-card-footer`, `.phase-pill`, `.badge`, `.badge.concurrency`, `.badge.working`, `.badge.rtt`.

4. **Build & Verification**:
   - Run `cargo test` in `aether`.
   - Run `npm run build` in `apps/desktop`.
   - Run `npm run sync-www` in `apps/android`.
