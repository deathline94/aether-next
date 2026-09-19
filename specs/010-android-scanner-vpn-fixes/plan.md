# Implementation Plan: Android Scanner Gateway Display & VPN Tunnel Leak Fixes

**Branch**: `010-android-scanner-vpn-fixes` | **Date**: 2026-09-18 | **Spec**: [`specs/010-android-scanner-vpn-fixes/spec.md`](spec.md)

**Input**: Feature specification from `specs/010-android-scanner-vpn-fixes/spec.md`

## Summary

This feature resolves two critical Android-specific issues in Aether:
1. **Scanner Discovered Gateways UI Distortion**: Restructures discovered gateway result cards for mobile portrait viewports ($\le 680\text{px}$) so that the IP and port render on a single unbroken line without single-character vertical wrapping, with clearly separated protocol badges, latency indicators, and accessible action buttons.
2. **Android VPN Traffic Leak & Route Bypass**: Resolves traffic leaking outside the VPN tunnel by eliminating fake-IP collisions between `mapdns` (`198.19.0.0/16`) and the TUN interface (`198.18.0.1`), enabling IPv6 handling in `hev-socks5-tunnel.yml`, and adding upstream DNS resolvers (`1.1.1.1`, `8.8.8.8`, `2606:4700:4700::1111`) to satisfy Android Private DNS (DoT port 853) validation without falling back to physical cellular carrier DNS.

## Technical Context

**Language/Version**: Kotlin 1.9 / Java 17, TypeScript 5.4, React 18, CSS3, C (libhev-socks5-tunnel.so)

**Primary Dependencies**: Android SDK `VpnService`, `hev-socks5-tunnel` (tun2socks), React, Lucide Icons

**Storage**: Android `noBackupFilesDir` (ephemeral config `hev-socks5-tunnel.yml`), `SharedPreferences`

**Testing**: Android Gradle assemble (`./gradlew assembleRelease` / `check`), TypeScript typecheck (`tsc --noEmit`), device IP & DNS leak tests

**Target Platform**: Android 8.0+ (API 26+) through Android 15

**Project Type**: Android Mobile App (`apps/android`)

**Performance Goals**: 60fps smooth scroll in Scanner results; zero character-wrapping latency; full line-rate packet routing through `hev-socks5-tunnel`

**Constraints**: Mobile viewports down to 320px width; 0% DNS leaks to cellular carrier resolvers; compatible with Android system Private DNS (Automatic/DoT)

**Scale/Scope**: `apps/android` (`App.css`, `ScannerTab.tsx`, `AetherVpnService.kt`) + desktop parity validation (`apps/desktop/src/App.css`)

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

- **Core Principles**: Compliant. Preserves clean boundaries between mobile UI layer and low-level VPN service.
- **Testability**: Compliant. Quickstart defines measurable test scenarios for both UI layout and network routing.
- **Simplicity**: Compliant. No unnecessary native wrappers or third-party libraries; leverages existing `hev-socks5-tunnel` features and responsive CSS.

## Project Structure

### Documentation (this feature)

```text
specs/010-android-scanner-vpn-fixes/
├── spec.md              # Feature specification
├── plan.md              # This file (/speckit-plan output)
├── research.md          # Phase 0 research findings
├── data-model.md        # Phase 1 data entities and lifecycle
├── quickstart.md        # Phase 1 verification and run guide
├── checklists/
│   └── requirements.md  # Quality checklist
└── contracts/
    ├── scanner-ui.contract.md  # Responsive card layout contract
    └── android-vpn.contract.md # VpnService & hev configuration contract
```

### Source Code (repository root)

```text
apps/android/
├── src/
│   ├── App.css                            # Responsive layout rules for .discovered-row on mobile
│   └── components/
│       └── ScannerTab.tsx                 # Discovered gateway card structure & accessibility
└── android/app/src/main/java/app/aethernext/
    └── AetherVpnService.kt                # VpnService builder routes, DNS servers, and hev YAML config
apps/desktop/
└── src/
    └── App.css                            # Desktop parity check to ensure no regression
```

**Structure Decision**: Direct updates to `apps/android/src/App.css` and `apps/android/android/app/src/main/java/app/aethernext/AetherVpnService.kt`, with visual verification on `apps/desktop/src/App.css`.

## Complexity Tracking

| Violation | Why Needed | Simpler Alternative Rejected Because |
|:----------|:-----------|:-------------------------------------|
| *None* | N/A | N/A |
