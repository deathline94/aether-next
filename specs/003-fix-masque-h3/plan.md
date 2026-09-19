# Implementation Plan: Fix MASQUE H3 Connectivity and Upstream Alignment + Bug Remediation

**Branch**: `003-fix-masque-h3` | **Date**: 2026-09-16 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `specs/003-fix-masque-h3/spec.md` + user request to plan both MASQUE H3 protocol changes and all identified visual/functional bugs.

## Summary

This plan aligns the core Rust MASQUE HTTP/3 engine with upstream [CluvexStudio/Aether v2.0.0](https://github.com/CluvexStudio/Aether/releases/tag/v2.0.0) to achieve reliable connectivity on censored networks, while comprehensively resolving visual, ergonomic, and functional bugs across the desktop application.

Key initiatives:
1. **QUIC v2 Version Negotiation Baiting (`AETHER_QUIC_V2`)**: Punch middlebox NAT state and bypass DPI QUIC v1 handshake drops by dispatching a 1200-byte bait packet (`0xc3`, version `0x6b33_43cf`) before initiating QUIC v1.
2. **RFC 9220 / RFC 9484 CONNECT-IP Headers**: Eliminate non-standard custom headers (`cf-connect-proto`, `cf-pq-enabled`) that trigger HTTP 400 Bad Request on Cloudflare edges.
3. **Quiche Transport Parameter Alignment**: Remove obsolete ALPN `h3-29`, remove premature early data without tokens, disable active migration, and balance flow control windows.
4. **Data Plane Verification & Fail-Fast Stream Polling**: Require 2 consecutive successful DNS replies over H3 datagrams in `verify_masque()`; fail fast on non-2xx HTTP status or stream resets.
5. **Direct Connect Navigation & Peer Freedom**: Automatically switch to the Connection view upon clicking "Connect Direct"; clear temporary forced peers when clicking presets or the primary Connect button.
6. **Scanner Progress Retention & Telemetry**: Maintain scanner progress cards after completion; accurately report "Completed (0 found)" and suppress malformed log lines.
7. **TUN Mode Verification & Metric Accuracy**: Enable direct egress testing in TUN mode; correct contradictory process status displays ("PID 12345" + "Not running").
8. **Layout & Invariant Polish**: Contain discovered gateway lists with bounded vertical scrolling; advise users on UDP noise inapplicability under H2; reflect blocked saves during port collisions.

---

## Technical Context

**Language/Version**: Rust 1.75+ (2021 edition), TypeScript 5.x / React 19 (Desktop UI)

**Primary Dependencies**: `quiche` (0.22), `boring` / BoringSSL, `ureq` 2.x (Tauri client), `@tauri-apps/api` 2.x, `lucide-react`

**Storage**: Local file persistence (`settings.json`, cached credentials)

**Testing**: `cargo test --package aether --lib`, `npm run build` in `apps/desktop`

**Target Platform**: Windows 10/11 x64 (Tauri desktop app), Android (ARM64/v7a/x86_64)

**Project Type**: Systems network proxy & full-tunnel VPN with cross-platform GUI

**Performance Goals**: Sub-500ms handshake initiation with version baiting; sub-100ms tunnel setup; smooth 60fps UI rendering during concurrent network probing

**Constraints**: WinTUN driver requires elevation for TUN mode; QUIC Initial packets must adhere to 1200-byte minimum size; no breaking changes to Amnezia noise (`Jc`, `Jmin`, `Jmax`).

---

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

- [x] **Anti-Censorship Core**: Standard version negotiation baiting matches proven upstream v2.0.0 implementation.
- [x] **Zero Regression on Noise**: Amnezia noise and custom noise profiles remain intact on UDP transports.
- [x] **Type Safety**: Rust type system and TypeScript strict mode enforce protocol invariants.
- [x] **Observability**: Clear structured logging in both engine and UI console.

---

## Project Structure

### Documentation (this feature)

```text
specs/003-fix-masque-h3/
├── spec.md              # Feature specification
├── plan.md              # This file (/speckit-plan command output)
├── research.md          # Phase 0 research & architectural decisions
├── data-model.md        # Phase 1 data model & state machines
├── quickstart.md        # Phase 1 verification & run guide
├── contracts/           # Phase 1 interface contracts
│   ├── quic-bait-contract.md
│   └── tauri-ipc-contract.md
├── checklists/
│   └── requirements.md
└── tasks.md             # Phase 2 task breakdown (generated via /speckit-tasks)
```

### Source Code Targets

```text
aether/src/
├── quic.rs              # [MODIFY] Implement build_version_bait, send_version_bait, 2-probe DNS data plane
├── masque.rs            # [MODIFY] Standardize CONNECT-IP headers, fail-fast on non-2xx and stream resets
├── tls.rs               # [MODIFY] Align Quiche ALPN (b"h3" only), transport windows, disable active migration
├── prober.rs            # [MODIFY] Integrate version baiting into MASQUE prober routines
└── consts.rs            # [MODIFY] QUIC_V2_VERSION (0x6b33_43cf)

apps/desktop/
├── src-tauri/src/
│   └── lib.rs           # [MODIFY] Fix test_connection for TUN mode; scan_done 0-hit payload hygiene
├── src/
│   ├── App.tsx          # [MODIFY] Switch view on connectDirect; manage pinned peer lifecycle
│   ├── App.css          # [MODIFY] Add max-height/overflow-y to .discovered-list, overflow-wrap anywhere
│   ├── components/
│   │   ├── ScannerTab.tsx    # [MODIFY] Retain progress card post-scan; label H2 noise inapplicability
│   │   ├── ConnectionTab.tsx  # [MODIFY] Fix Process metric "Starting" status; clear peer on presets; TUN test accents
│   │   ├── SettingsTab.tsx    # [MODIFY] H2 noise advisory; blocked save bar on port collision
│   │   └── ActivityTab.tsx    # [MODIFY] Polish milestone rendering
│   └── hooks/
│       ├── useScanner.ts      # [MODIFY] Handle 0-hit completion phase and clean logs
│       ├── useRuntime.ts      # [MODIFY] Clear peer on standard connect/preset selection
│       └── useLogs.ts         # [MODIFY] Filter probe timeouts from milestones
```

---

## Complexity Tracking

| Violation | Why Needed | Simpler Alternative Rejected Because |
|---|---|---|
| QUIC v2 bait pre-handshake | DPI middleboxes drop QUIC v1 ClientHello unconditionally on restricted networks | QUIC v1 directly fails on 100% of tested connections under censorship firewalls |
| Direct egress test in TUN mode | TUN mode routes system-wide at L3 and does not bind loopback proxy port 1820 | Launching a dummy HTTP proxy in TUN mode wastes resources and doesn't verify the WinTUN adapter route |
