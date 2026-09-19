# Implementation Plan: Comprehensive Codebase Bug Audit & Precision Remediation

**Branch**: `004-codebase-bug-audit-remediation` | **Date**: 2026-09-16 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `/specs/004-codebase-bug-audit-remediation/spec.md`

## Summary

Remediate all cataloged backend, networking, desktop frontend, and mobile bugs discovered during the comprehensive codebase audit:
1. **Netstack & SOCKS5**: Fix `flush_tx` queue packet inversion under backpressure; fix SOCKS IPv6 DNS resolver parser; implement multi-socket routing for SOCKS UDP Associate.
2. **HTTP Proxy & Routing**: Preserve query strings in HTTP proxy URI rewriting; scope Windows TUN route removal to Aether and default physical interface indices; enforce thread-safe `runtime_env` lookups in `select_peer`.
3. **Desktop Host & UI**: Handle `connectToPeer` errors gracefully without infinite spinning; filter auto-save persistence to avoid error logging during port typing; synchronize obfuscation profiles across ScannerTab and SettingsTab; ensure log readiness fallback string matches actual engine output.
4. **Mobile (Android)**: Re-enable SPKI certificate pinning on Android; set standard mobile scan timeout floor to 6000ms.

## Technical Context

**Language/Version**: Rust 1.88 (2021 edition), TypeScript 5.8 / React 19, Kotlin 1.9 / Android SDK 34.

**Primary Dependencies**: smoltcp, quiche/boring, tokio 1.52, Tauri 2.0, Vite 7.3, Lucide React, hev-socks5-tunnel.

**Storage**: Local JSON / TOML (`aether.toml`, `settings.json`).

**Testing**: `cargo test --bin aether`, `cargo check` in `apps/desktop/src-tauri`, `npm run build` in `apps/desktop`.

**Target Platform**: Windows 10/11 x64, Android (ARM64, ARMv7, x86_64).

**Project Type**: Multi-component workspace (Rust CLI engine, Tauri desktop client, Android VpnService client).

**Performance Goals**: Zero packet reordering under heavy download streams; instantaneous error reporting on connection failure; responsive UI with debounced auto-save.

**Constraints**: Preserves RFC 1928 SOCKS5, RFC 9220 / 9484 CONNECT-IP, and Windows TUN isolation.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

- **Principle I: Library & Architecture Integrity**: PASSED. Changes improve correctness within existing abstractions (`StackDevice`, `configured_dns_servers`, `rewrite_absolute_uri`, `useRuntime`).
- **Principle II: Zero Data Races & Thread Safety**: PASSED. Replaces `std::env::var` with `runtime_env` in `select_peer`.
- **Principle III: Test Verification**: PASSED. Automated unit tests cover queue ordering and IPv6 DNS parsing; end-to-end scenarios cover UI and routing.

## Project Structure

### Documentation (this feature)

```text
specs/004-codebase-bug-audit-remediation/
├── spec.md              # Feature specification
├── plan.md              # This plan
├── research.md          # Technical decisions & rationale
├── data-model.md        # Entities, queue invariants, and validation rules
├── quickstart.md        # Runnable verification guide
├── contracts/           # Netstack, DNS parser, and IPC state contracts
│   ├── netstack-contract.md
│   ├── dns-parser-contract.md
│   └── tauri-ipc-contract.md
└── checklists/
    └── requirements.md  # Spec quality checklist
```

### Source Code Targets

```text
aether/src/
├── netstack.rs          # Fix flush_tx packet inversion on buffer full
├── socks.rs             # Fix IPv6 DNS parser and UDP associate multi-client routing
├── http_proxy.rs        # Preserve query strings in rewrite_absolute_uri
├── tun_win.rs           # Scope install_routes route cleanup to tun_if and phys_if
└── session.rs           # Use runtime_env in select_peer

apps/desktop/
├── src-tauri/src/lib.rs # Sync socks5 listening on readiness string in handle_engine_line
├── src/hooks/
│   └── useRuntime.ts    # Handle connectToPeer errors & filter auto-save on colliding ports
└── src/components/
    └── ScannerTab.tsx   # Synchronize obfuscation dropdown options with canonical profiles

apps/android/android/app/src/main/java/app/aethernext/
├── EngineRunner.kt      # Remove unconditional AETHER_DANGEROUS_DISABLE_TLS_VERIFY
└── AetherBridge.kt      # Default probe timeout floor to 6000ms
```

## Implementation Phases

### Phase 1: Core Engine & Protocol Fixes
- Fix `flush_tx` queue reconstitution in `aether/src/netstack.rs` and add unit test verifying FIFO order under full queue conditions.
- Fix `configured_dns_servers` in `aether/src/socks.rs` to parse IPv4 and bare/bracketed IPv6 addresses with default port 53; add unit tests.
- Fix `rewrite_absolute_uri` in `aether/src/http_proxy.rs` to retain query parameters; add unit tests.
- Scope route cleanup in `install_routes` in `aether/src/tun_win.rs` to `tunIf` and `physIf`.
- Switch `std::env::var` in `select_peer` in `aether/src/session.rs` to `runtime_env::var`.

### Phase 2: Desktop Host & Frontend Resilience
- In `apps/desktop/src/hooks/useRuntime.ts`, set `status: "error"` when `connectToPeer` catches an error.
- In `apps/desktop/src/hooks/useRuntime.ts`, guard `persistSettings` against port collisions or ports outside 1024..=65535.
- In `apps/desktop/src/components/ScannerTab.tsx`, update obfuscation `<select>` options to match canonical names.
- In `apps/desktop/src-tauri/src/lib.rs`, match `"socks5 listening on"` and `"http proxy listening"` in readiness detection.

### Phase 3: Mobile Security & Reliability
- In `apps/android/android/app/src/main/java/app/aethernext/EngineRunner.kt`, remove unconditional `AETHER_DANGEROUS_DISABLE_TLS_VERIFY = "1"`.
- In `apps/android/android/app/src/main/java/app/aethernext/AetherBridge.kt`, set scan probe default timeout to 6000ms.

### Phase 4: Verification & Validation
- Execute `cargo test --bin aether` to verify all unit tests pass with 0 warnings.
- Run `cargo check` in `apps/desktop/src-tauri`.
- Run `npm run build` in `apps/desktop`.
- Complete all scenarios in `quickstart.md`.
