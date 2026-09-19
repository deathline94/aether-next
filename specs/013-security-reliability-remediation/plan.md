# Implementation Plan: Full-Stack Security, Reliability & Quality Audit Remediation

**Branch**: `013-security-reliability-remediation` | **Date**: 2026-09-19 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `/specs/013-security-reliability-remediation/spec.md`

---

## Summary

Remediate all 22 actionable security, reliability, lifecycle, and verification issues cataloged across the first-party Rust engine, Windows desktop app, Android mobile app, and CI pipelines:
1. **Desktop Privileged Elevation & DPAPI Identity Protection (P1)**: Authenticode publisher/chain validation, embedded release hash verification, `perMachine` Program Files installer ACLs, Windows DPAPI master key management, atomic migration of plaintext identities, and memory key zeroing.
2. **Core Engine Storage Atomicity, Provisioning Locks & Safe Routing (P2)**: Non-failing-open `ProvisionGuard` with PID liveness tracking; atomic file replacement using `ReplaceFileW`/`MoveFileExW` with backup retention; Windows TUN route verification before split-defaults; strict 16 KiB HTTP proxy header limit enforcement.
3. **Mobile Process Supervisor, VPN Lifecycle & Scanner Completion Barriers (P3)**: State machine (`IDLE`, `SCANNING`, `CONNECTING`, `CONNECTED`, `STOPPING`) with blocking `stopAndWait(timeout)` completion barrier; automatic scan stop and await before direct connect; transactional foreground service rollback; VPN generation token guard; fixed numeric engine PID reflection.
4. **Responsive Scanner Cancellation & Unified Probe Timeout Architecture (P4)**: Cooperative `CancellationToken` integrated into `tokio::select!` and probe futures for sub-10ms wake on cancel; unified single source of truth for probe timeouts (6000ms default, protocol-specific floors).
5. **Configuration Resilience, Registry Recovery & Settings Integrity (P5)**: Windows proxy deletion error propagation and post-deletion read-back verification; desktop child-exit classification retaining `ever_connected` state; webview settings hydration in `finally` blocks; Android native settings enum and boundary validation; `ConfigKeyStore` corruption recovery; Android settings migration preserving user routing choices; Android 10+ boot receiver notifications.
6. **Automated Regression Harness & Release Quality Gates (P6)**: Unit/integration tests across frontend hooks, Kotlin lifecycle, and Rust fault-injection; CI release workflow gated on full CI pass; pinned toolchains.

---

## Technical Context

**Language/Version**: Rust 1.88 (2021 edition), TypeScript 5.8 / React 19, Kotlin 1.9 / Android SDK 34.

**Primary Dependencies**: smoltcp, quiche/boring, tokio 1.52 (`tokio_util`), Tauri 2.0, Vite 7.3, Lucide React, hev-socks5-tunnel.

**Storage**: Local JSON / TOML (`aether.toml`), DPAPI envelope (`config_key.dpapi`), Android SharedPreferences + KeyStore.

**Testing**: `cargo test` in `aether/`, `cargo check` in `apps/desktop/src-tauri`, `npm test` / `npm run build` in `apps/android` and `apps/desktop`, `./gradlew testDebugUnitTest` and `compileDebugKotlin` in `apps/android/android`.

**Target Platform**: Windows 10/11 x64, Android (ARM64, ARMv7, x86_64).

**Project Type**: Multi-component workspace (Rust CLI engine, Tauri desktop client, Android VpnService client).

**Performance Goals**: Scanner cancellation latency < 50 ms; zero process collisions across 100 rapid stop/start cycles; 0% unencrypted identity writes on Windows.

**Constraints**: Preserves RFC 1928 SOCKS5, RFC 9220 / 9484 CONNECT-IP, Windows TUN isolation, and Android 10+ background execution limits.

---

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

- **Principle I: Library & Architecture Integrity**: PASSED. Enhancements strengthen error handling, process boundaries, and validation without violating existing module structures.
- **Principle II: Zero Data Races & Thread Safety**: PASSED. Synchronizes supervisor operations via reentrant locks, uses atomic cancellation tokens in asynchronous loops, and enforces OS file locks for provisioning.
- **Principle III: Test Verification & Quality Gates**: PASSED. Mandates automated test coverage across all modified seams and gates production release builds on full CI pass.

---

## Project Structure

### Documentation (this feature)

```text
specs/013-security-reliability-remediation/
├── spec.md              # Feature specification
├── plan.md              # This plan
├── research.md          # Technical decisions & rationale
├── data-model.md        # Entities, state machines, and validation schemas
├── quickstart.md        # Runnable verification guide
├── contracts/           # Supervisor, scanner, and DPAPI contracts
│   ├── supervisor-lifecycle-contract.md
│   ├── scanner-cancellation-contract.md
│   └── dpapi-storage-contract.md
└── checklists/
    └── requirements.md  # Spec quality checklist
```

### Source Code Targets

```text
aether/src/
├── config.rs            # Atomic file replacement (ReplaceFileW), backup retention, fatal ACL handling
├── cache.rs             # Non-failing-open ProvisionGuard with PID liveness tracking
├── session.rs           # Robust provisioning synchronization
├── tun_win.rs           # Mandatory peer route check & rollback on split-default failure
├── prober.rs            # CancellationToken integration into tokio::select! and probe futures
└── http_proxy.rs        # Strict MAX_HEADER chunk boundary enforcement

apps/desktop/
├── src-tauri/
│   ├── Cargo.toml       # Add windows-sys features (WinVerifyTrust, DPAPI) if needed
│   ├── tauri.conf.json  # Set NSIS installMode to perMachine
│   └── src/
│       ├── lib.rs       # Authenticode/hash verification, DPAPI key generation, ever_connected fix, proxy restore check
│       └── ...
├── src/hooks/
│   └── useRuntime.ts    # Complete settings hydration in finally block, display retry banner
└── src/components/      # Settings error state and retry UI

apps/android/
├── src/
│   ├── App.tsx          # Stop scanner and await idle before connectDirect
│   └── hooks/
│       └── useRuntime.ts # Settings hydration in finally block, retry banner
├── android/app/src/main/java/app/aethernext/
│   ├── EngineRunner.kt  # State machine, stopAndWait(timeout) completion barrier, Long PID reflection
│   ├── SessionController.kt # Auto-stop scan on connect, transactional foreground service rollback, enum validation
│   ├── AetherVpnService.kt  # Generation token guard for establishTun
│   ├── ConfigKeyStore.kt    # Corruption recovery, key rotation, and reprovisioning
│   ├── SettingsStore.kt     # Preserve explicit routing mode during migration
│   └── BootReceiver.kt      # Android 10+ compliant user notification
└── ...

.github/workflows/
├── ci.yml               # Comprehensive test suite (Rust, Node, Kotlin)
└── build.yml            # Gate release builds on CI success (needs: [test]), pin toolchains
```

---

## Implementation Phases

### Phase 1: Core Engine Integrity, Storage & Networking
- **Prober Cancellation (Issue 5 & 20)**: Integrate `CancellationToken` into `hunt_best` select loop and verification futures in `aether/src/prober.rs`. Unify probe timeout floor to 6000ms.
- **Atomic File Replacement & ACLs (Issue 8 & 2)**: Rewrite `write_private_file` in `aether/src/config.rs` using `ReplaceFileW`/`MoveFileExW`, maintaining `.bak` until replace succeeds. Make ACL failure fatal.
- **Provisioning Lock (Issue 7)**: Implement `ProvisionGuard` with exclusive file lock and PID liveness tracking in `aether/src/cache.rs` and `aether/src/session.rs`.
- **Windows Route Fallback (Issue 9)**: Enforce peer route success with physical interface index and transactional rollback in `aether/src/tun_win.rs`.
- **HTTP Header Cap (Issue 19)**: Enforce chunk length clamping and `find_header_end` boundary in `aether/src/http_proxy.rs`.

### Phase 2: Desktop Privilege Elevation, DPAPI & Lifecycle
- **Elevated Binary Verification (Issue 1)**: Implement Authenticode signature and embedded release hash validation in `apps/desktop/src-tauri/src/lib.rs`. Update NSIS `installMode` to `perMachine` in `tauri.conf.json`.
- **DPAPI Key Management (Issue 2)**: Implement `CryptProtectData` / `CryptUnprotectData` master key generation in `lib.rs` and pass via `AETHER_CONFIG_KEY`. Securely zero key buffers.
- **Proxy Restore Verification (Issue 11)**: Propagate real deletion errors and verify registry state via read-back before unlinking recovery files in `lib.rs`.
- **Child Exit Classification (Issue 12)**: Preserve `ever_connected` state before invoking `cleanup_routing` in `lib.rs`.
- **Settings Hydration Resilience (Issue 13)**: Ensure `setSettingsLoaded(true)` executes in `finally` block in `apps/desktop/src/hooks/useRuntime.ts`.

### Phase 3: Android Process Supervisor, VPN & Settings
- **Completion Barrier & State Machine (Issue 4 & 15)**: Implement `stopAndWait(timeout)` and `SupervisorState` in `EngineRunner.kt`. Fix PID reflection from `Number.toInt()`.
- **Direct Connect Auto-Teardown (Issue 3)**: Auto-stop scanner and await exit in `SessionController.connect` and `App.tsx::connectDirect`.
- **Foreground Service Rollback (Issue 6)**: Wrap service startup in transactional try-catch with engine/VPN teardown on failure in `SessionController.kt`.
- **VPN Generation Guard (Issue 10)**: Add generation token and return boolean from `establishTun` in `AetherVpnService.kt`.
- **Native Settings Validation (Issue 14)**: Implement comprehensive enum and range validation in `SessionController.validate`.
- **ConfigKeyStore Recovery (Issue 16)**: Catch crypto exceptions and rotate corrupted keys in `ConfigKeyStore.kt`.
- **Settings Migration Preservation (Issue 17)**: Only apply default `"tun"` when settings store is completely empty in `SettingsStore.kt`.
- **Boot Notification (Issue 18)**: Post notification on boot completed in `BootReceiver.kt`.
- **Android Settings Hydration (Issue 13)**: Ensure `setSettingsLoaded(true)` executes in `finally` block in `apps/android/src/hooks/useRuntime.ts`.

### Phase 4: Automated Testing & CI Release Gates
- **Automated Tests (Issue 21)**: Add unit tests for Rust engine (cancellation, header bounds, atomic writes), Android Kotlin (supervisor, settings validation), and frontend hooks.
- **CI Pipeline & Toolchain Pinning (Issue 22)**: Make release builds in `build.yml` depend on `ci.yml`, pin Rust 1.88 and JDK 21.
