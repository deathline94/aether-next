# Implementation Plan: Audit Remediation Hardening & Verification Completeness

**Branch**: `014-audit-remediation-hardening` | **Date**: 2026-09-20 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `specs/014-audit-remediation-hardening/spec.md`

## Summary

Remediate all 8 partial and 5 failed audit issues identified against commit `7cb7d31`:
1. Establish separate Authenticode publisher verification policies for `aether.exe` (`deathline94`) and `wintun.dll` (`WireGuard LLC`), and enforce fail-closed embedded release hash validation.
2. Canonicalize the Android settings schema to accept `gool` preset and all active noise modes (`off`, `light`, `medium`, `high`, `max`, `custom`).
3. Harden the Android `EngineRunner` process supervisor barrier to retain `STOPPING` state on kill failure, abort launch in `SessionController`, and support process factory injection.
4. Enforce fatal error propagation on plaintext config migration failure in `aether/src/config.rs`, and quarantine corrupted key store files in `ConfigKeyStore.kt`.
5. Implement generation-owned scan cancellation tokens in `aether/src/prober.rs` and enforce unified 6000ms H3 timeout floors across all boundaries.
6. Make PowerShell TUN route installation transactional with `try/catch` cleanup, and expand Windows proxy restoration to verify `ProxyEnable`, `ProxyServer`, and `ProxyOverride` before deleting recovery data.
7. Expose `settingsLoadError` and `retrySettings` in `useRuntime` with an interactive UI retry banner, and decompose high-complexity orchestrators (`AetherBridge.invoke`, `EngineRunner.start`, `AetherVpnService.establishTun`).
8. Pin all third-party GitHub Actions in CI workflows to immutable 40-character commit SHAs.

---

## Technical Context

**Language/Version**: Rust 1.88.0 (2021 edition), Kotlin 1.9.24 / JVM 21, TypeScript 5.8 / React 19

**Primary Dependencies**: Tauri v2, `windows-sys` 0.59 (`Win32_Security_WinTrust`, `Win32_Security_Cryptography`), `tokio` 1.52, `tokio-util` 0.7 (`CancellationToken`), `fs2` 0.4, `zeroize` 1.8, Android SDK 34 / NDK r27d, Vite 7, Tailwind CSS v4, Vitest 3

**Storage**: Windows DPAPI encrypted `aether.toml`, Android encrypted `aether.toml` with AndroidKeyStore AES-GCM wrapping, atomic replace via `ReplaceFileW` / `MoveFileExW` with `.bak` retention

**Testing**: `cargo test` (unit and integration tests in `aether/tests/` and `apps/desktop/src-tauri/tests/`), `./gradlew testDebugUnitTest` (JUnit 4 in `apps/android/android/app/src/test/`), `vitest run` (frontend hook tests in `apps/android/` and `apps/desktop/`)

**Target Platform**: Windows 10/11 x64 (desktop), Android 8.0+ / API 26+ (mobile)

**Project Type**: Multi-platform hybrid: native Rust core engine, Tauri desktop GUI, Android native VPN & process supervisor with webview UI

**Performance Goals**: Sub-50ms scanner cancellation abort; < 1s settings hydration; zero concurrent process collisions

**Constraints**: Strict Authenticode compliance; zero plaintext credential leakage on disk; immutable CI action references

**Scale/Scope**: 14 audit remediation areas spanning 4 subsystem layers (Rust engine, Windows Tauri backend, Android Kotlin native, React frontend) and CI pipelines

---

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

- **Constitution Status**: `.specify/memory/constitution.md` is an unfilled template; principle gates skipped gracefully per Spec Kit governance rules.
- **Architectural Constraints**:
  - Security invariants must fail-closed (no bypass on missing hashes, failed encryption, or unkillable processes).
  - All external interfaces and native bridge methods must validate inputs against explicit schemas.
  - Automated tests must cover all touched subsystems.

---

## Project Structure

### Documentation (this feature)

```text
specs/014-audit-remediation-hardening/
├── spec.md              # Feature specification
├── plan.md              # This implementation plan
├── research.md          # Phase 0 technical research & decisions
├── data-model.md        # Phase 1 data models & schemas
├── quickstart.md        # Phase 1 verification scenarios
├── contracts/           # Phase 1 interface & lifecycle contracts
│   ├── elevation-policy.contract.md
│   ├── settings-validation.contract.md
│   └── supervisor-barrier.contract.md
├── checklists/
│   └── requirements.md  # Quality validation checklist
└── tasks.md             # Phase 2 output (/speckit-tasks)
```

### Source Code Touched

```text
aether/
├── src/
│   ├── config.rs              # Plaintext migration fatal error propagation
│   ├── prober.rs              # Generation-owned cancellation & 6000ms timeout floor
│   └── tun_win.rs             # Transactional PowerShell route rollback
└── tests/
    └── scanner_cancellation_test.rs # Generation cancellation tests

apps/desktop/
├── package.json
├── src/
│   ├── components/SettingsTab.tsx # Settings hydration retry banner
│   └── hooks/useRuntime.ts        # settingsLoadError & retrySettings
└── src-tauri/
    ├── src/lib.rs                 # Distinct policies (Wintun vs Engine), hash fail-closed, 3-tuple proxy read-back
    └── tests/
        └── elevation_trust_test.rs # Policy & release hash validation tests

apps/android/
├── package.json
├── src/
│   ├── components/SettingsTab.tsx # Settings hydration retry banner
│   ├── hooks/useRuntime.ts        # settingsLoadError & retrySettings
│   └── hooks/useScanner.ts        # Unified 6000ms H3 timeout clamp
└── android/app/
    └── src/
        ├── main/java/app/aethernext/
        │   ├── AetherBridge.kt      # Decomposed command handlers, 6000ms floor
        │   ├── AetherVpnService.kt  # Decomposed TUN & network helpers
        │   ├── ConfigKeyStore.kt    # Corrupt key quarantine & reprovision trigger
        │   ├── EngineRunner.kt      # ProcessLauncher injection, unkillable retention
        │   └── SessionController.kt # stopAndWait inspection, canonical settings schema
        └── test/java/app/aethernext/
            ├── EngineRunnerTest.kt  # Real process lifecycle tests (graceful, forced, unkillable)
            └── SettingsStoreTest.kt # Comprehensive enum validation tests

.github/workflows/
├── ci.yml    # Pinned 40-char commit SHAs
└── build.yml # Pinned 40-char commit SHAs & Authenticode release signing
```

---

## Complexity Tracking

| Violation / Complexity Area | Why Needed | Simpler Alternative Rejected Because |
|---|---|---|
| Distinct Signer Policies (`aether.exe` vs `wintun.dll`) | Wintun is signed by WireGuard LLC, while engine is signed by project team. | Single policy caused 100% of production Windows TUN connections to fail. |
| Injectable `ProcessLauncher` in `EngineRunner` | Allows unit testing process termination barriers (graceful, force-kill, unkillable) in JVM tests. | Standalone atomic tests simulated artificial state rather than testing production code. |
| Full 3-Tuple Proxy Registry Read-Back | Ensures `ProxyEnable`, `ProxyServer`, and `ProxyOverride` all match pre-session state. | Verifying only `ProxyEnable` left system proxy server or override configurations corrupted. |
