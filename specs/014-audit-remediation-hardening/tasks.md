# Tasks: Audit Remediation Hardening & Verification Completeness

**Feature**: `014-audit-remediation-hardening`
**Plan**: [plan.md](plan.md) | **Spec**: [spec.md](spec.md)

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Build configuration, release hash generation infrastructure, and test harness setup

- [x] T001 Update `apps/desktop/src-tauri/build.rs` to compute release artifact SHA-256 hashes when staging engine/wintun and inject them into compile-time environment
- [x] T002 [P] Create mock process launcher and test fixtures in `apps/android/android/app/src/test/java/app/aethernext/ProcessTestFixtures.kt`
- [x] T003 [P] Add proxy restoration regression test skeleton in `apps/desktop/src-tauri/tests/proxy_restore_test.rs`

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Core synchronization and policy abstractions required across multiple user stories

**⚠️ CRITICAL**: User story implementation depends on these foundational components

- [x] T004 Define distinct `TrustedBinaryPolicy` constructors (`for_engine` and `for_wintun`) with `enforce_hash_match` in `apps/desktop/src-tauri/src/lib.rs`
- [x] T005 [P] Define `ProcessLauncher` interface and inject default `DefaultProcessLauncher` into `EngineRunner` in `apps/android/android/app/src/main/java/app/aethernext/EngineRunner.kt`
- [x] T006 [P] Add monotonic `SCAN_GENERATION: AtomicU64` tracker and generation-scoped token lookup in `aether/src/prober.rs`

**Checkpoint**: Core policy, launcher, and generation foundations ready — user story implementation can begin

---

## Phase 3: User Story 1 - Production Windows Elevation Trust & Wintun Verification (Priority: P1) 🎯 MVP

**Goal**: Permit production Windows TUN execution by validating `wintun.dll` under `WireGuard LLC` and `aether.exe` under `deathline94`, and fail-closed when release hashes are missing or mismatched.

**Independent Test**:
1. Run `cargo test --test elevation_trust_test`; verify `wintun.dll` passes with `WireGuard LLC` CN and fails with mismatched publisher.
2. Verify binaries fail with `BinaryTrustError::MissingHash` or `HashMismatch` when release hash enforcement is enabled and hash is absent from table.

### Tests for User Story 1
- [x] T007 [P] [US1] Update `apps/desktop/src-tauri/tests/elevation_trust_test.rs` to verify distinct publisher policies (`WireGuard LLC` vs `deathline94`) and fail-closed release hash validation (missing entry returns error)

### Implementation for User Story 1
- [x] T008 [US1] Re-engineer `verify_elevated_binary` in `apps/desktop/src-tauri/src/lib.rs` to reject binaries when `policy.enforce_hash_match` is true and no matching hash is present in `embedded_hashes`
- [x] T009 [US1] Update elevated execution call-sites in `apps/desktop/src-tauri/src/lib.rs` to apply `TrustedBinaryPolicy::for_engine()` to `aether.exe` and `TrustedBinaryPolicy::for_wintun()` to `wintun.dll`
- [x] T010 [US1] Embed authoritative release hashes for `aether.exe` and `wintun.dll` in `EMBEDDED_RELEASE_HASHES` in `apps/desktop/src-tauri/src/lib.rs`

**Checkpoint**: User Story 1 complete — production Windows TUN launches safely without certificate policy conflicts or bypassed hash checks

---

## Phase 4: User Story 2 - Android Settings Schema Canonicalization & UI Consistency (Priority: P1)

**Goal**: Ensure all settings options presented in the Android UI (`gool` preset, noise modes `off`..`custom`) are recognized and accepted by native validation without error.

**Independent Test**:
1. Run `./gradlew testDebugUnitTest --tests "app.aethernext.SettingsStoreTest"`; verify 100% pass across all UI presets and noise profiles.

### Tests for User Story 2
- [x] T011 [P] [US2] Expand `apps/android/android/app/src/test/java/app/aethernext/SettingsStoreTest.kt` with parameterized test validating all presets (`warp`, `gool`) and all noise modes (`off`, `light`, `medium`, `high`, `max`, `custom`)

### Implementation for User Story 2
- [x] T012 [US2] Update `SessionController.validateSettings` in `apps/android/android/app/src/main/java/app/aethernext/SessionController.kt` to accept `gool` in `validPresets`
- [x] T013 [US2] Update `SessionController.validateSettings` in `apps/android/android/app/src/main/java/app/aethernext/SessionController.kt` to accept `off`, `light`, `medium`, `high`, `max`, `custom` in `validNoise`
- [x] T014 [US2] Synchronize default schema fallback values in `apps/android/src/components/SettingsTab.tsx` with native validation rules

**Checkpoint**: User Story 2 complete — UI settings selections perfectly align with native validation

---

## Phase 5: User Story 3 - Mobile Process Supervisor Barrier Integrity & Unkillable Process Handling (Priority: P1)

**Goal**: Guarantee single-instance mutual exclusion on Android by retaining `STOPPING` state when process termination fails, and enforcing launch aborts in `SessionController`.

**Independent Test**:
1. Run `./gradlew testDebugUnitTest --tests "app.aethernext.EngineRunnerTest"`; verify unkillable process causes `stopAndWait` to return `false` and subsequent starts to be rejected.

### Tests for User Story 3
- [x] T015 [P] [US3] Re-engineer `apps/android/android/app/src/test/java/app/aethernext/EngineRunnerTest.kt` to test real `start` and `stopAndWait` using mock `ProcessLauncher` covering graceful exit, forced exit, and unkillable process

### Implementation for User Story 3
- [x] T016 [US3] Update `EngineRunner.stopAndWait` in `apps/android/android/app/src/main/java/app/aethernext/EngineRunner.kt` to retain `STOPPING`, keep `running=true`, and preserve `process` reference when forced kill fails
- [x] T017 [US3] Update `SessionController.connect` in `apps/android/android/app/src/main/java/app/aethernext/SessionController.kt` to check `runner.stopAndWait(3000)` return boolean and abort startup if false
- [x] T018 [US3] Update `SessionController.scan` in `apps/android/android/app/src/main/java/app/aethernext/SessionController.kt` to check `runner.stopAndWait(3000)` return boolean and abort scan if false

**Checkpoint**: User Story 3 complete — Android process supervisor barrier cannot be bypassed and prevents dual-engine collisions

---

## Phase 6: User Story 4 - Cryptographic Identity Migration & Android KeyStore Quarantine (Priority: P1)

**Goal**: Prevent plaintext credential usage if encrypted migration fails on desktop, and quarantine corrupted key files on Android to enable clean reprovisioning.

**Independent Test**:
1. Run `cargo test --test atomic_write_test`; verify config loader returns fatal error when encrypted save fails during migration.
2. Run KeyStore corruption test; verify `aether.toml` and `.bak` are quarantined/deleted and reprovisioning event is emitted.

### Tests for User Story 4
- [x] T019 [P] [US4] Add test verifying fatal error return on encrypted migration save failure in `aether/tests/atomic_write_test.rs`
- [x] T020 [P] [US4] Add test verifying corrupted key store quarantines old `aether.toml` in `apps/android/android/app/src/test/java/app/aethernext/ConfigKeyStoreTest.kt`

### Implementation for User Story 4
- [x] T021 [US4] Update `try_migrate_plaintext_to_encrypted` in `aether/src/config.rs` to propagate `save_config` error and return fatal `Err(AetherError::Config(...))`
- [x] T022 [US4] Update `ConfigKeyStore.loadOrCreate` in `apps/android/android/app/src/main/java/app/aethernext/ConfigKeyStore.kt` to delete/quarantine corrupted `aether.toml` and `aether.toml.bak` on crypto exceptions and emit a reprovisioning signal

**Checkpoint**: User Story 4 complete — failed encryption never leaks plaintext identities, and corrupted KeyStores recover cleanly

---

## Phase 7: User Story 5 - Scanner Cancellation Generation Tracking & Consistent Handshake Timeouts (Priority: P2)

**Goal**: Guarantee that early cancellation signals are never wiped by scan startup, and unify H3/QUIC handshake timeout floors to at least 6000ms across all layers.

**Independent Test**:
1. Run `cargo test --test scanner_cancellation_test`; verify cancellation requested prior to `hunt_best` immediately aborts scan generation.
2. Verify probe timeout floor is at least 6000ms across engine, native bridge, and UI.

### Tests for User Story 5
- [x] T023 [P] [US5] Add unit test for pre-hunt cancellation and generation token tracking in `aether/tests/scanner_cancellation_test.rs`

### Implementation for User Story 5
- [x] T024 [US5] Update `hunt_best` in `aether/src/prober.rs` to check `SCAN_GENERATION` and avoid clearing cancellation for the active generation
- [x] T025 [US5] Update `EXPENSIVE_MIN_TIMEOUT` in `aether/src/prober.rs` from 5000ms to 6000ms
- [x] T026 [US5] Update `AetherBridge.kt` in `apps/android/android/app/src/main/java/app/aethernext/AetherBridge.kt` to clamp H3 probe timeouts to `Math.max(6000, timeoutMs)`
- [x] T027 [US5] Update `apps/android/src/hooks/useScanner.ts` and `apps/desktop/src/hooks/useScanner.ts` to enforce a 6000ms floor for H3/QUIC scans

**Checkpoint**: User Story 5 complete — early cancellation is reliable and probe timeout floors are strictly consistent

---

## Phase 8: User Story 6 - Windows Route Transactional Rollback & Proxy Registry Read-Back Verification (Priority: P2)

**Goal**: Prevent orphaned routes during PowerShell TUN setup via self-cleaning rollback, and verify all 3 proxy registry values before deleting recovery data.

**Independent Test**:
1. Simulate route script failure; verify PowerShell script catches error and removes all added routes before re-throwing.
2. Run `cargo test --test proxy_restore_test`; verify `proxy_recovery.json` is preserved if `ProxyServer`, `ProxyOverride`, or `ProxyEnable` fails read-back verification.

### Tests for User Story 6
- [x] T028 [P] [US6] Implement unit test for complete 3-tuple proxy read-back verification in `apps/desktop/src-tauri/tests/proxy_restore_test.rs`

### Implementation for User Story 6
- [x] T029 [US6] Wrap PowerShell route setup in `try { ... } catch { Remove-NetRoute for added routes; throw }` in `aether/src/tun_win.rs`
- [x] T030 [US6] Update `windows_proxy::restore` in `apps/desktop/src-tauri/src/lib.rs` to read back and compare `ProxyEnable`, `ProxyServer`, and `ProxyOverride` (handling present and absent cases) before deleting `proxy_recovery.json`

**Checkpoint**: User Story 6 complete — routing modifications are transactional and proxy recovery data is safeguarded

---

## Phase 9: User Story 7 - Frontend Settings Hydration Retry UI & Architectural Decomposition (Priority: P2)

**Goal**: Provide user-visible retry banners on settings hydration failure, and decompose complex orchestrators into testable helper functions.

**Independent Test**:
1. Run `npm test` in `apps/desktop` and `apps/android`; verify `settingsLoadError` exposes retry banner and `retrySettings` triggers reload.
2. Verify cyclomatic complexity of `AetherBridge.invoke`, `EngineRunner.start`, and `AetherVpnService.establishTun` is reduced below 15.

### Tests for User Story 7
- [x] T031 [P] [US7] Update `apps/desktop/src/hooks/useRuntime.test.ts` and `apps/android/src/hooks/useRuntime.test.ts` to test `settingsLoadError` and `retrySettings` callback

### Implementation for User Story 7
- [x] T032 [US7] Update `apps/desktop/src/hooks/useRuntime.ts` and `apps/android/src/hooks/useRuntime.ts` to return `settingsLoadError` and `retrySettings`
- [x] T033 [US7] Update `apps/desktop/src/components/SettingsTab.tsx` and `apps/android/src/components/SettingsTab.tsx` to render an interactive retry warning banner when `settingsLoadError` is true
- [x] T034 [US7] Decompose `AetherBridge.invoke` in `apps/android/android/app/src/main/java/app/aethernext/AetherBridge.kt` into dedicated command handler functions (`handleGetSettings`, `handleSaveSettings`, `handleScan`, `handleConnect`, `handleDisconnect`)
- [x] T035 [US7] Decompose `EngineRunner.start` in `apps/android/android/app/src/main/java/app/aethernext/EngineRunner.kt` into `buildProcessCommand` and `configureProcessEnvironment`
- [x] T036 [US7] Decompose `AetherVpnService.establishTun` in `apps/android/android/app/src/main/java/app/aethernext/AetherVpnService.kt` into `configureTunBuilder` and `registerUnderlyingNetworkCallbacks`

**Checkpoint**: User Story 7 complete — frontend settings recovery is transparent to users and core orchestrators are modular

---

## Phase 10: User Story 8 - CI Action Immutability & Action Pinning (Priority: P2)

**Goal**: Guarantee supply-chain integrity by pinning all third-party GitHub Actions to immutable 40-character commit SHAs.

**Independent Test**:
1. Verify that every `uses:` entry in `.github/workflows/ci.yml` and `.github/workflows/build.yml` matches a 40-character commit SHA with inline version comment.

### Implementation for User Story 8
- [x] T037 [US8] Pin all third-party GitHub Actions in `.github/workflows/ci.yml` to immutable commit SHAs with inline version comments
- [x] T038 [US8] Pin all third-party GitHub Actions in `.github/workflows/build.yml` to immutable commit SHAs with inline version comments

**Checkpoint**: User Story 8 complete — CI workflows are protected against upstream action mutations

---

## Phase 11: Polish & Cross-Cutting Concerns

**Purpose**: Cross-cutting verification, build artifact validation, and quickstart execution

- [x] T039 [P] Reconcile previous feature specs (`specs/013-security-reliability-remediation/spec.md`) with hardened elevation and supervisor contracts
- [x] T040 Execute full end-to-end quickstart verification workflow across Rust engine, desktop backend, Android native, and frontend test suites per `specs/014-audit-remediation-hardening/quickstart.md`

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies — can start immediately
- **Foundational (Phase 2)**: Depends on Setup completion — BLOCKS all user stories
- **User Stories (Phase 3+)**: All depend on Foundational phase completion
  - P1 Stories (US1 → US2 → US3 → US4) are executed in priority order
  - P2 Stories (US5 → US6 → US7 → US8) can proceed once P1 is validated
- **Polish (Phase 11)**: Depends on all user stories completing

### User Story Dependencies

- **User Story 1 (P1)**: Depends on T001, T004. Standalone MVP.
- **User Story 2 (P1)**: Depends on Foundational phase.
- **User Story 3 (P1)**: Depends on T002, T005.
- **User Story 4 (P1)**: Independent of US1–US3; depends on core config.
- **User Story 5 (P2)**: Depends on T006.
- **User Story 6 (P2)**: Depends on T003.
- **User Story 7 (P2)**: Depends on US2 settings schema and US3 supervisor.
- **User Story 8 (P2)**: Independent of code changes; touches CI workflow files.

---

## Parallel Opportunities

- **Phase 1**: T002 (Android test fixtures) and T003 (proxy test skeleton) can run concurrently with T001 (desktop build.rs).
- **Phase 2**: T005 (Kotlin ProcessLauncher) and T006 (Rust SCAN_GENERATION) can run in parallel with T004 (TrustedBinaryPolicy).
- **Phase 3 (US1)**: T007 (elevation trust test) and T010 (release hashes) can run concurrently.
- **Phase 4 (US2)**: T011 (SettingsStoreTest) runs before T012/T013.
- **Phase 5 (US3)**: T015 (EngineRunnerTest) runs before T016/T017.
- **Phase 6 (US4)**: T019 (atomic write test) and T020 (KeyStore test) can run in parallel.
- **Phase 7 (US5)**: T023 (scanner cancel test) can run concurrently with T027 (frontend useScanner timeout).
- **Phase 8 (US6)**: T028 (proxy restore test) runs before T030.
- **Phase 9 (US7)**: T031 (useRuntime test) runs before T032/T033; T034, T035, T036 can run in parallel across separate files.
- **Phase 10 (US8)**: T037 (ci.yml) and T038 (build.yml) can run concurrently.

---

## Implementation Strategy

### MVP First (User Story 1 Only)
1. Complete Phase 1 (Setup) and Phase 2 (Foundational).
2. Complete Phase 3 (User Story 1: Production Windows Elevation Trust & Wintun Verification).
3. **STOP and VALIDATE**: Verify distinct policies (`wintun.dll` vs `aether.exe`) and fail-closed release hash validation.

### Incremental Delivery
1. Phase 1 + 2 → Foundational policy, launcher, and generation primitives ready.
2. Phase 3 (US1) → Windows TUN elevation blocker unblocked (MVP).
3. Phase 4 (US2) → Android settings validation fully canonicalized for all UI options.
4. Phase 5 (US3) → Mobile process supervisor barrier hardened against unkillable processes.
5. Phase 6 (US4) → Plaintext migration and KeyStore recovery quarantined.
6. Phase 7 (US5) → Scanner cancellation generation tracking & 6000ms timeout floor active.
7. Phase 8 (US6) → Transactional route setup and 3-tuple proxy read-back verified.
8. Phase 9 (US7) → Frontend settings retry banner & orchestrator decomposition.
9. Phase 10 (US8) → CI action SHA pinning.
10. Phase 11 → Final end-to-end quickstart validation.
