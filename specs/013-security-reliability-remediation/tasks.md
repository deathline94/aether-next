# Tasks: Full-Stack Security, Reliability & Quality Audit Remediation

**Feature**: `013-security-reliability-remediation`
**Plan**: [plan.md](plan.md) | **Spec**: [spec.md](spec.md)

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Project initialization, dependency additions, and build configuration

- [x] T001 Update dependencies in `aether/Cargo.toml` (`tokio-util`, `zeroize`) and `apps/desktop/src-tauri/Cargo.toml` (`windows-sys` features for `Win32_Security_Cryptography`, `Win32_Security_WinTrust`, `Win32_System_Threading`)
- [x] T002 [P] Configure NSIS installer `installMode` to `"perMachine"` in `apps/desktop/src-tauri/tauri.conf.json`
- [x] T003 [P] Pin toolchains (Rust 1.88.0, JDK 21) and action versions in `.github/workflows/ci.yml` and `.github/workflows/build.yml`

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Core synchronization primitives and cryptographic abstractions required by multiple user stories

**⚠️ CRITICAL**: User story implementation depends on these foundational components

- [x] T004 Implement `ScanCancellationToken` wrapper around `tokio_util::sync::CancellationToken` in `aether/src/prober.rs`
- [x] T005 [P] Define `SupervisorState` enum (`IDLE`, `SCANNING`, `CONNECTING`, `CONNECTED`, `STOPPING`) and generation token tracker in `apps/android/android/app/src/main/java/app/aethernext/EngineRunner.kt`
- [x] T006 [P] Implement Windows DPAPI helper functions (`CryptProtectData`/`CryptUnprotectData`) with memory zeroing in `apps/desktop/src-tauri/src/lib.rs`

**Checkpoint**: Core synchronization and DPAPI foundations ready — user story implementation can now begin

---

## Phase 3: User Story 1 - Desktop Privileged Elevation & Cryptographic Identity Protection (Priority: P1) 🎯 MVP

**Goal**: Protect elevated execution against binary substitution (Authenticode, publisher CN, release hash, perMachine ACL) and encrypt desktop identity secrets at rest with Windows DPAPI per-user key derivation.

**Independent Test**:
1. Replace `aether.exe` with another valid PE binary; verify elevated launch is rejected with a signature/hash error.
2. Inspect `%APPDATA%\Aether\aether.toml`; verify it begins with `AETHERCFG1\n` and contains zero plaintext credentials.
3. Place a legacy plaintext identity; verify seamless atomic migration to encrypted format on startup.

### Tests for User Story 1
- [x] T007 [P] [US1] Write test verifying tampering rejection for non-Authenticode / hash-mismatched elevated binaries in `apps/desktop/src-tauri/tests/elevation_trust_test.rs`
- [x] T008 [P] [US1] Write unit test for Windows DPAPI master key derivation, roundtrip encryption, and zeroize cleanup in `apps/desktop/src-tauri/tests/dpapi_key_test.rs`

### Implementation for User Story 1
- [x] T009 [US1] Implement `verify_elevated_binary` in `apps/desktop/src-tauri/src/lib.rs` verifying Authenticode signature, publisher CN (`CN="deathline94"`), certificate chain, and embedded release hash table
- [x] T010 [US1] Implement `get_or_create_dpapi_config_key` in `apps/desktop/src-tauri/src/lib.rs` and inject `AETHER_CONFIG_KEY` into the elevated/normal `Command` environment for `aether.exe`
- [x] T011 [US1] Update `apps/desktop/src-tauri/src/lib.rs` to make filesystem ACL restriction failure fatal when initializing `%APPDATA%\Aether`
- [x] T012 [US1] Implement automatic migration in `aether/src/config.rs` to detect legacy plaintext `aether.toml` on startup when `AETHER_CONFIG_KEY` is present and atomically re-save as an encrypted payload

**Checkpoint**: User Story 1 complete — elevated desktop execution and identity secrets are cryptographically secured

---

## Phase 4: User Story 2 - Core Engine Storage Atomicity, Concurrency Guards & Safe Routing (Priority: P2)

**Goal**: Prevent provisioning race conditions with non-failing-open `ProvisionGuard`, guarantee atomic identity persistence via `ReplaceFileW` with backup retention, ensure Windows TUN routes never blackhole host connectivity, and enforce strict 16 KiB HTTP proxy header limits.

**Independent Test**:
1. Run concurrent provisioning attempts; verify secondary instance yields recoverable error without duplicate account registration.
2. Simulate process interruption during config write; verify previous identity file remains intact.
3. Simulate route failure in Windows TUN fallback; verify physical peer escape route is verified and routes roll back cleanly.
4. Send an HTTP request with headers exceeding 16 KiB at chunk boundary; verify connection is immediately closed with HTTP 400.

### Tests for User Story 2
- [x] T013 [P] [US2] Write unit test for `ProvisionGuard` verifying exclusive lock holding and non-failing-open retry behavior in `aether/tests/provision_lock_test.rs`
- [x] T014 [P] [US2] Write unit test for `write_private_file` fault injection verifying backup preservation upon rename failure in `aether/tests/atomic_write_test.rs`
- [x] T015 [P] [US2] Write unit test for `read_header` verifying strict 16 KiB boundary rejection in `aether/tests/http_header_test.rs`

### Implementation for User Story 2
- [x] T016 [US2] Implement `ProvisionGuard` with OS-level exclusive file lock (`FileExt::try_lock_exclusive`) and PID heartbeat liveness check in `aether/src/cache.rs` and `aether/src/session.rs`
- [x] T017 [US2] Re-engineer `write_private_file` in `aether/src/config.rs` using `ReplaceFileW`/`MoveFileExW` with replacement semantics, maintaining a `.bak` copy until replacement succeeds
- [x] T018 [US2] Update Windows route configuration in `aether/src/tun_win.rs` to require peer escape route command success with physical interface index (`IF phys_if`), verify peer route before applying split-defaults, and execute transactional route rollback on failure
- [x] T019 [US2] Update `read_header` in `aether/src/http_proxy.rs` to clamp read chunks to remaining allowance (`MAX_HEADER - header.len()`) and reject header terminators positioned past 16 KiB

**Checkpoint**: User Story 2 complete — core engine file operations, provisioning concurrency, routing fallback, and proxy parser bounds are resilient

---

## Phase 5: User Story 3 - Mobile Process Supervisor, VPN Lifecycle & Scanner Completion Barriers (Priority: P3)

**Goal**: Eliminate Android engine process collisions via `stopAndWait(timeout)` completion barrier, automatically stop active scans before "Connect Direct", roll back engine processes on foreground service startup failure, guard VPN establishment with generation tokens, and fix native PID reflection.

**Independent Test**:
1. Rapidly stop and start the engine 100 times; verify zero concurrent process collisions or port binding errors.
2. Tap "Connect Direct" while a standalone scan is active; verify the scan is halted, exit is confirmed, and tunnel connects cleanly on the first attempt.
3. Simulate `ForegroundServiceStartNotAllowedException`; verify engine process and VPN state are cleanly torn down.
4. Query runtime state; verify native process ID is reported as a valid positive integer.

### Tests for User Story 3
- [x] T020 [P] [US3] Write unit test for `EngineRunner` verifying `stopAndWait` blocking barrier and single-instance mutual exclusion in `apps/android/android/app/src/test/java/app/aethernext/EngineRunnerTest.kt`
- [x] T021 [P] [US3] Write unit test for `AetherVpnService` generation token lifecycle guard in `apps/android/android/app/src/test/java/app/aethernext/AetherVpnServiceTest.kt`

### Implementation for User Story 3
- [x] T022 [US3] Implement `stopAndWait(timeoutMs: Long)` with `Process.waitFor()`, escalation to `destroy()` / `destroyForcibly()`, and reentrant lock synchronization in `apps/android/android/app/src/main/java/app/aethernext/EngineRunner.kt`
- [x] T023 [US3] Fix PID reporting in `EngineRunner.pid()` to cast reflection result to `java.lang.Number` and invoke `toInt()` in `apps/android/android/app/src/main/java/app/aethernext/EngineRunner.kt`
- [x] T024 [US3] Update `SessionController.connect` and `SessionController.scan` in `apps/android/android/app/src/main/java/app/aethernext/SessionController.kt` to automatically stop active scans with `runner.stopAndWait(3000)` before connecting
- [x] T025 [US3] Update `connectDirect` in `apps/android/src/App.tsx` and `useRuntime.ts` to stop the active scanner and await idle state before initiating direct peer connection
- [x] T026 [US3] Wrap `context.startForegroundService` in `SessionController.connect` in a transactional try-catch, invoking `runner.stopAndWait()` and resetting runtime status on failure in `apps/android/android/app/src/main/java/app/aethernext/SessionController.kt`
- [x] T027 [US3] Add `vpnGeneration` atomic token, return boolean from `establishTun()`, and guard `onVpnEstablished` notification in `apps/android/android/app/src/main/java/app/aethernext/AetherVpnService.kt`

**Checkpoint**: User Story 3 complete — Android process lifecycle, VPN transitions, and direct connect barriers operate safely without races

---

## Phase 6: User Story 4 - Responsive Scanner Cancellation & Unified Probe Timeout Architecture (Priority: P4)

**Goal**: Ensure scanner cancellation wakes immediately (< 10 ms) during in-flight network probes in the core Rust engine, and enforce unified probe timeout floors across UI, native bridges, and engine configurations.

**Independent Test**:
1. Trigger scanner cancellation with multiple permanently pending candidate verification futures; verify `hunt_best` aborts within < 50 ms and persists best candidate found so far.
2. Pass 100 ms timeout to scanner bridge; verify it is clamped to unified minimum (3000 ms fast / 5000 ms H3 / 6000 ms standard).

### Tests for User Story 4
- [x] T028 [P] [US4] Write unit test verifying scanner cancellation aborts within 50ms during pending probe futures in `aether/tests/scanner_cancellation_test.rs`

### Implementation for User Story 4
- [x] T029 [US4] Integrate `CancellationToken` into `hunt_best` main `tokio::select!` loop and propagate child tokens into candidate verification futures in `aether/src/prober.rs`
- [x] T030 [P] [US4] Unify probe timeout floors across `apps/android/src/hooks/useScanner.ts`, `apps/desktop/src/hooks/useScanner.ts`, and `apps/android/android/app/src/main/java/app/aethernext/AetherBridge.kt` with a 6000ms default and 3000ms minimum boundary clamp

**Checkpoint**: User Story 4 complete — scanner aborts promptly on user request and enforces safe handshake timeouts

---

## Phase 7: User Story 5 - Configuration Resilience, Registry Recovery & Settings Integrity (Priority: P5)

**Goal**: Guarantee settings panel recovery on IPC failure, verify Windows system proxy registry deletion, preserve desktop connection history across exits, validate Android native settings against schema, detect and recover from corrupted key stores, preserve user routing preferences on migration, and post Android 10+ boot notifications.

**Independent Test**:
1. Reject `get_settings` IPC call; verify webview settings controls unlock in fallback mode with a retry banner.
2. Disconnect on Windows with simulated registry deletion failure; verify error is reported and backup file is preserved.
3. Simulate disconnect after successful session; verify exit classifier logs normal disconnect rather than gateway error.
4. Pass invalid enum or out-of-range port across Android bridge; verify native validation returns structured error.
5. Corrupt Android `ConfigKeyStore` preferences; verify automatic key rotation, reprovisioning, and clean recovery.
6. Upgrade Android app with `routingMode="proxy-only"`; verify preference is not overwritten to `"tun"`.

### Tests for User Story 5
- [x] T031 [P] [US5] Write unit test for `SettingsStore` validation verifying enum rejection and user routing preference preservation in `apps/android/android/app/src/test/java/app/aethernext/SettingsStoreTest.kt`
- [x] T032 [P] [US5] Write unit test for `useRuntime` verifying settings hydration completes in `finally` block on IPC error in `apps/android/src/hooks/useRuntime.test.ts`

### Implementation for User Story 5
- [x] T033 [US5] Update `windows_proxy::restore` in `apps/desktop/src-tauri/src/lib.rs` to propagate non-NotFound registry deletion errors, verify registry values via read-back, and preserve `proxy_recovery.json` on failure
- [x] T034 [US5] In `watch_child` in `apps/desktop/src-tauri/src/lib.rs`, read `ever_connected` state before invoking `cleanup_routing` to prevent misclassifying disconnects as gateway errors
- [x] T035 [US5] In `apps/desktop/src/hooks/useRuntime.ts` and `apps/android/src/hooks/useRuntime.ts`, complete settings hydration in a `finally` block with fallback defaults and a retry indicator
- [x] T036 [US5] Implement comprehensive enum and range validation (`protocol` in `["wireguard", "masque"]`, `transport` in `["h2", "h3"]`, `scanMode` in `["turbo", "balanced", "thorough", "stealth", "ironclad"]`, `ipVersion` in `["v4", "v6", "both"]`, `routingMode` in `["tun", "proxy-only", "system-proxy"]`) in `apps/android/android/app/src/main/java/app/aethernext/SessionController.kt`
- [x] T037 [US5] Add corruption recovery in `ConfigKeyStore.loadOrCreate` to catch crypto exceptions, rotate wrapped keys, and purge stale identity files in `apps/android/android/app/src/main/java/app/aethernext/ConfigKeyStore.kt`
- [x] T038 [US5] Update `SettingsStore.load` in `apps/android/android/app/src/main/java/app/aethernext/SettingsStore.kt` to only apply default `"tun"` on fresh installs, preserving explicit user routing choices
- [x] T039 [US5] Update `BootReceiver.onReceive` in `apps/android/android/app/src/main/java/app/aethernext/BootReceiver.kt` to post a high-priority user notification instead of attempting a disallowed background activity launch

**Checkpoint**: User Story 5 complete — settings integrity, registry safety, and mobile platform behaviors are robust

---

## Phase 8: User Story 6 - Automated Regression Harness, Release Gates & Quality Verification (Priority: P6)

**Goal**: Provide automated test execution across frontend, Android Kotlin, and Rust engine components; gate release workflows on full CI pass; pin dependencies; and decompose high-complexity orchestration functions.

**Independent Test**:
1. Run `npm test` across frontend packages; verify all hook and state tests pass.
2. Push commit with simulated test failure to release branch; verify release workflow is blocked.

### Implementation for User Story 6
- [x] T040 [P] [US6] Add frontend test runners and test scripts (`"test": "vitest run"`) to `apps/android/package.json` and `apps/desktop/package.json`
- [x] T041 [P] [US6] Make release builds in `.github/workflows/build.yml` depend on CI verification (`needs: [test]`) and block untrusted direct pushes
- [x] T042 [US6] Decompose large orchestration functions (`AetherBridge.invoke`, `AetherVpnService.establishTun`, `EngineRunner.start`) into smaller, single-responsibility helper methods with dedicated unit tests

**Checkpoint**: User Story 6 complete — automated regression harness and release quality gates are active

---

## Phase 9: Polish & Cross-Cutting Concerns

**Purpose**: Cross-feature documentation updates, spec alignment, and end-to-end quickstart validation

- [x] T043 [P] Reconcile and update previous specifications (`specs/004-codebase-bug-audit-remediation/spec.md`, `specs/012-fix-android-scanner-timeout-ui/spec.md`) to reflect unified probe timeouts and supervisor contracts in `specs/`
- [x] T044 Execute complete quickstart verification workflow across Rust, Android Kotlin, and desktop builds per `specs/013-security-reliability-remediation/quickstart.md`

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies — can start immediately
- **Foundational (Phase 2)**: Depends on Setup completion — BLOCKS all user stories
- **User Stories (Phase 3+)**: All depend on Foundational phase completion
  - User stories proceed in priority order: P1 (MVP) → P2 → P3 → P4 → P5 → P6
  - Within each story, tests run first, followed by models/primitives, service logic, and UI integration
- **Polish (Phase 9)**: Depends on completion of all user stories

### User Story Dependencies

- **User Story 1 (P1)**: Depends on T001, T002, T006. Standalone MVP.
- **User Story 2 (P2)**: Depends on T001. Can run in parallel with US1 on core engine files.
- **User Story 3 (P3)**: Depends on T005. Focuses on Android supervisor and VPN.
- **User Story 4 (P4)**: Depends on T004. Extends prober cancellation.
- **User Story 5 (P5)**: Depends on US3 supervisor state and US1 DPAPI primitives.
- **User Story 6 (P6)**: Depends on test artifacts created across US1–US5.

---

## Parallel Opportunities

- **Phase 1**: T002 (tauri.conf.json) and T003 (CI workflow) can run concurrently with T001 (Cargo.toml).
- **Phase 2**: T005 (Kotlin supervisor state) and T006 (Rust DPAPI helpers) can run in parallel.
- **Phase 3 (US1)**: T007 (elevation trust test) and T008 (DPAPI key test) can run in parallel.
- **Phase 4 (US2)**: T013 (provision lock test), T014 (atomic write test), and T015 (header cap test) can run concurrently across independent test files.
- **Phase 5 (US3)**: T020 (EngineRunner test) and T021 (VpnService test) can run concurrently.
- **Phase 7 (US5)**: T031 (Kotlin SettingsStore test) and T032 (TypeScript useRuntime test) can run concurrently.

---

## Implementation Strategy

### MVP First (User Story 1 Only)
1. Complete Phase 1 (Setup) and Phase 2 (Foundational).
2. Complete Phase 3 (User Story 1: Desktop Elevation & DPAPI Identity Protection).
3. **STOP and VALIDATE**: Test tampering rejection and encrypted identity storage independently.

### Incremental Delivery
1. Phase 1 + Phase 2 → Solid foundational primitives ready.
2. Phase 3 (US1) → Critical privilege escalation and plaintext identity exposures remediated (MVP).
3. Phase 4 (US2) → Core engine storage atomicity, provisioning concurrency, and route safety secured.
4. Phase 5 (US3) → Mobile process supervisor barriers and direct connect auto-teardown active.
5. Phase 6 (US4) → Sub-10ms scanner cancellation and unified timeout architecture in place.
6. Phase 7 (US5) → Settings integrity, registry safety, and platform resilience hardened.
7. Phase 8 (US6) & Phase 9 → Automated regression suites, release CI gates, and final verification.
