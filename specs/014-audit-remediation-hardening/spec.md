# Feature Specification: Audit Remediation Hardening & Verification Completeness

> **Superseded by `specs/015-full-audit-remediation`.** Every "fixed" statement
> below describes the tree as it was when this document was written. 015
> re-audited these claims against source and found that several of the guards
> they record were unreachable, inverted, or never wired into CI. Read the code
> before quoting this file as evidence that something is done.


**Feature Branch**: `014-audit-remediation-hardening`

**Created**: 2026-09-20

**Status**: Draft

**Input**: User feedback on commit `7cb7d31`: 9 complete, 8 partial, 5 failed audit fixes across Windows elevation, embedded hashes, Android settings schema, supervisor barriers, plaintext migration, route transactions, proxy restoration, CI action pinning, and architectural decomposition.

---

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Production Windows Elevation Trust & Wintun Verification (Priority: P1) 🎯 MVP

A Windows user launching Aether in elevated TUN mode requires that the application successfully starts in production without being rejected by mismatched digital certificate policies, while ensuring that arbitrary binary substitution remains strictly impossible through separate publisher policies and verified cryptographic release hashes.

**Why this priority**: In production builds, `aether.exe` and `wintun.dll` have different publishers (`aether.exe` is published by the project team, while `wintun.dll` is officially signed by `WireGuard LLC`). Enforcing a single publisher policy for both binaries blocks 100% of production Windows TUN connections from starting. Furthermore, embedded release hash checks must actively enforce binary integrity rather than succeeding when hash entries are missing.

**Independent Test**:
1. Launch elevated TUN mode with production-signed `wintun.dll` (WireGuard LLC) and `aether.exe`; verify the elevated launcher validates each binary against its specific publisher policy and successfully starts.
2. Attempt to launch an elevated binary when release hash validation is enforced but the binary's hash is absent or mismatched; verify elevated execution is strictly rejected.

**Acceptance Scenarios**:
1. **Given** an elevated launch request for `wintun.dll`, **When** the binary signature is validated, **Then** the system verifies the digital signature against the Wintun publisher policy (`CN="WireGuard LLC"`) and certificate chain before loading.
2. **Given** an elevated launch request for `aether.exe`, **When** the binary signature is validated, **Then** the system verifies the digital signature against the Aether publisher policy (`CN="deathline94"`) and certificate chain before executing.
3. **Given** elevated binary verification with embedded release hashes, **When** validating `aether.exe` or `wintun.dll`, **Then** the system requires a matching SHA-256 release hash entry in the embedded policy table and rejects any binary with a missing or mismatched hash entry.

---

### User Story 2 - Android Settings Schema Canonicalization & UI Consistency (Priority: P1)

An Android user configuring connection parameters, obfuscation noise, or endpoint presets requires that every option presented in the user interface is accepted and applied by the native backend rather than rejected with validation errors.

**Why this priority**: Native bridge validation previously rejected the `gool` preset and rejected active noise modes (`light`, `medium`, `high`, `max`, `custom`) that the UI explicitly offered, preventing users from saving settings or connecting with supported configurations.

**Independent Test**:
1. Select the `gool` preset in the Android settings tab and save; verify the settings store and native validation accept the configuration without error.
2. Select each noise mode (`off`, `light`, `medium`, `high`, `max`, `custom`) in the UI; verify `SessionController.validateSettings` validates all modes successfully.

**Acceptance Scenarios**:
1. **Given** a settings configuration payload containing `endpointPreset="gool"`, **When** native validation runs, **Then** the validator recognizes `gool` as a valid endpoint preset.
2. **Given** a settings configuration payload containing noise mode in `["off", "light", "medium", "high", "max", "custom"]`, **When** native validation runs, **Then** the validator accepts all supported noise profile selections.
3. **Given** the settings schema, **When** evaluated across the TypeScript frontend and Kotlin native layer, **Then** both layers share an identical canonical definition of all valid settings enums and boundary constraints.

---

### User Story 3 - Mobile Process Supervisor Barrier Integrity & Unkillable Process Handling (Priority: P1)

An Android user stopping or restarting the networking engine requires that background processes are completely terminated before any new engine process can start, ensuring that failed process kills never leave orphaned background engines or cause dual-engine collisions.

**Why this priority**: If a background process fails to terminate within the timeout, clearing the process reference and setting state to `IDLE` allows a second engine process to launch concurrently, leading to socket binding conflicts, memory waste, and unpredictable tunnel behavior.

**Independent Test**:
1. Trigger a stop operation on a simulated hung process; verify `EngineRunner.stopAndWait` returns `false`, retains `SupervisorState.STOPPING`, preserves `running=true`, and keeps the process reference until the OS confirms exit.
2. Verify that `SessionController.connect` and `SessionController.scan` inspect the return value of `stopAndWait` and strictly abort startup if the previous process is still running.

**Acceptance Scenarios**:
1. **Given** an engine process that does not exit after `destroy()` and `destroyForcibly()`, **When** `stopAndWait(timeoutMs)` expires, **Then** the runner returns `false`, maintains the `STOPPING` state, keeps `running=true`, and retains the process reference.
2. **Given** a connection or scan launch request while a previous engine process is stopping, **When** `stopAndWait` returns `false`, **Then** the controller aborts the launch request, logs an error, and leaves runtime state in an unconflicted state.
3. **Given** unit testing for `EngineRunner`, **When** executing test suites, **Then** tests invoke production `start` and `stopAndWait` logic via an injectable process factory, covering graceful exit, forced exit, and unkillable process states.

---

### User Story 4 - Cryptographic Identity Migration & Android KeyStore Quarantine (Priority: P1)

A user on desktop or mobile whose credentials require migration or recovery requires that unencrypted identities are never used if encrypted persistence fails, and that corrupted Android KeyStore keys do not leave unreadable identity files stranded on disk.

**Why this priority**: Failing to write an encrypted identity while continuing to use a plaintext file leaves secret keys exposed on disk. On Android, rotating the wrapping key without purging the old unreadable ciphertext leaves the app permanently unable to connect.

**Independent Test**:
1. Simulate a disk write error during plaintext identity encryption on desktop; verify the engine aborts startup and refuses to establish sessions using exposed credentials.
2. Corrupt the Android KeyStore master key; verify the system rotates the key, quarantines or deletes the old unreadable `aether.toml` and `.bak` files, emits a recovery event to the UI, and initiates clean reprovisioning.

**Acceptance Scenarios**:
1. **Given** an unencrypted `aether.toml` file on desktop, **When** migration to DPAPI encryption fails, **Then** the engine propagates the error and terminates startup rather than continuing with plaintext credentials.
2. **Given** an unreadable `aether.toml` due to KeyStore corruption on Android, **When** `ConfigKeyStore` detects the crypto failure, **Then** it rotates the wrapping key, deletes or quarantines the corrupted `aether.toml` and backup copies, emits a user-visible recovery notification, and triggers fresh provisioning.

---

### User Story 5 - Scanner Cancellation Generation Tracking & Consistent Handshake Timeouts (Priority: P5)

A user scanning for clean endpoints on desktop or mobile who cancels an active scan expects the cancellation signal to be immediately respected, even if cancellation was requested during scan startup, and expects network handshakes to be evaluated with consistent, protocol-safe timeout budgets across all layers.

**Why this priority**: If scan startup unconditionally clears cancellation flags, early user cancel clicks are erased and scans run to completion against the user's intent. Conflicting timeout minimums (3s vs 5s vs 6s) cause high-latency QUIC/H3 handshakes to be prematurely cut off.

**Independent Test**:
1. Emit a scan cancellation signal immediately before `hunt_best` begins; verify the scan observes the generation-owned cancellation token and exits without launching pending probes.
2. Inspect probe timeout floors across engine, native bridge, and UI; verify all layers enforce at least 6000 ms for expensive QUIC/H3 handshakes.

**Acceptance Scenarios**:
1. **Given** an endpoint scan session, **When** the session begins, **Then** the scanner binds to a generation-owned cancellation token that is never cleared by session initialization.
2. **Given** an active scan, **When** a cancellation signal is emitted for the current scan generation, **Then** the cancellation token remains set and immediately aborts the scan.
3. **Given** probe timeout configuration across engine, Android bridge, and webview UI, **When** validating timeouts for H3/QUIC protocols, **Then** all layers enforce a consistent minimum floor of at least 6000 ms.

---

### User Story 6 - Windows Route Transactional Rollback & Proxy Registry Read-Back Verification (Priority: P6)

A Windows desktop user activating or deactivating system-wide TUN or proxy routing requires that route installations are fully transactional with clean rollbacks on error, and that system proxy settings are verified across all registry keys before backup recovery data is removed.

**Why this priority**: Partial route installations that leave peer routes behind cause fallback routing commands to collide and fail, disconnecting the host machine. Deleting proxy recovery files before verifying all registry keys leaves system proxy settings stranded if restore partially fails.

**Independent Test**:
1. Simulate a failure during split-default route installation in PowerShell; verify all partially installed routes (peer route, first split default) are cleaned up before fallback execution.
2. Restore system proxy settings on disconnect; verify `ProxyEnable`, `ProxyServer`, and `ProxyOverride` are read back and matched against the snapshot before `proxy_recovery.json` is deleted.

**Acceptance Scenarios**:
1. **Given** Windows TUN route configuration via PowerShell, **When** an error occurs after installing the peer route or a split route, **Then** the script executes a `try/catch` rollback cleaning all newly added routes before returning an error or triggering fallback.
2. **Given** Windows system proxy restoration, **When** resetting registry keys, **Then** the application reads back and verifies `ProxyEnable`, `ProxyServer`, and `ProxyOverride` (handling both present and absent states), retaining `proxy_recovery.json` if any value fails to match the original state.

---

### User Story 7 - Frontend Settings Hydration Retry UI & Architectural Decomposition (Priority: P7)

A user encountering temporary bridge communication failures during settings loading requires a visible error banner with an interactive retry action, and developers require that complex orchestrators are decomposed into testable, single-responsibility components.

**Why this priority**: Unlocking settings controls without surfacing why settings could not be fetched causes users to accidentally overwrite existing configurations with default settings. Large orchestrator functions with cyclomatic complexity > 20 are error-prone and untestable.

**Independent Test**:
1. Simulate an IPC failure during initial settings loading in webview; verify the UI displays a prominent warning banner stating settings could not be loaded and provides a "Retry" button that re-invokes hydration.
2. Inspect `AetherBridge.invoke`, `EngineRunner.start`, and `AetherVpnService.establishTun`; verify each orchestrator delegates to focused, single-responsibility helper methods with dedicated unit test coverage.

**Acceptance Scenarios**:
1. **Given** a failure during settings hydration in `useRuntime`, **When** the error occurs, **Then** the hook exposes `settingsLoadError` and a `retrySettings` callback.
2. **Given** an active `settingsLoadError`, **When** the settings panel renders, **Then** it presents an informative banner with a "Retry" button allowing the user to reload settings.
3. **Given** the native bridge and lifecycle orchestrators, **When** analyzed for complexity, **Then** command dispatching, process creation, and network interface construction are factored into discrete, testable sub-functions.

---

### User Story 8 - CI Action Immutability & Action Pinning (Priority: P8)

A project maintainer requires that all third-party GitHub Actions in CI workflows are pinned to full-length commit SHAs, guaranteeing that upstream tag mutations or compromises cannot alter release builds.

**Why this priority**: Referencing `@master` or mutable major tags (`@v4`) allows upstream repositories to inject breaking changes or security vulnerabilities into production release builds without notice.

**Independent Test**:
1. Inspect `.github/workflows/ci.yml` and `.github/workflows/build.yml`; verify all `uses:` statements for third-party actions reference 40-character commit SHAs with inline version comments.

**Acceptance Scenarios**:
1. **Given** CI workflow files, **When** referencing third-party GitHub Actions, **Then** every external action is pinned to an immutable 40-character commit SHA accompanied by a human-readable version comment.

---

## Edge Cases

- **Unkillable Android Engine Process**: What happens if an engine process ignores `destroyForcibly()` indefinitely? `EngineRunner.stopAndWait` returns `false`, maintains the `STOPPING` state, keeps `running=true`, and prevents any subsequent `start()` call until the process is confirmed dead by the OS.
- **Wintun Signature vs Aether Signature**: What happens if an attacker signs a malicious DLL with a valid certificate? The elevated launcher checks the specific publisher CN (`"WireGuard LLC"` for Wintun, `"deathline94"` for Aether) and verifies the embedded release hash, rejecting any unauthorized publisher.
- **Simultaneous Plaintext Migration Failure**: What happens if the filesystem runs out of disk space during DPAPI config migration? The engine aborts immediately, refuses to connect, logs the fatal persistence error, and preserves the original plaintext file for recovery.
- **Early Cancellation Before Hunt**: What happens if a user starts and cancels a scan within 5 milliseconds? The cancellation token for that scan generation is already cancelled when `hunt_best` checks it, aborting immediately without starting probes.
- **Proxy Key Absence Verification**: What happens when a user had no proxy configured before Aether ran? Restoration verifies that `ProxyServer` and `ProxyOverride` are absent (or empty) and `ProxyEnable` is `0`, verifying absence rather than failing when keys do not exist.

---

## Requirements *(mandatory)*

### Functional Requirements

#### Elevation Trust & Binary Verification
- **FR-001**: System MUST maintain distinct trusted binary policies for `aether.exe` (publisher `deathline94`) and `wintun.dll` (publisher `WireGuard LLC`).
- **FR-002**: System MUST generate SHA-256 release hashes during build/packaging, embed them in the desktop binary, and reject elevated execution if a binary's hash is missing or mismatched.
- **FR-003**: System MUST sign production desktop release binaries (`aether.exe`, desktop GUI) with Authenticode in the CI release pipeline.

#### Android Settings Schema Canonicalization
- **FR-004**: System MUST accept all supported endpoint presets (`warp`, `gool`) in `SessionController.validateSettings`.
- **FR-005**: System MUST accept all supported noise modes (`off`, `light`, `medium`, `high`, `max`, `custom`) in `SessionController.validateSettings`.
- **FR-006**: System MUST maintain strict schema synchronization between frontend select options and native Kotlin validation rules.

#### Android Process Supervisor & Barrier
- **FR-007**: `EngineRunner.stopAndWait` MUST retain `SupervisorState.STOPPING`, keep `running=true`, and preserve the process reference if process termination does not succeed within the timeout.
- **FR-008**: `SessionController` MUST inspect the boolean return value of `stopAndWait` in `connect()` and `scan()` and strictly abort execution if termination failed.
- **FR-009**: `EngineRunner` MUST support process factory injection to enable unit testing of graceful exit, forced exit, and unkillable process handling.

#### Credential Migration & Recovery
- **FR-010**: System MUST propagate DPAPI encryption errors during desktop startup migration and refuse to establish sessions if encrypted persistence fails.
- **FR-011**: System MUST quarantine or delete unreadable `aether.toml` and `.bak` files when Android KeyStore corruption is detected, emit a recovery notification, and initiate reprovisioning.

#### Scanner Cancellation & Handshake Timeouts
- **FR-012**: System MUST associate each scan session with a generation-owned `CancellationToken` that is never cleared by `hunt_best` initialization.
- **FR-013**: System MUST enforce a centralized minimum probe timeout floor of at least 6000 ms for QUIC/H3 across core engine, native bridges, and UI.

#### Transactional Routing & Proxy Restoration
- **FR-014**: Windows TUN route setup script MUST implement `try/catch` transactional rollback, removing any partially added routes before returning an error or falling back.
- **FR-015**: Windows proxy restoration MUST read back and verify `ProxyEnable`, `ProxyServer`, and `ProxyOverride` against the captured snapshot before deleting `proxy_recovery.json`.

#### UI Hydration Resilience & Code Decomposition
- **FR-016**: `useRuntime` hook MUST expose `settingsLoadError` and `retrySettings` callback when settings hydration fails.
- **FR-017**: Settings user interface MUST render a dismissible/retryable warning banner when `settingsLoadError` is present.
- **FR-018**: System MUST decompose `AetherBridge.invoke`, `EngineRunner.start`, and `AetherVpnService.establishTun` into testable helper functions with dedicated unit tests.

#### CI Action Pinning
- **FR-019**: System MUST pin all third-party GitHub Actions in `.github/workflows/ci.yml` and `.github/workflows/build.yml` to immutable 40-character commit SHAs.

---

### Key Entities

- **Signer Policy Specification**: Defines expected publisher Common Name (CN), certificate chain validation rules, and allowable debug overrides per binary name (`aether.exe` vs `wintun.dll`).
- **Embedded Release Hash Table**: Compile-time table mapping binary filenames to authoritative SHA-256 digests.
- **Canonical Settings Schema**: Unified specification of settings fields, allowable enum values, default fallbacks, and boundary constraints shared between webview and native bridges.
- **Process Supervisor Session**: Represents the active lifecycle and state of a background engine process, including process handle, state enum, and generation token.
- **Proxy Recovery Snapshot**: Captured Windows registry values (`ProxyEnable`, `ProxyServer`, `ProxyOverride`) verified during restoration before cleanup.

---

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: 100% of production Windows TUN connections start successfully with distinct publisher policies for `aether.exe` and `wintun.dll`.
- **SC-002**: 100% of elevated binaries are validated against non-empty embedded SHA-256 release hashes, with 0% false acceptance of tampered binaries.
- **SC-003**: 100% of settings options offered in the Android UI (`gool`, noise profiles `off` through `custom`) pass native validation and persist without errors.
- **SC-004**: Zero concurrent engine processes can execute on Android under any condition, including simulated unkillable processes.
- **SC-005**: 100% of failed DPAPI config migrations block tunnel session establishment until encrypted persistence succeeds.
- **SC-006**: 100% of KeyStore corruption events on Android cleanly purge orphaned identity files and re-enter provisioning without user-facing crashes.
- **SC-007**: Standalone scan cancellation requests emitted before or during probe execution abort within 50 ms in 100% of test runs.
- **SC-008**: 100% of Windows TUN route installation failures leave the host machine with zero orphaned routes and full physical connectivity.
- **SC-009**: 100% of third-party GitHub Actions in CI workflows are pinned to immutable commit SHAs.
- **SC-010**: Automated unit and integration test suites pass across all decomposed orchestrators, native supervisors, and frontend hooks.

---

## Assumptions

- Windows `wintun.dll` binary is digitally signed by `WireGuard LLC` with a valid certificate chain.
- Code signing certificate or CI secret will be configured for signing production `aether.exe` builds.
- Device KeyStore on Android can recover from corruption by generating a new master key alias and purging corrupted wrapped data.
- 6000 ms is sufficient for TLS and QUIC/H3 cryptographic handshakes under high-latency mobile conditions.
- Git commit SHAs for third-party actions correspond to stable, tagged releases.
