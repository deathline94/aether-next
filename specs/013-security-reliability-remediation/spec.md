# Feature Specification: Full-Stack Security, Reliability & Quality Audit Remediation

> **Superseded by `specs/015-full-audit-remediation`.** Every "fixed" statement
> below describes the tree as it was when this document was written. 015
> re-audited these claims against source and found that several of the guards
> they record were unreachable, inverted, or never wired into CI. Read the code
> before quoting this file as evidence that something is done.


**Feature Branch**: `013-security-reliability-remediation`

**Created**: 2026-09-19

**Status**: Draft

**Input**: User description: Remediate 22 actionable security, reliability, lifecycle, and verification issues across Rust engine, desktop, and Android.

---

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Desktop Privileged Elevation & Cryptographic Identity Protection (Priority: P1) 🎯 MVP

A desktop user running the application on Windows requires that elevated operations (such as installing virtual network adapters or system-wide routing) cannot be subverted by malicious local file substitution, and that private credentials (access tokens, cryptographic certificates, WireGuard keys) stored on disk are strictly encrypted at rest using system-level user key protection rather than stored in unencrypted plaintext.

**Why this priority**: Arbitrary code execution under Administrator privileges and plaintext exposure of private tunnel identity keys represent the two most critical security risks in the system. Securing elevated execution and credential storage at rest prevents local privilege escalation and credential compromise.

**Independent Test**:
1. Attempt to launch the elevated engine when the binary has been modified, tampered with, or replaced with another executable; verify the application detects the tampering via cryptographic signature and hash validation, aborts launch, and logs a security violation.
2. Inspect the saved user identity file on disk; verify it is encrypted with system-level user credential protection (Windows Data Protection API) and cannot be decrypted by an unauthorized account or when the key is absent.
3. Simulate an existing plaintext identity file; verify the application seamlessly and atomically upgrades the file to encrypted format on first launch without losing configuration or credentials.

**Acceptance Scenarios**:
1. **Given** an elevated launch request for the background networking engine or auxiliary library, **When** the launcher validates the binary, **Then** it verifies valid digital certificate signatures, publisher identity, certificate chain, and embedded release hash before launching with elevated privileges; if any check fails, elevated execution is rejected.
2. **Given** a user identity containing secret access keys, certificates, or tunnel tokens, **When** the identity is persisted to disk, **Then** it is encrypted using an operating-system-backed, per-user encryption key.
3. **Given** file permission hardening during configuration creation, **When** filesystem access control setup fails, **Then** the application treats this as a fatal initialization error rather than continuing silently with weak permissions.
4. **Given** an unencrypted legacy identity file on disk, **When** the application starts up, **Then** it atomically migrates the identity into an encrypted payload and securely wipes encryption key material from in-memory buffers after use.

---

### User Story 2 - Resilient Core Engine File Atomicity, Concurrency Guards & Safe Routing (Priority: P2)

A user running the core networking engine on desktop or mobile requires that simultaneous processes never corrupt identity files or overwrite account registrations, that configuration file writes are resilient against sudden power loss or process interruption, that Windows TUN route configuration never blackholes host internet connectivity, and that HTTP proxy parser memory is strictly bounded against header buffer overflows.

**Why this priority**: Concurrency races during provisioning overwrite valid identities; non-atomic configuration writes cause permanent profile loss; and missing escape routes in TUN mode disconnect the entire machine from the internet.

**Independent Test**:
1. Simulate two engine instances attempting concurrent device provisioning on the same machine; verify the secondary instance waits or returns a recoverable "provisioning in progress" state rather than acquiring an expired lock and overwriting credentials.
2. Trigger forced file write interruptions and filesystem errors during identity updates; verify the existing identity remains intact without data loss, using atomic replacement APIs.
3. Activate TUN mode with simulated route configuration failures; verify the system verifies the physical gateway escape route before installing split defaults, and rolls back all modifications upon failure.
4. Send HTTP requests with header boundaries matching and exceeding maximum allowed sizes; verify the proxy parser strictly enforces the 16 KiB ceiling and closes non-compliant connections.

**Acceptance Scenarios**:
1. **Given** an active device provisioning operation, **When** another process requests provisioning, **Then** the lock remains strictly held with active owner heartbeat/process tracking, preventing duplicate registrations or overwritten identities.
2. **Given** an identity update write operation, **When** persisting changes to disk, **Then** the engine utilizes atomic file replacement with backup preservation, guaranteeing that the previous valid identity is never deleted prior to successful replacement.
3. **Given** the installation of default split routes in Windows TUN mode, **When** the underlying routing command executes, **Then** the engine verifies that the physical peer escape route succeeds on the designated physical network interface before applying default routes; if any step fails, all newly installed routes are rolled back.
4. **Given** an incoming HTTP proxy connection, **When** headers are received, **Then** the parser enforces the maximum header limit strictly at the chunk boundary, rejecting requests that exceed the 16 KiB threshold.

---

### User Story 3 - Mobile Process Supervisor, VPN Lifecycle & Scanner Completion Barriers (Priority: P3)

An Android user expects that starting a direct connection while an endpoint scan is running seamlessly terminates the scan and establishes the tunnel; that stopping the engine waits for complete process termination before starting a new one; that foreground service startup errors cleanly tear down engine processes without orphaned state; that VPN establishment only signals success when the virtual interface is truly up; and that engine process identifiers are accurately tracked.

**Why this priority**: Unsynchronized engine processes lead to port conflicts, corrupt cache files, and orphaned background processes draining battery and leaving the UI stuck in unrecoverable error states.

**Independent Test**:
1. Start an exhaustive scan on Android, then immediately click "Connect Direct"; verify the application automatically stops the active scan, awaits confirmed process termination, transitions the runner to idle, and successfully establishes the connection.
2. Stop and immediately restart the engine within 300 ms; verify the process supervisor blocks startup until the old process has fully exited, preventing dual-engine collisions.
3. Simulate a system rejection of Android foreground service startup; verify the controller cleanly stops the newly spawned engine process, resets runtime status, and informs the user.
4. Interleave rapid Stop and Start commands during VPN negotiation; verify the VPN service only emits a connected state if the interface is established for the current generation.
5. Query the running engine process identifier; verify the native layer returns a valid positive integer PID rather than null.

**Acceptance Scenarios**:
1. **Given** an active standalone scan on Android, **When** the user initiates "Connect Direct" or peer connection, **Then** the application signals the scanner to stop, awaits confirmed process exit, and transitions the engine supervisor to idle before starting the tunnel.
2. **Given** a stop request to the engine supervisor, **When** the stop command is issued, **Then** the supervisor remains in a stopping state until the process has completely terminated, blocking subsequent launches until completion.
3. **Given** an attempt to launch the background engine, **When** the system raises a foreground service startup exception, **Then** the application aborts the launch, terminates any spawned engine process, cleans up VPN resources, and resets the UI runtime state.
4. **Given** a VPN establishment call, **When** the virtual network interface setup completes, **Then** the service reports success only if the active lifecycle token matches the current connection attempt and the tunnel interface is valid.
5. **Given** an engine process running on Android, **When** runtime telemetry queries the process information, **Then** the process identifier is correctly extracted and reported to the user interface.

---

### User Story 4 - Responsive Scanner Cancellation & Unified Probe Timeout Architecture (Priority: P4)

A user running an endpoint scan on desktop or mobile who cancels or stops the scan expects immediate termination without waiting for stalled, unresponsive network probes; furthermore, all layers of the application (UI, native bridges, core engine) must agree on consistent, protocol-safe probe timeouts.

**Why this priority**: Stalled probes delay cancellation by many seconds, causing Android to force-kill processes and discard gathered probe metrics; conflicting timeout definitions cause false-negative scans on high-latency networks.

**Independent Test**:
1. Start an endpoint scan with multiple unresponsive network endpoints, then immediately click "Cancel"; verify the engine wakes instantly from asynchronous wait states and finalizes gathered metrics within 500 ms.
2. Inspect probe timeout values across mobile frontend, desktop frontend, native bridge, and engine; verify all components enforce a unified, protocol-appropriate minimum timeout (e.g. 6000 ms for QUIC/H3 handshakes).

**Acceptance Scenarios**:
1. **Given** an active multi-endpoint probe with pending network requests, **When** a cancellation signal is emitted, **Then** the asynchronous scanner observes the cancellation token immediately within every active probe loop, persists the best endpoints discovered so far, and terminates cleanly.
2. **Given** a scan configuration request from any platform interface, **When** probe timeouts are configured, **Then** all client bridges and core engines validate and enforce a unified minimum probe duration sufficient for cryptographic handshakes on mobile networks.

---

### User Story 5 - Configuration Resilience, Registry Recovery & Settings Integrity (Priority: P5)

A user configuring application settings on desktop or mobile requires that settings never become permanently disabled due to temporary IPC or bridge glitches; that Windows proxy registry settings are verified during restoration; that engine exit classification preserves connection history; that Android native settings thoroughly validate all parameters; that corrupted security keys on Android have an automated recovery path; that Android settings upgrades never overwrite explicit user routing choices; and that boot startup on modern Android displays actionable notifications.

**Why this priority**: Broken settings locks render the application unusable; registry cleanup errors leave system proxy settings corrupted; and invalid settings parameters cause cryptic crashes in native code.

**Independent Test**:
1. Simulate a transient communication failure during initial settings loading; verify the settings interface finishes hydration in a fallback state, displays an informative notice with a retry option, and does not permanently lock the settings panel.
2. Force a failure during Windows system proxy registry key deletion; verify the error is detected, the registry state is verified via read-back, and the backup file is preserved until deletion succeeds.
3. Terminate an engine process that had previously established a connection; verify the exit classifier reports a runtime disconnection rather than a pre-connection gateway failure.
4. Submit invalid or malformed setting values across the Android bridge; verify native validation rejects unknown protocols, invalid ranges, and malformed strings with structured error messages.
5. Corrupt the Android encrypted key store file; verify the application detects the unreadable state, prompts the user or automatically regenerates the wrapping key, reprovisions credentials, and recovers without crashing.
6. Upgrade from an earlier Android release where the user explicitly selected proxy mode; verify the migration preserves the user's explicit routing choice.
7. Trigger system boot on Android 10+; verify the application posts a user-actionable notification rather than attempting a disallowed background activity launch.

**Acceptance Scenarios**:
1. **Given** settings retrieval from the native backend, **When** the retrieval fails or times out, **Then** the user interface completes hydration with safe defaults, unlocks configuration controls, and surfaces a retry banner.
2. **Given** system proxy restoration on Windows disconnect, **When** deleting Aether proxy keys, **Then** the application propagates real access errors, validates registry state post-deletion, and retains the recovery snapshot if restoration was incomplete.
3. **Given** an engine process exiting unexpectedly after having successfully established a tunnel, **When** the supervisor classifies the exit reason, **Then** it accurately logs a session disconnect rather than a failure to reach the gateway.
4. **Given** incoming settings updates on Android, **When** native code deserializes the configuration, **Then** it validates all protocol names, transport modes, IP versions, routing options, and numeric ranges against supported schemas.
5. **Given** a corrupted or invalidated encryption key store on Android, **When** reading credentials fails, **Then** the application triggers an automated key rotation and reprovisioning workflow with user feedback.
6. **Given** a user with explicit non-TUN routing preferences upgrading the Android application, **When** settings migration executes, **Then** explicit user preferences are preserved intact.
7. **Given** device reboot on modern Android versions, **When** the boot receiver executes, **Then** it issues a user-visible notification to launch or activate the connection in compliance with platform background restrictions.

---

### User Story 6 - Automated Regression Harness, Release Gates & Quality Verification (Priority: P6)

A software maintainer or release engineer requires that all claimed bug fixes, scanner lifecycles, and security invariants are backed by automated tests, that production releases in CI are strictly gated upon passing the full test suite, and that complex core modules are decomposed into testable, cohesive units.

**Why this priority**: Without automated regression tests and mandatory CI gates, fixed defects immediately regress in subsequent releases.

**Independent Test**:
1. Execute the automated test suite across frontend hooks, Kotlin lifecycle controllers, and Rust engine components; verify all test scenarios pass.
2. Attempt to trigger a release workflow on a branch with failing unit tests; verify the release job is blocked until the test suite succeeds.
3. Inspect the automated CI pipeline; verify development toolchains, SDKs, and third-party actions are pinned to specific versions.

**Acceptance Scenarios**:
1. **Given** any codebase modification, **When** automated testing runs, **Then** unit and integration tests validate scanner lifecycle transitions, cancellation responsiveness, settings hydration, and routing safety.
2. **Given** a tag or release trigger, **When** the release pipeline executes, **Then** release artifact generation is strictly dependent upon successful completion of the full CI validation suite.
3. **Given** the core orchestration modules, **When** evaluated for architectural complexity, **Then** state machines, process supervisors, and command dispatchers are modularized with clear interface contracts.

---

## Edge Cases

- **Simultaneous Scan and Connect**: What happens when a user starts an exhaustive scan and immediately presses the connect button? The active scan is commanded to halt immediately via responsive cancellation token, the runner waits for confirmed exit, and the connection sequence begins cleanly.
- **Process Termination Timeout**: What happens if an engine process ignores a graceful termination signal during shutdown? The supervisor enforces a definitive timeout (e.g. 3000 ms) before forcefully terminating the process, awaiting OS confirmation, and only then releasing the idle barrier.
- **Windows File Lock Contention**: What happens when anti-virus or file indexers temporarily lock the identity file during an atomic update? The engine uses replacement semantics with fallback retries, never deleting the primary copy until replacement is confirmed.
- **Hardware Network Switch During Probe**: What happens if Wi-Fi disconnects during an ongoing scanner probe on mobile? The cancellation token triggers on network change or user abort, terminating active connection sockets without hanging the scanning thread.
- **Corrupt Encryption Key**: What happens if the Android KeyStore master key is invalidated by a device biometric reset or keystore corruption? The system detects the decryption failure, wipes the unrecoverable ciphertext, and initiates a clean reprovisioning sequence.
- **Dual VPN Conflict on Android**: What happens if another VPN app takes over the Android VpnService while Aether is active? The VPN service lifecycle receives the revoke event, cleans up the engine supervisor, and transitions the UI to disconnected.
- **Physical Gateway Disappearance on Windows**: What happens if the physical network adapter loses its default gateway while TUN split routes are being configured? Route setup detects the missing physical escape route, rejects default route installation, and restores existing adapter metrics.
- **Settings Hydration Failure**: What happens if the webview bridge fails during initial startup? The settings panel displays default configuration values with an indicator that remote settings could not be fetched, allowing the user to click "Retry".

---

## Requirements *(mandatory)*

### Functional Requirements

#### Privileged Execution & Desktop Security
- **FR-001**: System MUST verify Authenticode digital signatures, certificate publisher identity (enforcing distinct publisher policies: `aether.exe` under `deathline94` and `wintun.dll` under `WireGuard LLC`), and full certificate chain before executing with Administrator privileges.
- **FR-002**: System MUST verify embedded cryptographic release hashes for privileged binaries prior to launch as a secondary tamper check, failing closed if hashes are absent from embedded tables or mismatched.
- **FR-003**: System MUST reject elevated execution if binary path validation, signature verification, or hash checks fail, logging an explicit security violation.
- **FR-004**: System MUST encrypt desktop user identity credentials at rest using Windows Data Protection API (DPAPI) per-user key derivation.
- **FR-005**: System MUST fail startup fatally if filesystem access control list (ACL) hardening fails on sensitive configuration directories.
- **FR-006**: System MUST atomically migrate existing unencrypted identity files to encrypted storage on startup, propagating any write failures as fatal errors.
- **FR-007**: System MUST securely zero sensitive cryptographic key buffers in memory immediately after use.

#### Core Engine Storage, Concurrency & Routing
- **FR-008**: System MUST utilize an operating-system-backed, non-failing-open lock (`ProvisionGuard`) with process liveness tracking for device provisioning, preventing concurrent registrations.
- **FR-009**: System MUST perform identity file writes using atomic filesystem replacement APIs (`ReplaceFileW`/`MoveFileExW`) and preserve backup copies until replacement succeeds.
- **FR-010**: System MUST verify physical peer route creation before installing split-default routes in Windows TUN mode, and roll back all newly added routes in a self-cleaning `try/catch` block if any step fails.
- **FR-011**: System MUST strictly enforce the 16 KiB HTTP proxy header limit at read chunk boundaries, terminating connections that exceed the maximum size.

#### Android Lifecycle & Process Supervision
- **FR-012**: System MUST maintain an explicit engine supervisor state machine with mutually exclusive states: `idle`, `scanning`, `connecting`, `connected`, and `stopping`.
- **FR-013**: System MUST provide a blocking `stopAndWait(timeout)` completion barrier that awaits OS process exit confirmation before allowing new process launches, retaining `STOPPING` state and preserving process references if a process proves unkillable.
- **FR-014**: System MUST automatically stop active scans and await confirmed process termination before executing "Connect Direct" or tunnel connection requests.
- **FR-015**: System MUST roll back engine processes, VPN services, and runtime status if Android foreground service startup throws an exception.
- **FR-016**: System MUST report VPN establishment success only when the virtual network interface is established for the current lifecycle generation.
- **FR-017**: System MUST correctly extract and report the native engine operating system process ID (PID) as a numeric value.

#### Responsive Scanner & Unified Timeouts
- **FR-018**: System MUST integrate cooperative cancellation tokens into all asynchronous scan loops, tracking monotonic scan generations so early cancellations are never cleared by scan startup, waking immediately on abort signals without waiting for pending network socket timeouts.
- **FR-019**: System MUST enforce a unified, protocol-appropriate minimum probe timeout (minimum 6000 ms for QUIC/H3) across UI, native bridges, and engine configurations.

#### Settings Integrity & Platform Resilience
- **FR-020**: System MUST ensure settings hydration in UI runtime hooks completes in a `finally` block, exposing a visible retry banner upon communication errors.
- **FR-021**: System MUST verify all 3 Windows system proxy registry values (`ProxyEnable`, `ProxyServer`, and `ProxyOverride`) on read-back and maintain the recovery file until restoration is verified.
- **FR-022**: System MUST track connection establishment history across process exits to distinguish normal session disconnects from pre-connection gateway failures.
- **FR-023**: System MUST validate all configuration fields, enums (including `gool` preset and noise modes `off` through `custom`), protocols, and ranges at the native Android bridge boundary before applying settings.
- **FR-024**: System MUST provide automated recovery, key rotation, corrupted configuration quarantine (`aether.toml.corrupted.<timestamp>`), and reprovisioning when Android configuration key store corruption is detected.
- **FR-025**: System MUST preserve explicit user routing selections during Android settings migrations.
- **FR-026**: System MUST post user-actionable notifications on Android 10+ boot events rather than attempting disallowed background activity launches.

#### Testing & CI Quality Gates
- **FR-027**: System MUST include automated tests verifying scanner cancellation, lifecycle transitions, atomic file writes, settings hydration, and process barriers.
- **FR-028**: System MUST gate release packaging workflows upon successful completion of the full automated CI test suite.
- **FR-029**: System MUST pin all compiler toolchains, SDKs, build dependencies, and CI third-party actions to immutable 40-character commit SHAs with inline version comments.

---

### Key Entities *(include if feature involves data)*

- **Process Supervisor State**: Represents the execution state of the engine runner (`idle`, `scanning`, `connecting`, `connected`, `stopping`), associated with a monotonically increasing generation token.
- **Identity Store**: Encrypted container holding access tokens, client certificates, WireGuard private keys, and server metadata, protected at rest by platform encryption.
- **Provision Guard**: Concurrency synchronization entity tracking active provisioning operations, holding owner process identification and heartbeat timestamps.
- **Routing Snapshot**: Windows registry and network interface state captured prior to tunnel or proxy activation, retained until restoration is verified.
- **Probe Specification**: Unified configuration entity defining target endpoints, transport protocols, cryptographic timeouts, and cancellation tokens.

---

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: 100% of elevated desktop engine executions verify digital signature and hash integrity before execution; tampered binaries are rejected with 0% false acceptance.
- **SC-002**: 100% of saved desktop identities on Windows are encrypted with platform user protection; zero plaintext credentials are written to disk.
- **SC-003**: Standalone scanner cancellation halts the engine and finalizes data in under 500 ms, even when all pending network probes are unresponsive.
- **SC-004**: Stopping an active engine and starting a new one results in zero concurrent process collisions or port binding conflicts across 100 repeated rapid-fire stop/start cycles.
- **SC-005**: Initiating "Connect Direct" while a scan is active succeeds on the first attempt 100% of the time without requiring manual intervention.
- **SC-006**: Failed Windows TUN route installations leave the host machine with 100% restored physical internet connectivity across all test scenarios.
- **SC-007**: 100% of invalid configuration values passed across the mobile bridge are caught and rejected with structured validation errors without engine crashes.
- **SC-008**: Settings panels on desktop and mobile recover and remain interactive after 100% of simulated initial bridge communication failures.
- **SC-009**: Automated test suite achieves complete coverage over process lifecycle state machines, atomic file replacement, and scanner cancellation.
- **SC-010**: 100% of production release builds are blocked unless all automated unit, integration, and security checks pass in CI.

---

## Assumptions

- Operating system user credentials on Windows provide a functioning Data Protection API (DPAPI) environment for the current interactive user session.
- Authenticode signing certificates and valid publisher signatures will be integrated into the automated release pipeline for production binaries.
- Android devices running version 10 (API 29) and above strictly enforce background activity launch restrictions; notifications provide the standard platform-compliant user engagement model.
- Core network probe timeout minimum of 6000 ms is sufficient for TLS and QUIC cryptographic handshakes across high-latency mobile networks while avoiding excessive user wait times.
- Legacy plaintext identity files found on disk during startup were created by the current authorized user and can be safely upgraded in-place to encrypted format.
