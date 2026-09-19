# Technical Research: Audit Remediation Hardening & Verification Completeness

## Research Phase 0 Findings & Architectural Decisions

### 1. Distinct Elevation Trust Policies (aether.exe vs wintun.dll)
- **Problem**: In release builds, `verify_elevated_binary` evaluated both `aether.exe` and `wintun.dll` against a single `TrustedBinaryPolicy` requiring `expected_publisher_cn: "deathline94"`. Because `wintun.dll` is officially signed by `WireGuard LLC`, verifying Wintun against `deathline94` caused `WinVerifyTrust` to fail with certificate publisher mismatch in production TUN mode.
- **Decision**: Define distinct policies per binary:
  - `TrustedBinaryPolicy::for_engine()`: `expected_publisher_cn: "deathline94"`, release hash required in production, unsigned allowed only in debug.
  - `TrustedBinaryPolicy::for_wintun()`: `expected_publisher_cn: "WireGuard LLC"`, release hash required, unsigned never allowed.
- **Rationale**: Wintun is an upstream third-party kernel driver interface provided by WireGuard LLC; project binaries are signed with the project's code signing certificate. Differentiating them maintains strict Authenticode validation without cross-signing third-party binaries.
- **Alternatives Considered**: Cross-signing or re-signing `wintun.dll` with project certificate was rejected because modifying third-party driver binaries invalidates upstream driver signatures.

### 2. Embedded Release Hash Enforcement
- **Problem**: In commit `7cb7d31`, `EMBEDDED_RELEASE_HASHES` was empty (`&[]`), and the hash verification loop in `verify_elevated_binary` succeeded when no matching hash was found, effectively disabling hash verification.
- **Decision**:
  - In `verify_elevated_binary`, when hash validation is enabled (`!policy.embedded_hashes.is_empty()` or in non-debug production builds), require that `policy.embedded_hashes` contains a matching entry for `filename`. If missing or if the digest does not match, return `BinaryTrustError::HashMismatch` or `BinaryTrustError::MissingHash`.
  - In `build.rs` or CI packaging, calculate SHA-256 for release artifacts and embed them into the desktop binary.
- **Rationale**: Hash checking must fail-closed. If release hashes are part of the security contract, the absence of a hash is a verification failure, not a bypass.

### 3. Android Settings Schema Canonicalization
- **Problem**: `SessionController.validateSettings` rejected `endpointPreset == "gool"` and rejected noise modes `light`, `medium`, `high`, `max`, and `custom` emitted by `SettingsTab.tsx:175`.
- **Decision**:
  - Establish a shared canonical schema:
    - `validPresets = setOf("warp", "gool")`
    - `validNoise = setOf("off", "light", "medium", "high", "max", "custom")`
    - `validTransports = setOf("h2", "h3")`
    - `validProtocols = setOf("wireguard", "masque")`
    - `validRouting = setOf("tun", "proxy-only", "system-proxy")`
    - `validIpVersions = setOf("v4", "v6", "both")`
    - `validScanModes = setOf("turbo", "balanced", "thorough", "stealth", "ironclad")`
  - Write parameterized unit tests in `SettingsStoreTest.kt` iterating through every single enum option.
- **Rationale**: UI options and backend validation must be 100% symmetric. Any option selectable in the UI must pass backend validation.

### 4. Android Process Supervisor Barrier & Injection
- **Problem**: If `EngineRunner.stopAndWait` encounters a process that refuses to terminate even after `destroyForcibly()`, it previously marked state as `IDLE`, set `running=false`, and set `process = null`. When `SessionController.connect` immediately followed, it ignored the return value and launched a second engine process while the first was still alive.
- **Decision**:
  - In `EngineRunner.stopAndWait`:
    ```kotlin
    if (!forceDestroyed) {
        log("Process failed to exit even after destroyForcibly")
        return false // State remains STOPPING, running remains true, process reference retained
    }
    ```
  - In `SessionController.connect` and `scan`:
    ```kotlin
    val stopped = runner.stopAndWait(3000)
    if (!stopped) {
        log("Cannot proceed: previous engine process could not be terminated")
        return
    }
    ```
  - Refactor `EngineRunner` with an injectable `ProcessLauncher` interface to allow testing real `start` and `stopAndWait` behavior in JUnit without needing native binaries.
- **Rationale**: The supervisor must strictly maintain single-instance mutual exclusion. An unkillable process must block new launches rather than allowing dual-process collisions.

### 5. Plaintext Migration Error Propagation
- **Problem**: `config.rs:274` logged an error if `save_config` failed during plaintext-to-encrypted migration, but returned `Ok(cfg)` anyway, continuing the session with exposed plaintext on disk.
- **Decision**: If `AETHER_CONFIG_KEY` is set and plaintext migration is triggered, failure to write the encrypted configuration must return `Err(AetherError::Config(...))` and abort engine startup.
- **Rationale**: Security invariants cannot fail open. If encryption at rest is mandated, failing to encrypt must block operation.

### 6. Android KeyStore Recovery Quarantine
- **Problem**: `ConfigKeyStore.loadOrCreate` caught crypto exceptions and rotated the key, but left the existing `aether.toml` (encrypted under the lost key) in `files/config/`. When the engine attempted to load the config, it failed with decryption errors.
- **Decision**: When KeyStore corruption is detected in `ConfigKeyStore`:
  1. Rotate the key.
  2. Delete or rename `aether.toml` and `aether.toml.bak` in the config directory.
  3. Emit a recovery event so the app prompts for clean reprovisioning.
- **Rationale**: A file encrypted with a permanently lost key is cryptographically unrecoverable; keeping it prevents new valid credentials from being generated.

### 7. Scanner Cancellation Generation Ownership
- **Problem**: `prober.rs:344` stored `SCAN_CANCEL.store(true, ...)` upon cancellation, but `hunt_best` unconditionally ran `SCAN_CANCEL.store(false, ...)` at line 375, wiping cancellation if the user clicked cancel during scan initialization.
- **Decision**:
  - Maintain a monotonically increasing `scan_generation: AtomicU64`.
  - When `request_scan_cancel()` is called, record cancellation for the current generation.
  - When `hunt_best` runs, check if the current generation is already cancelled; if so, abort immediately before initiating probe futures.
- **Rationale**: Asynchronous cancellations must not race with session startup. A cancel request emitted during scan setup must be honored.

### 8. Probe Timeout Floor Consistency
- **Problem**: The engine enforced `EXPENSIVE_MIN_TIMEOUT = Duration::from_millis(5000)` at `prober.rs:192`, while Android bridge permitted 3000ms at `AetherBridge.kt:51`, and UI defaulted to 6000ms.
- **Decision**:
  - Set `EXPENSIVE_MIN_TIMEOUT = Duration::from_millis(6000)` in `prober.rs`.
  - In `AetherBridge.kt`, enforce `Math.max(6000, timeoutMs)` for H3/QUIC scans.
  - In `useScanner.ts`, default to 6000ms and clamp to 6000ms for expensive protocols.
- **Rationale**: All subsystems must adhere to the exact same 6000ms handshake contract to prevent premature probe abortion on mobile networks.

### 9. PowerShell Transactional Routing Rollback
- **Problem**: In `tun_win.rs:246`, if PowerShell route script fails after adding the peer escape route or the first split route, it leaves orphaned routes in the Windows routing table. The fallback `route.exe` command then attempts `route add <peer>`, which fails with exit code 1 because the route already exists.
- **Decision**:
  - In the PowerShell script passed to `powershell.exe`, wrap the route additions in:
    ```powershell
    $added = @()
    try {
        # Add peer route
        New-NetRoute ...; $added += @{ DestinationPrefix = $peerPrefix; InterfaceIndex = $physIf }
        # Add split routes
        New-NetRoute ...; $added += @{ DestinationPrefix = '0.0.0.0/1'; InterfaceIndex = $tunIf }
        New-NetRoute ...; $added += @{ DestinationPrefix = '128.0.0.0/1'; InterfaceIndex = $tunIf }
    } catch {
        foreach ($r in $added) { Remove-NetRoute -DestinationPrefix $r.DestinationPrefix -InterfaceIndex $r.InterfaceIndex -Confirm:$false -ErrorAction SilentlyContinue }
        throw
    }
    ```
- **Rationale**: The route setup script must be self-cleaning on failure so the routing table remains untouched if an error occurs.

### 10. Complete Proxy Registry Read-Back
- **Problem**: `windows_proxy::restore` only verified `ProxyEnable` and the absence of `ProxyServer`. It failed to verify restored `ProxyServer` values (when originally present) and completely ignored `ProxyOverride`.
- **Decision**:
  - Compare all three keys against the snapshot:
    - If `snapshot.server` is `Some(s)`: read-back must equal `s`. If `None`: key must be absent or empty.
    - If `snapshot.override_` is `Some(o)`: read-back must equal `o`. If `None`: key must be absent or empty.
    - `ProxyEnable` read-back must equal `snapshot.enable`.
  - Only delete `proxy_recovery.json` if all 3 match.
- **Rationale**: System proxy restore must leave the system in the exact pre-session state.

### 11. Frontend Settings Hydration Retry Banner
- **Problem**: When settings loading fails in `useRuntime.ts`, it catches the error and unlocks controls, but does not expose an error flag or retry mechanism.
- **Decision**:
  - Expose `settingsLoadError: boolean` and `retrySettings: () => Promise<void>` in `useRuntime.ts` (desktop and mobile).
  - In `SettingsTab.tsx`, render a warning banner with an interactive "Retry" button.
- **Rationale**: Users must know if settings failed to load and have a 1-click action to retry without restarting the application.

### 12. Orchestrator Complexity Decomposition
- **Problem**: `AetherBridge.invoke` (complexity 22), `EngineRunner.start` (complexity 20), and `AetherVpnService.establishTun` (complexity 26) exceed maintainability thresholds.
- **Decision**:
  - `AetherBridge.kt`: Extract command handlers (`handleGetSettings`, `handleSaveSettings`, `handleScan`, `handleConnect`, `handleDisconnect`, etc.).
  - `EngineRunner.kt`: Extract `buildProcessCommand` and `configureProcessEnvironment`.
  - `AetherVpnService.kt`: Extract `configureTunBuilder` and `registerUnderlyingNetworkCallbacks`.
- **Rationale**: Decoupling command dispatch and system configuration reduces cyclomatic complexity and enables targeted unit testing.

### 13. CI Action Immutability
- **Problem**: `.github/workflows/ci.yml` and `build.yml` referenced mutable tags (`@v4`, `@master`).
- **Decision**: Pin every external action to full 40-character commit SHAs with inline version comments.
- **Rationale**: Supply-chain security requirement to ensure deterministic, immutable builds.
