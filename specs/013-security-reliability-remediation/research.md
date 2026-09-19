# Technical Research & Decision Record: Full-Stack Audit Remediation

**Feature**: `013-security-reliability-remediation`
**Date**: 2026-09-19
**Scope**: 22 actionable security, reliability, lifecycle, and verification issues across Rust engine, Windows desktop app, Android mobile app, and CI pipelines.

---

## 1. Privileged Binary Validation & Elevation Security (Issue 1)

### Decision
Implement multi-tier elevated execution validation in `apps/desktop/src-tauri/src/lib.rs`:
1. **Windows Authenticode & Trust Chain Verification**: Use the Windows WinVerifyTrust API (`wintrust.dll` / `WinVerifyTrust`) with `WINTRUST_ACTION_GENERIC_VERIFY_V2` to verify that `aether.exe` and `wintun.dll` are digitally signed by a valid, trusted certificate with an unbroken chain to a trusted root authority.
2. **Mandatory Publisher Identity & Embedded Release Hash Check**: Check that the subject/publisher matches `CN="deathline94"` (or the configured release publisher) and that the SHA-256 hash of the binary matches the embedded release hash table compiled into the Tauri binary.
3. **Protected Installation Scope**: Update `apps/desktop/src-tauri/tauri.conf.json` NSIS installer configuration from `"installMode": "currentUser"` to `"perMachine"` (`C:\Program Files\Aether Next`), ensuring only Administrators can write to the application and DLL directories. Reject elevation if binaries reside in user-writable `%LOCALAPPDATA%` without passing all cryptographic checks.

### Rationale
Validating file presence and the `MZ` header is insufficient on Windows because a non-privileged user or process could replace `aether.exe` in `%LOCALAPPDATA%` with a malicious executable, which would then be executed with full Administrator privileges when the user clicks "Elevate". Authenticode plus embedded hash validation creates an immutable defense-in-depth barrier against binary hijacking.

### Alternatives Considered
- *Standalone Windows Service*: Creating a separate Windows Service running under `NT AUTHORITY\SYSTEM` to manage TUN interfaces. Rejected for this phase as it introduces substantial installer and IPC complexity compared to Authenticode validation + perMachine ACL protection.
- *Only Embedded Hash Check*: Storing hardcoded hashes of `aether.exe` and `wintun.dll`. Insufficient on its own because dev builds and varied compiler versions change hashes; combining Authenticode chain verification with hash verification provides flexibility for signed builds and strict pinning for release builds.

---

## 2. Desktop Identity Encryption at Rest via Windows DPAPI (Issue 2)

### Decision
1. **DPAPI Master Key Management**: On Windows desktop, when Tauri initializes (`setup` hook in `lib.rs`), derive or load a 32-byte secret key protected by Windows DPAPI (`CryptProtectData` with `CRYPTPROTECT_UI_FORBIDDEN`). Store the DPAPI-encrypted envelope in `%APPDATA%\Aether\config_key.dpapi`.
2. **Environment Injection**: Decrypt the key in memory during startup using `CryptUnprotectData`, pass it to the engine subprocess via the `AETHER_CONFIG_KEY` environment variable, and immediately zero (`Zeroize`) the key buffers in both Tauri and Rust engine after configuration decoding.
3. **Fatal ACL Enforcement**: If `icacls` or Windows security descriptor API fails to restrict access permissions to `(OI)(CI)(F)` for the current user and `SYSTEM`, fail startup fatally instead of logging a non-fatal warning.
4. **Atomic Migration**: If `aether.toml` exists in plaintext (unencrypted format without the `AETHERCFG1\n` header), decrypting proceeds with the plaintext fallback; the engine then immediately re-saves it in encrypted format using `AETHER_CONFIG_KEY` and atomically replaces the file.

### Rationale
The core engine already implements ChaCha20-Poly1305 authenticated encryption in `aether/src/config.rs`, but gracefully falls back to plaintext if `AETHER_CONFIG_KEY` is not set. The Tauri desktop app never set this key, leaving all private keys and access tokens in plaintext. DPAPI provides per-user hardware-backed/OS-backed key derivation with zero user password prompt friction.

### Alternatives Considered
- *Prompting user for passphrase*: High user friction; breaks auto-connect and background launch features.
- *Hardcoded static key*: Cryptographically useless; vulnerable to static analysis.

---

## 3. Android Scanner & Connection Lifecycle Concurrency (Issues 3 & 4)

### Decision
1. **Explicit Supervisor State Machine**: Define an atomic state enum in `EngineRunner.kt`: `IDLE`, `SCANNING`, `CONNECTING`, `CONNECTED`, `STOPPING`.
2. **Blocking `stopAndWait` Completion Barrier**:
   - Replace the fire-and-forget `stop()` method with `stopAndWait(timeoutMs: Long = 5000): Boolean`.
   - Send `cancel\n` (for scan) or `shutdown\n` (for tunnel) over standard input.
   - Use `Process.waitFor(timeoutMs, TimeUnit.MILLISECONDS)`. If still alive, call `destroy()`. If still alive after 1000ms, call `destroyForcibly()`.
   - Keep runner state in `STOPPING` until `Process.waitFor()` confirms process death. Only then reset runner state to `IDLE`.
   - Synchronize `start`, `startScan`, and `stopAndWait` with a reentrant lock to eliminate process spawn races.
3. **Automatic Scan Teardown on Direct Connect**:
   - In `SessionController.kt`, if `connect()` or `connectDirect()` is invoked while the runner is in `SCANNING`, automatically issue `runner.stopAndWait(3000)` before proceeding with the connection sequence.
   - In `apps/android/src/App.tsx`, update `connectDirect` to explicitly invoke `scanner.stop()` and await state transition before dispatching `connectToPeer`.

### Rationale
Currently, `EngineRunner.stop()` sets `running=false` immediately while the background thread waits up to 5 seconds. When `scan()` or `connectDirect()` is invoked, it only sleeps 300ms, leading to dual engines running simultaneously on the same SOCKS/HTTP ports and corrupting shared caches. A blocking completion barrier guarantees strict single-instance mutual exclusion.

---

## 4. Prompt Scanner Cancellation in Rust Core (Issue 5)

### Decision
1. In `aether/src/prober.rs`, replace the static `AtomicBool` polling check with a `tokio_util::sync::CancellationToken` or static `tokio::sync::watch` channel.
2. In `hunt_best`, incorporate cancellation as a first-class branch in the main `tokio::select!`:
   ```rust
   tokio::select! {
       _ = cancel_token.cancelled() => {
           log::info!("[*] scan cancelled by request; finalizing with best so far");
           break;
       }
       item = stream.next() => { ... }
       _ = deadline_future => { ... }
   }
   ```
3. Pass child cancellation tokens into candidate verification futures (`verify(&candidate, cancel_child.clone())`), so ongoing QUIC/TLS handshakes abort socket operations immediately rather than waiting for 5-second socket timeouts.

### Rationale
An atomic boolean is only inspected at loop boundaries. When `stream.next()` is awaiting pending socket futures, the loop is asleep in the tokio runtime and cannot notice the atomic flag until a socket times out or errors. Integrating `CancellationToken` directly into `tokio::select!` wakes the runtime immediately on the next event loop iteration (< 1 ms).

---

## 5. Android Foreground Service Startup Rollback (Issue 6)

### Decision
In `SessionController.connect(s: Settings)`:
1. Wrap `context.startForegroundService(svc)` in a strict `try-catch` block.
2. If `ForegroundServiceStartNotAllowedException` or `SecurityException` is caught:
   - Terminate the newly launched engine via `runner.stopAndWait(2000)`.
   - Clean up any allocated VPN state via `stopVpnService()`.
   - Set `runtime.status = "error"` with an explanatory message ("Background service startup restricted by OS").
   - Return the error string to the caller.

### Rationale
Android 12+ (API 31+) strictly regulates when applications may call `startForegroundService()` from the background. If rejected, the unhandled exception crashed the bridge or left `libaether.so` running as an orphaned daemon while the UI remained in an invalid state.

---

## 6. Concurrency Locks for Account Provisioning (Issue 7)

### Decision
1. In `aether/src/cache.rs`, replace the advisory `CacheLock` with a robust `ProvisionGuard` returning `Result<ProvisionGuard, AetherError>`.
2. Use OS-level file locking via `fs2::FileExt::try_lock_exclusive` (or Windows `LockFileEx` / Unix `flock`), tied to an open file handle that is automatically closed and unlocked on process termination.
3. Write the owner PID into the lock file. If lock acquisition fails because another process holds it, check process liveness (`kill -0` on Unix, `OpenProcess` with `PROCESS_QUERY_LIMITED_INFORMATION` on Windows). Only steal the lock if the holding process has demonstrably died.
4. In `session.rs`, if `load_or_provision` cannot acquire the lock within 30 seconds, fail with `AetherError::Other("Provisioning in progress by concurrent process; retry shortly")` instead of failing open and duplicating registration.

### Rationale
A 20-second timeout that silently proceeds without holding the lock guarantees duplicate Warp registrations and account identity overwrites when Cloudflare API calls take longer than 20 seconds.

---

## 7. Atomic Identity Persistence & Windows Route Fallback (Issues 8 & 9)

### Decision
1. **Atomic File Replacement**:
   - In `aether/src/config.rs::write_private_file`:
   - On Windows, use `windows_sys::Win32::Storage::FileSystem::ReplaceFileW` (or `MoveFileExW` with `MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH`).
   - Create a temporary backup file (`path.bak`). Only delete `path.bak` after the replace API succeeds. Never unlink the destination before replacing it.
2. **Windows TUN Route Safety**:
   - In `aether/src/tun_win.rs`:
   - Require `run_cmd("route", &["add", &peer_s, "mask", "255.255.255.255", &gw_s, "metric", "1", "IF", &phys_if])` to succeed. Check the return code; if it fails, abort immediately.
   - Verify the peer route exists on `phys_if` before adding split-default routes (`0.0.0.0/1` and `128.0.0.0/1`).
   - If split-default route installation fails, roll back all newly added routes and restore adapter metrics.

---

## 8. Android VPN Lifecycle & Settings Store Integrity (Issues 10, 14, 15, 16, 17, 18)

### Decision
1. **VPN Setup Generation Token (Issue 10)**: Introduce `vpnGeneration = AtomicLong(0)` in `AetherVpnService.kt`. `establishTun()` returns `Boolean`. `onVpnEstablished` is only signaled if `tun != null` AND `currentGeneration == token` AND `!stopRequested`.
2. **Native Settings Validation (Issue 14)**: In `SessionController.validate(s: Settings)`, validate all enum fields:
   - `protocol`: `wireguard`, `masque`
   - `transport`: `h2`, `h3`
   - `scanMode`: `turbo`, `balanced`, `thorough`, `stealth`, `ironclad`
   - `ipVersion`: `v4`, `v6`, `both`
   - `noize`: `off`, `light`, `medium`, `high`, `max`, `custom`
   - `routingMode`: `tun`, `proxy-only`, `system-proxy`
   - Reject invalid values with `IllegalArgumentException`.
3. **Android Process PID Reflection (Issue 15)**: In `EngineRunner.pid()`, inspect `Process.pid()` as `java.lang.Number` and invoke `toInt()`.
4. **ConfigKeyStore Corruption Recovery (Issue 16)**: In `ConfigKeyStore.loadOrCreate(c: Context)`, catch `AEADBadTagException`, `GeneralSecurityException`, and `IllegalArgumentException`. On failure, delete corrupted `wrapped` preference, remove stale identity file, generate a fresh AES key, and log a warning.
5. **Settings Migration Routing Preservation (Issue 17)**: In `SettingsStore.load()`, only apply `routingMode = "tun"` if the preferences file was completely empty (first-time install), never overriding an existing explicit `"proxy-only"` or `"system-proxy"` setting.
6. **Android 10+ Boot Notification (Issue 18)**: In `BootReceiver.kt`, instead of calling `context.startActivity(launch)`, build and post a high-priority user notification with a `PendingIntent` that opens `MainActivity`.

---

## 9. Desktop Platform Resilience (Issues 11, 12, 13)

### Decision
1. **Windows Registry Proxy Deletion (Issue 11)**: In `windows_proxy::restore`, catch errors from `key.delete_value`. Ignore only `io::ErrorKind::NotFound` (`ERROR_FILE_NOT_FOUND`). For any other error, return `Err`. Verify registry values via read-back before unlinking `proxy_recovery.json`.
2. **Child Exit Classification State (Issue 12)**: In `watch_child` in `apps/desktop/src-tauri/src/lib.rs`, read `let ever_connected = state.connected_once.load(Ordering::SeqCst);` BEFORE invoking `cleanup_routing`.
3. **Settings Hydration Resilience (Issue 13)**: In both `apps/android/src/hooks/useRuntime.ts` and `apps/desktop/src/hooks/useRuntime.ts`, move `setSettingsLoaded(true)` into a `finally` block. If `loadedSettings` is null, preserve defaults and display a retry alert.

---

## 10. Parser Boundaries, Timeouts & CI Verification (Issues 19, 20, 21, 22)

### Decision
1. **HTTP Header Cap (Issue 19)**: In `aether/src/http_proxy.rs::read_header`, enforce `count <= MAX_HEADER - header.len()`. If `find_header_end` finds `\r\n\r\n` beyond `MAX_HEADER`, return `AetherError::Other("HTTP header too large")`.
2. **Unified Probe Timeout (Issue 20)**: Establish a shared contract: default probe timeout 6000ms, minimum acceptable timeout 3000ms. Update `useScanner.ts`, `AetherBridge.kt`, and `prober.rs`.
3. **Automated Regression Harness (Issue 21)**: Add test suites:
   - Frontend: Vitest scripts in `apps/android` and `apps/desktop` for `useRuntime` and `useScanner` hooks.
   - Kotlin: Unit tests for `SettingsStore` validation and `ConfigKeyStore` recovery.
   - Rust: Unit tests for `read_header`, atomic file replacement, and cancellation tokens.
4. **CI Release Gating & Pinning (Issue 22)**:
   - In `.github/workflows/build.yml`, make the release job depend on `.github/workflows/ci.yml` (`needs: [test]`).
   - Pin Rust toolchain to `1.88.0` and Java SDK to JDK 21 in CI action files.
