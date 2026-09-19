# Quickstart & Verification Guide: Feature 014

## Prerequisites
- Rust 1.88.0 toolchain (`cargo`, `rustc`)
- Node.js 22 & npm
- JDK 21 (`JAVA_HOME` pointing to JDK 21)
- Windows PowerShell 5.1+ / pwsh

---

## Verification Scenarios

### 1. Elevation Trust & Wintun Verification
Verify distinct publisher CN policies and release hash fail-closed enforcement:
```powershell
cd apps/desktop/src-tauri
cargo test --test elevation_trust_test
```
**Expected Outcome**: All tests pass. `wintun.dll` validated with WireGuard LLC publisher policy; `aether.exe` validated with deathline94 publisher policy; missing or mismatched release hash strictly rejected.

---

### 2. Android Settings Schema Validation
Verify canonical settings schema acceptance for `gool` preset and all noise modes:
```powershell
cd apps/android/android
$env:JAVA_HOME = "C:\Program Files\Eclipse Adoptium\jdk-21.0.4.7-hotspot"
./gradlew testDebugUnitTest --tests "app.aethernext.SettingsStoreTest"
```
**Expected Outcome**: 100% pass across all supported presets (`warp`, `gool`) and noise profiles (`off`, `light`, `medium`, `high`, `max`, `custom`).

---

### 3. Supervisor Process Barrier & Unkillable Process Handling
Verify `stopAndWait` mutual exclusion and refusal to launch over alive processes:
```powershell
cd apps/android/android
$env:JAVA_HOME = "C:\Program Files\Eclipse Adoptium\jdk-21.0.4.7-hotspot"
./gradlew testDebugUnitTest --tests "app.aethernext.EngineRunnerTest"
```
**Expected Outcome**: All tests pass. Unkillable process returns `false`, maintains `STOPPING`, and blocks subsequent starts.

---

### 4. Scanner Cancellation & Handshake Timeout Floor
Verify generation-owned cancellation token and unified 6000ms H3 timeout floor:
```powershell
cd aether
cargo test --test scanner_cancellation_test
```
**Expected Outcome**: 100% pass. Early cancellation aborts within 50ms without being wiped by session initialization.

---

### 5. Windows Proxy Registry Read-Back Verification
Verify three-tuple comparison (`ProxyEnable`, `ProxyServer`, `ProxyOverride`) before recovery cleanup:
```powershell
cd apps/desktop/src-tauri
cargo test --test proxy_restore_test
```
**Expected Outcome**: 100% pass. `proxy_recovery.json` is preserved if any of the three values fails to match pre-session snapshot.

---

### 6. Frontend Settings Hydration Retry Banner
Verify retry state exposure and interactive retry banner rendering:
```powershell
cd apps/desktop
npm test
cd ../android
npm test
```
**Expected Outcome**: All tests pass. `settingsLoadError` exposes banner and `retrySettings` triggers reload.

---

### 7. CI Action Pinning Verification
Verify all external actions in workflow files use 40-character commit SHAs:
```powershell
Select-String -Path .github/workflows/*.yml -Pattern "uses:\s+[a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+@"
```
**Expected Outcome**: Every external action reference matches `[a-f0-9]{40}`.
