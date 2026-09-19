# Quickstart: Security & Reliability Verification Guide

**Feature**: `013-security-reliability-remediation`
**Target Audience**: Developers, QA Engineers, Security Auditors

---

## 1. Prerequisites

- **Rust Toolchain**: 1.88+ (`cargo check`, `cargo test`)
- **Node.js**: 20+ (`npm run build`, `npm test`)
- **Java**: JDK 21+ (`gradlew compileDebugKotlin`, `gradlew testDebugUnitTest`)
- **Platform**: Windows 10/11 x64 (for DPAPI, Authenticode, and TUN route tests), Android emulator/device (for supervisor tests).

---

## 2. Automated Test Verification

### A. Core Rust Engine & Protocol Tests
Run unit tests verifying HTTP header bounds, atomic file replacement, and cancellation:

```powershell
cd c:\Users\SLiM\Desktop\Project\Aether\aether
cargo test --test prober_cancel_tests
cargo test --test http_header_tests
cargo test --test config_atomic_tests
```

**Expected Outcome**: All tests pass. Prober cancellation halts within < 50ms. HTTP parser rejects 16 KiB + 1 byte headers.

### B. Android Native Kotlin Unit Tests
Run supervisor lifecycle, settings validation, and ConfigKeyStore recovery tests:

```powershell
cd c:\Users\SLiM\Desktop\Project\Aether\apps\android\android
$env:JAVA_HOME='C:\Program Files\Java\jdk-24'
.\gradlew testDebugUnitTest
```

**Expected Outcome**: `EngineRunnerTest` verifies `stopAndWait` barrier; `SettingsStoreTest` verifies schema rejection of invalid enums and preservation of user routing mode.

### C. Desktop Webview & Android Webview Unit Tests
Run frontend hook regression tests:

```powershell
cd c:\Users\SLiM\Desktop\Project\Aether\apps\android
npm test

cd c:\Users\SLiM\Desktop\Project\Aether\apps\desktop
npm test
```

**Expected Outcome**: `useRuntime.test.ts` proves settings hydration unlocks controls in `finally` block even when backend IPC fails.

---

## 3. End-to-End Manual Verification Scenarios

### Scenario 1: Elevated Binary Tampering Rejection
1. Place a renamed `cmd.exe` or third-party executable at the `aether.exe` path.
2. Launch desktop GUI and click Connect with TUN mode.
3. **Expected Outcome**: GUI displays "Elevated launch rejected: signature verification failed", engine is not spawned.

### Scenario 2: Identity Encryption at Rest
1. Connect once in the desktop app.
2. Inspect `%APPDATA%\Aether\aether.toml`.
3. **Expected Outcome**: File begins with `AETHERCFG1\n` header followed by encrypted binary payload. Zero plaintext keys are visible.

### Scenario 3: Android Direct Connect during Scan
1. In Android app, open Scanner tab and click "Start Scan".
2. When endpoints appear, tap "Connect Direct" on any discovered gateway.
3. **Expected Outcome**: Scan stops cleanly, process exit is confirmed, and tunnel connects immediately to the selected endpoint without error.
