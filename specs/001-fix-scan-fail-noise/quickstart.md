# Quickstart & Validation Guide: Scan Failure Reversion & Modernized Noise

## Overview
This document outlines runnable test and validation steps to confirm:
1. The Start/Connect button automatically returns to the idle "CONNECT" state when an endpoint discovery scan finds zero reachable endpoints.
2. The engine process terminates promptly without blocking or leaving orphan background processes.
3. Pre-handshake noise injection across WireGuard, WARP-in-WARP, MASQUE H2, and MASQUE H3 uses the modernized 5-packet burst (`Jc=5`, `Jmin=50`, `Jmax=128`, `delay=0ms`).

---

## Prerequisites
- Rust toolchain (`cargo`, `rustc`)
- Node.js & npm (for Tauri desktop app)
- Local test environment on Windows

---

## Validation Scenarios

### Scenario 1: Auto-Reset on MASQUE H3 Scan Failure
1. Launch the Aether Next desktop app (`cd apps/desktop && npm run tauri dev`).
2. Select the **MASQUE H3** preset on the Connection tab.
3. Simulate endpoint unreachability (or disconnect uplink / point to an unreachable subnet).
4. Click **CONNECT**.
5. Observe the UI:
   - Status changes to `connecting` ("Finding a clear path").
   - Endpoint discovery runs.
   - When 0 endpoints are found, the engine outputs `[-] session failed: No working gateway found`.
6. **Expected Outcome**:
   - The power button immediately reverts to the idle state (**"CONNECT"**).
   - An error banner displays the failure explanation.
   - The button does NOT stay stuck in "DISCONNECT".
   - The user can immediately click "CONNECT" again or select another preset.

---

### Scenario 2: Process Cleanup & No Lingering Ports
1. Following the failure in Scenario 1:
2. Open PowerShell and check for lingering `aether.exe` processes:
   ```powershell
   Get-Process -Name "aether" -ErrorAction SilentlyContinue
   ```
3. Check that local ports 1819 and 1820 are released:
   ```powershell
   Get-NetTCPConnection -LocalPort 1819, 1820 -ErrorAction SilentlyContinue
   ```
4. **Expected Outcome**:
   - Zero `aether.exe` orphan processes running.
   - Ports 1819 and 1820 are completely free and unallocated.

---

### Scenario 3: Pre-Handshake Noise Validation
1. Run engine tests verifying the noise packet generation:
   ```powershell
   cd aether
   cargo test --lib noize
   cargo test --lib aethernoize
   cargo test --lib obfuscation
   ```
2. Verify:
   - 5 pre-handshake datagrams are generated per connection attempt.
   - Each datagram payload length is uniformly distributed between 50 and 128 bytes.
   - Inter-packet interval is 0 ms.

---

### Scenario 4: Settings Defaults Verification
1. Open the Settings tab in the application.
2. Select Obfuscation profile: **Custom**.
3. Inspect default parameters:
   - Junk count (`noizeJc`): **5**
   - Min size (`noizeJmin`): **50**
   - Max size (`noizeJmax`): **128**
   - Interval (`noizeIntervalMs`): **0**
