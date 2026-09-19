# Quickstart Validation Guide: Comprehensive Codebase Bug Audit & Precision Remediation

## Prerequisites
- Rust stable toolchain (`cargo`, `rustc`)
- Node.js (v20+) & npm
- PowerShell (Windows)

---

## Validation Scenarios

### Scenario 1: Engine Unit Tests & Netstack/DNS Invariants
Verify that all unit tests in the core Rust engine pass, including packet queue ordering and IPv6 DNS parsing:
```powershell
cd aether
cargo test --bin aether
```
**Expected Outcome**:
- All 49+ tests pass with 0 failures and 0 warnings.
- New unit tests for `flush_tx` queue FIFO order and `configured_dns_servers` IPv6 parsing succeed.

### Scenario 2: Desktop Tauri Host Check
Verify that the desktop host crate builds cleanly with the updated log patterns and IPC validation:
```powershell
cd apps/desktop/src-tauri
cargo check
```
**Expected Outcome**:
- Clean compilation with 0 errors.

### Scenario 3: Desktop Frontend Build
Verify that TypeScript and Vite production bundling succeed without type errors:
```powershell
cd apps/desktop
npm run build
```
**Expected Outcome**:
- Vite build completes with exit code 0 (`dist/` generated).

### Scenario 4: Direct Connect Error Handling
1. Launch Desktop app in dev mode (`npm run tauri dev`).
2. Go to **Scanner** tab and run a quick scan.
3. Select an invalid or stopped endpoint and click **Connect Direct**.
4. **Expected Outcome**:
   - The UI transitions smoothly to the **Home** tab.
   - If connection fails, the status updates to `error` and displays the error banner.
   - The Power button returns to idle (`CONNECT`) and does not remain stuck spinning.

### Scenario 5: Settings Port Validation & Auto-Save
1. In the **Settings** tab, edit the HTTP port to match the SOCKS port.
2. Observe the sticky save bar and Activity tab.
3. **Expected Outcome**:
   - The save bar indicates "Save blocked: fix port collision" with a red `X`.
   - No error logs are written to the Activity feed while the collision exists.
   - Changing the port to a unique valid number immediately restores "Saved" status.
