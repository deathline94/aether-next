# Quickstart & Verification Guide: Backend & Technical Bug Fixes

## 1. Automated Unit Tests

### Engine Unit Tests (`aether/`)
Run Rust unit tests to verify CIDR pools, seeds, port prioritization, and TLS verification:
```powershell
cd aether
cargo test
```
**Expected Outcome**:
- All tests in `prober::tests`, `wireguard::tests`, and `tls::tests` pass with 0 failures.
- No `8.x.x.x` addresses present in candidate generation.

---

## 2. Frontend Build Verification

### Desktop App (`apps/desktop/`)
```powershell
cd apps/desktop
npm run build
```
**Expected Outcome**:
- TypeScript compilation passes with 0 errors.
- Production bundle created in `apps/desktop/dist/`.

### Android Web Layer (`apps/android/`)
```powershell
cd apps/android
npm run sync-www
```
**Expected Outcome**:
- TypeScript compilation passes with 0 errors.
- Bundle compiled and synchronized to `apps/android/android/app/src/main/assets/www`.

---

## 3. Manual Verification Scenarios

### Scenario A: Activity Tab Scan Banner Spacing
1. Launch Desktop or Android app.
2. Navigate to Scanner tab and click "Start Standalone Edge Scan".
3. Immediately switch to the Activity tab.
4. **Verify**:
   - The banner shows `Active Engine Scan (MODE)` separated cleanly from the status pill (`Probing Pool`).
   - Badges display `X workers` and `Y working` in distinct colored pill chips with clear gaps.
   - The footer numbers show `Probed X / Y candidates` on the left and percentage `Z%` on the right.
   - No characters collide or touch.

### Scenario B: SPKI Pin Diagnostic Demotion
1. During a standalone scan, observe incoming logs in the Activity tab under the "Milestones" and "Errors" filters.
2. **Verify**:
   - Zero `[tls] SPKI pin mismatch` warnings appear in the terminal during candidate scanning.
   - Discovered working endpoints stream cleanly into the Scanner tab.

### Scenario C: Android Full-Device VPN Traffic Flow
1. Install and launch Aether on an Android device.
2. Connect using MASQUE H3 or WireGuard. Accept the Android VPN permission prompt.
3. Once connected, open Chrome or another browser on the device.
4. Navigate to `https://1.1.1.1/help` or `https://cloudflare.com/cdn-cgi/trace`.
5. **Verify**:
   - `warp=on` or `warp=plus`.
   - The reported IP address is a Cloudflare Anycast IP, proving all device traffic is successfully captured and routed through the tunnel.
