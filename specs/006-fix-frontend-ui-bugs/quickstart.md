# Quickstart & Verification Guide: Frontend Bug Fixes & State Remediation

**Feature**: Frontend & UI Visual Polish & State Remediation (`006-fix-frontend-ui-bugs`)  
**Date**: 2026-09-17  

---

## 1. Automated Build Verification

Both desktop and Android packages must compile cleanly with zero TypeScript or bundling errors.

### 1.1 Desktop Build Verification
```powershell
cd apps/desktop
npm run build
```
- **Expected Outcome**: `tsc` passes with 0 errors; Vite bundle succeeds in producing production assets in `dist/`.

### 1.2 Android Build Verification
```powershell
cd apps/android
npm run build
npm run sync-www
```
- **Expected Outcome**: `tsc -b` passes with 0 errors; Vite bundle builds cleanly; `sync-www` copies distribution files to Android native assets.

---

## 2. End-to-End Visual & Functional Verification Scenarios

### Scenario 1: Speed Profile High-Contrast Card Visual Verification
1. Launch app on desktop or mobile (`npm run dev` or native launch).
2. Look at the Speed Profiles preset section beneath the hero connection switch.
3. **Verify**:
   - Each preset (`MASQUE H3`, `MASQUE H2`, `WireGuard`, `Gool`) is enclosed in a clearly visible, distinct card with high-contrast borders (`1px solid rgba(255, 255, 255, 0.14)`).
   - Card backgrounds (`#0d131a`) contrast clearly against the surrounding panel.
   - Text does not run together: card titles sit on the header row, separated from the subtitle hints.
   - Active preset has a glowing emerald border (`var(--emerald)`) and `ACTIVE` badge.

### Scenario 2: Action-Triggered Session Log Flushing
1. Open the **Activity Tab**; observe any existing logs from initialization.
2. Go to the **Scanner Tab** and click "Start Standalone Edge Scan".
3. Return to the **Activity Tab**; verify that previous logs were completely cleared, and only the newly started scan logs appear.
4. Go to the **Connection Tab** and toggle "Connect"; return to Activity Tab; verify logs were flushed, beginning cleanly with the connection sequence.

### Scenario 3: Activity Tab Auto-Scroll Following
1. While an engine scan or tunnel connection is streaming logs, observe the log console.
2. **Verify**:
   - The view automatically and smoothly scrolls down, keeping the newest log entry at the bottom visible.
3. Manually scroll up `>60px`.
4. **Verify**:
   - Auto-scroll pauses, and a "Follow" button appears in the terminal controls.
5. Click "Follow" (or scroll back to the very bottom).
6. **Verify**:
   - View snaps to the bottom and auto-scroll resumes immediately.

### Scenario 4: Strict Hits Filter (IPs Only)
1. In the **Activity Tab**, click the "Hits" filter tab pill.
2. **Verify**:
   - Every single displayed line contains a valid IPv4 or IPv6 socket address.
   - Zero lines that merely mention generic words like "gateway" or "probing" are included.
   - If no hits have occurred yet, the "No Records In Selected Filter" empty state is displayed.

### Scenario 5: Scanner Protocol Organization & Overwrite
1. Navigate to the **Scanner Tab**.
2. Run a scan with protocol `MASQUE H3`.
3. Verify discovered endpoints appear with clear protocol tags (`MASQUE H3`), sorted by lowest latency.
4. Run a second scan with protocol `WireGuard` or `MASQUE H2`.
5. **Verify**:
   - Previous scan results are immediately wiped and replaced by the new scan's discoveries.
   - Discovered endpoints can be filtered or viewed by protocol tab (`All`, `MASQUE H3`, `MASQUE H2`, `WireGuard`).
