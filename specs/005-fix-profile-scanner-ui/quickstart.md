# Quickstart & Verification Guide: Speed Profile & Scanner Tab Visual Polish

**Feature**: Speed Profile & Scanner Tab Visual Polish & Spatial Architecture (`005-fix-profile-scanner-ui`)  
**Date**: 2026-09-16  

---

## 1. Prerequisites & Setup

Ensure dependencies are installed across desktop and Android frontend packages:

```powershell
# Verify desktop build dependencies
cd apps/desktop
npm install

# Verify Android build dependencies
cd ../android
npm install
cd ../..
```

---

## 2. Automated Build Verification

Both desktop and Android packages must compile cleanly with zero TypeScript or CSS bundling errors.

### 2.1 Desktop Verification
```powershell
cd apps/desktop
npm run build
```
- **Expected Outcome**: Vite production bundle completes successfully with exit code 0 (`dist/` generated with zero errors).

### 2.2 Android Verification
```powershell
cd apps/android
npm run build
npm run sync-www
```
- **Expected Outcome**: Vite production bundle compiles cleanly and `sync-www` synchronizes the distribution assets into `android/app/src/main/assets/public/` with zero errors.

---

## 3. End-to-End Visual & Functional Verification Scenarios

### Scenario 1: Speed Profiles Placement & Visual Hierarchy
1. Launch or run dev server: `npm run dev` in `apps/desktop`.
2. Observe the primary **Connection Tab**:
   - Verify `<section className="profiles-panel">` renders directly beneath the Hero Connection stage (`.connection-stage.cyber-hero`) and **above** the Telemetry Bento Grid (`.telemetry-bento`).
   - Confirm all 4 profile cards (`MASQUE H3`, `MASQUE H2`, `WireGuard`, `Gool`) display inside a uniform 4-column grid (`.profile-grid`).
   - Confirm each card is styled with dark obsidian background (`var(--panel-nested)`), subtle micro-border, and crisp typography with title and hint text.

### Scenario 2: Speed Profile Tactile Feedback & Active State
1. Click on the `MASQUE H3` profile card.
2. Confirm the card activates immediately:
   - Border illuminates in phosphor emerald (`var(--emerald-border)`).
   - Card displays an ambient emerald glow.
   - Phosphor emerald `ACTIVE` pill tag appears in the card header.
   - Activity log emits: `"Applied profile: MASQUE H3 — MASQUE h3 · noise off · balanced scan · system proxy"`.
3. Click on the `WireGuard` profile card:
   - Confirm active indicator transitions smoothly to `WireGuard`.
   - Confirm `MASQUE H3` reverts to its idle subtle border state.

### Scenario 3: Scanner Tab Two-Card Partitioning
1. Navigate to the **Scanner Tab**.
2. Confirm the view is cleanly divided into distinct architectural cards:
   - **Card 1: Radar HUD Card (`.radar-hud-container`)**:
     - Contains rotating sweep scope reticle, status line ("RADAR ENGINE DORMANT"), and primary scan CTA ("Start Standalone Edge Scan").
   - **Card 2: Scan Configuration Card (`.settings-section.tactical-panel`)**:
     - Contains header: `PROBE PARAMETERS` / `Engine Handshake Configuration`.
     - Contains Target Protocol and IP Family segmented selectors.
     - Contains Concurrency and Timeout numeric inputs.
     - Contains Handshake Obfuscation selector styled with `.tactical-select`.
   - **Card 3: Telemetry Results Card (`.discovered-panel`)**:
     - Contains discovered endpoints list or empty status message.

### Scenario 4: Concurrency & Timeout Structured Input Alignment
1. Inspect the Concurrency and Timeout inputs in the Scan Configuration Card:
   - Confirm each field is wrapped in `.param-field-block`.
   - Confirm the header displays a bold label (`Concurrency (Workers)` / `Probe Timeout`) and a right-aligned hint (`1–2000 active` / `100–30000 ms`).
   - Confirm the stepper input fills the block width with zero ugly line wraps, overlapping text, or browser default arrow spinners.

### Scenario 5: Responsive Breakpoints & Mobile Adaptability
1. In developer tools, resize viewport width to `390px` (iPhone / Android standard):
   - Confirm the Speed Profiles grid adapts from 4 columns to a balanced 2-column layout (`repeat(2, minmax(0, 1fr))`).
   - Confirm Concurrency and Timeout fields in the Scanner tab stack vertically (`width: 100%`) with comfortable touch targets (`>= 44px`).
   - Confirm the radar scope and meta header resize gracefully without horizontal scrollbars or clipped text.
2. Resize viewport width to `320px` (narrow mobile):
   - Confirm the Speed Profiles grid collapses into a single column (`1fr`).
   - Confirm all text and controls remain comfortably readable and accessible.
