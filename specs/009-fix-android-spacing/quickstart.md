# Quickstart Validation Guide: Android UI Spacing & Mobile Density

**Feature Directory**: `specs/009-fix-android-spacing`  
**Date**: 2026-09-18  
**Status**: Ready for Validation  

---

## 1. Prerequisites & Setup

Ensure dependencies are installed and the development build environment is ready:

```powershell
# From repository root
cd apps/android
npm run build
```

---

## 2. Validation Scenarios

### Scenario 1: Settings Tab - Android Routing & Topology Scanner Cards
- **Objective**: Verify that single-row cards on mobile no longer have the 400px empty vertical void.
- **Viewport**: Mobile portrait emulation (e.g. 390px × 844px or Android device).
- **Steps**:
  1. Open Aether on Android (or Chrome DevTools with mobile portrait device preset).
  2. Navigate to the **Settings** tab.
  3. Inspect the **Android Routing** card.
- **Expected Outcome**:
  - The "Routing Mode" label and description appear at the top of the card.
  - The `<select>` dropdown (`Full VPN (Android VpnService)`) appears **immediately below** the description with a clean 10px gap.
  - Total card height is approximately 120px–150px (down from ~400px).
  - Inspect the **Topology Scanner** card: "Probe Velocity Profile" dropdown is situated directly under its description.

### Scenario 2: Settings Tab - Proxy Endpoints Multi-Input Block
- **Objective**: Verify that HTTP and SOCKS5 port configuration inputs do not have 200px arbitrary vertical expansion.
- **Viewport**: Mobile portrait emulation (390px × 844px).
- **Steps**:
  1. In the **Settings** tab, scroll down to **Proxy Endpoints** (Local Listeners card).
  2. Observe the layout of the HTTP Proxy Port and SOCKS5 Port steppers.
- **Expected Outcome**:
  - Both port field blocks are stacked vertically with a compact 12px gap.
  - Number steppers and input boxes span the available container width.
  - Zero empty dead space exists between the HTTP port and SOCKS5 port fields.

### Scenario 3: Settings Tab - IP Pool Family Segmented Control
- **Objective**: Verify that segmented buttons span the card width with balanced proportions.
- **Viewport**: Mobile portrait emulation (390px × 844px).
- **Steps**:
  1. In the **Settings** tab, inspect the **IP Pool Family** row.
- **Expected Outcome**:
  - The segmented buttons (`IPv4 Only`, `IPv6 Only`, `Dual-Stack`) span 100% of the card width with even distribution.
  - Button text is centered and comfortably readable.
  - The segmented group sits immediately beneath the description text.

### Scenario 4: Scanner Tab - Handshake Parameters & Radar HUD
- **Objective**: Verify that scanner controls and telemetry fit cleanly on mobile screens without runaway gaps.
- **Viewport**: Mobile portrait emulation (390px × 844px).
- **Steps**:
  1. Navigate to the **Scanner** tab.
  2. Inspect the **Radar HUD** and **Engine Handshake Configuration** card.
- **Expected Outcome**:
  - "Target Protocol" and "IP Family" segmented options sit tightly stacked below their labels.
  - Concurrency Workers and Probe Timeout steppers stack cleanly with balanced touch heights.
  - Action buttons ("Start Standalone Edge Scan") and radar reticle render in compact mobile scale.

### Scenario 5: Sticky Topbar Scroll Bleed-Through Test
- **Objective**: Verify that scrolled content does not bleed through behind the sticky topbar.
- **Steps**:
  1. On either the **Settings** or **Scanner** tab, scroll up and down repeatedly.
  2. Watch the topbar header ("Settings" or "Edge Topology Scanner").
- **Expected Outcome**:
  - The topbar background is solid `#07090b` (completely opaque).
  - No text from cards scrolling underneath bleeds through or clashes with header text.

### Scenario 6: Sticky Save Dock Clearance Test
- **Objective**: Verify that the auto-save dock sits above the bottom navigation bar without clipping.
- **Steps**:
  1. On the **Settings** tab, make a change (e.g. change scan mode or toggle noise).
  2. Observe the floating save dock at the bottom.
- **Expected Outcome**:
  - The dock floats comfortably above the bottom navigation bar (`bottom: 8px`).
  - All status text ("Synchronizing changes…", "All parameters synchronized") is legible and unclipped.

---

## 3. Automated Check Commands

```powershell
# Android app type check & build
cd apps/android
npm run build

# Desktop app type check & build (verify parity & zero regressions)
cd ../desktop
npm run build
```
