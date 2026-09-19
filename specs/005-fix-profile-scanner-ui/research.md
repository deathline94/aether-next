# Research & Architectural Decisions: Speed Profile & Scanner Tab Visual Polish

**Feature**: Speed Profile & Scanner Tab Visual Polish & Spatial Architecture (`005-fix-profile-scanner-ui`)
**Date**: 2026-09-16

---

## 1. Speed Profile Presets: Spatial Hierarchy & Placement

### Context & Problem
In both `apps/desktop/src/components/ConnectionTab.tsx` and `apps/android/src/components/ConnectionTab.tsx`, the Speed Profiles section was placed *below* the entire 12-column Telemetry Bento Grid. Users had to scroll past four detailed diagnostic cards (Gateway Edge Route, Carrier & Cipher, Routing Topology, Core Daemon Subsystem) before reaching the profile presets. Furthermore, `.profiles-panel`, `.profile-grid`, and `.profile-card` classes were completely missing in `App.css`, causing preset buttons to render as unstyled, misaligned default HTML `<button>` elements.

### Decision
1. **Hierarchy Reordering**: Relocate `<section className="profiles-panel">` directly beneath the Hero Connection Stage (`.connection-stage`) and above the Telemetry Bento Grid (`.telemetry-bento`).
2. **Preset Grid Architecture**:
   - Container: `.profiles-panel` with tactical obsidian card surface (`var(--panel)`), micro-borders, and 14px border radius.
   - Grid: `.profile-grid` utilizing CSS grid with `grid-template-columns: repeat(4, minmax(0, 1fr))` on desktop/tablet viewports.
   - Mobile: Responsive breakpoint collapses `.profile-grid` to `grid-template-columns: repeat(2, 1fr)` at `<=680px`, and `1fr` at `<=380px`.
3. **Tactile Hardware Card Styling (`.profile-card`)**:
   - Card layout: `display: flex; flex-direction: column; gap: 6px;` with dark nested background (`#090d12` / `var(--panel-nested)`).
   - Interaction: `scale(0.98)` on active tap, smooth hover border brightening (`rgba(255, 255, 255, 0.16)`).
   - Active State: When active settings match the preset, apply `border-color: var(--emerald-border)`, inner glow `rgba(0, 240, 138, 0.08)`, and an illuminated phosphor emerald `ACTIVE` pill tag.

### Alternatives Considered
- *Inline segmented control in the Hero*: Rejected because 4 profiles with titles and descriptive subtitle hints (e.g. "MASQUE h3 · noise off · balanced scan") cannot fit into a compact inline switch without truncation.
- *Leaving Profiles below Telemetry*: Rejected because speed profile selection is an input action performed before connecting, not a diagnostic output.

---

## 2. Scanner Tab: Modular Panel Partitioning & Input Alignment

### Context & Problem
In `ScannerTab.tsx`, the radar HUD scope, telemetry banner, target protocol, IP family, concurrency/timeout numeric fields, obfuscation selector, live progress bar, and primary scan CTA button were all crammed into a single monolithic card (`.radar-hud-container`). Additionally:
- The Concurrency and Timeout inputs were rendered in an unstyled `<div className="setting-row input-row">` with naked `<label>` tags, causing the labels and number steppers to wrap awkwardly across the flex line with broken gaps.
- The Handshake Obfuscation selector lacked the `.tactical-select` class, rendering as an unstyled generic browser select dropdown.

### Decision
1. **Two-Panel Architecture**:
   - **Card 1: Radar Engine HUD & Controls (`.radar-hud-container`)**:
     - Retains the animated sweep scope reticle, status line, and live probing description.
     - Houses the real-time scan progress bar, worker counts, healthy gateway counter, and best RTT badge (rendered during active scans or completed results).
     - Houses the high-visibility Primary Scan Action CTA ("Start Standalone Edge Scan" / "Halt Active Probe").
   - **Card 2: Scan Configuration Parameters (`.tactical-panel`)**:
     - Section heading: `PROBE PARAMETERS` / `Engine Handshake Configuration`.
     - Target Protocol segmented control (`MASQUE H3`, `MASQUE H2`, `WireGuard`).
     - IP Family segmented control (`IPv4`, `IPv6`, `Dual-Stack`).
     - Structured Concurrency & Timeout input blocks (`.param-field-block`).
     - Handshake Obfuscation selector with uniform `.tactical-select` styling.
2. **Structured Parameter Input Blocks (`.param-field-block`)**:
   - Each input is enclosed in a `.param-field-block` containing a `.field-meta` header (strong title on left, hint on right) and a full-width stepper `NumberField`.
   - Grid/flex layout ensures clean 50/50 horizontal distribution on desktop, stacking vertically on mobile (`<=680px`).

### Alternatives Considered
- *Keeping single monolithic card*: Rejected because mixing live real-time radar sweep output with static form inputs creates an overwhelming, cluttered visual interface.
- *Placing Scan CTA inside Parameters card*: Rejected because the scan trigger directly operates the radar engine and progress bar, so it belongs in the Radar HUD Card.

---

## 3. Cross-Platform Consistency (Desktop & Android)

### Context & Problem
Desktop and Android share identical functional requirements and data models, but have different viewport aspect ratios and interaction patterns (mouse hover vs touch).

### Decision
- Use identical component layouts in both `apps/desktop/src/components/` and `apps/android/src/components/`.
- Ensure all clickable cards and buttons maintain `min-height: 44px` on mobile for touch accessibility.
- Enforce `tabular-nums` on all metrics (workers, timeouts, latencies, percentages).
- Keep CSS variables unified across desktop and mobile `App.css`.

---

## 4. Verification Strategy
- Static check: TypeScript compiles with 0 errors on both desktop and mobile.
- Build check: `npm run build` in `apps/desktop` and `npm run sync-www` in `apps/android`.
- Layout check: Verify responsive grid breakpoints (desktop >900px, tablet 681–900px, mobile <=680px, narrow <=380px).
