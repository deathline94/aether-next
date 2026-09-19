# Research & Architectural Decisions: Frontend & UI Visual Polish

**Feature**: Frontend & UI Visual Polish & State Remediation (`006-fix-frontend-ui-bugs`)  
**Date**: 2026-09-17  

---

## 1. Speed Profile Presets: Visual Contrast & Hardware Card Boundaries

### Context & Problem
In the user's running application screenshot (`media_1789675623086.jpg`), the Speed Profile buttons rendered without visible borders, card surfaces, or spacing boundaries. `MASQUE H3 [ACTIVE]` and `MASQUE H2 (Default)` sat directly adjacent to each other on the same line, and their subtitle hints touched without spacing. This occurred because:
1. Low contrast border and background variables (`rgba(255, 255, 255, 0.07)` on `#090d12`) are nearly invisible on standard mobile and desktop displays.
2. In Tailwind CSS v4, default button resets remove borders and background colors unless explicit high-contrast classes are declared.

### Decision
1. **High-Contrast Surface Palette**:
   - Card background: `#0d131a` (contrasting against `#07090b` canvas and `#090c0f` panel).
   - Default border: `1px solid rgba(255, 255, 255, 0.14)`.
   - Hover border: `1px solid rgba(255, 255, 255, 0.24)` with subtle elevation `transform: translateY(-1px)`.
   - Active border: `1px solid var(--emerald)` with inner glow `inset 0 1px 2px rgba(0, 240, 138, 0.25)` and background `linear-gradient(135deg, rgba(0, 240, 138, 0.08) 0%, #0d1a14 100%)`.
2. **Strict Spacing & Grid Geometry**:
   - Container: `.profile-grid` with `display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; padding: 18px 22px;`.
   - Mobile breakpoint (`<=680px`): `grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px; padding: 14px 16px;`.
   - Narrow breakpoint (`<=380px`): `grid-template-columns: 1fr;`.
3. **Card Content Layout**:
   - `.profile-card`: `display: flex; flex-direction: column; align-items: stretch; gap: 8px; padding: 14px 16px; min-height: 88px;`.
   - `.profile-card-top`: `display: flex; align-items: center; justify-content: space-between; gap: 8px; width: 100%;`.
   - `.profile-hint`: `display: block; font-size: 11px; color: var(--muted); font-family: var(--font-mono); line-height: 1.4; word-break: break-word;`.

### Alternatives Considered
- *Border-only styling without dark surface*: Rejected because dark-on-dark transparent cards lack visual presence and look like plain floating text on varied monitors.
- *Inline segmented toggle*: Rejected because preset descriptions (e.g. `MASQUE h3 · noise off · balanced scan · system proxy`) require sufficient vertical and horizontal room.

---

## 2. Activity Tab: Automatic Log Buffer Flush on Action

### Context & Problem
Currently, session logs accumulate infinitely in `useLogs` across multiple scans, tunnel connections, and diagnostic actions. Users cannot easily discern which logs belong to their most recent action without manually hunting for the "Clear" button.

### Decision
1. **Automatic Action Flushes**:
   - Wire `clearLogs()` into:
     - `startScan()` in `useScanner` (or in the scan trigger handler).
     - `toggleConnection()` in `App.tsx` (clears logs immediately when initiating connect or disconnect).
     - `connectDirect()` in `ScannerTab.tsx` (clears logs before targeting and engaging the endpoint).
     - `runTest()` in `ConnectionTab.tsx` (clears logs before launching path verification).
2. **Pure & Immediate State Reset**:
   - `clearLogs()` resets `logs = []` and resets the sequential counter to ensure clean state and 0 buffer count.
   - Preserves manual "Clear" button in `ActivityTab.tsx` for on-demand user flushing.

### Alternatives Considered
- *Session divider lines instead of clearing*: Rejected because the user explicitly requested: *"after every scan , connect and action please clear all the logs"*.
- *Retaining last 10 logs*: Rejected; a fresh action requires a dedicated, unambiguous console view.

---

## 3. Activity Tab: Reliable Auto-Scroll Following

### Context & Problem
In `ActivityTab.tsx`, programmatic `scrollIntoView` calls asynchronously trigger `onScroll` events where `scrollHeight - el.scrollTop - el.clientHeight` can calculate to `>= 40px` mid-layout, causing `handleScroll` to mistakenly flip `autoScroll` to `false` and disabling autoscroll permanently during high-frequency log streams.

### Decision
1. **Direct Container Scroll Lock**:
   - Instead of relying solely on `logEndRef.current?.scrollIntoView()`, directly assign:
     `consoleRef.current.scrollTop = consoleRef.current.scrollHeight;`
2. **Scroll Feedback Guard**:
   - Use an `isProgrammaticScrollRef` ref flag during programmatic scroll updates to prevent `handleScroll` from misinterpreting daemon-induced scrolling as user scroll gestures.
3. **Ergonomic Follow Button**:
   - When user manually scrolls up (`> 60px` away from bottom), set `autoScroll = false` and display a prominent floating/header "Follow" button.
   - Clicking "Follow" snaps to bottom and re-engages `autoScroll = true`.

---

## 4. Activity Tab: Strict Valid IP Filtering in "Hits"

### Context & Problem
In `useLogs.ts`, the `isHit` predicate currently matches `l.message.includes("gateway")`. As a result, generic log lines such as *"Scanning gateway edge pool..."*, *"Gateway error: unreachable"*, or *"Gateway probing complete"* match as "Hits", polluting the tab with non-hit entries.

### Decision
1. **Strict IP Validation Regex**:
   - Must contain a valid IPv4 address (`\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b`) or IPv6 address (`\[?[0-9a-fA-F:]{4,}\]?(?::\d+)?`).
2. **Hit Context Validation**:
   - In addition to containing an IP, the entry must represent a successful discovery or selection event (`scan_hit`, `candidate ok`, `Tier-0`, `EndpointSelected`, `best:`).
   - Any log entry lacking a valid IP address is strictly excluded from `hits`.

---

## 5. Scanner Tab: Protocol-Categorized Results & Scan Overwrite

### Context & Problem
Discovered endpoints are currently rendered in a single flat list without protocol grouping or filtering. When a user runs a second scan, they want previous results completely overwritten and the findings organized into their respected protocol categories.

### Decision
1. **Clean Overwrite on Scan**:
   - In `startScan()`: `setEndpoints([])` immediately clears previous candidates before the IPC scan invocation.
2. **Protocol Segmentation in Scanner View**:
   - Add a Protocol Filter pill dock in `ScannerTab.tsx`:
     - `All (${endpoints.length})`
     - `MASQUE H3 (${h3Hits})`
     - `MASQUE H2 (${h2Hits})`
     - `WireGuard (${wgHits})`
   - When `All` is active, render endpoints organized by protocol groups with clean section dividers, or allow filtering by clicking a protocol pill.
3. **Endpoint Optimization & Ordering**:
   - Endpoints are always ordered ascending by latency (`a.rttMs - b.rttMs`).
   - Clean tabular display with protocol tag, IP copy button, latency badge, and "Connect Direct" button.

---

## 6. Cross-Platform Parity & Verification
- Symmetrically apply all component and CSS changes to `apps/desktop` and `apps/android`.
- Automated checks:
  - `npm run build` in `apps/desktop`.
  - `npm run build` & `npm run sync-www` in `apps/android`.
