# Research: Unbounded Scanner Execution & Mobile Terminal Header UI Fixes

**Feature**: `012-fix-android-scanner-timeout-ui`
**Status**: Complete

## 1. Standalone Scanner Timeout Decoupling

### Context & Root Cause
In the Scanner tab, starting a standalone scan currently gets aborted or prematurely terminated because connection watchdog and session timeout logic meant exclusively for the VPN tunnel connection flow is inadvertently applied to scanning:
1. **Android Session State Collision**:
   - When a user starts a scan on Android, `SessionController.scan(...)` calls `setRuntime("connecting", "Scanning IP pool", runner.pid(), null)`.
   - This emits `session://state` with `runtime.status = "connecting"`.
   - In `apps/android/src/hooks/useRuntime.ts`, an active connection watchdog timer (`CONNECT_WATCHDOG_MS = 90_000`) is armed whenever `runtime.status === "connecting"`.
   - After 90 seconds, the watchdog triggers `Connection timed out after 90s; engine stopped.` and calls `invoke("disconnect")`, killing the active scanner process.
   - Furthermore, the UI displays a yellow `● CONNECTING` badge in the header, falsely indicating that a tunnel connection is being negotiated.
2. **Engine Overall Deadline in `prober.rs`**:
   - In `aether/src/prober.rs`, line 334, `AETHER_SCAN_EXHAUSTIVE` previously capped `st.overall_deadline = Duration::from_secs(600)` (10 minutes), while standard scan modes capped it at 15s–120s.
   - For an exhaustive standalone scan probing up to 20,000+ candidate IPs across multiple CIDRs, any artificial deadline causes the prober loop to abort with `[-] scan deadline reached` before the pool is fully probed.

### Decision
- **Decouple `SessionController.scan()` from `runtime.status`**:
  - `SessionController.scan()` will NOT alter `runtime.status` to `"connecting"`.
  - The VPN tunnel state remains `"disconnected"` (or idle) while scanning.
  - The connection watchdog in `useRuntime.ts` will not be armed.
  - In `onExit` inside `SessionController.kt`, if `runner.isScanMode()` is true, exit code handling will not set `runtime.status = "error"` with "Could not find a working gateway". It will simply emit `scan_done` if not already sent and keep `runtime.status = "disconnected"`.
- **Remove Overall Deadline for Standalone Scans in Engine**:
  - In `aether/src/prober.rs`, when `exhaustive` (`AETHER_SCAN_EXHAUSTIVE=1`) is active, set `st.overall_deadline = Duration::MAX`.
  - The prober stream continues until all candidates in the candidate list are exhausted or until the user explicitly cancels (`scan_cancelled()`).
  - Connection flows (`hunt_best_gateway` for tunnels) retain their fast 15s–120s deadlines and 90s watchdogs so tunnel handshakes fail fast as intended.

### Alternatives Considered
- *Add a separate "scanning" status to `runtime.status`*: Rejected. `Status` in `types.ts` is strictly `"disconnected" | "connecting" | "connected" | "error"`. Changing this would require updating status badges, button states, and connection logic across both Android and Desktop. Standalone scanning already has its own dedicated `scanState` (`ScanState.active`) and structured event stream (`scan://event`).
- *Extend the connection watchdog to 60 minutes*: Rejected. A connection watchdog is meant to fail fast (90s) when establishing a tunnel. Extending it would break fast failure for broken tunnel endpoints while still arbitrarily capping scans.

---

## 2. Mobile Terminal Window Header Layout

### Context & Root Cause
In `apps/android/src/components/ActivityTab.tsx`, the terminal header (`.terminal-header-chrome`) contains three child groups:
1. `.terminal-window-controls`: Three colored window dots (`.win-dot`) + title text `aether@android:~# session-log`.
2. `.terminal-center-telemetry`: Status dot + stream count `X shown / Y buffer`.
3. `.terminal-action-buttons`: Optional `Follow` button + `Copy Buffer` button + `Clear` button.

In `apps/android/src/App.css`, `.terminal-header-chrome` uses:
```css
display: flex;
align-items: center;
justify-content: space-between;
gap: 14px;
padding: 12px 18px;
```
On mobile viewports (360px–412px wide):
- Available width inside the chassis is only ~320px–340px.
- The three children require ~380px–420px when laid out horizontally.
- Without `white-space: nowrap` and responsive wrapping rules:
  - Title wraps: `aether@android:~#` breaks onto a second line.
  - Telemetry wraps: each word splits into a 4-line vertical stack (`2` \n `shown` \n `/ 15` \n `buffer`).
  - Action buttons overflow the right edge and get clipped by card boundaries ("Copy Buffe"), while "Clear" is entirely hidden.

### Decision
Implement a responsive CSS Grid layout for `.terminal-header-chrome` on mobile screens (`@media (max-width: 680px)`):
```css
@media (max-width: 680px) {
  .terminal-header-chrome {
    display: grid;
    grid-template-columns: 1fr auto;
    grid-template-areas:
      "controls telemetry"
      "actions actions";
    gap: 8px 10px;
    padding: 10px 12px;
  }
  .terminal-window-controls {
    grid-area: controls;
    min-width: 0;
    white-space: nowrap;
  }
  .terminal-title-text {
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .terminal-center-telemetry {
    grid-area: telemetry;
    white-space: nowrap;
    justify-self: end;
  }
  .stream-count {
    white-space: nowrap;
  }
  .terminal-action-buttons {
    grid-area: actions;
    display: flex;
    justify-content: flex-end;
    gap: 8px;
    width: 100%;
  }
}
```

### Rationale
- **Two Distinct Tiers**:
  - **Tier 1 (Telemetry & Brand)**: Window dots + session title on the left; clean, single-line telemetry counter (`2 shown / 15 buffer`) on the right.
  - **Tier 2 (Actions)**: All action buttons (`Follow`, `Copy Buffer`, `Clear`) span full width with right alignment, guaranteeing they never clip or overflow offscreen.
- **Ellipsis Safety**: If an unusually small screen (320px) or extreme font scaling is used, `.terminal-title-text` uses ellipsis rather than breaking words or corrupting the layout.
- **Desktop Preservation**: Desktops and tablets (>680px) retain the existing single-row flex layout without disruption.

---

## 3. Implementation Verification Strategy

1. **Unit & Build Validation**:
   - Run `npm run build` in `apps/android` to verify TypeScript and Vite bundling.
   - Run `./gradlew compileDebugKotlin` in `apps/android/android` to verify Kotlin compilation.
   - Run `cargo check` in `aether/` to verify Rust engine changes.
2. **Behavioral Testing**:
   - Verify that calling `scan` on Android keeps `runtime.status == "disconnected"` and does not trigger the 90s connection watchdog.
   - Verify that scans can run past 300 seconds without interruption.
   - Verify responsive rendering on mobile viewport sizes (360px, 390px, 412px).
