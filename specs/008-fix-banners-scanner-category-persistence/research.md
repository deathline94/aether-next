# Technical Research: Connection Banners, Scanner Inputs & Category Persistence

## Decision 1: Connection Tab Banners CSS Architecture

### Context
In `apps/desktop/src/components/ConnectionTab.tsx` and `apps/android/src/components/ConnectionTab.tsx`, three status banners render between the master toggle switch and the presets panel:
1. `.error-banner`: Displays runtime/scan errors (`runtime.detail`).
2. `.pinned-peer-bar`: Displays forced gateway target (`settings.peer`) with clear button.
3. `.update-banner`: Displays pending client updates.

In previous versions, these elements had no CSS rules in `App.css`. Inline spans and buttons rendered with transparent backgrounds, unpadded text, and colliding elements (e.g. `162.159.198.240:443Clear (Scan dynamically)`).

### Decision
Implement dedicated cyber-tactical CSS rules in both desktop and mobile stylesheets:
- `.error-banner`:
  - `display: flex; align-items: center; justify-content: space-between; gap: 12px;`
  - `padding: 10px 16px; border-radius: 8px;`
  - `background: rgba(255, 92, 92, 0.08); border: 1px solid var(--coral-border); color: #ff8585;`
  - Icon on left (`flex-shrink: 0`), text flex-grow, dismiss button with hover opacity and focus rings.
- `.pinned-peer-bar`:
  - `display: flex; align-items: center; justify-content: space-between; gap: 12px; flex-wrap: wrap;`
  - `padding: 8px 14px; border-radius: 8px;`
  - `background: rgba(56, 189, 248, 0.08); border: 1px solid rgba(56, 189, 248, 0.28); color: #e0f2fe;`
  - Peer address wrapped in `<code>` with monospace font, dark pill background, and distinct margins.
  - Action button styled as tactical secondary pill (`background: rgba(255, 255, 255, 0.08); border: 1px solid rgba(255, 255, 255, 0.12); padding: 4px 10px; border-radius: 5px`).
- `.update-banner`:
  - Emerald accent badge (`var(--emerald-dim)`, `var(--emerald-border)`) with distinct CTA button.

---

## Decision 2: Scanner Tab Stepper Input Sizing & Validation

### Context
In `apps/desktop/src/components/ScannerTab.tsx`:
- `<NumberField min={1} max={2000} step={10} value={concurrency} />`
- The wrapper `.stepper-input-wrapper` was styled `display: inline-flex` inside a block label that expanded 100% of the container width. The stepper buttons (`−` and `+`) and the `clean-number-input` occupied only ~118px on the left, leaving 80% dead space to the right. The `+` button in the center appeared as an accidental vertical divider.
- HTML5 input constraint validation rejected `240` because `(240 - 1) % 10 = 9 != 0`, triggering the browser tooltip: *"Please enter a valid value. The two nearest valid values are 231 and 241"*.

### Decision
1. **Input Step Constraint**:
   - In `NumberField` (`apps/desktop/src/components/ui.tsx` and `apps/android/src/components/ui.tsx`), set `<input type="number" step="any" min={min} max={max} ...>`.
   - This allows users to type any valid integer within `[min, max]` (e.g. 1, 240, 250, 500) without triggering step-lattice mismatch errors.
   - Stepper buttons (`−` / `+`) continue to increment/decrement by `step` (10 for concurrency, 100 for timeout).
2. **Compact Sizing**:
   - Style `.stepper-input-wrapper` with a compact width (`width: 140px;` or `width: fit-content;`).
   - Center the numeric input between the two stepper buttons: `[ − ] [ 240 ] [ + ]`.
   - Eliminates dead space and removes the visual divider artifact.

---

## Decision 3: Category Isolation for Discovered Endpoints

### Context
In `useScanner.ts`, invoking `startScan` currently runs:
```ts
setEndpoints([]);
```
This wiped all endpoints across all protocols. If a user previously scanned WireGuard and found 20 endpoints, then scanned MASQUE H2, all WireGuard endpoints were lost.

### Decision
Scope the endpoint reset on new scans strictly to the category being scanned:
```ts
function isProtocolMatch(endpointProtocol: string, scanProtocol: string): boolean {
  const norm = endpointProtocol.toLowerCase();
  if (scanProtocol === "masque-h3") return norm.includes("h3");
  if (scanProtocol === "masque-h2") return norm.includes("h2");
  if (scanProtocol === "wireguard") return norm.includes("wireguard") || norm.includes("wg");
  return false;
}

// In startScan:
setEndpoints(prev => prev.filter(e => !isProtocolMatch(e.protocol, protocol)));
```
This ensures:
- Scanning MASQUE H2 only clears and updates MASQUE H2 endpoints.
- Previously discovered WireGuard and MASQUE H3 endpoints remain in memory and visible under their respective tabs in the Protocol Dock.

---

## Decision 4: MASQUE H3 Anti-DPI Prober Wiring & Leniency

### Context
On restrictive networks (e.g. Iranian ISPs), MASQUE H3 (QUIC/UDP 443) frequently fails because:
1. `AETHER_QUIC_INITIAL_FRAG` was not passed to the standalone `scan` child process in `apps/desktop/src-tauri/src/lib.rs`, leaving the `ClientHello` unfragmented during scans and vulnerable to SNI filtering.
2. In `aether/src/quic.rs`, `verify_masque` required 2 full data-plane roundtrips within a tight 2-second window. Any packet loss or latency spike causes an otherwise valid QUIC connection to fail.

### Decision
1. Pass `AETHER_QUIC_INITIAL_FRAG` in `apps/desktop/src-tauri/src/lib.rs` during scan commands if enabled in settings (or default to 96 bytes for H3 scans).
2. In `aether/src/quic.rs`: accept 1 confirmed data-plane roundtrip during scan verification (`dp_successes >= 1`) and relax the data-plane timeout window to 3.5 seconds.
3. In the UI, provide an immediate 1-click fallback recommendation to MASQUE H2 if H3 completes with 0 hits.
