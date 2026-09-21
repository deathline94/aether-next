# Contract: UI Design & Behaviour

**Feature**: `015-full-audit-remediation` | Applies to: `packages/ui/*`, `apps/desktop/src/{App.css,index.html,components,hooks}`, `apps/android/src/*`, `apps/desktop/src-tauri/tauri.conf.json`

This contract is **checkable**, not aspirational. Every rule maps to `scripts/verify-invariants` or a unit test. "Fails today" is stated so the gate is proven reachable.

## U-A: Shared source of truth

**U-A1** `packages/ui` (root npm workspace) owns `tokens.css`, types and shared components. Desktop and Android consume it; platform differences are **props**. *Fails today:* no root workspace exists; two stylesheets differ by 359 lines; `ui.tsx`'s `Badge` is styled on Android and unstyled on desktop.
**U-A2** Behavioural parity is a contract item, not a coincidence: desktop gains the connect watchdog; both merge hydration over defaults; both use identical scan-completion wording. *Fails today:* only Android has `CONNECT_WATCHDOG_MS`; only Android merges defaults, so a dropped Rust field throws at desktop render and the app-level boundary white-screens the window.
**U-A3** `bindings.ts` is generated and never hand-edited (see `ipc-contract.md`).

## U-B: Rendered-class integrity

**U-B1** Every `className` token in TSX resolves to a selector in CSS or Tailwind source. *Fails today:* `.metric-icon` is used 4× and defined **0×** in both stylesheets — four bare white 18 px icons with no housing, and the blue/coral/green/yellow card colour-coding is entirely lost. Also undefined: `.btn`, `.btn-secondary`, `.retry-btn`, `.status-text`, `.tactile-badge`.
**U-B2** No selector is defined that nothing renders. *Fails today:* ~9 orphans from the pre-rewrite ActivityTab (`.activity-view`, `.log-line`, `.metrics-grid`, `.status-chip`, `.power-button`, `.save-bar`, …). `.log-line time` was the rule meant to give log timestamps tabular figures.
**U-B3** One component primitive per concept: a single `.panel` with modifiers replaces 8 near-duplicate panel definitions with 3 shadow alphas, of which 6 elements are currently **double-classed** (`settings-section radar-hud-container`, `settings-section tactical-panel`) so only one `margin-top` survives.
**U-B4** Duplicate selectors with conflicting values are removed. *Fails today:* `.tactile-copy-btn` at `App.css:1126` and `:2277` — the later, equal-specificity block kills the emerald hover on all five copy buttons.
**U-B5** Colour literals live only in `tokens.css`; no inline `style={{}}` colour, no Tailwind palette class (`text-red-400`) alongside `--coral`, no second red.

## U-C: Typography

**U-C1** Fonts are self-hosted, same-origin, hashed into `dist/`; no third-party font or stylesheet request from the packaged app. *Fails today:* `index.html` loads Google Fonts, the CSP (`style-src 'self' 'unsafe-inline'; font-src 'self'`) blocks the stylesheet **and** the font origin, and there is no `@font-face` anywhere — the entire typographic identity silently renders as Segoe UI / Consolas, while `npm run dev` (no CSP) leaks a pre-tunnel third-party request from a tool whose premise is that nothing bypasses the tunnel.
**U-C2** Weight tiers must survive the fallback: re-measure `letter-spacing` and weight synthesis against the **actually rendered** font, not the intended one. *Fails today:* `font-synthesis: none` with 550/650/700 tiers collapses to 400 or 700 arbitrarily.
**U-C3** All numeric/live counters use `font-variant-numeric: tabular-nums` and fixed-width tracks. *Partially passes:* `.stat-value`/`.progress-metric`/`.chip-count` carry it, but `.log-line time` is dead and the `64px` time track overflows a 12-hour locale string (`02:15:33 PM` ≈ 69 px), so log rows re-align twice a day. Timestamps become 24-hour.
**U-C4** Minimum rendered size is 11 px. *Fails today:* `.stat-label` 8.5 px, `.nav-pill`/`.switch-action-hint` 9 px, topbar eyebrow 9 px.

## U-D: Contrast

**U-D1** Text ≥4.5:1 (≥3:1 for ≥24 px). **U-D2** State-bearing non-text (borders, indicators, focus rings) ≥3:1 per WCAG 1.4.11. **U-D3** No state is signalled by colour alone; no text sits on a gradient without a solid backdrop.

| Element | fg | bg | ratio | verdict |
|---|---|---|---|---|
| Body copy | `#edf2f5` | `#07090b` | 17.68 | PASS |
| Log timestamps, field hints, stat labels, version bar, empty states, "buffer truncated" | `#47535e` | `#090d12`/`#0d1116`/`#040608` | **2.40–2.58** | **FAIL AA + AAA-large** |
| `.nav-shortcut` | `#47535e` | `#101316` | 2.37 | FAIL |
| `<select>` option list (UA light surface) | `#edf2f5` | `#ffffff` | 1.13 | FAIL — invisible |
| Text selection (UA highlight) | `#d8e2ec` | `#accef7` | 1.24 | FAIL — text vanishes |
| Card boundary `--border-card` | `rgba(255,255,255,.07)` | `#0d1116` | 1.18 | FAIL 1.4.11 |
| Divider `--border-subtle` | `rgba(255,255,255,.05)` | `#0d1116` | 1.12 | FAIL 1.4.11 |
| `.signal-field span` | `rgba(255,255,255,.03)` | `#090c10` | 1.05 | invisible decoration |
| Emerald / coral / amber pills | `#00f08a`/`#ff5c5c`/`#facc15` | dark tints | 5.5–9.9 | PASS |

**U-D4** `--muted-dark` `#47535e` is replaced by a ≥4.5:1 token; the informational tier is not allowed to be dimmer than the decorative tier.
**U-D5** `color-scheme: dark` on `:root`, explicit `option` styling, `::selection` defined. *Fails today:* zero occurrences of any of the three.

## U-E: Edges, scaling and effects

**U-E1** Meaning-bearing edges use `box-shadow: inset 0 0 0 1px var(--edge-interactive)` with **opaque** colours; alpha-over-surface hairlines are prohibited for them. *Fails today:* all three structural border tokens measure 1.05–1.47:1 and a 1 CSS px line antialiases away at Windows 125/150 %, which is the mechanical cause of the reported "borderless, floating, out of place" cards.
**U-E2** No `transition: all` (property lists only). *Fails today:* 17 occurrences, including 5-layer `box-shadow` stacks and `transition: height` on 16 sparkline bars driven by inline styles.
**U-E3** Motion is composited: `transform`/`opacity`, never `height`/`top`/`width`.
**U-E4** `@media (prefers-reduced-motion)` covers every looping animation and is placed so that defining an animation does not depend on it. *Fails today:* the single reduced-motion block names `.spin` and `.power-button`, which do not exist elsewhere, and omits the 7 animations that actually loop (`radar-sweep-spin`, `ping-ring-pulse`, `breathing-glow`, `sparkline-jitter`, `pulse`, `save-sync-pulse`).
**U-E5** **Spinners must animate.** `.spin`/`.spin-icon` get real keyframes outside the reduced-motion query. *Fails today:* they appear **only** inside the reduced-motion block, so while the tunnel is engaging the power button shows a static glyph — a healthy engine reads as hung.
**U-E6** `overflow: hidden` on a container may not clip its own decorative or state-bearing layer. *Fails today:* `.connection-stage` clips the radar ping rings (they scale to ≈246 px in a 290 px stage) into arcs, and `.profiles-panel` clips `.profile-card.active`'s glow.
**U-E7** `scrollbar-gutter: stable` on scrolling lists. *Fails today:* absent against a 6 px custom scrollbar, so the 1fr column narrows 6 px and every row re-wraps at the exact moment a scan starts.

## U-F: Responsive, Android and windowing

**U-F1** `100svh`/`100dvh`, never `100vh`. *Fails today:* 8 `100vh`, 0 `dvh`; `.tactical-activity-view{height:calc(100vh - 76px)}` under-runs a topbar that is 74 px plus the safe-area inset, so the terminal's bottom rows sit behind the 62 px tab bar.
**U-F2** Breakpoints may not coincide with a configured window minimum. *Fails today:* `minWidth: 900` and `@media (max-width: 900px)` — at the minimum legal window size the mobile block applies and hides `.sidebar-bottom`, which contains the app's primary status widget.
**U-F3** `@media (hover: hover) and (pointer: fine)` guards every hover rule. *Fails today:* 27 unguarded hover rules; `.profile-card:hover` sets a **brighter** border than `.profile-card.active`, so after a tap on Android an unselected card looks more selected than the selected one, persistently.
**U-F4** Touch targets ≥24 CSS px (WCAG 2.5.8), 44 px for primary controls. *Fails today:* 28×28 copy buttons, 26 px chips, 24 px toggles, 32 px steppers.
**U-F5** Safe-area insets honoured via `viewport-fit=cover` + `env()`; OS chrome colours match the app. Android additionally needs `enableEdgeToEdge()` and the removal of `statusBarColor`/`navigationBarColor` from `themes.xml`, plus a `values-night/` variant — today a `DayNight` parent with a hardcoded near-black bar paints dark icons on dark, and `colorPrimary #66E3A4` is a different mint from `--emerald #00f08a`.
**U-F6** `maximum-scale=1.0` removed (WCAG 1.4.4); no layout that can overflow horizontally at 360 px; `min-width: 0` on the flex child that actually holds long text — *fails today:* the unclassed wrapper at `ConnectionTab.tsx:261` makes `text-overflow: ellipsis` inert, so `flex-shrink: 0` status chips are pushed out of the card and clipped (visible with an IPv6 endpoint).
**U-F7** Grid layouts must not leave empty cells at any breakpoint (the ≤680 px endpoint rows leave a 36 px notch), and horizontal scrollers must show a fade or affordance (the protocol dock hides its scrollbar entirely).

## U-G: Controls, state and feedback

**U-G1** Every interactive element is a real control with a `type`; no `<div onClick>`. *(Passes today.)*
**U-G2** `:focus-visible` is defined and visible for every control; `:active` defined for every pressable control. *Fails today:* press states exist on 3 of ~20 controls.
**U-G3** Disabled state must not hide the state that matters. *Fails today:* `.profile-card:disabled{opacity:.45}` dims the card marked "ACTIVE" along with the rest while the tunnel runs, so the user cannot tell which profile is in use. Disabled opacity currently takes 6 distinct values; radii 12; white border alphas 15.
**U-G4** A control that cannot act is disabled and explains why. *Fails today:* "Clear (Scan dynamically)" lacks `disabled={settingsLocked}` while `patchSettings` early-returns when locked — a visible button that does nothing, with no toast or error.
**U-G5** Composite widgets match their ARIA role: filter chips become an APG radio group with roving tabindex and arrow keys; `role="tablist"` is reserved for the real tab strip with `aria-controls`/`aria-selected`/`role="tabpanel"`; `tabIndex={-1}` on stepper buttons is removed (mouse-only controls); a wrapped `<label>` and an `aria-label` may not give one control two different names; shortcut handling ignores `ctrlKey/metaKey/altKey`.
**U-G6** Keyboard-reachable scrolling: every `overflow:auto` region gets `tabIndex={0}` + `aria-label`. *Fails today:* the log console and hits list cannot be scrolled by keyboard at all.
**U-G7** Region changes are announced: focus transfers to the panel heading on tab switch, `aria-live="polite"` on hero and save dock, and the raw status enum is not printed next to a friendly label ("DISCONNECTED" in the topbar vs "Standby" in the sidebar).
**U-G8** Per-tab `ErrorBoundary` with a reset key and a working Retry; one bad IPC payload must not take down the window.
**U-G9** Auto-scroll state must not latch: the programmatic-scroll flag resets synchronously, not inside a `requestAnimationFrame` that is throttled when the window is hidden to tray.

## U-H: Data honesty and lifecycle

**U-H1** No metric without a measured source; `null` renders `—`. Deletes `< 45 ms`, `PACKET LOSS 0.0%`, the hardcoded sparkline array, `PORT 1820: HTTP LISTENING / SOCKS5 READY` shown beside `DORMANT`, `END-TO-END TLS 1.3` on the WireGuard path, `V4 DUAL-READY`.
**U-H2** No claim of an action that did not happen: "Cleared", "Synchronized", "Update Now", "ready to update" must each be true at the moment they render. The update banner says "a new version is available" and opens a link; there is no signed updater.
**U-H3** A new scan clears prior results, counters and best-selection; row identity keys on `addr + protocol`; `bestRtt` is derived from the sorted list, not the most recent hit. *Fails today:* `useScanner.ts:106` removes only same-protocol rows, so a WireGuard scan after an H3 scan shows 41 rows with 40 stale ones interleaved.
**U-H4** A large streamed list is windowed (`@tanstack/react-virtual`, `overscan: 8`) with memoised sort/filter; per-event frame time stays under budget at 2 000 rows.
**U-H5** Log lifecycle: the buffer is bounded at the single append site *(passes today)*; logs are not cleared on every connect/disconnect/test — the user must be able to press "Try again" and still see the error they were about to copy; the Hits filter is built from structured `scan_hit` events, not prose substrings. *Fails today:* every hit is counted twice (the human line and the raw JSON line each match), and two clauses can never match (`EndpointSelected` vs serde's `endpoint_selected`; `"Selected edge"` exists nowhere).
**U-H6** Units are labelled and correct (kB vs kb, ms with units, RTT `null` vs 0).

## Acceptance protocol

1. `scripts/verify-invariants --ui` → class resolution, banned patterns, undefined vars, duplicate selectors, contrast from tokens, no remote requests in `dist/`.
2. `scripts/verify-invariants --selftest-fail` → each gate injects its own defect and exits non-zero.
3. Rendered measurement, not computed: screenshots at Windows 100/125/150 %, Android at 360×640 in light and dark, and a 2 000-row scan with a frame-time assertion.
4. axe scan per tab: zero role/attribute violations with the APG widget replacements in place.
