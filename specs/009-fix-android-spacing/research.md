# Phase 0 Research: Android UI Spacing & Mobile Density Overhaul

**Feature Directory**: `specs/009-fix-android-spacing`  
**Date**: 2026-09-18  
**Status**: Completed  

---

## 1. Problem Statement & Root Cause Analysis

On Android devices (and viewports with width $\le 680\text{px}$), users observed that every section and card in the **Settings** and **Scanner** tabs suffered from massive vertical dead space (approximately 300px–400px of empty black gap per setting row). This forced excessive scrolling (6+ viewports) to view a handful of settings, pushed form controls far from their labels, created visual disconnections, and caused text bleed-through when scrolling behind the sticky topbar.

### Root Cause 1: Vertical Axis Inversion in Flexbox
In `apps/android/src/App.css` line 1516:
```css
.setting-row > div:first-child {
  min-width: 0;
  flex: 1 1 240px;
}
```
In desktop wide layout, `.setting-row` has `flex-direction: row`. Here, `flex-basis: 240px` represents horizontal width.
On mobile (`@media (max-width: 680px)`), `.setting-row` changes to:
```css
.setting-row {
  align-items: flex-start;
  flex-direction: column;
}
```
When `flex-direction` switches to `column`, the flex main axis becomes **vertical**. Consequently:
- `flex-basis: 240px` instructs the browser to allocate at least $240\text{px}$ of **vertical height** to the title `div`.
- `flex-grow: 1` instructs the browser to grow vertically if any remaining vertical space exists in the parent card.
- `.setting-row` retains `justify-content: space-between`, which in a column container pushes the title `div` to the absolute top and the form control (`<select>`, `<Segmented>`, `<NumberField>`) to the absolute bottom of the row, opening a 350px–400px empty void.

### Root Cause 2: Missing Mobile Reset for Port Field Blocks
In `apps/android/src/App.css` line 1602:
```css
.port-field-block,
.param-field-block {
  flex: 1 1 200px;
  min-width: 0;
}
```
In `@media (max-width: 680px)`, `.param-field-block` had a responsive reset (`flex: 1 1 100%; width: 100%;`), but `.port-field-block` had **no mobile override**. When `.setting-row.input-row` switched to `flex-direction: column`, each `.port-field-block` (HTTP Port and SOCKS5 Port) insisted on a 200px vertical height basis, creating another ~400px empty gap in the "Proxy Endpoints" card.

### Root Cause 3: Topbar Ghosting & Bleed-Through in Android WebView
In `apps/android/src/App.css` line 426:
```css
.topbar {
  background: rgba(7, 9, 11, 0.82);
  backdrop-filter: blur(24px) saturate(180%);
}
```
On Android WebView (Chromium embedded), hardware-accelerated scrolling layers frequently drop or fail to render CSS `backdrop-filter`. Because the background is `rgba(7, 9, 11, 0.82)` (18% transparent), scrolled card text directly collides with the sticky header text (e.g. "Settings" clashing with "CONFIGURATION LOCAL LISTENERS Proxy Endpoints").

### Root Cause 4: Stacked Redundant Margins & Desktop-Scale Padding
In `apps/android/src/App.css` line 1237:
```css
.proxy-panel, .settings-section, .test-panel, .profiles-panel {
  margin-top: 16px;
}
```
Simultaneously, container views have `display: grid; gap: 16px;`. The grid gap plus the `margin-top: 16px` produced $32\text{px}$ of stacked vertical margin between cards. Furthermore, `.section-heading` and `.setting-row` both had $68\text{px}$ minimum heights and $16\text{px} \times 22\text{px}$ padding designed for desktop mouse interaction.

---

## 2. Research Decisions & Design Matrix

### Decision 1: Mobile Flexbox Reset for `.setting-row`
- **Decision**: In `@media (max-width: 680px)`:
  - Reset `.setting-row > div:first-child` to `flex: 0 0 auto; width: 100%; min-width: 0;`.
  - Update `.setting-row` to `align-items: stretch; flex-direction: column; justify-content: flex-start; gap: 10px; min-height: auto; padding: 14px 16px;`.
- **Rationale**: Setting `flex: 0 0 auto` ensures the label/description container only occupies its natural content height. `justify-content: flex-start` with `gap: 10px` places controls immediately beneath the description. `align-items: stretch` ensures controls fill the card width naturally.
- **Alternatives Considered**:
  - *Hardcoding fixed pixel heights on rows*: Rejected. Fails when user has high accessibility font sizes or when descriptions wrap onto multiple lines.
  - *Refactoring rows to CSS Grid*: Rejected. Unnecessary overhead; flexbox with proper basis reset cleanly solves both horizontal and vertical axis constraints with minimal CSS footprint.

### Decision 2: Mobile Reset for Multi-Field Input Blocks
- **Decision**: Include `.port-field-block` alongside `.param-field-block` in the mobile media query:
  ```css
  .port-field-block,
  .param-field-block {
    flex: 1 1 auto;
    width: 100%;
    min-width: 0;
  }
  .setting-row.input-row {
    flex-direction: column;
    gap: 12px;
  }
  ```
- **Rationale**: Prevents `.port-field-block` from expanding vertically, grouping HTTP and SOCKS5 port controls tightly inside the Proxy Endpoints card.
- **Alternatives Considered**:
  - *Keeping side-by-side 2-column layout on mobile*: Rejected. On portrait screens ($w \le 390\text{px}$), side-by-side number steppers truncate labels and input buttons.

### Decision 3: Opaque Topbar Masking on Mobile
- **Decision**: In `@media (max-width: 680px)`, set:
  ```css
  .topbar {
    height: auto;
    min-height: 56px;
    padding: calc(10px + env(safe-area-inset-top, 0px)) 16px 10px !important;
    background: #07090b !important;
    border-bottom: 1px solid var(--border-card);
  }
  ```
- **Rationale**: An opaque `#07090b` (exact background hex of `--bg-app`) guarantees 100% masking of cards scrolling underneath on Android WebView, without relying on unstable `backdrop-filter`. Decreasing minimum height from $72\text{px}$ to $56\text{px}$ preserves vertical screen area for content.
- **Alternatives Considered**:
  - *High-contrast backdrop filters*: Rejected. Still fails on Android devices where GPU acceleration turns blur transparent.

### Decision 4: Full-Width Mobile Controls (`tactical-select` and `segmented`)
- **Decision**: On mobile viewports:
  ```css
  .tactical-select {
    width: 100%;
    min-width: 0;
  }
  .segmented {
    width: 100%;
  }
  .segmented button {
    flex: 1 1 0;
    min-width: 0;
    text-align: center;
    justify-content: center;
    padding: 0 8px;
  }
  ```
- **Rationale**: Instead of floating with awkward right margins, controls expand to full container width with balanced tab distribution.
- **Alternatives Considered**:
  - *Centering controls with auto margins*: Rejected. Looks unaligned in mobile cards; full-width feels app-native (iOS/Material 3 style).

### Decision 5: Compact Panel Spacing & Margin Cleanup
- **Decision**:
  - In base styles, reset `margin-top: 0` for `.settings-section`, `.proxy-panel`, `.test-panel`, `.profiles-panel` when inside grid containers (`.settings-view`, `.scanner-view`, `.home-view`).
  - In mobile media query, update view container padding:
    ```css
    .home-view, .settings-view, .logs-view, .scanner-view {
      padding: 14px 14px 24px;
      gap: 12px;
    }
    ```
  - Reduce `.section-heading` from `min-height: 68px; padding: 16px 22px;` to `min-height: 48px; padding: 12px 16px;`.
- **Rationale**: Eliminates redundant $32\text{px}$ gaps between cards, compressing the overall page height by over 60%.

### Decision 6: Sticky Tactical Save Dock Layout
- **Decision**: On mobile:
  ```css
  .tactical-save-dock {
    position: sticky;
    bottom: 8px;
    margin-top: 12px;
    padding: 10px 14px;
    border-radius: 10px;
    background: rgba(9, 12, 15, 0.96);
    border: 1px solid var(--border-card);
  }
  ```
- **Rationale**: Floats cleanly above the bottom navigation bar without obscuring inputs, and wraps the sync indicator and status text without vertical bloating.

### Decision 7: Symmetrical Parity in Desktop App
- **Decision**: Apply the same `@media (max-width: 680px)` responsive rules in `apps/desktop/src/App.css`.
- **Rationale**: When desktop users resize the Aether window to mobile portrait dimensions, the UI maintains clean, compact rendering with zero regressions.

---

## 3. Technology Evaluation Summary

| Technique | Status | Pros | Cons |
| :--- | :--- | :--- | :--- |
| `flex: 0 0 auto` on title `div` | **Selected** | Zero extra height, respects natural text height, font-scale safe | Requires responsive media query override |
| `justify-content: flex-start` | **Selected** | Groups control directly below label | None |
| Full-width controls (`flex: 1 1 0`) | **Selected** | Native mobile segment feel, no dead margins | Requires `min-width: 0` for text overflow handling |
| Opaque `#07090b` topbar | **Selected** | Completely prevents text bleed-through in WebView | Slight loss of blur transparency (worthwhile tradeoff) |
| Grid gap reduction (12px) | **Selected** | 50%+ reduction in total page scroll length | None |
