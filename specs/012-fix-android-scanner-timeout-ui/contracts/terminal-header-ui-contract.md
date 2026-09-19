# Contract: Mobile Terminal Header UI & Responsive Layout

**Feature**: `012-fix-android-scanner-timeout-ui`
**Status**: Stable

## 1. Terminal Window Header DOM Structure

```html
<header className="terminal-header-chrome">
  <!-- Controls Area -->
  <div className="terminal-window-controls">
    <span className="win-dot red" aria-hidden="true" />
    <span className="win-dot yellow" aria-hidden="true" />
    <span className="win-dot green" aria-hidden="true" />
    <span className="terminal-title-text font-mono">aether@android:~# session-log</span>
  </div>

  <!-- Telemetry Area -->
  <div className="terminal-center-telemetry">
    <span className="status-dot ${status}" aria-hidden="true" />
    <span className="stream-count tabular-nums">
      {filterCounts[logFilter].toLocaleString()} shown / {filterCounts.raw.toLocaleString()} buffer
    </span>
  </div>

  <!-- Action Buttons Area -->
  <div className="terminal-action-buttons">
    <button type="button" className="tactile-terminal-btn follow-btn">...</button>
    <button type="button" className="tactile-terminal-btn">...</button>
    <button type="button" className="tactile-terminal-btn danger">...</button>
  </div>
</header>
```

---

## 2. Layout Specifications & Breakpoints

### Mobile Viewport (`max-width: 680px`)
- **Display**: CSS Grid with designated areas:
  ```css
  grid-template-columns: 1fr auto;
  grid-template-areas:
    "controls telemetry"
    "actions actions";
  gap: 8px 10px;
  padding: 10px 12px;
  ```
- **`.terminal-window-controls`**:
  - `grid-area: controls;`
  - `min-width: 0;`
  - `display: flex; align-items: center; gap: 7px;`
- **`.terminal-title-text`**:
  - `white-space: nowrap;`
  - `overflow: hidden;`
  - `text-overflow: ellipsis;`
  - `font-size: 11px;`
- **`.terminal-center-telemetry`**:
  - `grid-area: telemetry;`
  - `white-space: nowrap;`
  - `justify-self: end;`
  - `display: flex; align-items: center; gap: 6px;`
- **`.stream-count`**:
  - `white-space: nowrap;`
  - `font-size: 10.5px;`
- **`.terminal-action-buttons`**:
  - `grid-area: actions;`
  - `display: flex;`
  - `justify-content: flex-end;`
  - `align-items: center;`
  - `gap: 8px;`
  - `width: 100%;`
- **Touch Target & Bounds Constraints**:
  - Minimum button height: 30px (touch-friendly).
  - All action buttons stay 100% inside card boundaries.
  - Zero word fragmentation or vertical multi-line wrapping on text elements.

---

### Desktop Viewport (`min-width: 681px`)
- **Display**: Single-row flexbox (`justify-content: space-between`).
- Controls, telemetry, and action buttons align horizontally across the card.
