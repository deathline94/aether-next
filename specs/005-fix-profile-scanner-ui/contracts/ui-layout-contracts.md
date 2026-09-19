# UI Layout & Component Contracts: Speed Profile & Scanner Tab

**Feature**: Speed Profile & Scanner Tab Visual Polish & Spatial Architecture (`005-fix-profile-scanner-ui`)  
**Date**: 2026-09-16  

---

## 1. Speed Profile Presets Layout Contract

### 1.1 DOM Placement & Hierarchy
In both `apps/desktop/src/components/ConnectionTab.tsx` and `apps/android/src/components/ConnectionTab.tsx`, the Speed Profiles panel MUST be positioned directly beneath the Hero Connection Stage and above the Telemetry Bento Grid.

```html
<div className="home-view">
  <!-- 1. Master Connection Stage (Hero) -->
  <section className="connection-stage cyber-hero ..."> ... </section>

  <!-- 2. Banners (Error / Update / Pinned Peer) -->
  ...

  <!-- 3. Speed Profile Presets (NEW POSITION: Immediately after Hero & Banners) -->
  <section className="profiles-panel" aria-label="Speed Profile Presets">
    <div className="section-heading">
      <div>
        <p className="panel-eyebrow">PRESETS</p>
        <h3>Speed Profiles</h3>
      </div>
      <Gauge size={20} aria-hidden="true" />
    </div>

    <div className="profile-grid">
      <!-- 4x Profile Cards -->
      <button type="button" className="profile-card [active]" ...>
        <div className="profile-card-top">
          <strong>{profile.label}</strong>
          {active && <span className="profile-active-tag">ACTIVE</span>}
        </div>
        <span className="profile-hint">{profile.hint}</span>
      </button>
    </div>

    {!admin && (
      <p className="profile-note"> ... </p>
    )}
  </section>

  <!-- 4. Telemetry & Metrics Bento Grid -->
  <section className="telemetry-bento" aria-label="Tunnel Telemetry and Subsystem Status">
    ...
  </section>

  <!-- 5. Proxy Endpoints, Verification, About Panels -->
  ...
</div>
```

### 1.2 Speed Profiles CSS Contract (`App.css`)
The following CSS rules MUST be implemented across both desktop and Android:

```css
/* Profiles Container Panel */
.profiles-panel {
  margin-top: 16px;
  border: 1px solid var(--border-card);
  border-radius: 14px;
  background: var(--panel);
  box-shadow: 0 4px 20px rgba(0, 0, 0, 0.25), var(--inner-highlight);
  overflow: hidden;
}

/* 4-Column Responsive Grid */
.profile-grid {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 12px;
  padding: 18px 22px;
}

/* Tactile Hardware Profile Card */
.profile-card {
  display: flex;
  flex-direction: column;
  align-items: stretch;
  text-align: left;
  gap: 6px;
  min-height: 84px;
  padding: 14px 16px;
  border-radius: 10px;
  border: 1px solid var(--border-card);
  background: var(--panel-nested);
  cursor: pointer;
  user-select: none;
  transition: all 0.18s var(--ease-spring);
  box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.04);
}

.profile-card:hover:not(:disabled) {
  border-color: rgba(255, 255, 255, 0.16);
  background: var(--panel-hover);
  transform: translateY(-1px);
}

.profile-card:active:not(:disabled) {
  transform: scale(0.98);
}

.profile-card:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

/* Active Highlighted State */
.profile-card.active {
  border-color: var(--emerald-border);
  background: linear-gradient(135deg, rgba(0, 240, 138, 0.06) 0%, var(--panel-nested) 100%);
  box-shadow: 0 0 18px rgba(0, 240, 138, 0.12), inset 0 1px 1px rgba(0, 240, 138, 0.2);
}

.profile-card-top {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
}

.profile-card-top strong {
  font-size: 13px;
  font-weight: 700;
  color: #ffffff;
  letter-spacing: -0.01em;
}

.profile-active-tag {
  padding: 1px 6px;
  border-radius: 4px;
  background: var(--emerald-dim);
  border: 1px solid var(--emerald-border);
  color: var(--emerald);
  font-size: 9px;
  font-weight: 750;
  letter-spacing: 0.06em;
  font-family: var(--font-mono);
}

.profile-card span,
.profile-hint {
  font-size: 11px;
  color: var(--muted);
  line-height: 1.4;
  font-family: var(--font-mono);
  overflow-wrap: break-word;
}

.profile-note {
  margin: 0;
  padding: 12px 22px;
  border-top: 1px solid var(--border-subtle);
  font-size: 11px;
  color: var(--muted-dark);
  line-height: 1.5;
}
```

---

## 2. Scanner Tab Partitioning Contract

### 2.1 Two-Card Architecture DOM Structure
In `apps/desktop/src/components/ScannerTab.tsx` and `apps/android/src/components/ScannerTab.tsx`, the tab MUST partition into two separate cards:

```html
<div className="scanner-view">
  <!-- CARD 1: Radar HUD & Master Prober Control -->
  <section className="radar-hud-container" aria-label="Edge Radar Prober">
    <div className="section-heading">
      <div>
        <p className="panel-eyebrow">STANDALONE ENGINE PROBER</p>
        <h3>Cloudflare Edge Scanner</h3>
      </div>
      <Radio size={20} className={active ? "spin-icon" : ""} aria-hidden="true" />
    </div>

    <!-- Animated Radar Scope & Scope Meta -->
    <div className="radar-telemetry-banner">
      <div className="radar-radar-scope" aria-hidden="true"> ... </div>
      <div className="radar-scope-meta"> ... </div>
    </div>

    <!-- Live Scan Progress Bar (rendered when active or scanned > 0) -->
    {(scanState.active || scanState.scanned > 0) && (
      <div className="scan-inline-progress"> ... </div>
    )}

    <!-- Master Action CTA Button -->
    <div className="scanner-action-bar">
      <button type="button" className="primary-cta connect|disconnect" ...>
        ...
      </button>
    </div>
  </section>

  <!-- CARD 2: Scan Configuration Parameters -->
  <section className="settings-section tactical-panel" aria-label="Probe Parameters">
    <div className="section-heading">
      <div>
        <p className="panel-eyebrow">PROBE PARAMETERS</p>
        <h3>Engine Handshake Configuration</h3>
      </div>
      <SlidersHorizontal size={20} className="panel-head-icon" aria-hidden="true" />
    </div>

    <!-- Row 1: Target Protocol -->
    <div className="setting-row">
      <div>
        <strong>Target Protocol</strong>
        <span>Service carrier used for probing edge handshakes</span>
      </div>
      <Segmented ... />
    </div>

    <!-- Row 2: IP Family -->
    <div className="setting-row">
      <div>
        <strong>IP Family</strong>
        <span>Address family pool to enumerate and probe</span>
      </div>
      <Segmented ... />
    </div>

    <!-- Row 3: Concurrency & Timeout Structured Field Blocks -->
    <div className="setting-row input-row">
      <div className="param-field-block">
        <label>
          <div className="field-meta">
            <strong>Concurrency (Workers)</strong>
            <span className="field-hint">1–2000 active</span>
          </div>
          <NumberField min={1} max={2000} step={10} value={concurrency} disabled={active} onCommit={setConcurrency} />
        </label>
      </div>

      <div className="param-field-block">
        <label>
          <div className="field-meta">
            <strong>Probe Timeout</strong>
            <span className="field-hint">100–30000 ms</span>
          </div>
          <NumberField min={100} max={30000} step={100} value={timeoutMs} disabled={active} onCommit={setTimeoutMs} />
        </label>
      </div>
    </div>

    <!-- Row 4: Handshake Obfuscation -->
    <div className="setting-row">
      <div>
        <strong>Handshake Obfuscation</strong>
        <span>Anti-DPI noise profile injected during probe</span>
      </div>
      <select className="tactical-select" value={...} disabled={...} onChange={...}>
        <option value="off">Off — Zero Noise</option>
        <option value="light">Light — Low Noise</option>
        <option value="medium">Medium — Default</option>
        <option value="high">High — Stronger</option>
        <option value="max">Max — Highest Entropy</option>
        <option value="custom">Custom — Manual Values</option>
      </select>
    </div>
  </section>

  <!-- CARD 3: Telemetry Results (Discovered Endpoints) -->
  <section className="discovered-panel"> ... </section>
</div>
```

### 2.2 Scanner Parameters CSS Contract (`App.css`)
```css
/* Parameter input block inside flex row */
.param-field-block {
  flex: 1 1 220px;
  min-width: 0;
}

.param-field-block label {
  display: grid;
  gap: 6px;
  width: 100%;
}

.param-field-block .field-meta {
  display: flex;
  align-items: baseline;
  justify-content: space-between;
  gap: 8px;
}

.param-field-block .field-meta strong {
  font-size: 12px;
  font-weight: 650;
  color: #ffffff;
}

.param-field-block .field-hint {
  font-family: var(--font-mono);
  font-size: 10px;
  color: var(--muted-dark);
}

/* Ensure setting-row input-row wraps and distributes cleanly */
.setting-row.input-row {
  display: flex;
  align-items: flex-start;
  gap: 16px;
}
```

---

## 3. Responsive Breakpoints Contract

| Breakpoint | Target Selector | Layout Rules |
|---|---|---|
| `<= 680px` (Mobile) | `.profile-grid` | `grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px; padding: 14px 16px;` |
| `<= 680px` (Mobile) | `.param-field-block` | `flex: 1 1 100%; width: 100%;` |
| `<= 680px` (Mobile) | `.setting-row.input-row` | `flex-direction: column; gap: 14px;` |
| `<= 680px` (Mobile) | `.radar-telemetry-banner` | `grid-template-columns: 72px 1fr; gap: 14px; padding: 14px 16px;` |
| `<= 680px` (Mobile) | `.radar-radar-scope` | `width: 72px; height: 72px;` |
| `<= 380px` (Narrow) | `.profile-grid` | `grid-template-columns: 1fr;` |
| `<= 380px` (Narrow) | `.radar-telemetry-banner` | `grid-template-columns: 1fr; text-align: center; justify-items: center;` |
