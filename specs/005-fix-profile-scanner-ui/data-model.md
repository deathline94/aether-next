# Data Model: Speed Profile & Scanner Tab Visual Polish

**Feature**: Speed Profile & Scanner Tab Visual Polish & Spatial Architecture (`005-fix-profile-scanner-ui`)  
**Date**: 2026-09-16  

---

## 1. Entities & Structural Definitions

### 1.1 Speed Profile Preset (`SpeedProfile`)
Represents an ergonomic, pre-configured routing optimization preset available on the primary Connection stage.

- **Fields**:
  - `id`: Unique string identifier (`"masque-h3"` | `"masque-h2"` | `"wireguard"` | `"gool"`).
  - `label`: Display title rendered in bold uppercase header (`"MASQUE H3"`, `"MASQUE H2 (Default)"`, `"WireGuard"`, `"Gool"`).
  - `hint`: Monospaced secondary descriptive subtitle explaining the underlying configuration (e.g., `"MASQUE h3 · noise off · balanced scan · system proxy"`).
  - `patch: Partial<Settings>`: Key-value map of configuration changes applied when activated:
    - `protocol`: `"masque"` | `"wireguard"` | `"gool"`
    - `transport`: `"h2"` | `"h3"`
    - `noize`: `"off"` | `"light"` | `"medium"` | `"high"` | `"max"` | `"custom"`
    - `scanMode`: `"turbo"` | `"balanced"` | `"thorough"` | `"stealth"`
    - `ipVersion`: `"v4"` | `"v6"` | `"both"`
    - `routingMode`: `"system-proxy"` | `"proxy-only"` | `"tun"`
- **Derived Active State**:
  - `active = (Object.keys(patch)).every((k) => settings[k] === patch[k])`
- **Validation Rules & Invariants**:
  - When settings are locked (`settingsLocked === true` or tunnel is running), profile buttons are disabled (`disabled={settingsLocked}`).
  - Clicking an already active profile is a no-op (`if (active) return`).
  - Applying a profile resets any pinned peer endpoint (`peer: ""`).

---

### 1.2 Scanner Radar HUD State (`RadarHudState`)
Models the live scanning engine telemetry, radar reticle animation, and primary trigger controls in the dedicated Radar HUD Card.

- **Fields**:
  - `active: boolean`: Whether a background probing operation is actively executing.
  - `busy: boolean`: Whether an IPC command to start/stop the scan is in-flight.
  - `scanState: ScanState`: Real-time scan telemetry emitted from the Rust/Kotlin engine:
    - `active: boolean`: Engine scan running status.
    - `phase: string`: Current operational phase (e.g., `"IDLE"`, `"DISPATCHING"`, `"PROBING"`, `"RESOLVING"`).
    - `mode: string`: Active scan mode profile (`"turbo"` | `"balanced"` | `"thorough"` | `"stealth"`).
    - `scanned: number`: Count of probed IP endpoints.
    - `total: number`: Total candidate endpoint pool size.
    - `working: number`: Count of discovered healthy endpoints responding under the timeout threshold.
    - `concurrency: number`: Active probe worker count.
    - `bestRtt: string | null`: Lowest observed RTT string (e.g. `"14 ms"`).
- **Derived Metrics**:
  - `progressPct = total > 0 ? Math.min(100, Math.round((scanned / total) * 100)) : 0`
- **State Transitions**:
  - `Dormant` (`active: false, scanned: 0`): Sweep reticle dormant, status reads "RADAR ENGINE DORMANT", CTA is "Start Standalone Edge Scan".
  - `Probing` (`active: true`): Reticle spins beam at 2.2s linear infinite, status reads "PROBING POOL (<MODE>)", inline progress bar and worker pill stats displayed, CTA is "Halt Active Probe".
  - `Completed` (`active: false, scanned > 0`): Sweep reticle stops, progress shows 100%, stats chips show final results and best RTT, CTA reverts to "Start Standalone Edge Scan".

---

### 1.3 Scanner Parameters Configuration (`ScannerParamsState`)
Models the tunable parameters for probe dispatch housed in the dedicated Scan Parameters Card.

- **Fields**:
  - `protocol`: Target probe carrier (`"masque-h3"` | `"masque-h2"` | `"wireguard"`).
  - `ipScan`: IP address family pool (`"v4"` | `"v6"` | `"both"`).
  - `concurrency`: Concurrently dispatched probing workers (`number`, bounds: `1..2000`, step: `10`, default: `64`).
  - `timeoutMs`: Per-probe round-trip timeout threshold (`number`, bounds: `100..30000`, step: `100`, default: `2000`).
  - `noize`: Handshake obfuscation profile (`"off"` | `"light"` | `"medium"` | `"high"` | `"max"` | `"custom"`).
- **Validation Rules & Invariants**:
  - When `protocol === "masque-h2"`, noise obfuscation is disabled (`disabled={true}`) and value clamped to `"off"`, because UDP junk frames do not apply to TCP/HTTP2.
  - When `active === true`, all parameter controls (segmented switches, number fields, select dropdowns) MUST be disabled to prevent mid-scan parameter corruption.
  - Concurrency input is clamped between `min: 1` and `max: 2000`.
  - Timeout input is clamped between `min: 100` and `max: 30000` ms.

---

### 1.4 Discovered Gateway Endpoint (`DiscoveredEndpoint`)
Represents an edge gateway responding successfully during the scan.

- **Fields**:
  - `addr: string`: IPv4 or IPv6 socket address of the Cloudflare edge gateway.
  - `rttMs: number`: Round-trip time in milliseconds.
  - `lossRate: number`: Observed packet drop rate (`0.0` to `1.0`).
  - `proto: string`: Protocol identified during handshake (`"MASQUE H3"`, `"MASQUE H2"`, `"WireGuard"`).
- **RTT Tier Classification**:
  - `rttMs < 20`: `rtt-ultra-green` (`"ULTRA FAST"`, `#00f08a`)
  - `20 <= rttMs <= 60`: `rtt-optimal-cyan` (`"OPTIMAL"`, `#38bdf8`)
  - `60 < rttMs <= 100`: `rtt-acceptable-amber` (`"NORMAL"`, `#facc15`)
  - `rttMs > 100`: `rtt-high-coral` (`"HIGH LATENCY"`, `#ff5c5c`)

---

### 1.5 Responsive Viewport State & Layout Breakpoints (`ViewportLayout`)
Governs grid geometry and column distributions across device form factors.

| Viewport Width | Profile Grid Columns (`.profile-grid`) | Parameter Row Layout (`.param-field-block`) | Radar Scope Layout (`.radar-telemetry-banner`) |
|---|---|---|---|
| **Desktop (> 900px)** | `repeat(4, minmax(0, 1fr))` | 2-column flex row (`flex: 1 1 200px`) | Horizontal 2-col (84px scope + meta) |
| **Tablet (681px - 900px)** | `repeat(4, minmax(0, 1fr))` | 2-column flex row (`flex: 1 1 200px`) | Horizontal 2-col (84px scope + meta) |
| **Mobile (381px - 680px)** | `repeat(2, minmax(0, 1fr))` | 1-column stacked (`width: 100%`) | Horizontal or centered stacked |
| **Narrow Mobile (<= 380px)** | `1fr` (single column) | 1-column stacked (`width: 100%`) | Centered stacked scope |
