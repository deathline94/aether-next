# Data Model: Frontend & UI Visual Polish & State Remediation

**Feature**: Frontend & UI Visual Polish & State Remediation (`006-fix-frontend-ui-bugs`)  
**Date**: 2026-09-17  

---

## 1. Entities & Structural Definitions

### 1.1 Speed Profile Preset (`SpeedProfilePreset`)
Represents a predefined performance routing profile available on the primary Connection stage.

- **Fields**:
  - `id: string`: Unique preset identifier (`"masque-h3"` | `"masque-h2"` | `"wireguard"` | `"gool"`).
  - `label: string`: Display title rendered in the bold card header (`"MASQUE H3"`, `"MASQUE H2 (Default)"`, `"WireGuard"`, `"Gool"`).
  - `hint: string`: Monospaced secondary descriptive text explaining the preset parameters.
  - `patch: Partial<Settings>`: Configuration patch applied upon click:
    - `protocol`: `"masque"` | `"wireguard"` | `"gool"`
    - `transport`: `"h2"` | `"h3"`
    - `noize`: `"off"` | `"light"` | `"medium"` | `"high"` | `"max"`
    - `scanMode`: `"balanced"` | `"turbo"` | `"thorough"` | `"stealth"`
    - `ipVersion`: `"v4"` | `"v6"` | `"both"`
    - `routingMode`: `"system-proxy"` | `"proxy-only"` | `"tun"`
- **Derived State**:
  - `active: boolean`: True when all keys in `patch` match the current `Settings` state.
- **Visual Invariants**:
  - Distinct dark surface background (`#0d131a`) contrasting against the obsidian panel.
  - High-contrast border: `1px solid rgba(255, 255, 255, 0.14)` default; `1px solid rgba(255, 255, 255, 0.24)` on hover; `1px solid var(--emerald)` when active.
  - `ACTIVE` phosphor emerald tag badge when active.

---

### 1.2 Log Entry & Filter Model (`LogEntry`, `LogFilter`)
Models diagnostic events streamed from the Tauri/Android background daemon to the Activity console.

- **Fields**:
  - `id: number`: Monotonically increasing sequential identifier.
  - `ts: number`: Epoch millisecond timestamp of log arrival.
  - `level: "info" | "warn" | "error"`: Severity level.
  - `message: string`: Unformatted raw log string.
- **Filter Categories (`LogFilter`)**:
  - `"milestones"`: High-level state transitions and connection events, suppressing verbose per-probe packet noise.
  - `"hits"`: Strictly verified endpoint discoveries containing a valid IP socket address and discovery confirmation.
  - `"errors"`: All entries with `level === "error"` or `level === "warn"`.
  - `"raw"`: Complete, unfiltered log stream.
- **Strict Hits Predicate Specification**:
  ```ts
  const IP_SOCKET_REGEX = /\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b|\[?[0-9a-fA-F:]{4,}\]?(?::\d+)?/;
  const isHit = (l: LogEntry): boolean => {
    if (!IP_SOCKET_REGEX.test(l.message)) return false;
    return (
      l.message.includes("candidate ok") ||
      l.message.includes("Tier-0") ||
      l.message.includes("scan_hit") ||
      l.message.includes("EndpointSelected") ||
      l.message.includes("verified") ||
      l.message.includes("Selected edge") ||
      l.message.includes("best:")
    );
  };
  ```

---

### 1.3 Discovered Scanner Endpoint (`DiscoveredEndpoint`)
Represents an edge gateway responding to background UDP/TCP probe datagrams.

- **Fields**:
  - `addr: string`: Socket address string (`<IP>:<PORT>`).
  - `rtt: string`: Formatted human-readable latency string (e.g. `"24 ms"`).
  - `rttMs: number`: Numerical latency in milliseconds for sorting.
  - `protocol: string`: Carrier protocol used during discovery (`"masque-h3"` | `"masque-h2"` | `"wireguard"`).
- **Sorting Invariant**:
  - Discovered endpoints in state must strictly maintain ascending order by `rttMs` (`(a, b) => a.rttMs - b.rttMs`).

---

### 1.4 Scanner Protocol Grouping Model (`ScannerProtocolGroup`)
Enables organized display of endpoints categorized by protocol.

- **Fields**:
  - `protocolKey: "masque-h3" | "masque-h2" | "wireguard"`: Protocol identifier.
  - `protocolLabel: string`: Display header (e.g. `"MASQUE H3"`, `"MASQUE H2"`, `"WireGuard"`).
  - `endpoints: DiscoveredEndpoint[]`: Sorted list of endpoints matching this protocol.
  - `count: number`: Count of discovered healthy endpoints for this protocol.
  - `bestRtt: string | null`: Lowest observed RTT in this protocol group.
- **Filter State (`ScannerFilterTab`)**:
  - `"all"` | `"masque-h3"` | `"masque-h2"` | `"wireguard"`

---

## 2. State Lifecycle & Transitions

### 2.1 Action-Triggered Log Reset Transition
Whenever a primary user action commences:
1. Trigger event emitted (`startScan`, `toggleConnection`, `connectDirect`, `runTest`).
2. `clearLogs()` invoked synchronously.
3. Log state resets to `[]` and `nextIdRef.current = 0`.
4. The first log emitted is the action initiation event (e.g., `"Starting standalone scan: MASQUE H3..."` or `"Connecting to edge daemon..."`).

### 2.2 Scanner Run Overwrite Transition
Whenever `startScan()` is called:
1. `setEndpoints([])` immediately executes.
2. `scanState` resets to `{ ...initialScanState, active: true, phase: "Starting" }`.
3. Discovered results panel displays 0 entries.
4. Incoming `scan_hit` events populate fresh endpoints without stale residue from previous runs.
