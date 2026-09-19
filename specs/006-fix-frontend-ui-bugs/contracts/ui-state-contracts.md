# UI & State Contracts: Frontend Bug Fixes & State Remediation

**Feature**: Frontend & UI Visual Polish & State Remediation (`006-fix-frontend-ui-bugs`)  
**Date**: 2026-09-17  

---

## 1. Speed Profile Card Styling & Visual Contract

### 1.1 DOM Hierarchy
```html
<section className="profiles-panel" aria-label="Speed Profile Presets">
  <div className="section-heading">
    <div>
      <p className="panel-eyebrow">PRESETS</p>
      <h3>Speed Profiles</h3>
    </div>
    <Gauge size={20} aria-hidden="true" />
  </div>

  <div className="profile-grid">
    {speedProfiles.map((profile) => (
      <button
        key={profile.id}
        type="button"
        className={`profile-card ${active ? "active" : ""}`}
        disabled={settingsLocked}
        aria-pressed={active}
        onClick={...}
      >
        <div className="profile-card-top">
          <strong>{profile.label}</strong>
          {active && <span className="profile-active-tag">ACTIVE</span>}
        </div>
        <span className="profile-hint">{profile.hint}</span>
      </button>
    ))}
  </div>
</section>
```

### 1.2 CSS Contract (`App.css`)
```css
/* High-Contrast Preset Card Surfaces & Borders */
.profiles-panel {
  margin-top: 16px;
  border: 1px solid rgba(255, 255, 255, 0.12);
  border-radius: 14px;
  background: var(--panel);
  box-shadow: 0 4px 20px rgba(0, 0, 0, 0.35), var(--inner-highlight);
  overflow: hidden;
}

.profile-grid {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 12px;
  padding: 18px 22px;
}

.profile-card {
  display: flex;
  flex-direction: column;
  align-items: stretch;
  text-align: left;
  gap: 8px;
  min-height: 88px;
  padding: 14px 16px;
  border-radius: 10px;
  border: 1px solid rgba(255, 255, 255, 0.14);
  background: #0d131a;
  cursor: pointer;
  user-select: none;
  transition: all 0.18s var(--ease-spring);
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.35), inset 0 1px 0 rgba(255, 255, 255, 0.05);
}

.profile-card:hover:not(:disabled) {
  border-color: rgba(255, 255, 255, 0.26);
  background: #121a24;
  transform: translateY(-1px);
}

.profile-card:active:not(:disabled) {
  transform: scale(0.98);
}

.profile-card.active {
  border-color: var(--emerald);
  background: linear-gradient(135deg, rgba(0, 240, 138, 0.08) 0%, #0d1a14 100%);
  box-shadow: 0 0 16px rgba(0, 240, 138, 0.18), inset 0 1px 1px rgba(0, 240, 138, 0.25);
}

.profile-card-top strong {
  font-size: 13px;
  font-weight: 700;
  color: #ffffff;
  letter-spacing: -0.01em;
}

.profile-active-tag {
  padding: 2px 7px;
  border-radius: 4px;
  background: var(--emerald-dim);
  border: 1px solid var(--emerald-border);
  color: var(--emerald);
  font-size: 9px;
  font-weight: 800;
  letter-spacing: 0.06em;
  font-family: var(--font-mono);
}

.profile-card span,
.profile-hint {
  display: block;
  font-size: 11px;
  color: var(--muted);
  line-height: 1.45;
  font-family: var(--font-mono);
  overflow-wrap: break-word;
}
```

---

## 2. Action-Triggered Log Reset Contract

### 2.1 Invocation Points
Every primary action MUST invoke `clearLogs()` before emitting its initial log event:

1. **Scan Start**:
   ```ts
   const startScan = useCallback(async () => {
     if (busy || active) return;
     clearLogs();
     setEndpoints([]);
     ...
   });
   ```
2. **Tunnel Connect / Disconnect Toggle**:
   ```ts
   const toggleConnection = useCallback(async () => {
     if (busy) return;
     clearLogs();
     if (connected || running) {
       ...
     } else {
       ...
     }
   });
   ```
3. **Direct Endpoint Connection**:
   ```ts
   const handleConnectDirect = useCallback(async (item: DiscoveredEndpoint) => {
     clearLogs();
     connectDirect(item);
   });
   ```
4. **Verification Test**:
   ```ts
   const handleRunTest = useCallback(async () => {
     clearLogs();
     runTest();
   });
   ```

---

## 3. Activity Tab Console Auto-Follow Contract

### 3.1 Lock & Guard Mechanism
In `ActivityTab.tsx`:
```ts
const isProgrammaticScrollRef = useRef(false);

useEffect(() => {
  if (autoScroll && consoleRef.current) {
    isProgrammaticScrollRef.current = true;
    consoleRef.current.scrollTop = consoleRef.current.scrollHeight;
    requestAnimationFrame(() => {
      isProgrammaticScrollRef.current = false;
    });
  }
}, [visibleLogs, autoScroll]);

const handleScroll = () => {
  if (isProgrammaticScrollRef.current) return;
  const el = consoleRef.current;
  if (!el) return;
  const distanceFromBottom = el.scrollHeight - el.scrollTop - el.clientHeight;
  if (autoScroll && distanceFromBottom > 60) {
    setAutoScroll(false);
  } else if (!autoScroll && distanceFromBottom <= 20) {
    setAutoScroll(true);
  }
};
```

---

## 4. Strict Hits Filter Contract

### 4.1 Filter Predicate
```ts
const IP_SOCKET_REGEX = /\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b|\[?[0-9a-fA-F:]{4,}\]?(?::\d+)?/;

export const isHit = (l: LogEntry): boolean => {
  // Reject any message lacking an IP address immediately
  if (!IP_SOCKET_REGEX.test(l.message)) return false;

  // Confirm discovery / selection event context
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

## 5. Scanner Results Protocol Grouping Contract

### 5.1 Protocol Segmentation & Overwrite
```html
<section className="discovered-panel" aria-label="Discovered Endpoints">
  <div className="section-heading">
    <div>
      <p className="panel-eyebrow">TELEMETRY RESULTS</p>
      <h3>Discovered Gateways ({endpoints.length})</h3>
    </div>
    
    <!-- Protocol Filter Tabs -->
    <div className="discovered-proto-dock">
      <button className={protoFilter === "all" ? "active" : ""} onClick={() => setProtoFilter("all")}>
        All ({endpoints.length})
      </button>
      <button className={protoFilter === "masque-h3" ? "active" : ""} onClick={() => setProtoFilter("masque-h3")}>
        MASQUE H3 ({h3Count})
      </button>
      <button className={protoFilter === "masque-h2" ? "active" : ""} onClick={() => setProtoFilter("masque-h2")}>
        MASQUE H2 ({h2Count})
      </button>
      <button className={protoFilter === "wireguard" ? "active" : ""} onClick={() => setProtoFilter("wireguard")}>
        WireGuard ({wgCount})
      </button>
    </div>
  </div>

  <div className="discovered-list">
    {filteredEndpoints.map((item) => (
      ...
    ))}
  </div>
</section>
```
