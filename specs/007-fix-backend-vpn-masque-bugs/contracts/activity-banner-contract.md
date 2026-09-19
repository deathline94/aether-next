# Activity Tab Banner CSS Contract

## 1. Required CSS Classes & Properties

```css
.scan-card-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  flex-wrap: wrap;
}

.scan-title {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 13px;
  color: #fff;
}

.scan-title strong {
  font-weight: 700;
  letter-spacing: -0.01em;
}

.phase-pill {
  padding: 2px 7px;
  border-radius: 4px;
  background: var(--emerald-dim);
  border: 1px solid var(--emerald-border);
  color: var(--emerald);
  font-size: 10px;
  font-weight: 700;
  font-family: var(--font-mono);
  letter-spacing: 0.04em;
  text-transform: uppercase;
}

.scan-badges {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}

.scan-badges .badge {
  padding: 2px 8px;
  border-radius: 6px;
  border: 1px solid var(--border-card);
  background: var(--panel-nested);
  color: var(--muted-light);
  font-size: 10.5px;
  font-weight: 600;
  font-family: var(--font-mono);
}

.scan-badges .badge.concurrency {
  border-color: rgba(56, 189, 248, 0.25);
  color: #38bdf8;
  background: rgba(56, 189, 248, 0.08);
}

.scan-badges .badge.working {
  border-color: var(--emerald-border);
  color: var(--emerald);
  background: var(--emerald-dim);
}

.scan-badges .badge.rtt {
  border-color: rgba(250, 204, 21, 0.3);
  color: #facc15;
  background: rgba(250, 204, 21, 0.1);
}

.scan-card-footer {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  font-size: 11px;
  color: var(--muted);
  font-family: var(--font-mono);
}
```
