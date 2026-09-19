# Banners CSS & Component Contract

## CSS Classes for Status Banners

```css
/* Error Banner */
.error-banner {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 10px 16px;
  border-radius: 8px;
  background: rgba(255, 92, 92, 0.08);
  border: 1px solid var(--coral-border);
  color: #ff8585;
  font-size: 12.5px;
  margin-bottom: 12px;
  box-shadow: 0 4px 16px rgba(0, 0, 0, 0.3), var(--inner-highlight);
}

.error-banner span {
  flex: 1;
  min-width: 0;
  line-height: 1.4;
}

.error-banner button {
  background: transparent;
  border: 0;
  color: #ff8585;
  cursor: pointer;
  padding: 4px;
  display: grid;
  place-items: center;
  border-radius: 4px;
  opacity: 0.8;
  transition: opacity 0.15s, background 0.15s;
}

.error-banner button:hover {
  opacity: 1;
  background: rgba(255, 92, 92, 0.15);
}

/* Pinned Peer (Forced Endpoint) Bar */
.pinned-peer-bar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 8px 14px;
  border-radius: 8px;
  background: rgba(56, 189, 248, 0.08);
  border: 1px solid rgba(56, 189, 248, 0.28);
  color: #e0f2fe;
  font-size: 12px;
  margin-bottom: 12px;
  flex-wrap: wrap;
}

.pinned-peer-bar span {
  display: flex;
  align-items: center;
  gap: 6px;
  flex-wrap: wrap;
}

.pinned-peer-bar code {
  font-family: var(--font-mono);
  font-size: 11.5px;
  padding: 2px 7px;
  border-radius: 4px;
  background: rgba(0, 0, 0, 0.45);
  border: 1px solid rgba(56, 189, 248, 0.2);
  color: #38bdf8;
}

.pinned-peer-bar button {
  background: rgba(255, 255, 255, 0.07);
  border: 1px solid rgba(255, 255, 255, 0.12);
  color: #ffffff;
  font-size: 11px;
  font-weight: 550;
  padding: 4px 10px;
  border-radius: 5px;
  cursor: pointer;
  transition: background 0.15s, border-color 0.15s;
}

.pinned-peer-bar button:hover {
  background: rgba(255, 255, 255, 0.14);
  border-color: rgba(255, 255, 255, 0.25);
}

/* Update Banner */
.update-banner {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 10px 16px;
  border-radius: 8px;
  background: var(--emerald-dim);
  border: 1px solid var(--emerald-border);
  color: var(--emerald);
  font-size: 12.5px;
  margin-bottom: 12px;
}
```
