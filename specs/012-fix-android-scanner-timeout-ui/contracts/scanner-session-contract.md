# Contract: Scanner Session & Lifecycle Separation

**Feature**: `012-fix-android-scanner-timeout-ui`
**Status**: Stable

## 1. Native / Engine Invocation Contracts

### `scan` Invocation
Triggered from the frontend when the user starts a standalone scan.

**Arguments**:
```json
{
  "protocol": "masque-h3",
  "ipVersion": "v4",
  "concurrency": 250,
  "timeoutMs": 3000,
  "noize": "off"
}
```

**State Guarantee**:
- Calling `scan` MUST NOT change `session://state` status to `"connecting"`.
- Device VPN service and foreground notification service are NOT started.
- The connection watchdog in the webview is NOT armed.

### `stop_scan` Invocation
Triggered from the frontend when the user stops an active scan.

**Behavior**:
- The engine process receives `cancel\n` on stdin for graceful finalization.
- The scanner state transitions to `phase: "Stopped"`, `active: false`.
- Discovered endpoints are preserved.
- `session://state` remains `"disconnected"` without generating an error alert.

---

## 2. Engine Environment Contract (`Aether` Engine)

| Variable | Connection Mode | Standalone Scanner Mode |
|---|---|---|
| `AETHER_SCAN_ONLY` | Absent / `"0"` | `"1"` |
| `AETHER_SCAN_EXHAUSTIVE` | Absent / `"0"` | `"1"` |
| `AETHER_TUN` | `"1"` (or per settings) | `"0"` |
| `st.overall_deadline` | 15s to 120s | `Duration::MAX` (no deadline limit) |
| `st.target_successes` | 1 to 3 | `0` (unlimited, probe whole pool) |
| `st.early_exit_first` | True (Turbo) / False | `false` |
| `st.quiet_after_first` | 8s to 15s | `Duration::ZERO` (no early cutoff) |
