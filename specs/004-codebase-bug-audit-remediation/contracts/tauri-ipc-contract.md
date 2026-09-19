# Contract: Tauri IPC & Desktop State Invariants

## 1. Direct Connect Error Handling (`connectToPeer`)
When `connectToPeer` is triggered by the UI:
- **Pre-condition**: Engine is disconnected or connecting.
- **Action**: State updates to `status: "connecting"`. `connect` is invoked.
- **Post-condition on failure**: If `connect` rejects with error $E$:
  - State MUST transition to `status: "error"`, with `detail: String(E)`.
  - Error MUST NOT leave the Power button in spinning/connecting state.

## 2. Settings Auto-Save Filtering (`useRuntime.ts`)
- **Debounce Invariant**:
  Auto-save debounce MUST NOT invoke `save_settings` if:
  - `toSave.httpPort === toSave.socksPort`
  - `toSave.httpPort < 1024` or `toSave.httpPort > 65535`
  - `toSave.socksPort < 1024` or `toSave.socksPort > 65535`
- **Result**: No backend validation errors or error log lines are triggered during intermediate user typing.

## 3. Log Stream Pattern Matching (`lib.rs`)
The Tauri log parser MUST match:
- `socks5 listening on`
- `http proxy listening on`
- `[+] socks5 listening on`
- `[+] http proxy listening on`
as valid `socks_seen` readiness events.
