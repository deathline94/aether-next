# Interface Contract: Engine Structured Events & Exit Lifecycle

## Purpose
Specifies the event schema and process exit guarantees between the Rust core engine (`aether.exe`) and host application shells (Tauri desktop and Android bridge).

## Event Protocol
All events are emitted to standard output (STDOUT) formatted as:
```
AETHER_EVENT <JSON_PAYLOAD>\n
```
The line MUST be flushed immediately upon writing.

### Error Event Schema
Emitted whenever an unrecoverable condition occurs, including when endpoint discovery fails to find any reachable gateway.

```json
{
  "type": "error",
  "message": "No working gateway found. Try HTTP/2, another scan mode, or a different network."
}
```

### Process Lifecycle Contract on Error
1. When `session::run_session` returns `Err(AetherError::...)`:
   - An `error` event MUST be emitted to STDOUT with a user-actionable message.
   - Any active network sockets, listeners, or netstack handles MUST be closed.
   - The engine process MUST call `std::process::exit(1)` within 150ms of emitting the error.
   - It MUST NOT block on `tokio::io::stdin()` or worker thread teardown.

2. Application Shell Contract:
   - Upon receiving `{"type": "error", "message": "..."}` or upon detecting process exit code `!= 0`:
     - Transition internal status to `"error"`.
     - Set `running = false`.
     - Revert Start/Connect button to idle state.
     - Paint error message banner in UI.
     - Release any held routing or proxy locks so the user can immediately click Connect again.
