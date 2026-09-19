# Interface Contract: Tauri IPC & Scanner Events

**Subsystem**: Desktop Frontend (`apps/desktop`) <-> Rust Host (`apps/desktop/src-tauri`)

---

## 1. Tauri Commands

### `test_connection`
- **Input**: `settings: Settings`
- **Behavior**:
  - Validates ports and settings format.
  - If `settings.routing_mode == "tun"`:
    - Performs direct HTTPS GET to `https://www.cloudflare.com/cdn-cgi/trace` via system network stack.
    - Returns string: `OK via TUN · ip=<ip> loc=<loc>`.
  - If `settings.routing_mode == "system-proxy"` or `"proxy-only"`:
    - Performs proxy-routed HTTPS GET via `http://127.0.0.1:<http_port>`.
    - Returns string: `OK via http://127.0.0.1:<port> · ip=<ip> loc=<loc>`.
  - On failure: Returns `Err(String)` describing the error.

### `connect`
- **Input**: `settings: Settings`
- **Behavior**:
  - Spawns engine process with active protocol, transport, routing mode, noise, and optional `peer`.
  - Emits runtime status changes (`connecting` -> `connected` or `error`).

---

## 2. Event: `scan://event` Payload Schema

### Event Types

```typescript
export type ScanEvent =
  | {
      type: "scan_start";
      mode: string;
      total: number;
      concurrency: number;
    }
  | {
      type: "scan_progress";
      scanned: number;
      total: number;
      working: number;
    }
  | {
      type: "scan_hit";
      addr: string;
      rtt: string;
      rttMs: number;
      protocol: string;
    }
  | {
      type: "scan_done";
      scanned: number;
      total: number;
      working: number;
      addr: string;  // Empty string if working == 0
      rtt: string;   // Empty string if working == 0
    }
  | {
      type: "scan_failed";
      message: string;
    };
```

**Frontend Handling Rules**:
- When `type === "scan_done"`:
  - If `working > 0`: sets `phase = "Verified"`, logs `Scan complete — best: <addr> (<rtt>)`.
  - If `working === 0`: sets `phase = "Completed (0 found)"`, logs `Scan complete — no working endpoints found.`.
- Scan summary card remains rendered after `scan_done` and `scan_failed` until a new scan is started.
