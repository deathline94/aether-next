# Contract: Engine → Shell Event Protocol (NDJSON) and Liveness

**Feature**: `015-full-audit-remediation` | Applies to: `aether/src/session_event.rs`, `aether/src/quic.rs`, `aether/src/prober.rs`, `apps/desktop/src-tauri/src/lib.rs`, `apps/android/.../SessionController.kt`, `apps/desktop/src/hooks/*`

## Framing

Each line on **stderr** is either human log text or exactly `AETHER_EVENT ` + one JSON object. JSON payloads MUST be produced by `serde_json` and MUST NOT be built by string interpolation.

**Why this rule exists**: `quic.rs:85-88` interpolates `detail`, which carries `String::from_utf8_lossy(header value)` from the **peer** (`:713`), into `"detail":"{detail}"`. The doc comment asserts "must not contain double quotes"; nothing enforces it. A peer can therefore break the JSON or forge sibling fields on the event stream — the only channel the GUI trusts for status.

## Event catalogue

| Event | Emitted today | Contract |
|---|---|---|
| `state` | ✓ | Typed `RuntimeState`; unchanged. |
| `log` | ✓ | Level + message. |
| `scan_start` | ✓ | `total` = candidates **actually** examined under the deadline, plus `run_id`. |
| `scan_progress` | ✓ | `scanned`, `total`, `working` (authoritative), `run_id`. |
| `scan_hit` | ✓ | `addr`, `rtt_ms: Option<u32>`, `protocol`, `transport`, `run_id`. |
| `scan_done` | ✓ | Adds `working` and `best_rtt_ms: Option<u32>` — or the TS-only `working` field is deleted. Currently `session.rs` emits `rtt: String::new()`, producing UI text like `best: 1.1.1.1:443 ()`. |
| `scan_failed` | ✗ | New typed variant with `run_id` and a reason. Today `types.ts:111` declares it, `session_event.rs:48-52` has no failure variant, and `lib.rs:1761-1792` forwards four types with `_ => {}` swallowing the rest — so a scan that dies internally reports "Completed (0 found)". |
| `phase_heartbeat` | ✗ | New: ≤15 s cadence while the engine is alive and working. |
| `ready` (`proxy_ready`, `tunnel_ready`) | ✓ | Gates `connecting`. |
| `endpoint_selected` | ✓ | serde tag is `endpoint_selected`; the Android matcher looks for `"EndpointSelected"`, which never appears. |

## Liveness contract

1. **Heartbeat beats exit.** `watch_child` fires only on `try_wait() -> Ok(Some(_))` (process exit), so a hung-but-alive engine is currently unobservable. The shell treats three missed heartbeats as a stall: kill child, emit `error`.
2. **Connect deadline is shell-side.** 90 s from `connect` entry, stamped against the existing `generation: AtomicU64`; if still `connecting` for *that* generation, kill + `error`. It cannot live in the UI: WebView2 throttles timers in occluded windows, and this app hides to tray on close (`lib.rs:2216`) — which is why Android's `CONNECT_WATCHDOG_MS` exists and desktop's does not.
3. **`Ok(())` is reserved for local shutdown.** A peer-initiated or error-driven close returns `Err` (R4).
4. **Teardown before kill.** The engine holds a duplicate of the parent process handle and waits on it, so a graceful teardown handshake precedes `child.kill()`; grace 5 s → 15 s; the job object stays as backstop (R15).
5. **Bounded drain, not sleep.** Teardown must not depend on spawning `powershell.exe`; see `host-state-contract.md`.

## run_id / generation rules

- Shell mints `run_id` (scan) and `generation` (connect); each is handed to the child as a control token.
- Every emitted event echoes the token; the shell drops non-matching events **before** forwarding; the UI drops them again (defence in depth).
- `stop_scan` cancels a specific `run_id`.
- `stop_scan_child` drains stdout to EOF (bounded) after `cancel` **before** `kill()` — today a late synthetic `scan_done` from the aborted run deactivates a live scan.
- A child killed without a terminal event yields a typed `scan_failed { run_id }`, never a `scan_done` with an empty `addr` that maps to "no working endpoints found".

## Parsing rules (shell and Android)

1. `serde_json::from_str::<SessionEvent>()` — typed, never `Value` + `match ty`.
2. Unknown variant ⇒ counted and logged at `warn!` (never `_ => {}`).
3. Malformed JSON ⇒ one bounded sample per minute, then a counted summary.
4. **Android must not match log prose.** `SessionController.kt:314-326` infers connectivity from `line.contains("handshake successful")` — a string that does not exist in the Rust source — so the guard's trigger is unreachable. Structured events only; fail-closed default `disconnected` (R40).

## Cross-platform mapping

Desktop forwards to `session://state` / `session://log` / `scan://event`. Android emits the same logical names over the async bridge with the same payload types from the same generated source (BC-22). The two UIs must not maintain separate copies of the event union.

## Verification

| Test | Fails today because |
|---|---|
| Peer sends 103 then 200 on the request stream ⇒ `tunnel_ready` | `quic.rs:715-719` treats any non-2xx as fatal. |
| 200 on a non-request stream ⇒ readiness does not latch | `quic.rs:717` positive check is not stream-scoped. |
| Peer-initiated close ⇒ `run()` returns `Err` and a failure is recorded | `quic.rs:627-680` returns `Ok(())`; `session.rs:222-226` records success. |
| Silent child ⇒ `session://state` reaches `error` within 90 s | No desktop watchdog exists. |
| `run_id: 1` hit after scan #2 ⇒ row count unchanged | No run identifier exists on any event. |
| Malformed event ⇒ counter increments | `_ => {}` discards silently. |
| Android: an event stream with no prose still reaches `connected` | Status depends on log substring matching. |
| Forged `detail` containing `","x":"y"` still yields valid JSON | Manual interpolation into the event line. |
