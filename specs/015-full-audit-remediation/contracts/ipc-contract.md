# Contract: Tauri IPC (shell ⇄ webview)

**Feature**: `015-full-audit-remediation` | Applies to: `apps/desktop/src-tauri/src/lib.rs`, `apps/desktop/src/bindings.ts`, `apps/desktop/src/hooks/*`, `apps/android/src/bridge.ts`

## Purpose

Make the three-way drift between engine, shell and UI structurally impossible. Every finding below is a **current, confirmed** contract defect.

## Rules

**C-IPC-1 — Single source of truth.** `Settings`, `RuntimeState`, `SessionEvent`, `ScanEvent` and every numeric limit are defined once in Rust and exported to TypeScript as `bindings.ts` via `tauri-specta` (`#[derive(specta::Type)]`, `Builder::constant`), generated in CI and checked with `git diff --exit-code`. Hand-editing `bindings.ts` is prohibited. `@tauri-apps/specta` is **not** a dependency (it does not exist on npm); the generated file imports only `@tauri-apps/api/core` and `/event`.

**C-IPC-2 — Typed errors.** Every command returns `Result<T, CommandError>`; `Result<_, String>` is banned (BC-20). `CommandError` carries a machine-readable `kind` plus, for validation failures, the offending **field name**, so the UI can render an inline field error instead of an eternal "Auto-Saving" state (today `useRuntime.ts:134-141` only appends a log line and `SettingsTab.tsx:497,515` keeps reading "Synchronizing changes…").

**C-IPC-3 — Enums, not strings.** `IpVersion`, `ScanMode`, `Protocol`, `TransportKind`, `RoutingMode` are enums on both sides. `IpVersion` has no `Both` member — the UI's `"both"` currently violates `validate_settings` (`lib.rs:533-537`) and hard-breaks Connect while the Scanner's identical label works. `ScanMode` loses the `"thorogh"` typo.

**C-IPC-4 — Shared constants.** `SCAN_MAX_CONCURRENCY = 500` exported once; today `ScannerTab.tsx:236` offers `max={2000}` against `lib.rs:1647` `clamp(1, 500)`, so the UI silently caps out with no explanation.

**C-IPC-5 — Parity both directions.** Every command the UI invokes exists in `generate_handler!`, **and** every registered command is either invoked or explicitly allow-listed. Today 5 of 10 registered commands are never invoked by either frontend (`get_settings`, `get_state`, `is_admin`, `app_info`, `test_connection`); one-directional checking is why this went unseen.

**C-IPC-6 — Fail-closed hydration.** Settings hydration merges over defaults and validates; an unknown status payload falls back (`heroCopy[status] ?? heroCopy.disconnected`) rather than throwing at render. Today `types.ts` declares a narrow union over a Rust `String`, `noUncheckedIndexedAccess` is off, and `ErrorBoundary` wraps only `<App/>` — one unexpected payload white-screens the whole window, sidebar included.

**C-IPC-7 — One write owner.** Settings persistence is serialised through a single owner with a monotonic `saveSeq`; a superseded write's result is ignored. Today concurrent 400 ms debounced writes can let an older payload land last and flip the "Synchronized" indicator for the wrong write.

**C-IPC-8 — No optimistic commits without rollback.** A command that mutates persisted state (e.g. "Connect Direct" pinning a peer) commits only after the shell resolves. Today `useRuntime.ts:188-194` persists optimistically and never rolls back, so a failed connect permanently rewrites the user's protocol and pins a dead peer.

**C-IPC-9 — Free-text fields commit on blur.** `enginePath` and similar paths use local draft state + commit on blur/Enter, validated by existence. The 400 ms debounce alone currently persists half-typed paths (`C:\Users\SLiM\Desk`).

**C-IPC-10 — Field errors are visible in the tab that owns them.** Save rejection renders inside Settings with the field named; a log line in another tab is not an error surface.

## Command surface (target)

| Command | Arguments (typed) | Returns | Notes |
|---|---|---|---|
| `get_settings` | — | `Settings` | **Currently invoked by nobody**; the UI hydrates from another path. Resolve to one hydration route. |
| `save_settings` | `settings: Settings` | `Result<(), CommandError>` | Field-named validation error. |
| `get_state` | — | `RuntimeState` | Includes the new optional measured fields. |
| `is_admin` | — | `bool` | Used to gate TUN UI. |
| `connect` | `settings: Settings` | `Result<(), CommandError>` | Shell-side 90 s watchdog applies (see `engine-event-protocol.md`). |
| `disconnect` | — | `Result<(), CommandError>` | Must report partial failure, never assume success. |
| `test_connection` | `ipVersion, timeoutMs` | `TestOutcome { latency_ms: Option<u32>, … }` | A **typed** latency field, not a string to regex. Today the UI's `/(\d+)\s*ms/` can never match `OK via {via} · ip=… loc=…` (`lib.rs:1623`), so the card falls back to a fabricated `< 45 ms`. |
| `scan` | `… , scan_mode: ScanMode, concurrency: u16, run_id: u64` | `ScanHandle` | `AETHER_SCAN` must stop being hardcoded `"balanced"` (`lib.rs:1669`), which currently makes the "Probe Velocity Profile" setting inert. |
| `stop_scan` | `run_id: u64` | `Result<(), CommandError>` | Cancel is scoped to a run. |
| `app_info` | — | `AppInfo { version, … }` | Owns the version string the update banner compares against. |

## Events

`session://state` (typed `RuntimeState`), `session://log` (`LogEvent`), `scan://event` (`ScanEvent` + `run_id`). Event names are currently correct on both sides — the three names emitted are the three listened to — so the contract work is payload typing and run-scoping, not renaming.

## Android parity

`bridge.ts` must consume the **same generated types** over the `requestId`-correlated async bridge; the two shells already diverge behaviourally (only Android has the 90 s watchdog; only Android merges hydration defaults), which `spec.md` FR-029/BC-22 close via `packages/ui`.

## Verification

| Check | Command | Today |
|---|---|---|
| Types match | regenerate `bindings.ts` → `git diff --exit-code` | no generated file exists |
| Command parity (both ways) | `scripts/verify-invariants --ipc` | **fails** (5 unused commands) |
| No stringly errors | `grep -n 'Result<[^>]*, *String>' src-tauri/src/lib.rs` | fails |
| Enums canonical | Rust `#[test]` asserting each enum's serde names equal the engine's accepted values | fails on `both`/`thorogh` |
| Const parity | generated `SCAN_MAX` used in TS; `max={2000}` absent | fails |
| Gate is real | `--selftest-fail` injects a missing command and an unused command | must exit non-zero |
