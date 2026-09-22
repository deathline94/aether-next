# Tasks: Full-System Audit Remediation & Structural Regression Prevention

**Input**: Design documents from `specs/015-full-audit-remediation/`

**Prerequisites**: plan.md (required), spec.md (required for user stories), research.md (R1–R42), data-model.md, contracts/ (6), quickstart.md

**Tests**: **REQUIRED, and test-first is non-negotiable.** `spec.md` §Validation states every invariant must be observed failing against current code before implementation. Every story phase therefore begins with test tasks that must go red first. `quickstart.md`'s falsifiability protocol is binding: **red on old code → green on new code → guard reachable** (mutate/delete the guard and confirm the test still fails). A fix satisfying only the middle step is not done.

**Organization**: Grouped by user story (US1–US8 from spec.md). Workstream → story mapping: **A**→US1 · **B**→US2+US3 · **C**→US4 · **D**→US5 · **E**→US6+US8 · **F**→US6 · **G**→US7 · **H**→US2+US8.

**Format**: `[ID] [P?] [Story] Description` — `[P]` = parallelizable (different files, no incomplete dependency). Paths are repo-relative.

> **⚠️ Branch note**: `create-new-feature.ps1` did not switch branches; HEAD is `main`. Run `git checkout -b 015-full-audit-remediation` before T001.

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Create the scaffolding later tasks fill in, so no task edits a file that does not exist yet and the gate harness exists before any fix is attempted.

- [x] T001 Create the root npm workspace manifest `package.json` (`workspaces: ["packages/ui","apps/desktop","apps/android"]`, `private: true`) — the repo has **no** root `package.json` today; each app carries its own lockfile, which is how desktop and Android drifted apart behaviourally (only Android has the connect watchdog).
- [x] T002 [P] Scaffold `packages/ui/` with `packages/ui/package.json` (name `@aether/ui`), `packages/ui/tokens.css`, `packages/ui/src/index.ts`, `packages/ui/src/components/` — per plan.md §Structure.
- [x] T003 [P] Create `aether/src/trust.rs` and `aether/src/route_repair.rs` as documented skeletons and register both in `aether/src/lib.rs` (two new modules exist to end the "one policy, three copies" defect; see plan.md Complexity Tracking).
- [x] T004 [P] Create `apps/android/android/app/src/main/java/app/aethernext/Liveness.kt` with a pure `fun decideLiveness(prev: LongArray, now: LongArray, elapsedMs: Long, attempt: Int): Decision` stub returning `Alive` — T203's table tests target this file first.
- [x] T005 [P] Create `scripts/verify-invariants.ps1` and `scripts/verify-invariants.sh` with a `--selftest-fail` flag and a `-- <gate>` dispatcher, initially reporting every gate as not-implemented and **exiting non-zero** (a gate harness that exits 0 by default is the defect class this feature removes).
- [x] T006 [P] Create `scripts/verify-installers.ps1` skeleton: 7z-extract a `*setup.exe`, enumerate embedded `.exe`/`.dll`, **exit non-zero when zero binaries are found** — the fail-closed-on-emptiness rule (contracts/trust-verification-policy.md T-A9) must exist before the real checks are added.
- [x] T007 [P] Create `aether/clippy.toml` and `apps/desktop/src-tauri/clippy.toml` with `disallowed-methods` for `Mutex::lock().unwrap()` in lifecycle paths and `std::env::var`; create `deny.toml` at repo root for `cargo deny` with an initially permissive allow-list documented to shrink over time.
- [x] T008 [P] Create `.github/dependabot.yml` for `github-actions`, `npm` (root + both apps) and `cargo` (both crates).
- [x] T009 [P] Enable quiche's `internal` feature in `aether/Cargo.toml` under `[dev-dependencies]` only, exposing `quiche::test_utils::Pipe` for hostile-input tests — **never** in the release build.
- [x] T010 [P] Create `aether/examples/trust/fixtures/README.md` documenting the signed-elsewhere fixtures (a fixture signed by a different certificate than the pinned one is the only way to prove the pin fires).
- [x] T011 [P] Create `packaging/trust/engine-trust.json`, `packaging/trust/masque-pins.json`, `packaging/trust/README.md` stating the release job regenerates them **after signing** and `build.rs` must never hash the file it ships.
- [x] T012 Verify Phase 1: `scripts/verify-invariants --selftest-fail` exits non-zero with a per-gate "not implemented" report.

**Checkpoint**: Scaffolding exists; the gate harness is present and provably fails closed. No production behaviour changed.

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Cross-cutting substrate every story depends on.

**⚠️ CRITICAL**: No user-story work may begin until this phase completes. The blockers are what the audit proved: one configuration store, one typed contract, one falsifiable gate harness.

- [x] T013 [P] Implement the four always-checkable gates in `scripts/verify-invariants.*`: (a) `grep 'std::env::var("AETHER_'` permitted only in `aether/src/runtime_env.rs`; (b) every `className` token in `apps/desktop/src/**/*.tsx` + `apps/android/src/**/*.tsx` resolves to a selector; (c) no `Result<[^>]*, *String>` in `apps/desktop/src-tauri/src/lib.rs`; (d) no `unwrap`/`expect` on `Mutex::lock` in `apps/desktop/src-tauri/src/lib.rs`. **Expected: all four FAIL today** (baseline in quickstart.md §0).
- [x] T014 [P] Implement `RuntimeConfig` in `aether/src/runtime_env.rs` as the **sole** config reader: `var/set/remove/snapshot/flag/usize_or`, no fallthrough to the process environment after the initial snapshot, `parking_lot::RwLock` with `unwrap_or_else(PoisonError::into_inner)` so a poisoned lock never drops a write, and one truthiness helper where `1/true/yes/on` = true and `0/false/no/off/empty` = false — **presence alone never means true**. Closes the `h3_probe.rs:252`↔`tls.rs:128` split-brain and the inverted `AETHER_WG_NO_DATA_CHECK=0` semantics.
- [ ] T015 Convert every remaining direct reader to `runtime_env`: `aether/src/{session.rs:572,610,873,1255, masque_h2.rs:44,78,187, obfuscation.rs:55, wireguard.rs:429, tls.rs:96, lastconn.rs:33}`. Numeric parse failure must be **reported** (`AETHER_QUIC_MAX_UDP_PAYLOAD=abc` warns "invalid value, using 1350"), never silently defaulted.
- [x] T016 [P] Unify engine packaging (research R42): make `aether/src/main.rs` a thin binary calling `aether::run()`, deleting its private copy of all 30 modules so `aether/tests/*` exercises shipped code; add a build test asserting `aether::` symbols appear in the produced binary.
- [ ] T017 [P] Delete `aether/src/mac_test.rs` (referenced by no `mod`, therefore never compiled — an orphan that reads like live crypto), and remove or `#[cfg(any(test, feature = "dev"))]`-gate `ACL_FAIL_FOR_TEST` in `aether/src/config.rs:127-134`.
- [ ] T018 [P] Introduce the typed error surface in `apps/desktop/src-tauri/src/lib.rs`: `#[derive(thiserror::Error, Serialize, specta::Type)] enum CommandError { kind, field: Option<String>, message }`; convert **all 10** command signatures from `Result<_, String>`. `field` is what lets Settings render an inline error instead of an eternal "Auto-Saving".
- [ ] T019 Wire `tauri-specta` 2.0.0-rc.x + `specta` + `specta-typescript` in `apps/desktop/src-tauri/{Cargo.toml,src/lib.rs}`: derive `specta::Type` on `Settings`/`RuntimeState`/`LogEvent`, add `Builder::constant("SCAN_MAX", 500)`, and add `apps/desktop/src-tauri/src/bin/export-bindings.rs` writing `apps/desktop/src/bindings.ts` **statically** (the default `#[cfg(debug_assertions)] builder.export()` only works in dev, so CI would otherwise never regenerate it).
- [ ] T020 Convert `pump_scan_stream`/`handle_engine_line` in `apps/desktop/src-tauri/src/lib.rs` (`:1571-1610`, `:1761-1792`) from `serde_json::Value` + `match ty` to `serde_json::from_str::<SessionEvent>()` + typed re-emit, so a new engine variant fails the shell's compile instead of falling into `_ => {}`.
- [ ] T021 [P] Define the `ConfigEnvelope` format in `aether/src/config.rs`: magic `AETHERCFG2\n`, `u8` schema version, 12-byte `OsRng` nonce, ChaCha20-Poly1305 with **AAD = canonical absolute path + magic + schema version**; `KeySource::{Shell,DpapiFile,Keystore,None}`. Bind the rule verbatim: *with `KeySource::None`, `save()` writes only non-secret config and refuses secrets.*
- [ ] T022 [P] Create the `EndpointRegistry` actor skeleton in `aether/src/cache.rs` (one owning task, `mpsc` request/response, file as write-behind snapshot only) with existing free functions delegating to it so callers migrate incrementally.
- [ ] T023 [P] Add the counter substrate in `aether/src/netstack.rs` and `aether/src/quic.rs`: `tx_deferred`, `dgram_dropped`, `inbound_dropped`, `frames_lost`, `cache_entries_rejected`, `ignored_offstream_status`, `malformed_event` — every silent-drop path gets a number **before** the paths are fixed, so "did this guard ever fire?" is answerable.
- [ ] T024 Add a diagnostics export action in `apps/desktop/src-tauri/src/lib.rs` + `aether/src/session_event.rs` emitting engine version, resolved binary paths + digests, per-binary trust decisions, the effective `RuntimeConfig` snapshot, route/proxy journal state, and T023's counters.
- [x] T025 [P] Raise the panic hook in `aether/src/main.rs:104-117`: a netstack panic must emit `SessionEvent::Error` + `log::error!` (not `log::debug!`, invisible at the default `info` filter) and match the panic location **exactly**, not by `file().contains("smoltcp")` substring.
- [ ] T026 [P] Confirm `panic = "unwind"` stays in `aether/Cargo.toml:53-59` (it is load-bearing for R11's `catch_unwind` containment) and add a comment tying the setting to the tests relying on it.
- [x] T027 Add the **both-direction** IPC parity gate to `scripts/verify-invariants.*`: extract `generate_handler![…]` (`apps/desktop/src-tauri/src/lib.rs:2234-2245`) and every `invoke("…")` string from both frontends; fail on missing **and** on unused-unlisted. **Fails today**: `get_settings`, `get_state`, `is_admin`, `app_info`, `test_connection` are registered and never invoked.
- [x] T028 Enforce the anti-tautology rule in `scripts/verify-invariants.*`: every gate must register an injection handler so `--selftest-fail` can prove it fires. The repo's three precedent failures: `build.yml:194` verifies the wrong artifact; `build.rs` pins a hash of the file it ships; `AetherVpnServiceTest` asserts on an `AtomicLong`.
- [ ] T029 [P] Migrate `apps/desktop/src/components/*.tsx` and `apps/android/src/components/*.tsx` imports onto `@aether/ui` paths without moving code yet (alias-only in `apps/desktop/vite.config.ts` + `apps/android/vite.config.ts`), so T198 moves files rather than rewiring imports twice.
- [ ] T030 **Checkpoint gate**: run `cargo test -p aether`, `cargo test -p aether-desktop`, `npm test` in both apps, `npx tsc --noEmit` in both, and `scripts/verify-invariants` — the deliberate failures (T013, T027) must be the **only** reds.

**Checkpoint**: One config store, one typed contract, one gate harness, one counter substrate. US1–US8 can now proceed, several in parallel.

---

## Phase 3: User Story 1 — Host Network State Is Never Left Damaged (Priority: P1) 🎯 MVP

**Goal**: Routes, adapter DNS/metrics and the system proxy always return to their pre-Aether state after any termination path — button, crash, `taskkill /F`, uninstall — and a coexisting VPN's byte-identical split-default routes are never touched.

**Independent Test**: quickstart.md §1 — plant a decoy `0.0.0.0/1` on a second interface, zero the journal's identifiers, disconnect: decoy survives, Aether's routes clear. `taskkill /F` the engine, restart in **proxy-only** mode: stale state repaired. Teardown < 500 ms with `powershell.exe` removed from `PATH`.

### Tests for User Story 1 (write first — must fail)

- [ ] T031 [P] [US1] Failing test in `aether/tests/route_journal_scoping.rs`: with `tun_if == 0 && phys_if == 0` (what a `#[serde(default)]` legacy file yields), assert removal never targets `0.0.0.0/1` on unrecorded interfaces. Fails today: `aether/src/tun_win.rs:334-345` emits an unscoped `Get-NetRoute -DestinationPrefix '0.0.0.0/1' | Remove-NetRoute` with no `Where-Object`.
- [ ] T032 [P] [US1] Failing test in `aether/tests/route_teardown_budget.rs`: full teardown in < 500 ms with `powershell.exe` and `route.exe` absent from `PATH`. Fails today: three PowerShell cold starts (1-2 s each) plus `route.exe` exceed the 5 s window at `apps/desktop/src-tauri/src/lib.rs:1551-1571`.
- [ ] T033 [P] [US1] Failing test in `aether/tests/route_repair_unconditional.rs`: repair must run from GUI startup **without** entering TUN. Fails today: `recover_stale_routes()` is reachable only from `aether/src/tun_win.rs:566` (`tun_win::spawn`).
- [ ] T034 [P] [US1] Failing test in `apps/desktop/src-tauri/tests/proxy_restore_test.rs`: `ProxyEnable=1` + `ProxyServer=127.0.0.1:1820` with `proxy-recovery.json` deleted must be swept on restart. Fails today: replay depends solely on that file surviving.
- [ ] T035 [P] [US1] Failing test in `aether/tests/route_pid_liveness.rs`: PID liveness must be an exact column match. Fails today: `aether/src/tun_win.rs:490-496` uses `s.contains(&pid.to_string())`, so "4" matches memory/session columns and a dead holder looks alive.
- [ ] T036 [US1] Failing test in `aether/tests/route_double_instance.rs`: the second instance must refuse to mutate. Fails today: it overwrites the shared journal and its cleanup deletes the first instance's routes.

### Implementation for User Story 1

- [x] T037 [US1] Define `RouteJournal` in `aether/src/route_repair.rs` per data-model.md §5: `version`, `created_at`, `creator_pid`, `creator_process_start_time`, `tun_luid`, `tun_alias`, `tun_if_index`, `phys_luid`, `gateway`, `peer_host`, `entries[{prefix,next_hop,family,proto,valid_lifetime_s}]`, `before{adapter_dns,interface_metric,peer_route_present}` — written **before** any mutation.
- [x] T038 [US1] Implement deletion scoping in `aether/src/tun_win.rs::remove_routes`: identifiers present → by LUID + prefix + next-hop; absent/zero → **only** prefixes whose next-hop equals the recorded tunnel address; unscoped prefix deletion becomes unrepresentable. The comment being removed states legacy files "fall back to the old global behavior rather than leaking routes" — that fallback is the defect.
- [ ] T039 [US1] Replace all route/adapter mutation in `aether/src/tun_win.rs` with `netioapi` FFI via `windows-sys` (`aether/Cargo.toml` + `apps/desktop/src-tauri/Cargo.toml` features): `CreateIpForwardEntry2`/`DeleteIpForwardEntry2`/`GetIpForwardTable2`, `MIB_IPFORWARD_ROW2` keyed on `InterfaceLuid`+`DestinationPrefix`+`NextHop`, `Protocol = MIB_IPPROTO_NETMGMT`. No `powershell.exe`, `route.exe`, `netsh`, `ipconfig`.
- [x] T040 [US1] Call `route_repair::run_unconditionally()` as the **first** action of GUI setup in `apps/desktop/src-tauri/src/lib.rs` (~`:2120`), independent of `routing_mode`, emitting a `RepairRecord`.
  > Landed as an unconditional call at engine startup (`cli::run`, every non-scan launch) instead of in the GUI process: the journal is engine-owned and pid-guarded, so the process that may have died is the one that replays it. `--repair-routes` covers the manual case.
- [x] T041 [US1] Add `aether.exe --repair-routes` and `--repair-proxy` CLI paths in `aether/src/main.rs` so the uninstall flow can reverse state without ever entering TUN mode.
  > `--repair-routes` on the engine; `--repair-proxy` on the desktop app (restores, prints, exits before any window/tray/child exists).
- [x] T042 [US1] Restore adapter state from the journal's `before` block in `aether/src/tun_win.rs`: `InterfaceMetric` reverts to the recorded value (never a default) and DNS comes from `configured_dns_servers()`, removing today's hardcoded `Set-DnsClientServerAddress @('1.1.1.1','1.0.0.1')` at `:137` which the proxy path honours and the TUN path silently ignores.
  DNS half done; the line reference in this task was wrong (`:137` is the gateway script) — the literals were in `configure_adapter_ip`. The tunnel adapter now gets `socks::dns_servers_for_adapter(configured_dns_servers())`: same source of truth as the proxy path, order preserved, duplicates dropped, IPv6 excluded (the adapter's v6 binding is disabled a few lines earlier), and an IPv6-only list still falls back to usable defaults rather than leaving the NIC with no resolver. Both the PowerShell path and the `netsh` fallback use it. `adapter_resolvers_come_from_the_configured_list` lives in `socks.rs`, not `tun_win.rs`, so it runs on every CI OS rather than only on the one platform that can load the driver.
  InterfaceMetric half not done, and the reason is recorded here rather than hidden: the only adapter whose metric we change is the Wintun adapter we created, so resetting *it* to automatic is the correct inverse — `AdapterBefore` describes state the engine never touches, both production writers pass `before: None`, and nothing reads the field. Tracked as T042b.
- [ ] T042b [US1] Decide what `AdapterBefore` in `aether/src/route_repair.rs` is for: either snapshot the physical adapter (DNS servers, `InterfaceMetric`, MTU) before the first mutation and restore exactly those in `reset_adapter_config`, or delete the field. A journal schema that advertises a "before" state and is written as `None` on every path is a guarantee nothing checks — the same shape as a fix guard that cannot be reached.

- [x] T043 [US1] Remove every `let _ = ps(&script)` cleanup discard in `aether/src/tun_win.rs` (`:368` and siblings); cleanup failures become `log::error!` + `SessionEvent::Error` (INV-5).
- [ ] T044 [US1] Set 90 s `ValidLifetime`/`PreferredLifetime` with a 30 s refresh loop in `aether/src/tun_win.rs`, documented as a **backstop**, never the primary teardown mechanism.
  **Not implemented, on purpose — this task would trade a fail-closed failure for a fail-open one.** `New-NetRoute` does accept `-ValidLifetime`/`-PreferredLifetime` (verified against the cmdlet), so the mechanism exists. What does not hold is the premise that expiry is a safe backstop for *these* routes: the prefixes we install are the split defaults (`0.0.0.0/1`, `128.0.0.0/1`) on the tunnel interface. When they are present traffic goes through the tunnel; when they are absent traffic falls back to the physical default gateway. A stale route after a crash therefore black-holes (loud, no leak, and the journal replay at every start already clears it). A route that expires while the tunnel is up — refresh thread starved, laptop asleep, spawn failing inside the grace window — leaks every request while the UI still reads Connected. For a VPN the second is the worse bug.
  To take this up, the change is not "add lifetimes" but "add lifetimes **and** a presence watchdog that re-installs within ~1 s of a miss and treats a failed refresh as a hard tunnel error" — the leak must be impossible before the expiry is enabled. Until someone builds that pair, `recover_stale_routes()` at every engine start (T040/T041) plus the pid-liveness guard is the backstop, and it fails closed.
- [ ] T045 [US1] Move host-mutation ownership to the GUI in `apps/desktop/src-tauri/src/lib.rs` (already elevated in TUN mode at `:1349`); give the engine a `DuplicateHandle` of the parent process handle plus `WaitForSingleObject` so a graceful teardown handshake precedes `child.kill()`; raise the grace window at `:1551-1571` from 5 s to 15 s, keeping the job object as backstop.
  Grace window: done in `e159681` (15 s for both teardown and scan cancel, and a forced kill now always prints what it did and what to run next). Parent-handle watchdog and the ownership move are still open.
- [x] T046 [US1] Reject the `Start-Process -Verb RunAs` elevation path in `apps/desktop/src-tauri/src/lib.rs` and record why in `aether/src/trust.rs` docs: a job member spawned across a token boundary produces a process `AssignProcessToJobObject` cannot control, so an elevated `runas` child escapes kill-on-close and orphans with the proxy ON.
  The path this task asks to reject does not exist: `-Verb RunAs`, `ShellExecute`, `CreateProcessWithTokenW`, `CreateProcessAsUserW` and `LogonUser` appear nowhere in either binary (verified by grep across `aether/` and `apps/`), and TUN asks the *app* to be elevated up front instead of escalating a child mid-session. So the work is the durable half: the reason is written into `aether/src/trust.rs` (a job member created across a token boundary cannot be assigned to the caller's kill-on-close job, which is exactly how a crashed UI leaves a black-holed machine), and gate 13 `no-cross-token-elevation-spawn` [BC-05] now fails CI if anyone adds one, with comment lines exempt so the prohibition itself is not a violation. Self-tested against an injected `RunAs`/`runas`/`CreateProcessWithTokenW` file.
- [x] T047 [US1] Implement the per-instance named-mutex host-mutation guard in `aether/src/route_repair.rs`, reusing the `ProvisionGuard` model (`aether/src/cache.rs:199-320`), replacing substring PID matching (T035).
  Done as `aether/src/host_lock.rs`, wired into `install_routes`, `remove_routes` and `recover_stale_routes`. Windows uses a named mutex and Unix an advisory `flock` on a permanent file, so liveness is the kernel's answer rather than a staleness heuristic: `WAIT_ABANDONED_0` says the holder died, and a crashed process's flock goes with it — which is why the guard cannot wedge the host, and why no mtime window is consulted. Failing to acquire is a refusal to mutate, never a mutation without it; the refused teardown keeps the journal so the next start's pid-guarded replay does the removal.`remove_routes_locked` exists separately because `flock` is per-descriptor and would make a nested acquire fail and silently skip a removal.
  Reuses T083's proven pattern rather than `ProvisionGuard` verbatim, and the substring PID matching it mentions (T035) was already replaced by exact-field matching plus `OpenProcess`/`GetExitCodeProcess`. Two tests: contention from a second thread, and a holder that exits without releasing.
- [x] T048 [US1] Upgrade `ProxySnapshot` in `apps/desktop/src-tauri/src/lib.rs:1938-1954` to snapshot **all five** values with hard-fail reads (no `.unwrap_or(0)`): `ProxyEnable`, `ProxyServer`, `ProxyOverride`, `AutoConfigURL`, per-connection `INTERNET_PER_CONN_PROXY_PAC`; keep `InternetSetOptionW(SETTINGS_CHANGED)` then `(REFRESH)` after **both** directions.
  Four of the five done; the fifth is a registry shape, not an oversight. `ProxySnapshot` now carries `AutoConfigURL`, `enable` clears it while the tunnel owns the proxy, `restore` puts it back, and `verify_readback_values` takes two snapshots instead of three loose parameters so a future field cannot be written-and-never-compared again. The `.unwrap_or(0)` and the two `.ok()` reads are gone: a failed read used to become "there was no proxy", which the restore then honoured by *deleting* a value it had never successfully read. `#[serde(default)]` keeps a recovery file from an older build restorable (`a_recovery_file_from_an_older_build_still_-` `restores`).
  Per-connection `INTERNET_PER_CONN_PROXY_PAC` is not a registry value: it lives in the opaque `Connections\DefaultConnectionSettings` RAS blob and is set through `InternetSetOptionW(INTERNET_PER_CONN_LIST)` on a connection handle this process does not own. Snapshotting it means parsing that blob's versioned layout, which is a task of its own — filed as T048b rather than approximated here.
- [ ] T048b [US1] Per-connection proxy state: read and restore `Connections\DefaultConnectionSettings` (or `InternetQueryOptionW` with `INTERNET_PER_CONN_LIST`) so a machine whose proxy is configured per dial-up/VPN connection is not restored by half. Needs the blob's versioned layout decoded; the value-level snapshot in T048 does not cover it.

- [x] T049 [US1] Mirror the proxy journal to `HKCU\Software\AetherNext\ProxyJournal` and implement the startup orphan sweep in `apps/desktop/src-tauri/src/lib.rs` (INV-6), so AV deleting the file cannot hide an enabled proxy.
  Done. `enable` writes `HKCU\Software\AetherNext\ProxyJournal` (one REG_SZ, the same
      `ProxySnapshot` as JSON plus the writer's pid and time) *before* the recovery file, and
      `restore` clears it only after the values read back. Startup consumes the file first and
      sweeps the mirror only if the file is gone and the recorded pid is dead
      (`decide_sweep`, pure and table-tested) — restoring while another session is live would
      cut a working tunnel, and `holder_alive` errs toward "alive" when `OpenProcess` says
      nothing.
- [x] T050 [US1] Add the 30 s proxy coherence check while connected in `apps/desktop/src-tauri/src/lib.rs`: re-assert or report if a third party changed the setting.
  Done. `watch_child` re-reads the four proxy values every 30 s while connected and compares
      them with `verify_readback_values` against `applied_expectation(port, endpoint)` — the one
      definition the writer itself uses, so the check cannot validate a string nobody wrote. On
      drift it re-asserts and says so in the log; if the re-assert fails it says traffic may be
      leaving unproxied, because the alternative is a Connected badge over raw traffic.
- [x] T051 [US1] Make `disconnect()` in `apps/desktop/src-tauri/src/lib.rs` report partial failure (`disconnect_incomplete`) instead of unconditionally setting `disconnected/Ready`; final state comes from the teardown path that actually ran.
  Done. `cleanup_routing` returns what it could not undo instead of printing it, so a failed system-proxy restore can no longer be reported as `disconnected / Ready` while Windows is still pointed at a dead port; `disconnect` returns `disconnect_incomplete` with the joined reasons, and `watch_child` appends them to the status line rather than swallowing them. Both UIs gained `safeDisconnect`, because the remedy the message recommends (reconnect) must not be blocked by the error that recommends it.
- [x] T051b [US2] `CommandError` serialises as `self.message` alone, so the machine-readable `code` — `disconnect_incomplete`, `anchor_not_published`, `key_service_unavailable`, the field name for a validation failure — never reaches either UI. Contract C-IPC-2 asks for `{code, message, field}`; until that lands, every frontend branch that would distinguish an error has to match on prose. Serialise the struct, update both bridges and the parity gate,
  and keep the string form for anything that still renders an error as text.
  Landed. `CommandError` is `{code, message, field?}` on the wire (`Display` still yields the
  message, so every log line, `emit_log` and `format!` site is unchanged) and `validate_settings`
  names the `Settings` key it rejected in the camelCase the frontend state uses — including splitting
  "custom obfuscation values out of range", one sentence covering three inputs, into one error per
  bound. Both UIs read it through a new `src/ipcError.ts` (`ipcError/errorMessage/errorCode/errorField`),
  which also accepts a bare string or an `Error` because the Android bridge rejects with prose; all
  22 `String(error)` sites go through it. That helper was the load-bearing part, not the serde change:
  with the object shape and no helper, every one of those printed `[object Object]`, which is how a
  "typed error" fix normally ships broken. `SettingsTab` now keeps a rejected save visible in an
  `error-banner`, the status text stops reading "Synchronizing changes…" over a value that will never
  be accepted, and the offending input is marked `aria-invalid` so `field` has a consumer rather than
  being a spare key.
  Tests: `apps/desktop/src-tauri/tests/ipc_error_shape_test.rs` (4), `ipcError.test.ts` in both apps,
  plus one hook test per app asserting a rejected save surfaces code+field and clears on the next edit.
  Falsified rather than assumed: re-adding the string `Serialize` and dropping `Some(field)` turned 3
  of the 4 Rust tests red against the prose shapes. The first version of the hook test was blind in
  exactly the audit's own style — it rejected an HTTP port, which the form never sends, so it stayed
  green without the shell ever being reached; it now uses a value only the shell can refuse.
  Deviations: the contract says `kind`, the struct always said `code` — `code` won and the contract
  line is stale, not the wire. The parity gate needed no new check (`ipc-typed-errors` already forbids
  message-typed commands, and it caught this work on the first run by reading a doc comment as a
  `Result<_, String>` claim). Still open, filed as T051c: the Android envelope's `error` is a plain
  string, so the structure `bridge.ts` now preserves has no producer on that side yet.
- [x] T051c [US2] Emit `{code, message, field}` from the Android native envelope in
  `apps/android/android/app/src/main/java/app/aethernext/AetherBridge.kt` (`error` is a bare message
  string at `:120` today) so the code the TypeScript side preserves has a producer. Map the codes the
  shell already uses; `ipcError.ts`'s prose fallback can stay.
  Done. `BridgeEnvelope.kt` now owns the envelope and the two error kinds: `BridgeError(code, detail,
  field?)` for failures the bridge names itself (`unknown_command`, `scan_failed`, `connect_failed`),
  `SettingRejected(field, detail)` for a refused setting, and `invoke`'s catch chain reports
  `validation` / `encode` / `internal` accordingly instead of one flat string for all of them.
  `SettingRejected` deliberately subclasses `IllegalArgumentException` — that is what
  `SessionController.validateSettings` has always thrown and what the existing 13 `SettingsStoreTest`
  cases catch, so narrowing the type here would have broken callers that did nothing wrong.
  `validateSettings` now names the setting it rejected at all 14 of its guards (it previously named
  none: "Ports must be 1024-65535" and "Invalid noize jitter bounds" each covered three inputs under
  one sentence), in the camelCase key the React state uses, so the same `field` consumer the desktop
  form has can work on Android.
  Tests: `BridgeEnvelopeTest.kt` (6) — envelope shape, `field` omitted when there is none, the
  per-port and per-jitter field names, and that a rejected setting is still an
  `IllegalArgumentException`. Whole Android JVM suite green: 40 tests, 0 failures.
  The Android form does not yet read `field` (`endpointPreset` and `quicInitialFragSize` have no
  input-level consumer, and only the two ports are marked `aria-invalid`); that is the Android UI
  lifecycle work, not this wire change.

- [ ] T052b [P] Add an invariant gate that every `uses:` pin in `.github/workflows/` is a full
  40-character commit SHA (and that one action does not carry two different pins). The
  `engine-windows` job failed three runs in a row with "unable to resolve action
  `dtolnay/rust-toolchain@02cb101e…`", and the message echoed the *truncated* string, so it read as
  the same pin the passing jobs use and was written off as a transient runner fault twice before
  anyone compared the strings: the copy had lost six characters. A typo in a supply-chain pin is
  invisible to review and only shows up as infrastructure flakiness.
- [ ] T052 [US1] **Checkpoint**: T031–T036 green; then re-run each with its new guard deleted and confirm all go red again (quickstart step 3). Record both in the PR — a guard nobody has killed is not a guard.

**Checkpoint**: At this point US1 is fully functional and independently testable: the app can no longer leave the host's network misconfigured by any termination path.

---

## Phase 4: User Story 2 — Binary and Peer Trust Are Proven Before Execution (Priority: P1)

**Goal**: Release TUN works on a clean machine from a CI package; every engine/helper binary is verified before spawn in **every** mode; an independently pinned anchor set replaces the self-referential hash; no verification bypass is compiled into a release build.

**Independent Test**: quickstart.md §2 — release TUN with an engine re-signed by a **different** `CN=deathline94` certificate must be refused; the `AETHER_WINTUN` hijack must fail **and** the trojan's `DllMain` must never run; a release-binary string scan must find no dev-trust branch.

### Tests for User Story 2 (write first — must fail)

- [x] T053 [P] [US2] Failing test in `apps/desktop/src-tauri/tests/elevation_trust_test.rs`: verification must run for the resource-dir, portable-loop and repo-build resolutions in **non-TUN** modes. Fails today: `verify_elevated_binary` is called only at `apps/desktop/src-tauri/src/lib.rs:1373-1379` inside `if routing_mode == "tun"`, and `engine_path` (`:1046-1094`) returns unchecked paths.
  Done. `verify_engine_or_refuse(&executable)` now runs immediately before every `Command::new(&executable)` — connect in any routing mode and the scan child — so the resource-dir, portable-loop and repo-build resolutions of `engine_path` are all checked instead of only the TUN branch. A mode cannot opt out by accident any more: gate 12 (`engine-verified-before-every-spawn` [BC-02]) counts spawn sites against verify calls and also fails if a `verify_elevated_binary(&executable` reappears inside a `routing_mode == "tun"` branch, and it carries a self-test injection that does exactly that. Consequence to know about: a release build with an unpublished anchor now refuses in proxy mode too, not just TUN — which is the 'no bypass compiled in' posture, and the reason T075b's committed-witness gap matters.
- [ ] T054 [P] [US2] Failing test in `aether/tests/trust_anchor_independent.rs`: delete the shipped engine's `EMBEDDED_RELEASE_HASHES` entry and assert verification **fails**. Fails on two counts today: `apps/desktop/src-tauri/build.rs:38-53` hashes the file it ships (always matches), and `resources/*.exe` is gitignored so a clean checkout hashes nothing and emits no entry — the "missing digest is an error" guard is unreachable.
- [x] T055 [P] [US2] Failing test in `aether/tests/wintun_resolution.rs`: `AETHER_WINTUN` pointing at a foreign DLL ⇒ connect fails and the DLL marker file is never created. Fails today: `aether/src/tun_win.rs:25-47` reads the env var and a CWD-relative path in an **elevated** process.
  Test written and green: `tun_win::wintun_resolution_tests` (3 cases) — an
      `AETHER_WINTUN` plant in a temp directory is never resolved, the candidate is never read
      or written, only a plain `wintun.dll` inside the install roots is accepted, and the
      no-handoff fallback can only be the beside-exe copy whose error no longer advertises the
      removed override. The first version compared raw paths and stayed green with the env read
      put back — Windows 8.3 short names make a temp path and its canonical form differ as
      strings — so it now compares canonicalised paths, and was re-checked to fail against the
      old behaviour.
- [x] T056 [P] [US2] Failing test in `aether/tests/tls_pin_chain.rs`: a self-signed leaf whose SPKI **is** pinned but whose pin has expired must be rejected. Fails today: `aether/src/tls.rs:35-48` discards the precomputed `_ok`, so no chain building, signature check, validity check or hostname check happens at all.
  Test written and green: `aether/tests/tls_pin_chain.rs`, six cases against certificates
      generated in-process (expired leaf with a matching pin, not-yet-valid leaf, expired pin,
      unpinned key, valid baseline). The decision is now `tls::accept_pinned_leaf`, extracted so
      it can be tested without an edge to dial; removing the validity check turns two of the six
      red. The `install_pin_verification` path is also covered: an unknown host and an empty pin
      set are refusals, not fallbacks.
- [ ] T057 [P] [US2] Failing compile-fail test in `aether/tests/no_release_bypass.rs` that `VerifyPolicy::Insecure` is unnameable in release, plus a release-binary string grep for a dev-trust branch.
- [x] T058 [P] [US2] Failing test in `aether/tests/spki_pin_per_host.rs`: a pin issued for host A must not authenticate host B. Fails today: `MASQUE_PINS` (`aether/src/consts.rs:17-22`) is a global 2-entry set and `aether/src/masque_h2.rs:133` adds `set_verify_hostname(false)`.
  Covered by the last two cases above (per-host pin sets are enforced by lookup, a host with
      no set is an error rather than a pass) and by `masque_h2`'s per-set
      `require_hostname`, which is data-driven from `masque-pins.json` rather than a global
      `set_verify_hostname(false)`. The committed file still carries `require_hostname: false`
      for the two Cloudflare edges for the reason already recorded in `packaging/trust/README.md`:
      the peer is dialled by IP, and flipping it needs a live handshake to confirm which digest
      belongs to which SNI.
- [x] T059 [US2] Failing CI-fixture test that `scripts/verify-installers.ps1` exits non-zero for an unsigned build **and** when it extracts zero binaries. Fails today: `.github/workflows/build.yml:194-207` checks only the outer `setup.exe`, recording a pass while the installed GUI exe is unsigned.
  Done as `scripts/selftest-verify-installers.ps1`, run on every push by the new `installer-verifier`
  job in `.github/workflows/ci.yml`. Three fixtures, each checked red before the gate was believed:
  a package directory holding nothing checkable exits non-zero with "extracted zero PE files" (a gate
  that finds nothing must not go green), an unsigned `aether.exe` exits non-zero with both "the anchor
  still carries a placeholder digest" and "unsigned", and the committed `packaging/wintun.dll` is the
  positive control that proves the same code path can say *pass* — without it, a verifier that refused
  everything would also pass this test.

### Implementation for User Story 2

- [ ] T060 [US2] Implement the ordered binary-trust pipeline in `aether/src/trust.rs` (contract T-A3): resolve canonical path → file SHA-256 → leaf cert hash + SPKI hash → chain anchored **at the pinned leaf** → `CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_AUTHENTICODE)` → spawn.
- [x] T061 [US2] Make verification unconditional across every branch in `apps/desktop/src-tauri/src/lib.rs::engine_path` (`:1046-1094`) and `connect` (`:1368`), including custom `enginePath` and `AETHER_ENGINE`.
- [x] T062 [US2] Narrow the trusted root: remove `exe.parent().parent()` from the allowed roots in `apps/desktop/src-tauri/src/lib.rs:762-787` — for perMachine that is `C:\Program Files`, for portable a user-writable extraction directory, while the child is handed the DPAPI master key.
  Done. `allowed_binary_roots` replaces "the exe's directory and its parent": the roots are
  now the exe directory, `resources`, `engine`, and the fixed repository-build release path the
  dev fallback resolves. The parent was `C:\Program Files` for an installed app and the user's
  own extraction folder (or `Temp`) for the portable package, and the child launched from it is
  handed the DPAPI master key. `trusted_binary_roots_are_the_named_layout_directories_only`
  asserts a sibling install is outside every root, and was checked to fail with the parent put
  back into the list.
- [x] T063 [US2] Replace `AETHER_MASQUE_DISABLE_SPKI_PINS` / `AETHER_DANGEROUS_DISABLE_TLS_VERIFY` with an explicit `VerifyPolicy` parameter in `aether/src/{tls.rs,masque_h2.rs,h3_probe.rs}`; make `Insecure` `#[cfg(debug_assertions)]`-only; make an empty or fully-expired pin set `Err` (today `aether/src/tls.rs:31-33` maps empty pins to `SslVerifyMode::NONE`).
- [x] T064 [US2] Give `aether/src/h3_probe.rs` the `VerifyPolicy::ReadOnlyProbe` variant (chain-verified, unpinned, never used for tunnel traffic) passed into `quic::fingerprint_h3`, replacing the sticky `runtime_env::set` of a process-wide verification kill switch.
- [x] T065 [US2] Restore real chain verification inside the pin callback in `aether/src/tls.rs`: `ctx.verify_cert()? && pin_matches(host, leaf)` (boring 4.22's `X509StoreContextRef::verify_cert()` is documented as valid only inside `init`, and BoringSSL pre-initialises the store context with chain + `"ssl_server"` + SNI before invoking the callback).
- [x] T066 [US2] Convert the pin store to `PinSet { host, require_hostname, pins: [Pin{spki_sha256, expires_unix}] }` in `aether/src/{tls.rs,masque_h2.rs}` with ≥2 pins per host (live + next key), expiry checked at startup, loaded from `packaging/trust/masque-pins.json`.
- [x] T067 [US2] Delete `set_verify_hostname(false)` in `aether/src/masque_h2.rs:133`; verify the pinned host while setting the fronting SNI separately (`into_ssl(PIN_HOST)` then `set_hostname(front_sni)`), giving the fronted name its own `require_hostname: false` entry so `AETHER_MASQUE_SNI` keeps working without disabling name checks globally.
- [x] T068 [US2] Promote pin-loss diagnostics from `log::debug!` (`aether/src/tls.rs:41`) to `log::error!` + `SessionEvent::Error` naming host, observed leaf SPKI in hex, the `X509VerifyResult`, and the pin expiry date.
- [x] T069 [US2] Fix the WinTrust flags in `apps/desktop/src-tauri/src/lib.rs:930-940`: `WTD_REVOCATION_CHECK_NONE` is `0x40000`, not the `0x00000080` currently written under a comment claiming otherwise (`0x80` is `WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT`, so a per-run ephemeral CI cert additionally faces a revocation check it can never satisfy); use `WTD_UI_NONE` and `dwStateAction = WTD_STATEACTION_CLOSE` instead of `IGNORE`.
- [x] T070 [US2] Delete `allow_unsigned_in_debug` (`apps/desktop/src-tauri/src/lib.rs:849`, `:1034`) and gate any dev bypass on a compile-time-only variant (T057).
- [x] T071 [US2] Change `apps/desktop/src-tauri/build.rs:38-53` to embed the **bytes and hash of `packaging/trust/engine-trust.json`** and stop hashing `resources/aether.exe`; make an absent or short anchor file a hard compile error so the check can never be vacuous.
  Landed: `build.rs` now panics on absent / <256-byte / unparseable / incomplete anchor (verified reachable by truncating the file), emits `EMBEDDED_RELEASE_HASHES` from the anchor alone plus `ENGINE_TRUST_ANCHOR_BYTES`/`_SHA256`/`_HAS_PLACEHOLDER`, and `rerun-if-changed`s the anchor. Three tests guard it (`embedded_hashes_are_sourced_from_the_reviewed_anchor…`, `embedded_anchor_bytes_are_the_committed_file_itself`, `anchor_digests_match_the_committed_artifacts_they_describe`) and gate 10 `trust-anchor-not-self-generated` [BC-02] now runs in CI with a self-test case.
  Found on the way: the committed anchor's `wintun.dll` digest was **wrong** (`e5da74c1…` vs the tracked binary's `e5da8447…`, which is also what `build.yml` pinned) — a hand-written witness never measured against the thing it describes. Had T071 landed alone, release builds would have refused a legitimate driver. All-zero digests now refuse with `anchor_not_published` instead of reading as tampering.
- [x] T072 [US2] Delete the `AETHER_WINTUN` env read and CWD-relative fallback in `aether/src/tun_win.rs::find_wintun_dll`; accept the path as the first stdin control token from the verified parent and canonicalise it against the allow-list root.
  Done. `find_wintun_dll` in `aether/src/tun_win.rs` now takes the path only from the parent's `dll wintun <path>` stdin line (`keyhandoff::receive_if_requested`, read iff `AETHER_TUN` is on) or from beside `aether.exe`; the `AETHER_WINTUN` environment read and the CWD-relative probe are gone. The token is canonicalised and must land inside the install dir or its parent — the same roots the shell allow-lists — and is rejected if the resolved name is not `wintun.dll`. `handoff_preamble` in the shell writes both lines and zeroizes the buffer.
- [x] T073 [US2] Call `SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)` at engine startup and load with `LoadLibraryExW(LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32)` in `aether/src/{tun_win.rs,main.rs}`.
  Done. `aether/src/win_exec.rs`: `pin_dll_search_path()` (`SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)`) runs first in `cli::run()` and a failure is fatal rather than a warning, and `system_exe()` resolves every spawned tool (`route`, `tasklist`, `icacls`, and everything behind `run_cmd`) to its absolute `%WINDIR%\System32` path — the search order the default `Command::new("route")` uses includes the current directory, in a process started elevated.
  Deviation worth recording: there is no `LoadLibraryExW` call to pass flags to. The only library the engine loads is wintun, and `wintun-bindings` does that load internally via `libloading` (absolute path, `LOAD_WITH_ALTERED_SEARCH_PATH`); the process-wide default set by `SetDefaultDllDirectories` covers every other resolution, which is the outcome T073 was after.
- [x] T074 [US2] Verify `wintun.dll` **before** load using the `wintun` crate's `verify_binary_signature` feature (WinVerifyTrust VERIFY→CLOSE + signer `WireGuard LLC`, no `DllMain` execution) plus the pinned SHA-256; make the GUI's check mandatory rather than `if let Some(wintun) = wintun_path()`, which today is skipped precisely when the packaged DLL is missing.
  Done. `wintun-bindings` now builds with `verify_binary_signature`, which runs WinVerifyTrust (VERIFY then CLOSE) and requires the signer display name to be `WireGuard LLC` *before* `LoadLibrary`, so a substituted DLL is refused without executing its `DllMain`. The shell's check is no longer `if let Some(wintun) = wintun_path(&app)`: in TUN mode a missing `wintun.dll` is an error and the digest comparison against the anchor always runs.
- [ ] T075 [US2] Reorder `.github/workflows/build.yml` to sign **before** bundling: stable PFX from secrets → `cargo build --release` → sign `aether.exe` → verify signature → stage engine → **verify staged digest == `engine-trust.json` [NEW GATE]** → `npm ci && npm run build` → `npm run tauri build --config '{"bundle":{"windows":{"certificateThumbprint":…,"digestAlgorithm":"sha256","timestampUrl":…}}}'` → **extract-and-verify all inner binaries [NEW GATE]** → write release digests post-signing → upload.
  Partial: the trust-anchor publish step and three `--check` gates (staged, `dist-windows/portable/engine/*`, shipped `wintun.dll`) landed with T071 via `scripts/publish-engine-trust.mjs`, and the anchor now travels with the artifacts. Remaining: the sign-before-bundling reorder (`certificateThumbprint` handed to `tauri build` instead of post-hoc `Set-AuthenticodeSignature`) and the NSIS extract-and-verify gate — see T075b.
- [x] T076 [US2] Delete the "Sign and verify GUI and installer" step (`build.yml:150-170`) and rewrite "Verify all packaged Windows binaries" (`:194-207`) to call `scripts/verify-installers.ps1`. Document why: tauri-bundler signs the main exe after `patch_binary` (`bundle.rs:155`), sidecars while skipping already-signed files (`:296-336`), NSIS plugins/uninstaller/outer installer (`nsis/mod.rs:672-679`,`:306`,`:717`) and `resources/*` excluding signed files (`:792`) — so wintun's WireGuard LLC signature survives.
  Rewritten rather than deleted, and the task's premise corrected: that step is the only thing
  that *signs* the standalone GUI copy and the outer NSIS container (tauri-bundler signs the bundle
  it assembles, not the copies this job later re-stages), so removing it would drop a signature
  instead of removing a false claim. What was deleted is the claim itself — "Verified packaged
  artifact …" printed from `Get-AuthenticodeSignature` on `setup.exe` alone. "Verify all packaged
  Windows binaries" now keeps the outer checks and additionally calls
  `scripts/verify-installers.ps1 -Installer … -Portable … -Anchor …`, which extracts the container
  and the portable zip and checks every PE file inside: engine digest against the same anchor the
  running shell uses, wintun's WireGuard LLC signature plus its pinned digest, the GUI exe's
  publisher, and a non-empty set of binaries. The signature-verification half is therefore no
  longer vacuous — verified by T059's fixtures, which fail the gate on an unsigned engine.
- [x] T077 [US2] Record in `packaging/trust/README.md` and the workflow that Authenticode and the Tauri **updater** signature are unrelated (`TAURI_SIGNING_PRIVATE_KEY`/`createUpdaterArtifacts` produce a minisign signature over the update archive and never sign the PE), and log the rejected alternatives — paid EV, Azure Artifact Signing (~$9.99/mo per 5 000, legal-name CN requirement, no EV), installer-run `certutil -addstore TrustedPublisher` — with the reason: a control the maintainer cannot operate is a control that gets skipped.
  Documented in `packaging/trust/README.md` ("Authenticode and the updater signature are unrelated"), together with who publishes the anchor and why a per-run witness in a pipeline that mints an ephemeral certificate is still an independent one.
- [ ] T075b [US2] Split the Windows release into the two phases the anchor model needs: a `prepare-anchor` job that builds+signs the engine and commits the one-line `engine-trust.json` diff, and the tag job that refuses to bundle when the staged engine's digest is not the committed one. Today `build.yml` writes the anchor inside the runner's checkout, which is correct for the artifact pair but leaves no committed witness for a tag; close that gap rather than letting the placeholder come back.
- [ ] T078 [US2] **Checkpoint**: T053–T059 green; then delete the pin comparison in `aether/src/trust.rs` and confirm T054/T058 go red; run quickstart §2 on a clean Windows 11 VM with the CI package.

**Checkpoint**: US1 + US2 both independently functional: the host stays safe and release builds are trustworthy and actually usable.

---

## Phase 5: User Story 3 — Secrets and Learned State Are Authentic, Authoritative and Unclonable (Priority: P1)

**Goal**: No plaintext identity on disk anywhere, path-bound envelopes, no untrusted `.bak`, SID-derived ACLs (or the elevated child not touching the file at all), a validated non-authoritative endpoint cache, OS-backed locks that cannot be stolen, and an Android identity that survives a transient keystore failure.

**Independent Test**: quickstart.md §3 — copy a ciphertext to another path and it must fail authentication; a cache entry with a future timestamp + 2^31 successes + an out-of-allowlist address must be rejected without affecting ordering; `UnrecoverableKeyException` twice then success must leave the alias and config intact while `BadPaddingException` must quarantine.

### Tests for User Story 3 (write first — must fail)

- [x] T079 [P] [US3] Failing test in `aether/tests/envelope_v2.rs`: `save()` with `KeySource::None` writes no secret and names the error; with a key present the file carries the `AETHERCFG2` magic. Fails today: `aether/src/config.rs:107-108` returns plaintext when `AETHER_CONFIG_KEY` is unset — three live working-tree files demonstrate it.
- [x] T080 [P] [US3] Failing test in `aether/tests/envelope_v2.rs`: identical ciphertext at a different path must fail authentication. Fails today: no AAD binding exists, so an encrypted `aether-masque.toml` blob replays verbatim onto `aether.toml`.
- [x] T081 [P] [US3] Failing test in `aether/tests/atomic_write_test.rs` (extend): a planted `<path>.bak` with a foreign identity must be ignored by `load()`. Fails today: `aether/src/config.rs:270-278` copies it over the live file with the error ignored, and `:232-260` creates it via `std::fs::copy`/`MoveFileExW` outside the ACL-restricted writer.
- [x] T082 [P] [US3] Failing test in `aether/tests/cache_validation.rs`: `epoch > now + 300`, `successes ≥ 2^31`, and out-of-allowlist addresses must be dropped and counted. Fails today: `aether/src/cache.rs:96-107` uses `saturating_sub` on a wall clock so a future timestamp never decays and permanently earns the freshness bonus; `:65-93` does unchecked `successes + failures`; there is no provenance check at all.
- [x] T083 [P] [US3] Failing test in `aether/tests/cache_concurrency.rs`: 10 000 concurrent writers from two processes must lose no update. Fails today: `aether/src/cache.rs:157-191` treats a lock as stale at `mtime > 5 s` (stealing live holders), `unwrap_or(true)` on an `elapsed()` error makes it always stale, `continue` bypasses the deadline so it can spin, and `Drop` unlinks whoever's lock file exists.
  Done, with the assertion rewritten to something the design can actually satisfy. The task asked for "10 000 concurrent writers, no update lost" while T101 (already done) deliberately made a lock timeout *skip* the mutation instead of writing unlocked — skipping is losing an update, by choice. So the test states the property that survives that rule: an update a writer was told it applied must still be there afterwards, and one process's write must never erase another's (each writer rewrites the whole document, so that is the first thing a missing lock breaks). Two real OS processes, 120 updates each, plus a starvation guard that both made progress — otherwise the check passes on two empty histories. Verified falsifiable by an env-gated lock bypass, which turns it red.
  `record_success`/`record_failure`/`add_to_*_with_rtt`/`write_with_rtt` now return `cache::Mutation{Applied,Skipped}` and the connect and scan paths log the skip, because a function that can decline to do its job and says nothing is the same defect as a guard that cannot fail.
- [x] T084 [P] [US3] Failing test in `aether/tests/cache_read_nondestructive.rs`: a corrupt cache must be preserved as `.corrupt.<seq>` and a read must not rename it at all. Fails today: `aether/src/cache.rs:36-40` renames to a fixed `.corrupt` **from read paths** (`get_masque_sorted`/`get_wireguard_sorted` call `load_endpoints` without the lock), clobbering any prior `.corrupt`.
- [x] T085 [P] [US3] Failing test in `aether/tests/h2_endpoint_survival.rs`: an H2-cached gateway verified while `masque_h2::enabled()` must not accrue failures. Fails today: `aether/src/session.rs:583-607` always probes over QUIC while `prober.rs:458-513` shares one `CacheKind::Masque` slot, so healthy H2 gateways are evicted after 3 strikes and every connect pays a full scan.
  Done as part of T099. `CachedEndpoint.transport` separates the two histories and `session.rs`'s cached-gateway verify now calls `masque_h2::verify_h2` when H2 is on, so an H2 gateway is measured over the transport it will be used on. Guarded by `a_failure_over_one_transport_cannot_evict_the_other` and `a_success_over_one_transport_does_not_reset_the_other` (both verified to fail when the transport-blind matching is put back).
- [x] T086 [P] [US3] Failing test in `apps/android/android/app/src/test/java/app/aethernext/ConfigKeyStoreTest.kt`: `UnrecoverableKeyException` ×2 then success ⇒ alias survives and `aether.toml` intact; `BadPaddingException` ⇒ quarantine. Fails today: `ConfigKeyStore.kt:31-52` routes **any** exception into `rotateAndRecover()`, which deletes the key and quarantines the config — one transient `keystore2` failure costs the identity permanently.
- [x] T087 [P] [US3] Failing test in `aether/tests/acl_principal.rs`: the ACL principal must derive from the process token, not `%USERNAME%`. Fails today: `aether/src/config.rs:131-148` grants `/grant:r {USERNAME}:F` from an **elevated** process, so the next ordinary launch cannot read its own config and re-provisions a new WARP device.
- [x] T088 [P] [US3] Failing test in `apps/desktop/src-tauri/tests/dpapi_key_test.rs`: off-Windows the master key must not be stored in plaintext. Fails today: `apps/desktop/src-tauri/src/lib.rs:114-118`,`:163-167` make `encrypt`/`decrypt` the identity function off-Windows with a no-op ACL at `:57-60`.
  Done. `dpapi::KeyService` names the platform's secret store in one place; `encrypt_with`/`decrypt_with` take it explicitly and the `None` arm returns `key_service_unavailable` instead of the old `Ok(data.to_vec())`. The identity function is gone from the source, so no branch can be mistaken for protection. The guard test is deliberately *not* `#[cfg(windows)]` — that is what hid the defect: every assertion about the wrapping ran only on the one platform where it held. Verified falsifiable by re-injecting the pass-through, watching the test fail, then restoring. T096 (Keychain/libsecret) still owes macOS and Linux a real backend.

### Implementation for User Story 3

- [x] T089 [US3] Finish `ConfigEnvelope` in `aether/src/config.rs` (from T021): versioned magic + `u8` schema version + 12-byte `OsRng` nonce + `AeadInPlace` with the path-bound AAD; key sources `Shell/DpapiFile/Keystore/None`; refuse secrets with `None`. Bind the data-model rule verbatim: *"a reader must never fatal on a missing optional field, and a writer must never produce an artifact a previous version cannot parse without a `version` field."*
- [x] T090 [US3] Implement plaintext→v2 migration in `aether/src/config.rs`: detect the absent magic, re-encrypt, verify by read-back, only then overwrite; abort startup if the re-save fails (preserve the correct behaviour already at `:297-304`).
- [x] T091 [US3] Call `ReplaceFileW` with `lpBackupFileName = NULL` and delete both the `std::fs::copy(path,&bak)` fallback and the `.bak`-restoring branch in `aether/src/config.rs`; quarantine any pre-existing `.bak` to `.quarantined` instead of reading it.
- [x] T092 [US3] Give `write_private_file` in `aether/src/config.rs:162` the `{path}.{pid}.{seq}.{rand}.tmp` pattern already proven in `aether/src/cache.rs:353-356`, created exclusively; on Unix fsync the file **and** the parent directory after rename.
- [x] T093 [US3] Add `#[serde(deny_unknown_fields)]` to the persisted identity types in `aether/src/config.rs` so a mistyped `wg_priv_key` errors instead of silently defaulting, and validate `ipv4`/`ipv6`/`masque_endpoint` as parsed types.
- [x] T094 [US3] Apply the SID-derived protective ACL in `aether/src/config.rs`: principal from `OpenProcessToken` + `GetTokenInformation(TokenUser)` (or the active console session), descriptor `D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;<sid>)` via `ConvertStringSecurityDescriptorToSecurityDescriptorW` + `SetNamedSecurityInfoW(DACL_SECURITY_INFORMATION)`.
- [x] T095 [US3] Stop letting the elevated child own the identity file: decrypt in the GUI and hand configuration to the child over stdin; remove `AETHER_CONFIG_KEY` from the spawn env in `apps/desktop/src-tauri/src/lib.rs:1400`/`:1667` and `apps/android/.../EngineRunner.kt:103`/`:208`, zeroizing after handoff (the existing zeroize at `lib.rs:1470-1473` shows the intent).
- [ ] T096 [US3] Implement Keychain (macOS) and `libsecret` (Linux) key sources in `apps/desktop/src-tauri/src/lib.rs` so the off-Windows no-op path is gone (T088); absent a service, fall through to T089's refuse-secrets behaviour.
- [x] T097 [US3] Add `#[derive(ZeroizeOnDrop)]` to `Identity` (`aether/src/account.rs:88-97`) and `Zeroize` on `[u8;32]` key arrays; pass keys by reference instead of by value into `WgConfig`/`WgProbe`/`verify_endpoint_keep_session` (today one copy per scanned IP:port); generate from `StaticSecret::random_from_rng(OsRng)` rather than `thread_rng().fill_bytes` (`account.rs:284-296`). `zeroize` is currently a declared dependency used nowhere in `aether/src`.
- [x] T098 [US3] Complete the `EndpointRegistry` actor in `aether/src/cache.rs` (from T022): `{version:2, written_at, entries[]}`, `#[serde(default)]` on both arrays, `MAX_SUCCESSES = 1000` clamps, `saturating_add`, `(epoch_secs, monotonic_ticks)` with `epoch > now+300` rejected and **all decay on the monotonic term**, plus the `MASQUE_CIDRS_V4/V6` + `WG_PREFIXES_V4/V6` allowlist check (`prober.rs:1074+`, `wireguard.rs:562-576`).
- [x] T099 [US3] Add a `transport: TransportKind` discriminator to cache entries in `aether/src/cache.rs` and route `quick_verify_masque` through `masque_h2::verify_h2` when `masque_h2::enabled()` in `aether/src/session.rs:583-607` (fixes T085's eviction).
  Done. `cache::TransportKind{Quic,H2}` stamped by every masque writer from the single `active_masque_transport()` reader; `get_masque_sorted` filters to the transport in use and `get_masque_sorted_for` exposes the choice; `#[serde(default)]` keeps a pre-v2 file readable and a legacy entry decodes as the QUIC measurement it was. `saturating_add` on the counters came with it.
- [x] T100 [US3] Encode the authoritativeness rule in `aether/src/{session.rs,prober.rs}`: a cached endpoint may be **re-verified**, never preferred over fresh verification; fix `prober.rs:472-505` passing `ironclad = false` hardcoded so Ironclad mode's Tier-0 acceptance performs the HTTP proof, and stop caching handshake-RTT and HTTP-RTT as one comparable metric.
  Two of three clauses done. Tier-0 lives in `race_cached_endpoints` now and receives the scan's `ironclad` flag instead of hardcoding `false`, so a cached address must pass the same proof a fresh candidate would — `a_cache_hit_must_pass_the_proof_the_mode_asks_for` records the flag each probe was asked for and was checked to fail against the old call site. The same extraction made the cancel path testable (`cancellation_during_the_race_is_reported_as_cancelled`), and a token that is already cancelled no longer spawns up to five live probes.
  Not done, and deliberately not marked done: handshake-RTT and HTTP-RTT are still stored in one comparable field, so a cache written in one mode scores against measurements from the other. Tracked as T100b.
- [x] T101 [US3] Replace `CacheLock` in `aether/src/cache.rs:157-191` with `CreateMutexW` on Windows (`WAIT_ABANDONED_0` reveals a dead holder) and `flock` on a permanent fd on Unix; never `remove_file` a lock, never fail open after a timeout; delete the dead `PROVISION_LOCK_STALE` constant (`:33-34`).
- [x] T102 [US3] Fix the Android keystore policy in `apps/android/.../ConfigKeyStore.kt`: retry `getOrGenerate` 3× (200 ms/1000 ms) on `KeyStoreException|ProviderException|UnrecoverableKeyException` then **throw**; rotate only on `BadPaddingException`/short-buffer, writing `wrappedA` under `…-v1` and `wrappedB` under `…-v2` (B last, both validated before promoting); replace `require(b.size >= 12+16)` with a distinct `CorruptWrappingException`; keep `setUserAuthenticationRequired(false)` + `setInvalidatedByBiometricEnrollment(false)` and add `setRollbackResistant(true)` guarded at API 33+.
  Done, minus one clause that cannot be built. Durability is a second committed slot rather than a second alias: `wrapped_staging` is written and read back through the keystore key *before* `wrapped` is committed, then cleared, so an interrupt between the two leaves one decryptable copy instead of a config encrypted under a key that no longer exists (which the old code would have read as corruption and rotated away). `getOrGenerate` now also reads any stored wrapping **before** generating, so a lost authoritative pref recovers from staging instead of minting a second key; `rotateAndRecover` clears both slots, or the discarded key would be "recovered" back. `setUserAuthenticationRequired(false)` / `setInvalidatedByBiometricEnrollment(false)` are now explicit. Verified by `anInterruptedPromotionRecoversTheKeyFromTheStagingSlot` and `aFreshWrappingEndsUpInOneTrustedSlotAndReadsBack` (7 keystore tests pass; the first was checked to fail with the recovery branch stubbed out).
  `setRollbackResistant(true)` does not exist on `KeyGenParameterSpec.Builder` — and not on any class under `android.security`/`android.hardware` in the android-34 platform jar (checked with `javap` and a jar-wide symbol search). Rollback resistance is a KeyMint tag, not an AndroidKeyStore builder option, so the task's API-33 guard has nothing to guard. Recorded at the call site; the staging slot is the protection that is actually reachable.
  > Partially done: transient/corrupt classification, 3× backoff retry, `CorruptWrappingException` and both tests landed (T086). Remaining: the A/B alias staging (`wrappedA` under `…-v1`, `wrappedB` under `…-v2`, promote only after both validate) and `setRollbackResistant(true)` guarded at API 33+.
- [ ] T103 [US3] **Checkpoint**: T079–T088 green; then remove the AAD, the timestamp rejection and the retry classification in turn, confirming each has a test that fails.

- [ ] T100b [US3] Separate the two latency measurements in `aether/src/cache.rs`: an entry recorded by a handshake probe and one recorded by an Ironclad HTTP round trip are not the same number, and `trust_score` currently lets the cheaper measurement win. Stamp which measurement an entry carries (as `transport` now does) and ignore the RTT term when the kinds differ — do not silently zero it, which `sanitise` already reads as "unknown".

**Checkpoint**: All three P1 stories complete — the machine is safe, the binaries are trustworthy, and identities/learned state are authentic and durable. This is a shippable, defensible release.

---

## Phase 6: User Story 4 — The Tunnel Reports What It Actually Did (Priority: P2)

**Goal**: Peer-forced teardown is an error, not a success; readiness latches only on the right event; data-plane proof validates a real reply; every UI number is measured; Android derives status from structured events rather than log prose.

**Independent Test**: quickstart.md §6/§7 — feed a post-handshake packet that fails authentication and `run()` must return `Err` with the connection closed; 103 then 200 establishes; 200 on another stream does not latch readiness; the shipped frontend contains no fabricated metric strings.

### Tests for User Story 4 (write first — must fail)

- [x] T104 [P] [US4] Failing test in `aether/src/quic.rs` unit tests: peer-initiated close ⇒ `run()` is `Err`; local `closing` path ⇒ `Ok(())`. Fails today: `quic.rs:627-680` returns `Ok(())` for every close, including the `recv` error swallowed at `:482-484`, and `session.rs:222-226` then calls `record_success` on the peer that killed the tunnel.
  Already implemented when the task was written up, and re-read to confirm rather than
  assume: the close path in `aether/src/quic.rs` (now `:722-743`) returns
  `Err(Masque("tunnel died: …"))` when a `fatal` was recorded, `Err(…peer closed the tunnel…)`
  when `conn.peer_error()` is set, `Ok(())` **only** when `local_shutdown` is true, and
  `Err("connection closed without a local shutdown request")` otherwise — so an unrequested
  teardown can no longer credit the endpoint. A dedicated unit test would have to drive
  `run()`, which needs a live socket pair; the decision is left inline and the ECH-retry
  branch ahead of it is the reason it cannot be a pure function without a wider refactor.

- [x] T105 [P] [US4] Failing `classify_status` test in `aether/src/quic.rs`: off-stream 200 → ignored + counted; 103 → interim, continue; request-stream 200 → Ready; second final → fatal. Fails today: the negative check is stream-scoped (`:717`) while `if h.value() == b"200" { *h3_ready = true }` is not, and any non-2xx is fatal (`:715-719`, `:1263-1266`), so RFC 9114 §4.1 interim responses kill the tunnel.
  Covered by `quic::tests::status_is_stream_scoped_and_interim_responses_are_not_fatal`,
  which asserts the three cases the two-line rule got wrong: a 200 on a non-request stream
  does not establish, an interim 103 continues rather than aborting, and
  `classify_status` is the extracted pure function the test can reach. The second-final
  case is enforced where the state lives (`h3_ready` already true ⇒ `Err`), because
  `classify_status` alone cannot know it has answered before.

- [x] T106 [P] [US4] Failing test in `aether/tests/data_plane_proof.rs`: a peer echoing arbitrary bytes or an ICMP-shaped datagram must **not** satisfy verification. Fails today: `quic.rs:847-854` deliberately accepts "any datagram (even ICMP errors)" and the real validator `aether/src/dns.rs:222 is_dns_reply` is `#[cfg(test)]`-only.
  Covered by `quic::tests::data_plane_proof_rejects_icmp_errors_and_accepts_replies`:
  an ICMP destination-unreachable is not proof, a UDP message with no payload is not proof,
  an echo reply and a UDP payload are, and a header whose IHL claims 20 bytes but does not
  carry them is rejected without panicking.

- [ ] T107 [P] [US4] Failing test `drain_survives_undersized_reader` in `aether/src/quic.rs`: a 4 000-byte then a 64-byte datagram must both reach `inbound_tx`, and the queue must never exceed 2048 entries. Today `enable_dgram(true, 65536, 65536)` (`tls.rs:182`) sets an **entry count** (spec.md §Clarifications: the original "wedge" claim was disproved — `dgram_recv` pops before comparing lengths, `quiche/quiche/src/lib.rs:6802-6816`), so the true defects are queue depth permitting tens of MB, and `Err(_) => break` at `quic.rs:844-873` hiding fatal receive errors.
- [ ] T108 [P] [US4] Failing test in `aether/src/quic.rs`: `Error::Done` from `dgram_send`/`send_body` must increment `dgram_send_dropped` and preserve or report the loss, never discard silently (`:66-79`); with no request stream open, outbound packets must be counted, not dropped invisibly (`:492-508` has no `else`).
- [x] T109 [P] [US4] Failing test in `apps/desktop/src/components/__tests__/ConnectionTab.test.tsx`: every stat renders `—` when its field is `null`. Fails today: `ConnectionTab.tsx:88-94` regexes `/(\d+)\s*ms/` against a string containing no timing (`lib.rs:1623` returns `OK via {via} · ip=… loc=…`) and falls back to `< 45 ms`; `:283` shows `PACKET LOSS 0.0%`; `:293` animates `[42,68,55,84,…]`; `:423` prints `HTTP LISTENING / SOCKS5 READY` beside `DORMANT` at `:404-409`; `:348-353` asserts `END-TO-END TLS 1.3` for WireGuard.
  All five claims are gone from the tree, checked against the current file rather than the line
  numbers in the task (they had moved): latency is `not measured` unless `test_connection` really
  returned milliseconds, packet loss is `not measured` and always has been unavailable, the
  `HTTP LISTENING / SOCKS5 READY` and `END-TO-END TLS 1.3` strings no longer appear, and the
  fabricated equalizer — sixteen bars whose heights came from a literal
  `[42, 68, 55, 84, …]` and which animated only because `connected` was true — is deleted from
  **both** UIs, with the reason recorded in place of it. That one was still live when this was
  re-read: it was the least visible of the five because it asks nothing of the reader and looks
  exactly like a signal graph.
  Deviation on form: no `ConnectionTab.test.tsx` was added, because a component asserting today's
  strings would not catch the class. `no-fabricated-metrics` [BC-14] now bans the claim strings
  *and* any hard-coded numeric series of five or more values in either app's `src`, so
  reintroducing a fake chart or a `< 45 ms` fallback fails the gate on any pull. The new
  alternative's reachability was proven against the pre-fix files (it matched exactly the two
  sparkline arrays, nothing else in the tree), and the gate's inject defect now carries both
  banned forms. 10 desktop + 8 Android UI tests and all 13 gates pass.
  Still open and owned elsewhere: a real latency source for these two rows is T124
  (`handshake_rtt_ms` / `active_endpoint_rtt_ms` on `RuntimeState`); until then the honest
  rendering is "not measured", which is what ships.
- [ ] T110 [P] [US4] Failing test in `apps/android/android/app/src/test/java/app/aethernext/SessionControllerTest.kt`: a stream containing only `connected` reaches connected; log prose containing `"handshake successful"` must **not**. Fails today: `SessionController.kt:314-326` infers state by substring-matching prose — a string absent from the Rust source, so the guard's trigger is unreachable and the JSON parse error is swallowed.

### Implementation for User Story 4

- [x] T111 [US4] Add a `closing: bool` local-shutdown flag in `aether/src/quic.rs` (mirrored at `masque_h2.rs:600-603`) and return `Ok(())` only when set; every other close returns `Err` so failure is recorded and `main.rs` exits non-zero.
- [x] T112 [US4] Implement the readiness classifier in `aether/src/quic.rs::poll_h3` (research R2): stream-scoped, 1xx continue, single latched final, second final/3xx+ fatal; gate `dgram_by_peer` on `poll()` returning `Done` for the iteration (SETTINGS can land in the same batch); fall back to capsules when auto-negotiation picks datagram but `dgram_max_writable_len()` is `None`.
- [x] T113 [US4] Switch the drain loop in `aether/src/quic.rs:830-876` to `dgram_recv_buf()` terminated only by `Error::Done`, delete the 65 535-byte scratch buffer, set `enable_dgram(true, 2048, 2048)` in `aether/src/tls.rs:182`, cap the H3 path at MTU 1280 and gate sends on `dgram_max_writable_len()`.
- [x] T114 [US4] Apply the R3 error taxonomy across `aether/src/{quic.rs,masque_h2.rs}`: `recv` → `Done` benign, anything else closes (`0x1`, `0x101` for `TlsFail`) and returns `Err`; `flush` → `Done` break, else propagate; socket `WouldBlock` → break and re-arm on `conn.timeout()`; `BufferTooShort`/`InvalidState` on send are permanent. Note `h3::Error != quiche::Error` in this fork — never mix them.
- [x] T115 [US4] Make the data-plane probe real: promote `is_dns_reply` out of `#[cfg(test)]` in `aether/src/dns.rs:222` and match the session's own query id in `aether/src/quic.rs`, so an echoing peer or a captive edge that answers CONNECT then black-holes cannot be promoted into the trust cache.
- [x] T116 [US4] Fix the unreachable reader-death guard in `aether/src/quic.rs`: `net_tx` is created at `:372`, only `.clone()`d at `:380`, never dropped, so the `None =>` arm at `:486` (labelled `// L6 fix`) can never fire and a dead UDP reader leaves a tunnel reporting `dataplane_ok == true` until the 120 s idle timeout. `drop(net_tx)` after spawning readers, or poll a `Vec<JoinHandle>` with `is_finished()` each tick; delete the inert fast-fail block at `:440-452` or make it reachable.
- [x] T117 [US4] Fix `wait_stack_alive` in `aether/src/session.rs:62-80`: today `Ok(_)` covers the stack's own `Err` (`netstack closed`, `dropped`, `too many TCP connections`, `no free local ports`), so a dead local stack proves life — classify refusal vs local error, and `close()` the returned `TcpConn` (no `Drop` guard, unlike `UdpSender` at `netstack.rs:192-201`), which currently leaks an ESTABLISHED socket plus 1 MB per probe.
- [ ] T118 [US4] Fix `h3_probe`'s no-op axes: `AETHER_MASQUE_H3_HEADERS` is read only by an `#[allow(dead_code)]` helper (`aether/src/masque.rs:53-70`) and `AETHER_MASQUE_H3_PROTOCOL` by nobody, while `masque.rs:118-128` hardcodes `:protocol` — thread the mode into `connect_ip_request` or delete both, because the probe table prints `headers=cf proto=connect-ip` while sending something else, so every conclusion drawn from it is invalid.
- [x] T119 [US4] Propagate ECH injection failure in the probe path (`aether/src/quic.rs:1058-1060` uses `let _ =` while `:400-403` uses `?`) so a plaintext-SNI result is never attributed to the ECH configuration, and delete or implement the 0-RTT path (`:388-390` admits it is unimplemented while `:532-535` writes tickets that are never loaded and `enable_early_data()` is never called).
  Done: the probe path now propagates `tls::inject_ech(...)` instead of `let _ =`, so a
  connection that failed to apply the ECH extension fails its probe rather than being
  recorded as a success on the axis that was never applied. Not verified by a test —
  injecting a bad ECH list requires a live peer — and the local engine build is currently
  broken on this machine (boring-sys cannot configure without CMake), so this compiles or
  does not on CI, which is a weaker claim than the rest of this feature's and is stated as
  such rather than papered over.

- [x] T120 [US4] Serialise event payloads with `serde_json` in `aether/src/quic.rs:85-88` — `detail` currently carries `String::from_utf8_lossy(header value)` from the **peer** inside a hand-built JSON string, so the comment's "must not contain double quotes" is unenforced and a peer can forge sibling fields on the GUI's status channel.
- [x] T121 [US4] Implement the shell-side 90 s connect watchdog in `apps/desktop/src-tauri/src/lib.rs`, stamped against the existing `generation: AtomicU64` (`:315`,`:1170-1178`), killing the child and emitting `error` if that generation is still `connecting`. It must live in the shell: `watch_child` (`:1217`) fires only on process exit and WebView2 throttles timers in hidden windows (`:2216` hides to tray). Port semantics from `apps/android/src/hooks/useRuntime.ts` `CONNECT_WATCHDOG_MS = 90_000`.
  Done. `connect` stamps `(generation, Instant)` when it emits `connecting`; `watch_child`'s
  existing 500 ms loop consults it through `connect_watchdog_action`, a pure function of the stamp,
  the current generation, the status and the budget — because the two facts that decide it are easy
  to get wrong and impossible to exercise through a real hang: a stamp belongs to the session that
  made it (otherwise an old timeout kills the session running now), and a session that reached any
  terminal state must not be killed for a stamp it left behind. On a genuine timeout it takes the
  stamp before anything else (the loop would otherwise re-fire every tick), writes `shutdown`,
  kills, waits, runs `cleanup_routing`, bumps the generation, and emits `error` with the same
  "what could not be undone" suffix `disconnect` uses, so a timed-out connect cannot leave the
  system proxy configured.
  `connect_watchdog_action` is the guard; deleting its generation and status checks reddens exactly
  the two tests that assert them (verified by mutation, and the file was restored byte-identically
  afterwards). 40 shell tests and all 13 gates pass; clippy at the pinned 1.88 is clean.
  Side effect worth noting: because the shell now leaves `connecting`, the Settings tab unlocks on
  its own, which is half of what T174 asks for; T174's UI mirror is still open.
- [ ] T122 [US4] Add the `phase` heartbeat (≤15 s) in `aether/src/{session.rs,session_event.rs}` and treat three misses as a stall in `apps/desktop/src-tauri/src/lib.rs`.
- [x] T123 [US4] Make the engine's exit status agree with its event stream: `aether/src/main.rs` returns non-zero on an error outcome so the shell cannot observe a clean exit for a failed session.
- [ ] T124 [US4] Add `handshake_rtt_ms: Option<u32>` (from `aether/src/tunnelping.rs`) and `active_endpoint_rtt_ms: Option<u32>` to `RuntimeState` in `apps/desktop/src-tauri/src/lib.rs:292-297`, exported via `bindings.ts`, and delete every stat lacking a source (T109's list) rather than zero-filling it.
- [ ] T125 [US4] Fix keep-alive/idle in `aether/src/{quic.rs,tls.rs}`: 15 s ack-eliciting ping **followed by `flush()` in the same iteration** (`send_ack_eliciting` only sets a flag — `quiche/quiche/src/lib.rs:6744-6750`, emission at `:5343-5354` gated `:8268`), `conn.stats()` `recv` deltas with two unanswered pings tearing down, and `set_max_idle_timeout(45_000)` — quiche's effective timeout is `min(local,peer)` floored to 3×PTO (`:8897-8928`), so today's 120 s is both shortened by peers and far beyond NAT soft state.
- [ ] T126 [US4] Fix the WireGuard reuse/PSK decisions in `aether/src/{wireguard.rs,session.rs}`: thread `persistent_keepalive` into the probe (hardcoded `Some(25)` at `wireguard.rs:446`, and `from_established` silently discards `AETHER_WG_KEEPALIVE`); **delete** `preshared_key` (WARP enrolment returns none, and a nonzero PSK folds into `k2`/`mac2` in boringtun making the handshake unpairable); replace `WgSessionCache`'s `map.clear()` at 4 with a TTL of `REJECT_AFTER_TIME − REKEY_TIMEOUT = 175 s` plus LRU eviction; swap `.lock().unwrap()` for `parking_lot` so a poison cannot panic every later probe.
- [x] T127 [US4] Remove the misleading status claims in `apps/desktop/src/components/ConnectionTab.tsx`: `:21-26` shows `ENGAGING // 0-RTT PROBING` and `ACTIVE // 0-RTT TUNNEL` regardless of transport; `:189` claims an update "is ready" when none was downloaded; `:287` prints `V4 DUAL-READY`. Wire to measured state or delete.
  Done in both UIs. The desktop hero now derives its badge and body from
  `settings.routingMode`: TUN says it routes Windows traffic, system-proxy says only
  applications that follow the system proxy are covered, and `proxy-only` — where nothing
  is routed at all — says so. The early-data/0-RTT claim, the "traffic secure" eyebrow shown
  while disconnected, and "Route Compromised" for any error are gone; Android got the same
  de-escalation with its own wording, since its VPN genuinely does route once up.
  `no-fabricated-metrics` [BC-14] now bans the two claim strings outright, and its
  reachability was checked against the pre-fix file rather than assumed (it reports both
  phrases there). Side effect found and accepted: the gate greps raw text, so a comment
  naming a banned phrase trips it — the comments speak around the literals instead of
  weakening the gate.

- [x] T128 [US4] Downgrade the update banner in `apps/desktop/src/hooks/useRuntime.ts:99-116` + `components/ConnectionTab.tsx:185-201` to "a new version is available" with an opener link; document that `tauri-plugin-updater` is deliberately not adopted (needs `createUpdaterArtifacts`, a literal minisign pubkey, endpoint templates, an `updater:default` capability and a CI-generated manifest — with no key custody it would be misconfigured), and that today's check is an unauthenticated `api.github.com` fetch with `.catch(() => {})` so rate limiting makes the banner silently never appear.
  Done. The banner said "Aether {version} is ready. Restart or click to update!" over a
  button whose only effect is opening a URL, and the dismiss control was the same weight
  as an action that performed nothing — the app has no updater, so the sentence described
  a capability it does not have. It now reads "A new version is available: {version}" with
  a "View release" button. The hook carries why the fetch is advisory (unauthenticated
  `api.github.com`, error swallowed, so the 60/h IP limit can make it never appear) and
  why `tauri-plugin-updater` stays unadopted: an auto-updater is the one component that
  could install code as the user, and without key custody its signing setup would be
  misconfigured by construction.
  Deviation: the task text points at `ConnectionTab.tsx:185-201`; the banner is at
  `:211-227` now (the file moved under earlier work). The Android UI has no update banner,
  so there was nothing to mirror there. No test added — the defect is a sentence, and the
  guard against reintroducing it is the comment that explains the omission.
- [ ] T129 [US4] Replace the Android log-substring status path in `apps/android/.../SessionController.kt:303-326` with structured `AETHER_EVENT` consumption and a fail-closed `disconnected` default (fixes T110), surfacing the parse error into the log stream instead of swallowing it.
- [ ] T130 [US4] **Checkpoint**: T104–T110 green; delete the `closing` flag, the stream-scoped readiness check and the promoted `is_dns_reply`, confirming each has a red test.

**Checkpoint**: "Connected" now means connected; a false positive can no longer poison the trust cache and suppress rescans.

---

## Phase 7: User Story 5 — Idle Connections Survive; Dead Ones Are Reaped; the Scanner Is Honest (Priority: P2)

> **Note**: the renumbering below keeps US5 ids at T131+; T130 was consumed as US4's checkpoint.

**Goal**: SSH/IMAP/long-poll/WebSocket/DB sessions stay up when idle, a crashed peer is reaped in bounded time, wire order is preserved, uploads are not starved by downloads, the scan queue cannot exhaust memory, scanner budgets and progress are truthful, cancellation interrupts in-flight work, and scan load cannot starve the live tunnel.

**Independent Test**: quickstart.md §7 — an established connection idle 60 s both directions survives **and** emits a keep-alive frame; `[1448, 52, 1448, 60, 1448]` drains in exact order through `mpsc(1)`; a saturated `outbound_tx` bounds `device.tx` with a visible counter; 100 proxy associations leave DNS working; cancellation completes in < 50 ms.

### Tests for User Story 5 (write first — must fail)

- [ ] T131 [P] [US5] Failing test `idle_established_survives` in `aether/src/netstack.rs`: reach Established, advance the simulated clock 60 s with zero inbound, assert still `Established` **and** ≥1 egress frame observed. Fails today: `netstack.rs:562` sets a 10 s `set_timeout` never revised, and smoltcp's `timed_out` compares `remote_last_ts + timeout` (`smoltcp-0.12.0/src/socket/tcp.rs:2118-2122`, refreshed at `:1932`) — the connect-timeout fix silently became an idle killer, with `set_keep_alive` never enabled.
- [ ] T132 [P] [US5] Failing test `flush_tx_mixed_sizes_fifo` in `aether/src/netstack.rs`: `[1448, 52, 1448, 60, 1448]` through `mpsc(1)` must pop in push order. Fails today: `:817-851` sends every frame ≤128 B ahead of deferred larger frames, and the existing test at `:859-917` uses four identical 200-byte packets so it can never observe the inversion — **spec 004's FR-001 remains unmet**.
- [ ] T133 [P] [US5] Failing test `tx_ring_is_bounded` in `aether/src/netstack.rs`: saturate `outbound_tx`, assert `device.tx.len() ≤ TX_RING+32` with `tx_deferred > 0`. Fails today: `:31`,`:55-60`,`:822-851` append to an unbounded `VecDeque<Vec<u8>>` while every poll keeps producing.
- [ ] T134 [P] [US5] Failing test `cmd_not_starved_by_inbound` in `aether/src/netstack.rs`: preload 5× the ingest batch, assert a concurrent `OpenTcp` completes within ≤10 iterations. Fails today: `biased` select (`:499`) plus the ingest loop guarantees branch-1 priority.
- [ ] T135 [P] [US5] Failing test `stale_handle_does_not_panic` in `aether/src/netstack.rs`: remove a socket handle while its `tcp_conns` entry remains, then `handle_cmd` + `service_tcp`; assert no panic escapes, buffers untouched, task alive, next `open_tcp` succeeds. Fails today: `handle_cmd`/`handle_data` are outside the `catch_unwind` guard (`:456-491` vs `:545-676`) and call panicking `get::<T>()` — 0.12's `SocketSet` exposes **only** panicking accessors (`iface/socket_set.rs:98-130`).
- [ ] T136 [P] [US5] Failing test in new `aether/tests/socks_udp_associate.rs`: after origin-map overflow, replies must not be fallback-forwarded to the pinned client and idle associations must expire. Fails today: `aether/src/socks.rs:575` does `map.clear()` and `:627-647` falls back to `.or(client)`, so one client receives another flow's datagrams; inbound is not filtered by previously-contacted destination (`:643-652`, wildcard bind at `netstack.rs:621`).
- [ ] T137 [P] [US5] Failing test in `aether/tests/netstack_quotas.rs`: open 100 proxy UDP associations, assert `dns_resolve` still succeeds. Fails today: one shared `MAX_UDP_CONNECTIONS = 128` pool (`netstack.rs:23`) serves proxy and internal DNS, so exhaustion breaks every domain CONNECT.
- [ ] T138 [P] [US5] Failing test in `aether/tests/http_header_test.rs` (extend): a bare-LF request line must still forward `Host:`. Fails today: `aether/src/http_proxy.rs:45-52` parses with `text.lines()` (splits on `\n`) while `:233-258` splices to the first `\r\n`, so `GET http://a/ HTTP/1.1\nHost: a\r\n\r\n` loses the Host header — a parse/response divergence of request-smuggling shape.
- [ ] T139 [P] [US5] Failing test in `aether/tests/dns_ech_bootstrap.rs`: an ECH reply with a mismatched transaction ID, `QR == 0`, wrong question name, or `TC` set must be ignored. Fails today: `aether/src/dns.rs:35-103` validates none, and the id generated at `:44` never reaches the parser — one spoofed reply attributed to 1.1.1.1 installs an attacker-chosen ECHConfigList.
- [ ] T140 [P] [US5] Failing test in `aether/tests/port_randomisation.rs`: sample 1 000 allocated ports — all in band, unique vs live sockets, consecutive-difference stddev > 100. Fails today: `netstack.rs:405`,`:414-418` hand out 49152, 49153, …, making DNS spoofing retries free.
- [ ] T141 [P] [US5] Failing tests in new `aether/tests/scan_budget.rs` and extended `aether/tests/scanner_cancellation_test.rs`: `scan_start.total` must equal candidates actually examined; hits deduped by `(ip, port)`; drill-down must enumerate neighbours. Fails today: `prober.rs:416-419`/`:561-565` apply a 6 s floor and ≤16 workers against an unchanged 30/60 s deadline over 1 400–20 000 candidates (≈5 % coverage) while `:527-536` announces the full count; drill-down increments `found` but not `scanned` (`:627`,`:647`); and `:736-738` computes `(current_host.wrapping_sub(offset)) % 254`, which underflows to a near-random host.

### Implementation for User Story 5

- [ ] T142 [US5] Replace the loop's wall-clock base with a monotonic clock in `aether/src/netstack.rs:457` (`Duration::from_millis(start.elapsed().as_millis())`) — required before T131 can be written deterministically at all.
- [x] T143 [US5] On the `Established` transition (`aether/src/netstack.rs:690-702`) set `set_timeout(Some(75s))` **and** `set_keep_alive(Some(15s))` (75 > 4×15), keeping the 10 s connect timeout. In 0.12 keep-alive genuinely works: `set_keep_alive` (`tcp.rs:760`) arms `Timer::Idle` (`:318-330`), `dispatch` sends a 1-byte probe at `seq-1` (`:2448-2455`), the peer's ACK refreshes `remote_last_ts`, and `poll_at` surfaces the deadline (`:304-315`). `set_timeout(None)` was rejected — it leaves the stack unsupervised.
- [x] T144 [US5] Bound `device.tx` at `TX_RING = 256` with `transmit()` returning `None` at capacity and `tx_deferred++` in `aether/src/netstack.rs:72-74`, keeping `receive()`'s paired token **uncapped**: smoltcp maps exhaustion to `EgressError::Exhausted => break` and retries the segment (`iface/interface/mod.rs:668-671,745`; `tcp.rs:2494-2521`), but `ack_reply` updates `remote_last_ack` eagerly (`tcp.rs:1383-1391`) so a dropped reply is not regenerated.
- [ ] T145 [US5] Replace eager per-socket buffers with a 128 MB global admission budget in `aether/src/netstack.rs` (1 MB rx / 256 KB tx while ≥16 MB headroom, else 128 KB / 64 KB): today's `512 × 2 × 1 MB` (`:16`,`:552-553`) is a 1 GB ceiling that OOMs an 8 GB laptop or any Android device long before `MAX_TCP_CONNECTIONS` is useful.
- [x] T146 [US5] Delete the `ACKISH`/`deferred` split in `aether/src/netstack.rs:817-852` for strict FIFO with `push_front` on `Full`. Do not adopt content-based pure-ACK classification even though it is computable (`ihl`/`proto`/`data_off`/`flags`): promoting a smaller window or older ACK ahead of newer state is its own hazard, and ACK latency is already bounded by `socket_egress`'s one-packet-per-socket-per-poll rule (`iface/interface/mod.rs:657`) plus T144's ring cap.
- [ ] T147 [US5] Remove `biased` from the main select (`aether/src/netstack.rs:499`) and replace `iface.poll()` with bounded interleaving (`poll_ingress_single` ≤32 then one `poll_egress`) plus per-tick budgets (cmd ≤64, data ≤128); floor `poll_delay` at 250 µs when the ring is full, keep `delay.unwrap_or(250ms)` (`iface/interface/mod.rs:430-435`,`:449-462`,`:529-570`). `recv_many` may replace the `try_recv` drain.
- [ ] T148 [US5] Add non-panicking `with_tcp`/`with_udp` accessors over `sockets.iter_mut()` in `aether/src/netstack.rs` and use them at `:430`, `:440`, `:666` and every `get_mut`; extend `catch_unwind` to `handle_cmd`/`handle_data`; stop clearing `rx`/`tx` on recovery (`:467` discards good packets); keep the `JoinHandle` so `wait_stack_alive` owns a restart only when the **task** exits. Restart was rejected: for a VPN it kills up to 512 flows, worse than a scoped catch, and `panic = "unwind"` makes the catch real.
- [ ] T149 [US5] Implement per-class quotas in `aether/src/netstack.rs` (`MAX_UDP_PROXY = 96`, `MAX_UDP_RESOLVER = 32`, `MAX_TCP_PROXY = 480`, `MAX_TCP_RESOLVER = 32`) with a `resolver: bool` on `Cmd::OpenUdp`/`OpenTcp` — a runtime counter suffices because `SocketSet::new(Vec::new())` is the growing owned variant (`iface/socket_set.rs:82-90`), so no second set and no `Arc<Semaphore>` double-bookkeeping.
- [x] T150 [US5] Randomise ephemeral ports in `aether/src/netstack.rs:405-447`: seed `49152 + random % 16384`, advance by an **odd** stride (coprime with the 2^14 band so it cycles fully), `alloc_unique_port` retries ≤64 against a `HashSet<u16>` of live ports.
- [x] T151 [US5] Replace DNS cache eviction in `aether/src/socks.rs:306-311` with LRU per-key removal — today's `retain(|_, (_, at)| at.elapsed() < TTL)` at the 2048 cap removes nothing, so a wildcard-DNS page grows it unboundedly.
- [x] T152 [US5] Rewrite the SOCKS UDP origin map in `aether/src/socks.rs:562-662`: per-entry `Instant` + TTL/LRU eviction (never `clear()`), drop instead of fallback-forward on unknown origin, an inactivity timer on the association, reply filtering by previously-contacted destination, and a separate resolver quota so T137 passes.
- [x] T153 [US5] Fix the `UdpSender` clone-and-drop hazard in `aether/src/netstack.rs:192-201` (`try_send` of `UdpClose` is silently dropped under load, and **every clone's `Drop` issues `UdpClose(id)`** so the resolver clone in `socks.rs:574` can tear down a live association): move the close to a non-cloneable owner (`Arc<UdpConn>` dropping on last handle) with `send()` awaited on the shutdown path.
- [x] T154 [US5] Harden `aether/src/http_proxy.rs` to one boundary rule: explicit `\r\n` for the request line and the rewrite point, rejecting a bare LF, preserving the existing 16 KB cap and read timeout (`:149-181`).
- [x] T155 [US5] Validate the ECH bootstrap reply in `aether/src/dns.rs:35-103` — thread the transaction ID into `parse_https_ech`, check `QR`, the echoed question name, refuse `TC` on the fixed 4096-byte read. Model it on `parse_dns_answer_id` (`socks.rs:347-410`), which already does all of this correctly.
- [x] T156 [US5] Make writes into a dead or overflowed flow fail loudly in `aether/src/netstack.rs:649-657`,`:110-115`,`:143-148`: pending-data overflow currently sets `half_closed = true` and returns `Ok(())`, so an upload racing socket removal or a >512 KB burst is acknowledged as sent and then discarded mid-stream — truncated HTTP bodies and TLS records with no error anywhere. Reply per-write, or mark the connection dead so `TcpSender::send` returns `Err`.
- [ ] T157 [US5] Enforce the deny-list at the single post-resolution choke point `netstack::handle_cmd` in `aether/src/netstack.rs`: `127.0.0.0/8`, `::1`, `0.0.0.0/8`, `169.254.0.0/16` (IMDS), `100.64.0.0/10`, `fc00::/7`, RFC1918 opt-in; one gate variable (`AETHER_ALLOW_REMOTE_PROXY` in `aether/src/engine_config.rs`, deleting `AETHER_UNSAFE_PUBLIC_PROXY` from `aether/src/{socks.rs,http_proxy.rs}`); credentials mandatory for a non-loopback listener. Post-resolution because only then is the destination known — a pre-resolution check is defeated by DNS rebinding.
- [x] T158 [US5] Fix `aether/src/socks.rs` protocol edges: validate `RSVD` (`:74-92`), reject an unreadable domain length, stop silently dropping >63-byte labels in `build_dns_query` (`:334-340`) which currently resolves a **different name** than the client asked for, answer BIND (0x02) with a valid refusal rather than `0x07` on a socket it then closes, and reply with a valid `BND.ADDR`/`BND.PORT` pair instead of `0.0.0.0:0`.
- [x] T159 [US5] Fix scanner budgets in `aether/src/prober.rs`: derive `overall_deadline` from `candidates / concurrency × per_probe` (replacing the fixed 30/60 s against a 6 s `Expensive` floor at ≤16 workers), dedupe hits by `(ip, port)`, count drill-down toward `scanned`, evaluate `target_successes` in the drill-down arm too, and correct `:736-738` to `saturating_sub` with a `1..=254` clamp so "Stage-2 dense enumeration" stops probing arbitrary hosts.
- [ ] T160 [US5] Move probe persistence off the workers in `aether/src/prober.rs`: emit `ProbeOutcome` on an `mpsc` consumed by one `spawn_blocking` task with a 500 ms / 64-outcome debounce; delete `std::thread::sleep` from `aether/src/cache.rs:178` for the probe path; order each probe's `select!` `biased` with `sleep(conn.timeout())` first (the rule Cloudflare's driver documents at `tokio-quiche/src/quic/io/worker.rs:316-322`) so 8-16 concurrent probes stop inflating PTO.
- [ ] T161 [US5] Honour the scan mode in `apps/desktop/src-tauri/src/lib.rs:1669`: pass `scan_mode` through `scan` into `AETHER_SCAN` instead of hardcoding `"balanced"`, so the "Probe Velocity Profile" setting stops being inert while the banner still reads BALANCED.
- [ ] T162 [US5] Fix MTU handling in `aether/src/mtu.rs`: reject 576–1279 when IPv6 is configured (IPv6's link minimum is 1280 and smoltcp cannot fragment IPv6, so those flows just fail); make `probe_udp_size` require a DF-protected round trip instead of returning `true` for any `send_to` that does not hard-fail locally (today "auto" always yields 1400); serialise concurrent `resolve_mtu` probes.
- [ ] T163 [US5] Make session caps honest in `aether/src/{socks.rs:16,60,65, http_proxy.rs:13,28,33}`: an explicit refusal when `MAX_CLIENTS` saturates (today an accepted socket is dropped with no SOCKS reply = RST) and a documented, user-visible `MAX_SESSION` rather than a silent 4-hour abort mid-stream.
- [ ] T164 [US5] **Checkpoint**: T131–T141 green; delete the keep-alive call, the ring cap, the FIFO change and the port randomisation in turn, confirming each is observed.

**Checkpoint**: Idle real-world connections survive, order is preserved, memory is bounded, and the scanner's numbers mean what they say.

---

## Phase 8: User Story 6 — One Contract, Two Platforms, Zero Drift (Priority: P2)

**Goal**: Rust is the single type source and CI regenerates the TypeScript; both UIs render from one component/token source; every rendered class exists; the type system actually loads; contrast and scaling hold at every OS scale factor; the scanner resets honestly; no metric or label is a lie.

**Independent Test**: quickstart.md §6 — add a Rust field without updating TypeScript and the build fails; extract every `className` and all resolve (`.metric-icon` fails today); zero non-`ipc:` requests leave the packaged build; a WireGuard scan after an H3 scan shows only current-run rows; 2 000 rows stay under 16 ms p95.

### Tests for User Story 6 (write first — must fail)

- [ ] T165 [P] [US6] Wire the remaining gates into `scripts/verify-invariants.*`: bindings-diff; `className`→selector; banned-CSS (`100vh`, `transition: all`, bare `:hover`, `border: 1px solid rgba(255,255,255,<0.10)`, undefined `var(--x)`); contrast-from-tokens; "no breakpoint equals a window minimum"; "same component defined twice with different bodies". **Each fails today** with the evidence recorded in `contracts/ui-design-contract.md`.
- [ ] T166 [P] [US6] Failing test in `apps/desktop/src/hooks/__tests__/useScanner.test.ts`: scan A (40 H3 hits) then scan B (WireGuard) ⇒ heading reflects only B and rows key on `addr + protocol`. Fails today: `useScanner.ts:106` filters only same-protocol rows, and dedup at `:68` keys on `addr` alone, so an IP live on both transports keeps the old protocol and RTT and lands in the wrong bucket.
- [ ] T167 [P] [US6] Failing test `bestRtt`/`working` in `apps/desktop/src/hooks/__tests__/useScanner.test.ts`: `bestRtt` is the minimum of the sorted list and `working` is authoritative from `scan_progress`. Fails today: `useScanner.ts:65` `bestRtt: ev.rtt || prev.bestRtt` shows the most recent hit ("Best: 240 ms" above a "12 ms" row), and `:64`'s per-hit `working + 1` oscillates against `:57`'s overwrite from the engine's every-50-probes count.
- [ ] T168 [P] [US6] Failing test in `apps/desktop/src/components/__tests__/SettingsTab.test.tsx`: a rejected save renders an inline field error and clears optimistic state. Fails today: `useRuntime.ts:134-141` only appends a log line while `SettingsTab.tsx:497,515` keep reading "Synchronizing changes…" / "Auto-Saving" forever.
- [ ] T169 [P] [US6] Failing test: `NumberField` at value `0` steps to the clamped neighbour, not back to the previous value. Fails today: `apps/desktop/src/components/ui.tsx:113,139` use `parseInt(draft, 10) || value`, so 0 is treated as absent — Junk Packet Count shows 0, − yields 4, + yields 6.
- [ ] T170 [P] [US6] Failing test: the Hits filter counts hits exactly once over a 2 000-line buffer. Fails today: `useLogs.ts:12-23` double-counts because `pump_scan_stream` forwards both the human `[+] … candidate ok` line and the raw `AETHER_EVENT` line and each matches a different clause; `EndpointSelected` never matches (serde's tag is `endpoint_selected`); `"Selected edge"` exists nowhere; and the "valid IP" regex is unanchored so `":150` inside JSON counts — spec 006's Hits filter was never implemented.
- [ ] T171 [P] [US6] Failing a11y suite in `apps/desktop/src/components/__tests__/a11y.test.tsx` (axe) per tab with 2 000 mocked rows: zero role violations, focus visible, every scroll region keyboard-reachable, DOM nodes ≤ viewport+overscan.

### Implementation for User Story 6

- [ ] T172 [US6] Replace the stringly allowlists in `apps/desktop/src-tauri/src/lib.rs:512-545` with real enums (`IpVersion::{Auto,V4,V6,Dual}`, `ScanMode`, `Protocol`, `TransportKind`, `RoutingMode`) so `"both"` and the `"thorogh"` typo become non-representable, and align `aether/src/prober.rs:42` with the single meaning. The defect being removed: the Settings option is rejected by `validate_settings` (hard-breaking Connect) while the Scanner's identical label works.
- [ ] T173 [US6] Add `#[serde(default)]` to `Settings` fields (`apps/desktop/src-tauri/src/lib.rs:228-258`) and merge hydration over defaults in `apps/desktop/src/hooks/useRuntime.ts:74`,`:231` (Android already does at `apps/android/src/hooks/useRuntime.ts:71`), so a dropped or renamed field cannot produce `undefined` and a render-time throw.
- [x] T174 [US6] Give the desktop UI watchdog parity in `apps/desktop/src/hooks/useRuntime.ts` (T121's shell-side watchdog plus a UI mirror) and delete the resulting desktop-only failure where `settingsLocked` keeps the entire Settings tab locked forever.
  The failure is gone and the mirror is deliberately not built. `settingsLocked` is
  `running || !settingsLoaded` and `running` is `connecting || connected`, so the tab unlocks
  the moment anything moves the session out of `connecting` — which is exactly what T121's
  shell watchdog now guarantees within 90 s, without a reload. A second timer in the page
  would be the same design T121 rejected: WebView2 throttles timers in a window hidden to the
  tray, so a page-side watchdog is the one place this cannot be relied on, and two timers with
  the same budget disagree about which of them fired.
  Guard instead of mirror: `releases the Settings lock as soon as the session reaches a
  terminal state` drives `connecting` → `error` through the state channel and asserts the lock
  releases, so a future change that stops a terminal state from reaching the UI goes red.
  10 desktop UI tests pass.
- [ ] T175 [US6] Scope scan events by `run_id` end to end (on T020's typed pipeline): mint in `startScan`, echo through the shell, drop non-matching in both layers, and make the synthetic terminal event a typed `scan_failed { run_id }` instead of `{"type":"scan_done","addr":"","rtt":""}` at `apps/desktop/src-tauri/src/lib.rs:1736-1741`, which today reports "no working endpoints found" after a scan that found dozens and can deactivate a live scan.
- [ ] T176 [US6] Clear `endpoints`, counters and `bestRtt` unconditionally in `apps/desktop/src/hooks/useScanner.ts:startScan` and key rows on `addr + protocol` (fixes T166).
- [ ] T177 [US6] Delete `apps/desktop/src/types.ts:111-112`'s `scan_failed`/`scan_done.working` **or** emit them — with the generated type as arbiter (fixes the dead arm at `useScanner.ts:88-91`) — and carry `best_rtt_ms: Option<u32>` so completion stops logging `best: 1.1.1.1:443 ()` (`aether/src/session.rs:187,203,254,261,297` emit `rtt: String::new()`).
- [ ] T178 [US6] Add `saveSeqRef` ordering to `apps/desktop/src/hooks/useRuntime.ts:123-135` so a slow older write cannot land last and flip "Synchronized" for the wrong payload; serialise persistence through one owner.
- [ ] T179 [US6] Roll back optimistic commits on rejection in `apps/desktop/src/hooks/useRuntime.ts:188-194`: "Connect Direct" persists protocol/transport/pinned peer through the settings effect **and** `lib.rs:1340`, so a failed attempt permanently rewrites the user's carrier protocol and shows "Targeting forced endpoint" for a tunnel that never came up.
- [ ] T180 [US6] Commit free-text settings on blur/Enter with existence validation in `apps/desktop/src/components/SettingsTab.tsx:472-479` (the 400 ms debounce alone currently persists `C:\Users\SLiM\Desk` half-typed) and add a `saveError` state rendered in the save dock (fixes T168).
- [ ] T181 [US6] Fix `NumberField`'s zero handling in `apps/desktop/src/components/ui.tsx` to `Number.isNaN(parsed) ? value : parsed` (fixes T169; also affects "Burst Interval" which defaults to 0), and restore `disabled={settingsLocked}` + an explanatory tooltip on "Clear (Scan dynamically)" at `apps/desktop/src/components/ConnectionTab.tsx:210` — the one control lacking the guard while `patchSettings` early-returns, so it silently does nothing.
- [ ] T182 [US6] Rebuild `apps/desktop/src/hooks/useLogs.ts` hit filtering on structured `scan_hit` events already available from `useScanner`, delete the prose-substring predicates, and keep `MAX_LOGS` at the single append site (that part is already correct) (fixes T170).
- [ ] T183 [US6] Stop clearing logs on every connect/disconnect/test in `apps/desktop/src/hooks/useRuntime.ts:160,181,204` — the error line the user was about to copy currently vanishes the instant they press "Try again"; keep clearing only in the Activity tab's own Clear action.
- [ ] T184 [US6] Fix the auto-scroll latch in `apps/desktop/src/components/ActivityTab.tsx:84-89` by resetting `isProgrammaticScrollRef` synchronously after the scroll assignment, not inside a `requestAnimationFrame` throttled when the window is hidden to tray.
- [ ] T185 [US6] Adopt `@tanstack/react-virtual` 3.x (`useVirtualizer`, `estimateSize` + `measureElement`, `overscan: 8`) in `apps/desktop/src/components/ScannerTab.tsx:354` with `useMemo` on `filteredEndpoints` and the sort; `content-visibility: auto` for the log view only (it skips paint but never reduces node count).
- [ ] T186 [US6] Move `ErrorBoundary` to per-tab scope inside each `role="tabpanel"` in `apps/desktop/src/App.tsx` with `resetKeys={[tab, settingsLoadError]}` and a Retry calling `refreshSettings()`; today it wraps only `<App/>` (`main.tsx:8`) so one unexpected payload white-screens the window. Add a payload guard in the `session://state` listener, `heroCopy[status] ?? heroCopy.disconnected` in `ConnectionTab.tsx:86`, and `noUncheckedIndexedAccess` in `apps/desktop/tsconfig.json`.
- [ ] T187 [US6] Self-host the fonts: add `@fontsource-variable/geist` + `geist-mono` (OFL-1.1), import their CSS from TS so Vite hashes the woff2 into `dist/` same-origin under the existing `font-src 'self'`, and delete the Google Fonts `<link>`s from `apps/desktop/index.html:8-10`. No `asset:` protocol (needs enabling, scoping and `font-src asset: http://asset.localhost`) and no CSP relaxation for `fonts.gstatic.com` — a circumvention tool must not make a pre-tunnel third-party request from its UI, which dev mode currently does live.
- [ ] T188 [US6] Re-tune typography against the **actually rendered** font in `packages/ui/tokens.css`: `font-synthesis: none` with 550/650/700 tiers collapses arbitrarily against a static-weight system font and `letter-spacing: -0.012em` was tuned for Geist metrics; set `color-scheme: dark` on `:root`, style `option` elements, and define `::selection` (all three currently absent — 0 occurrences — so option lists are 1.13:1 and text selection 1.24:1, i.e. invisible).
- [ ] T189 [US6] Fix edges per contract U-E1 in `packages/ui/tokens.css` and `apps/desktop/src/App.css:26-29`: `box-shadow: inset 0 0 0 1px var(--edge-interactive)` with **opaque** pre-resolved colours and two tokens (`--edge` ≥1.6:1 decorative, `--edge-interactive` ≥3:1), replacing `--border-subtle .05` / `--border-card .07` / `--line .07` which measure 1.05–1.47:1 and antialiase away at Windows 125/150 % — the mechanical cause of the reported "borderless, floating, out of place" cards. Do not merely raise alpha (still composited, still antialiased); WCAG 1.4.11's 3:1 applies where the boundary is the sole affordance.
- [ ] T190 [US6] Restore motion correctness in `apps/desktop/src/App.css`: define `.spin`/`.spin-icon` keyframes **outside** the `prefers-reduced-motion` block (they currently appear **only** inside it, so both "working" spinners are frozen and a healthy engine looks hung), and make the reduced-motion block cover the 7 animations that actually loop (`radar-sweep-spin`, `ping-ring-pulse`, `breathing-glow`, `sparkline-jitter`, `pulse`, `save-sync-pulse`) instead of naming two non-existent selectors.
- [ ] T191 [US6] Add `@media (hover: hover) and (pointer: fine)` guards around all 27 hover rules in `apps/desktop/src/App.css` (and the mobile copy) — `.profile-card:hover` at `:1178` currently sets a **brighter** border than `.profile-card.active` at `:1193`, so after a tap on Android an unselected card looks more selected than the selected one, persistently.
- [ ] T192 [US6] Complete the CSS integrity pass in `apps/desktop/src/App.css` + `packages/ui/tokens.css`: add the missing rendered classes (`.metric-icon` + `.blue/.coral/.green/.yellow`, `.btn-secondary`, `.retry-btn`, `.status-text`, `.tactile-badge`); delete ~9 orphaned pre-rewrite selectors (`.activity-view`, `.log-line`, `.metrics-grid`, `.status-chip`, `.power-button`, `.save-bar`, …); delete the duplicate `.tactile-copy-btn` block at `:2277` whose equal-specificity position silently kills the emerald hover on all five copy buttons; collapse 8 panel definitions into one `.panel` + modifiers and un-double-class the 6 elements carrying two conflicting panel classes; replace 17 `transition: all`; raise `--muted-dark` `#47535e` (2.40–2.60:1) to ≥4.5:1 and floor labels at 11 px (`.stat-label` is 8.5 px today); unify 6 disabled opacities / 12 radii / 15 border alphas; add `scrollbar-gutter: stable`; make `.sparkline-bar` animate `transform: scaleY()`.
- [ ] T193 [US6] Fix layout traps in `apps/desktop/src/App.css`: `min-width: 0` on the **actual** flex child (the unclassed wrapper at `ConnectionTab.tsx:261`, not `.bento-title-group`) so the bento chip stops being pushed out of the card and clipped instead of ellipsising; stop `.connection-stage{overflow:hidden}` clipping the radar ping rings (≈246 px in a 290 px stage) and `.profiles-panel` clipping the active-card glow; widen the 64 px log time track and switch to 24-hour `hour12: false` (an en-US `02:15:33 PM` is ≈69 px, so rows mis-align twice a day); add `overflow-wrap` for IPv6 and PEM blobs.
- [ ] T194 [US6] Replace viewport and window maths: `100svh`/`100dvh` for all 8 `100vh` (including `.tactical-activity-view`'s `calc(100vh - 76px)`, which under-runs a 74 px + safe-inset topbar so the terminal's bottom rows sit behind the 62 px tab bar); move the desktop minimum off the collision point (`minWidth: 901` in `apps/desktop/src-tauri/tauri.conf.json` or `@media (max-width: 899px)` — today a legal 900 px window hides `.sidebar-bottom`, which contains the primary status widget); add the missing 680–900 px breakpoint so the 4-column profile grid does not squeeze to ~129 px cards; remove `maximum-scale=1.0`; fix the ≤680 px endpoint-row empty grid cell and the undiscoverable protocol-dock overflow.
- [ ] T195 [US6] Fix control semantics in `apps/desktop/src/components/{ui.tsx,ScannerTab.tsx,SettingsTab.tsx,App.tsx}`: filter chips become an APG radio group (`role="radiogroup"`/`radio`, `aria-checked`, roving `tabIndex`, arrow-key cycling) instead of a `role="tablist"` misuse with no `aria-controls`; `role="tablist"` is reserved for the real tab strip with `aria-controls`/`aria-selected`/`role="tabpanel"`; remove `tabIndex={-1}` from the −/+ steppers (mouse-only today); stop a wrapped `<label>` + `aria-label` giving one control two accessible names; ignore `ctrlKey/metaKey/altKey` in `App.tsx:40-52`; add `tabIndex={0}` + `aria-label` to `.tactical-terminal-screen` and `.discovered-list` (keyboard users cannot scroll them today); add `aria-live="polite"`/`role="status"` on the hero and save dock and transfer focus on tab switch; define `:active` press feedback (only 3 of ~20 controls have it); stop printing the raw `DISCONNECTED` enum beside a "Standby" beacon; make state never colour-only (the 7 px dot at 1.96:1 is currently the sole signal) and exclude `.profile-card.active` from the disabled dim so the ACTIVE profile stays identifiable while connected.
- [ ] T196 [US6] **Delete** `endpointPreset` from `apps/desktop/src/types.ts:56` (declared, read by nobody, absent from the Rust struct) and remove the inline hex styles + stray `text-red-400` from `SettingsTab.tsx:40-60`, replacing that banner with the shared `.error-banner` geometry and `var(--coral)`.
- [ ] T197 [US6] Fix Android visual parity in `apps/android/android/app/src/main/res/values/`: add `values-night/themes.xml` (today `Theme.MaterialComponents.DayNight` with a hardcoded `#0D1113` bar paints dark icons on dark in light mode), align `colorPrimary #66E3A4` with `--emerald #00f08a`, and unify the three near-black chrome colours (`#07090b` / `#0D1113` / `#101517`).
- [ ] T198 [US6] Migrate both UIs onto `packages/ui` for tokens, types and components, converting behavioural differences into props (watchdog enable, hydration merge, scan wording, and `speedProfiles` hint copy which lives inline in `ConnectionTab.tsx` on desktop but in `types.ts` on Android).
- [ ] T199 [US6] Reconcile the Android fork's known divergences while porting: `apps/android/src/hooks/useScanner.ts` sets `phase: "Verified"` unconditionally so an empty scan reads "Verified" (desktop's `hasHits` fix was never back-ported); the `.catch()` on `listen` was dropped; `startScan` calls `clearLogs?.()` but omits `clearLogs` from the deps array (stale closure); `defaults.routingMode` differs (`tun` vs `system-proxy` — intended, keep as a prop).
- [ ] T200 [US6] Remove the `/vite.svg` favicon reference from `apps/desktop/index.html` and `apps/android/index.html` (an absolute path the Android asset host blocks, 403-spamming the WebView log via `MainActivity.kt:104`) and add a real `assets/www/` icon.
- [ ] T201 [US6] **Checkpoint**: T165–T171 green; run quickstart §6 including measured screenshots at 100/125/150 % and the 2 000-row frame-time assertion.

**Checkpoint**: The UI stops lying by omission (unstyled blocks, frozen spinners, invisible option lists) and by fabrication (numbers that were never measured), and one type source now protects both platforms.

---

## Phase 9: User Story 7 — Android Keeps Working When the Network Changes (Priority: P2)

**Goal**: A Wi-Fi↔cellular handoff restores data within 30 s or states "reconnect required"; loop avoidance fails closed; nothing blocks the bridge thread; the process-singleton emitter survives activity churn; the APK meets 2026 Play and 16 KB page-size requirements.

**Independent Test**: quickstart.md §9 — a fake builder whose `addDisallowedApplication` throws must prevent `establish()`; `decideLiveness` table-driven across four signatures; `invoke()` returns < 50 ms behind a 12 s stub with every request id resolved exactly once; `onStop` of activity A leaves B receiving events.

### Tests for User Story 7 (write first — must fail)

- [ ] T202 [P] [US7] Failing test in `apps/android/android/app/src/test/java/app/aethernext/AetherVpnServiceTest.kt`: a fake `VpnService.Builder` whose `addDisallowedApplication` throws must prevent `establish()` and yield an error state. Fails today: `AetherVpnService.kt:130-134` swallows the exception with `catch (_: Exception) { }` and establishes `0.0.0.0/0` anyway — self-routing loop, MTU collapse, total no-connectivity, nothing logged. There is no `protect()` anywhere in the codebase.
- [ ] T203 [P] [US7] Failing table-driven test in new `apps/android/android/app/src/test/java/app/aethernext/LivenessTest.kt` against T004's `decideLiveness`: `rx↑ && tx==0` ×3 windows ⇒ Dead; all-zero ×6 with a failed probe ⇒ Dead; healthy ⇒ Alive; `attempt ≥ 3` ⇒ Exhausted. Fails today: `TProxyGetStats()` is declared at `AetherVpnService.kt:384` and **never called**; `onLost` only does `setUnderlyingNetworks(null)` (`:143-171`); `markConnected()` is a one-shot compare-and-set (`SessionController.kt:403-411`) that can never be revoked — a green badge over a blackhole is the default outcome of every handoff.
- [ ] T204 [P] [US7] Failing test in new `apps/android/android/app/src/test/java/app/aethernext/AetherBridgeTest.kt`: `invoke()` returns in < 50 ms while a 12 s stub blocks, and every request id receives exactly one resolution (ok or timeout). Fails today: `@JavascriptInterface invoke` runs on the JavaBridge thread and blocks there — `stopAndWait`'s `Thread.sleep(50)` poll (`EngineRunner.kt:291-305`), `VpnService.prepare()`'s binder call, `startForegroundService`, and a synchronous 12 s OkHttp `execute()` (`SessionController.kt:233-254`) — freezing the single-threaded JS runtime.
- [ ] T205 [P] [US7] Failing test in new `apps/android/android/app/src/test/java/app/aethernext/MainActivityTest.kt`: consent must be requested on the main thread, and `onStop` of activity A must leave activity B's listener receiving events. Fails today: `AetherBridge.kt:54` calls `activity.requestVpnPermission()` from the bridge thread, `MainActivity.kt:188-197` uses `startActivityForResult` there (main-thread-only; the bridge's `catch (e: Exception)` at `:31` swallows the outcome), and `onDestroy` installs a no-op emitter on the **process singleton** with `launchMode` default `standard` — one activity's destroy silences another's events.
- [ ] T206 [P] [US7] Failing test in `apps/android/.../SessionControllerTest.kt`: `stopVpnService()`/`disconnect()` must surface failure. Fails today: `:360-369` swallows `IllegalStateException` from a background `startService` and `disconnect()` unconditionally reports `disconnected/Ready` — the user is told the VPN is off while the tun is up. Also assert a reconnect with a **new** SOCKS port is honoured: `onStartCommand` sees `tun != null` and drops the new port without re-establishing and without `onVpnEstablished()` (`AetherVpnService.kt:65-66`, `SessionController.kt:148`), and `connect()` never calls `stopVpnService()` first.
- [ ] T207 [P] [US7] Failing Robolectric test in new `apps/android/android/app/src/test/java/app/aethernext/VpnBuilderArgsTest.kt` capturing `VpnService.Builder` arguments (addresses, routes, DNS, `setMtu(1280)`, per-family correctness) and network-callback behaviour via `ShadowConnectivityManager`. Replaces `AetherVpnServiceTest.kt:12-33`, which asserts on an `AtomicLong` — tautological, so the headline "VPN lifecycle" coverage is illusory.

### Implementation for User Story 7

- [ ] T208 [US7] Make loop avoidance fail-closed in `apps/android/.../AetherVpnService.kt` (fixes T202) and document why `protect()` cannot reach the engine's sockets (`protect(int)` operates on an fd in the caller's table and the engine is a `ProcessBuilder` child), so `addDisallowedApplication` is the mechanism and its failure is fatal.
- [ ] T209 [US7] Implement the liveness watchdog in `apps/android/.../AetherVpnService.kt` using `TProxyGetStats` (semantics `[tx_packets, tx_bytes, rx_packets, rx_bytes]`, zeroed on each `hev_socks5_tunnel_main()` entry, so capture the baseline **after** `TProxyStartService`), polling every 5 s on the worker, wired to `decideLiveness` in `Liveness.kt` (fixes T203).
- [ ] T210 [US7] Implement the supervised restart in `apps/android/.../SessionController.kt`: bump `vpnGeneration`, `TProxyStopService()`, close the fd, re-`establish()`, restart hev — 3 attempts with 2/8/30 s backoff, then a terminal `error` state with "Network changed — reconnect required" and no auto-retry until the user taps connect; make `markConnected()` revocable via `resetConnected()`.
- [ ] T211 [US7] Convert the bridge to async in `apps/android/.../AetherBridge.kt` + `apps/android/src/bridge.ts`: `invoke(cmd, argsJson, requestId)` returns immediately, work dispatches onto `SessionController.scope`, results resolve via `evaluateJavascript("__aetherResolve(<id>,<json>)")`, JS holds a `Map<id, resolver>` with a 30 s timeout (fixes T204). Rejected: Capacitor's plugin runtime (a whole runtime + config for one bridge) and `WebMessageListener` (needs a JS port handshake, unusable before page load).
- [ ] T212 [US7] Adopt coroutines as the module's single concurrency model in `apps/android/.../{SessionController,AetherVpnService,EngineRunner}.kt`: `SupervisorJob() + Dispatchers.IO`; make `disconnect()`/`testConnection` `suspend`; delete `Thread.sleep` poll loops. `kotlinx-coroutines-android` is already declared and unused — this is the decision that consumes it rather than dropping it.
- [ ] T213 [US7] Fix the activity lifecycle in `apps/android/.../{MainActivity,SessionController.kt}`: `@Volatile` emitter plus a `CopyOnWriteArrayList` listener registry added in `onStart`/removed in `onStop`, `launchMode="singleTask"` in `AndroidManifest.xml`, `registerForActivityResult` for consent, `pendingConnectAfterVpn` made `@Volatile` and reset inside the posted block, and `onRevoke` only setting flags + posting to the scope (AOSP documents that `onRevoke` "may not happen on the main thread" and requires closing the fd; note `stopProtected()` does **not** exist in AOSP and must not be planned around) (fixes T205).
- [ ] T214 [US7] Move teardown off the main thread and replace the fixed `Thread.sleep(150)` in `AetherVpnService.kt:291-333` with a bounded join or eventfd ack, so `onRevoke` from Quick Settings cannot ANR behind a lock held across `establish()`'s netd binder call.
- [ ] T215 [US7] Make cross-thread state actually volatile in `AetherVpnService.kt:36-39,65,73` and `SessionController.kt:33`: `tun`, `stopRequested`, `hevStarted`, `settings`, `emit`; read them **inside** `lifecycleLock`; have `getState()` return a snapshot copy (today `toJson()` can serialise `status="connected"` with a previous session's `pid`).
- [ ] T216 [US7] Honour a changed SOCKS port on reconnect in `apps/android/.../SessionController.kt`: bump `vpnGeneration`, tear down and re-establish, and call `stopVpnService()` at the top of `connect()` (fixes T206's second half).
- [ ] T217 [US7] Add supervision policy in `apps/android/.../{EngineService,AetherVpnService}.kt`: `START_STICKY` + `onTaskRemoved { stopSelf() }`, a partial wake lock only while `status == connected`, a `WorkManager` periodic keep-alive, and `ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS` offered with an eligibility explanation. Both services are currently `START_NOT_STICKY` with no retry, so a LowMemoryKiller kill ends everything silently and doze can stall QUIC timers.
- [ ] T218 [US7] Fix the boot path in `apps/android/.../BootReceiver.kt`: check `areNotificationsEnabled()` and fall back to a persistent in-app "tap to start" state (today a denied `POST_NOTIFICATIONS` silently drops `notify()` and the `catch` hides the rest, making "Launch at login" a no-op); delete the pre-Q `startActivity` branch that is dead at minSdk 26 on API 29+ devices.
- [ ] T219 [US7] Harden the WebView in `apps/android/.../MainActivity.kt`: HTML-escape `error.description`/`request.url` in `showLoadError` (`:170-185`), gate `invoke()` on the caller origin / `webView.url` host, and `removeJavascriptInterface` before loading any error page — that page still has the bridge attached today. Install `Thread.setDefaultUncaughtExceptionHandler` once from an `Application.onCreate` with an idempotency flag instead of re-chaining it every `onCreate` (`:32-47`).
- [ ] T220 [US7] Bump `compileSdk`/`targetSdk` to 36 with AGP ≥ 8.7 in `apps/android/android/build.gradle.kts` and `apps/android/android/app/build.gradle.kts` — Play requires API 36 for new apps and updates from 2026-08-31 (extendable 2026-11-01), so an API 34 APK is not updatable.
- [ ] T221 [US7] Meet the 16 KB page-size requirement (enforced from 2027-02-01 for apps targeting 35+): drop `useLegacyPackaging`/`extractNativeLibs="true"` for `extractNativeLibs=false` + AGP's 16 KB zip alignment, and add `RUSTFLAGS="-C link-arg=-Wl,-z,max-page-size=16384 -C link-arg=-Wl,-z,common-page-size=16384"` to the `cargo ndk` step in `.github/workflows/build.yml` (NDK r27d does **not** default to 16 KB). Note `useLegacyPackaging` fixes installation only, not ELF alignment.
- [ ] T222 [US7] Replace `test -s` with digest verification: add `apps/android/hev-lock.json` (upstream tag + per-ABI sha256 + build recipe) and build `libhev-socks5-tunnel` from that tag in CI, verifying `readelf -l` `p_align ≥ 0x4000` and the JNI symbols. Record honestly that the committed blobs are already 0x4000-aligned but **untraceable** — their strings show a `void TProxyStartService (Ljava/lang/String;I)V` signature differing from upstream and **no** `TProxyIsRunning`, built from `third_party/hev-socks5-tunnel/`, a directory absent from this repo.
- [ ] T223 [US7] Add a monochrome `apps/android/android/app/src/main/res/drawable/ic_notification.xml` and use it for `setSmallIcon` in `AetherVpnService.kt:275`, `EngineService.kt:31`, `BootReceiver.kt:46` (today `R.mipmap.ic_launcher` renders as a solid white silhouette), and set `isShrinkResources = true` alongside the existing `isMinifyEnabled`.
- [ ] T224 [US7] Update dependencies in `apps/android/android/app/build.gradle.kts`: `androidx.webkit` → 1.14.x, `okhttp` → 5.x; confirm the Play VPN declaration and prominent-disclosure requirement remains satisfied by the existing `FOREGROUND_SERVICE_SPECIAL_USE` + `PROPERTY_SPECIAL_USE_FGS_SUBTYPE` (audited clean today, along with `allowBackup="false"`, cleartext forbidden, explicit `exported` on every component, `FLAG_IMMUTABLE`, MODE_PRIVATE prefs, and the WebView's host-lock + `allowFileAccess=false`).
- [ ] T225 [US7] **Checkpoint**: T202–T207 green on Robolectric, then quickstart §9 on a real ARM device — 20 handoffs, task swipe, doze, locked-screen keystore access, fresh-install consent.

**Checkpoint**: The phone either works or says it does not. The most damaging Android failure — interface up, no data path, green badge — is closed.

---

## Phase 10: User Story 8 — Every Claim of "Fixed" Is Mechanically Refutable (Priority: P3)

**Goal**: No guard ships without a test that fails when it is removed; no build step silently produces an empty input for a later check; CI holds least privilege and never interpolates secrets into a shell; every invariant gate proves it can fire.

**Independent Test**: `scripts/verify-invariants --selftest-fail` exits non-zero (SC-013); a corrupted `hev-lock.json`/`engine-trust.json` fails the build; the traceability table maps every audit finding to a task and a red→green test.

### Tests for User Story 8 (write first — must fail)

- [ ] T226 [P] [US8] Failing test for the staged-digest gate: with `resources/aether.exe` absent (the normal clean-checkout state, since `.gitignore` excludes it), the pipeline must **error**, not emit an empty digest set. Fails today: `apps/desktop/src-tauri/build.rs:38-53` hashes nothing, emits no entry, and `unwrap_or_default()` swallows it — the canonical instance of the pattern this feature exists to kill.
- [ ] T227 [P] [US8] Failing tests in `apps/android/android/app/src/test/java/app/aethernext/{AetherVpnServiceTest.kt,EngineRunnerTest.kt}` proving the suites are not tautological: each must assert on the class under test, not on an `AtomicLong` or on enum **names** (supersedes the remaining supervisor-state case after T207's replacement).
- [ ] T228 [P] [US8] Failing static-analysis checks in CI: `zizmor` must flag the current `build.yml:304-305` secret interpolation (`printf '%s' "${{ secrets.ANDROID_KEYSTORE_BASE64 }}"` inside `run:`) and `ci.yml`'s missing `permissions:` block on a `pull_request` trigger; `actionlint` must be clean.

### Implementation for User Story 8

- [ ] T229 [US8] Implement every `--selftest-fail` injection handler in `scripts/verify-invariants.*` — one per BC-01…BC-22 invariant — each injecting the defect it detects and asserting non-zero exit (satisfies SC-013 and T028's rule).
- [ ] T230 [US8] Add `scripts/audit-traceability.ps1`, generating finding → invariant → task → test from the 2026-09-21 finding list and **failing when any finding is unmapped** (FR-046, SC-001).
- [ ] T231 [US8] Set `permissions: {}` at the top of `.github/workflows/{ci.yml,build.yml}` with per-job least privilege (`contents: read`; publish adds `contents: write` + `id-token: write`) and an `environment: release` with a required reviewer for tag runs.
- [ ] T232 [US8] Move all secret material into `env:` indirection in `.github/workflows/build.yml:304-305` with `::add-mask::` and never `echo` it; keep explicit file globs plus `if-no-files-found: error` on uploads; keep the publish job's artefacts flat (its `merge-multiple` whole-tree download is the risky pattern).
- [ ] T233 [US8] Add `actions/attest-build-provenance@v2` for the exe and APK (`subject-path: dist-windows/*`, `dist-android/*`) and document `gh attestation verify` in `Docs/GUIDE.en.md`.
- [ ] T234 [US8] Track `packaging/*.sha256` and `packaging/trust/certificate-sha256.txt`, and make `build.yml:315` read the expected wintun digest from them instead of a hardcoded constant.
- [ ] T235 [US8] Extend `.gitignore` with `*.key`, `*.pem`, `*.pfx`, `*.crt` plus explicit `!` exceptions for the vendored example keys under `quiche/` (2 147 tracked files live there — 88 % of the 2 433 tracked total — including `quiche/{apps/src/bin,fuzz,quiche/examples,tokio-quiche/examples}/cert.key`).
- [ ] T236 [US8] Pin the vendored `quiche/` tree with a committed checksum and `packaging/quiche-patches.md` recording every local deviation (the fork's `dgram_recv` pop-before-length-check, `to_wire()`'s non-standard `BufferTooShort → 0x999`, and the `h3::Error != quiche::Error` distinction Aether already trips over) so an upgrade cannot silently change semantics.
- [ ] T237 [US8] Wire `cargo deny check`, `osv-scanner`, `zizmor`, `actionlint` and the T007 disallowed-methods clippy gates into `.github/workflows/ci.yml`, and record the honest posture note: `RUSTSEC-2023-0071` is the **`rsa` Marvin** advisory, not a `ring` one, so `ring 0.16.20` via `boringtun 0.6.0` is an EOL/duplicate-crate risk rather than a known vulnerability; `x25519-dalek =2.0.0-rc.3` is a hard pin to a pre-release and must be raised or justified.
- [ ] T238 [US8] Add the release-time verification step recomputing the staged engine digest and failing on any mismatch with `packaging/trust/engine-trust.json` (pairs with T071/T226).
- [ ] T239 [US8] **Ratify the constitution** (FR-045): populate `.specify/memory/constitution.md` — currently an unpopulated template with `[PRINCIPLE_1_NAME]` placeholders, i.e. **zero ratified principles** — with BC-01…BC-22 as principles: falsifiable fixes, no unverifiable completion claims, fail-closed host mutation, no unencrypted secrets, no fabricated telemetry, one contract source. The empty template is why fourteen prior rounds could each claim completion.
- [ ] T240 [US8] Remove untracked working-tree clutter that misleads readers (`architecture-review-20260723.html`, `rustup-init.exe` 12 MB, stale `aether*.toml` working files), confirming via `git ls-files` that none are tracked so no history rewrite is needed.
- [ ] T241 [US8] **Checkpoint**: `scripts/verify-invariants` exits 0 **and** `--selftest-fail` exits non-zero; `zizmor` clean on both workflows; the traceability table generated with zero unmapped findings.

**Checkpoint**: The remediation is now self-defending: a future regression of any fixed class fails CI rather than waiting for another audit.

---

## Phase 11: Polish & Cross-Cutting Concerns

**Purpose**: The long tail of the audit — drift, dead code, silent substitutions and remaining bounds — plus final validation.

- [ ] T242 [P] Sweep dead code and drifted duplicates in `aether/src/`: unify two identical `bytes_to_ip` (`quic.rs:816`, `masque_h2.rs:810`) and two `drain_capsules` with opposite drop policies into `masque.rs`; stop `H3DgramMode::from_env()` being read once in `run` but re-read per probe and per 200 ms tick; fix `ReaderGuard`'s comment citing "every Migrate" while migration is disabled (`tls.rs:181`); replace `session.rs:1094`'s hardcoded 2048 with `tunnel::NET_QUEUE`; delete the dead `ScanCancellationToken` (`prober.rs:310-339`) and `SCAN_GENERATION` (`:341`, stored at `:396`, never read); correct `session.rs:167-169`'s port-tier comment, which is the **reverse** of `MASQUE_PORTS_T1/T2` (`prober.rs:1106-1107`).
- [ ] T243 [P] Propagate instead of substituting remaining identity/config parse errors in `aether/src/session.rs`: `parse().unwrap_or(Ipv4Addr::new(172,16,0,2))` at `:471-474,589-592,689-692` (a malformed tunnel address becomes a **wrong source address**, then fails as "network blocking QUIC"), `.parse().ok()` at `:756`, and `Protocol::parse` at `:92-98` mapping any typo to MASQUE; plus `account.rs:411-422` silently zeroing a corrupt `client_id`.
- [ ] T244 [P] Fix remaining engine leaks in `aether/src/`: bind and abort the H2 connection driver task (`masque_h2.rs:478-482`, today spawned with no handle while `send_task`/`recv_task` are correctly aborted at `:637-638`); cap the unbounded `while let Ok(more) = try_recv()` batch (`quic.rs:492-508`) at 128 as `masque_h2.rs:561` already does; use `base.saturating_add(off)` at `prober.rs:1028` mirroring `enumerate_cidr_v4` at `:1004`.
- [ ] T245 [P] Add obfuscation-layer bounds in `aether/src/{aethernoize.rs,obfuscation.rs}`: clamp `jmin/jmax` to `[0,512]` (an unbounded `AETHER_NOIZE_JMIN=1e8` allocates 100 MB per packet today), keep totals under the path MTU, replace the constant `0x00` emitted for a `(0,0)` pair (a worse fingerprint than sending nothing) with random 1-4-byte filler, remap the decoy first byte so the `+0x40` collision fix does not re-enter WG's 1-4 type range (`aethernoize.rs:281-284`), and `u16::try_from` the IKEv2 `sa_payload_length` (`:134`) instead of `as u16` truncation that makes the header lie.
- [ ] T246 [P] Make `client_id` injection a per-tunnel random 3-byte tag, **default off** (`aether/src/wireguard.rs:19-37`): `mac1` is computed over the packet with reserved bytes zeroed, so against any standards-strict WG peer every injected packet fails authentication (undialable, no diagnostic), and against Cloudflare it emits a stable cleartext per-account identifier on every packet including thousands of probe packets.
- [ ] T247 [P] Fix the two `let _ =` TLS no-ops in `aether/src/tls.rs:87-94`: `set_cipher_list` governs only pre-1.3 suites so the "rotate ClientHello profile per-session" control changes nothing while its error is discarded — use `set_ciphers13`/signature-algorithm permutation and propagate failure; raise the H2 floor from TLS 1.2 to 1.3 in `aether/src/masque_h2.rs:70-74`.
- [ ] T248 [P] Replace relative-path defaults in `aether/src/engine_config.rs:30` (`config_path` defaults to `"aether.toml"` against the CWD, so a desktop-shortcut launch can read/write in `C:\Windows`) with a per-user data directory, reject a relative `AETHER_CONFIG`, and stop deriving `cache_path`/`session_ticket_path` by string surgery on it.
- [ ] T249 [P] Add `cargo fmt --check`, `npx tsc --noEmit` for both apps, and stylelint to `.github/workflows/ci.yml`; run `npx stylelint 'apps/*/src/**/*.css' --fix` after T192's structural edits, then hand-verify the token diff.
- [ ] T250 [P] Update `Docs/GUIDE.en.md`, `README.md` and `PRODUCT.md` for the ratified constitution's invariants, the pin-rotation procedure, `--repair-routes`/`--repair-proxy`, the diagnostics export, and the deliberately-unsigned-updater decision.
- [ ] T251 [P] Mark `specs/001`–`specs/014` superseded by `015` with a one-line note each rather than deleting them, so no future reader treats `014`'s 40/40 `[x]` as evidence of fixed behaviour.
- [ ] T252 Run the complete `quickstart.md` validation end to end (all 9 sections including the §1 soak and §9 device pass), attach artefacts, and record each guard's step-3 mutation result.
- [ ] T253 Run `/speckit-converge` to diff the shipped tree against FR-001…FR-047 and append any unbuilt work as new tasks, then `/speckit-analyze` for cross-artifact consistency, then re-verify every `tasks.md` checkbox against source rather than trusting it — the discipline this feature exists to install.

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1, T001–T012)**: no dependencies.
- **Foundational (Phase 2, T013–T030)**: depends on Setup; **blocks every user story.** T014 (config store), T018–T020 (typed contract), T021–T022 (envelope + registry substrate), T023 (counters) and T005/T028 (gate harness) are what the stories consume.
- **User stories (Phases 3–10)**: all begin after Phase 2. They are **not** mutually independent at file level — see Serialisation Warnings.
- **Polish (Phase 11, T242–T253)**: after the stories it touches; T252–T253 last.

### Story Order and Cross-Story Constraints

| Story | Priority | Can start after | Hard constraints |
|---|---|---|---|
| US1 Host state | P1 🎯 MVP | Phase 2 checkpoint | None beyond Phase 2 |
| US2 Trust | P1 | Phase 2 **and T037** (the journal defines what teardown must survive) | Shares `apps/desktop/src-tauri/src/lib.rs` with US1 → serialise T045/T048–T051 against T060–T071 |
| US3 Secrets | P1 | T039 (the engine must stop owning the identity file before the envelope lands) | Shares `aether/src/config.rs` with T021/T091–T094 → one owner |
| US4 Transport truth | P2 | Phase 2 checkpoint | Shares `aether/src/quic.rs` with US5 → US4 before US5 |
| US5 Netstack | P2 | T113–T114 (shared fatal-vs-retryable conventions) | Depends on US4's error taxonomy |
| US6 Contract+UI | P2 | T019/T020 **and** T071/T098/T121/T175 (components must be rewritten against generated bindings and finalised behaviour) | Depends on US4's watchdog; T198 must follow US7's T211–T213 or `apps/android/src` is edited twice |
| US7 Android | P2 | T020 (typed events) + T121 (watchdog semantics) + T129 | Shares nothing outside `packages/ui` with US6 |
| US8 Gates | P3 | Every gate has a corresponding fix — run T229/T230 continuously; T239 last | — |

### Within Each User Story

Tests first and provably red → entities/models → services → host integration → guard-reachability mutation. No story checkpoint passes on a green-only run.

### Parallel Opportunities

- **Setup**: T002–T011 all parallel (distinct paths).
- **Foundational**: T013, T016–T017, T021–T027 largely parallel; T018→T019→T020 strictly sequential; T014→T015 sequential.
- **Across stories once Phase 2 is done** — four independent lanes: **US1** (T031–T052, `tun_win.rs` + `lib.rs`) ∥ **US4** (T104–T130, engine transports) ∥ **US5** (T131–T164, `netstack.rs`/proxies, after T113–T114) ∥ **US7** (T202–T225, Kotlin, after T020).
- **Within US3**: T079–T088 parallel (distinct test files), then three lanes: `config.rs` (T089→T094 serialised) ∥ `cache.rs` (T098→T101 serialised) ∥ T095/T096/T097/T102 independent.
- **Within US6**: T165–T171 parallel; T172–T186 mostly distinct TS/TSX files; **T187–T197 must not overlap** — all edit `apps/desktop/src/App.css` or `packages/ui/tokens.css`.
- **Within US8**: T226–T228 parallel; T231–T238 serialised by shared `ci.yml`/`build.yml`.

### Serialisation Warnings (shared files — assign one owner each)

| File | Tasks touching it |
|---|---|
| `apps/desktop/src-tauri/src/lib.rs` (2 248 lines) | T018–T020, T024, T045–T051, T060–T071, T095–T096, T121–T124, T128, T161, T172 |
| `apps/desktop/src/App.css` / `packages/ui/tokens.css` | T187–T198 |
| `aether/src/quic.rs` | T104–T108, T111–T120, T242, T244 |
| `aether/src/netstack.rs` | T131–T137, T142–T150, T153, T156 |
| `aether/src/config.rs` | T017, T021, T081, T089–T094 |
| `aether/src/cache.rs` | T022, T082–T084, T098, T101 |
| `aether/src/session.rs` | T117, T100, T122, T126, T242, T243 |
| `aether/src/{socks.rs,http_proxy.rs,dns.rs}` | T136–T141, T151–T158, T163 |
| `apps/android/.../{AetherVpnService,SessionController}.kt` | T202–T216 |
| `Cargo.toml` (engine + shell) | T009, T019, T075, T145, T221 |
| `.github/workflows/build.yml` | T075–T076, T221, T231–T238 |
| `.github/workflows/ci.yml` | T228, T231–T232, T237, T249 |

---

## Parallel Example: User Story 3 (Secrets & Learned State)

```bash
# Red tests first — distinct files, all parallel:
T079  aether/tests/envelope_v2.rs                T080  aether/tests/envelope_v2.rs (path-binding case)
T081  aether/tests/atomic_write_test.rs          T082  aether/tests/cache_validation.rs
T083  aether/tests/cache_concurrency.rs          T084  aether/tests/cache_read_nondestructive.rs
T085  aether/tests/h2_endpoint_survival.rs       T086  ConfigKeyStoreTest.kt
T087  aether/tests/acl_principal.rs              T088  dpapi_key_test.rs

# Then three independent implementation lanes:
Lane-1 (aether/src/config.rs, serialised): T089 → T090 → T091 → T092 → T093 → T094
Lane-2 (aether/src/cache.rs,  serialised): T098 → T099 → T100 → T101
Lane-3 (independent):                      T095 ∥ T096 ∥ T097 ∥ T102
```

## Parallel Example: User Story 5 (Netstack) — after T142

```bash
# aether/src/netstack.rs — same file, serialise within the lane:
T143  keep-alive + bounded abort on Established
T144  TX_RING bound + tx_deferred counter
T145  128 MB admission budget
T146  strict FIFO in flush_tx
T147  loop fairness (drop `biased`, poll_ingress/poll_egress split)
T148  non-panicking accessors + guard scope
T149  per-class quotas
T150  ephemeral port randomisation
T153  UdpSender ownership             T156  write-error propagation
# parallel with the above (different files):
T151  socks.rs  DNS cache LRU         T152  socks.rs  UDP origin map
T154  http_proxy.rs  CRLF boundary    T155  dns.rs  ECH reply validation
T157  netstack.rs+socks.rs deny-list  T158  socks.rs  protocol edges
T159  prober.rs budgets               T160  prober.rs  spawn_blocking persistence
T161  lib.rs  scan_mode plumbing      T162  mtu.rs     T163  caps honesty
```

## Parallel Example: Four-Lane Delivery after Phase 2

```bash
Lane-Windows : T031…T052   (US1) then T053…T078 (US2, lib.rs handoff to single owner)
Lane-Engine  : T104…T130   (US4) then T131…T164 (US5)
Lane-Kotlin  : T202…T225   (US7, after T020 + T121)
Lane-Contract: T165…T201   (US6, after T019/T020) — and T226…T241 (US8) continuously
```

---

## Implementation Strategy

### MVP First — User Story 1 only

The smallest slice that stops the application damaging the user's machine.

1. Complete Phase 1 Setup (T001–T012).
2. Complete Phase 2 Foundational (T013–T030) — **non-negotiable**: without the gate harness and the typed contract, later stories regenerate the same drift.
3. Complete Phase 3 US1 (T031–T052).
4. **STOP and VALIDATE**: quickstart §1 scenarios A–F, plus T052's guard-mutation pass.
5. Ship. Route/proxy state can no longer be left damaged by any termination path, and nothing else regressed.

### Incremental Delivery

1. **US1** → the machine is safe. *(MVP)*
2. **+ US2** → release TUN actually works for end users, and the engine cannot be swapped.
3. **+ US3** → identities and learned state are authentic; the Android identity stops self-destructing.
4. **+ US4** → "connected" means connected; a false positive stops poisoning the trust cache.
5. **+ US5** → idle sessions survive, memory is bounded, the scanner reports honestly.
6. **+ US6** → the UI stops rendering unstyled blocks and invented numbers, and drift becomes a build failure.
7. **+ US7** → the phone recovers from a handoff or admits it needs a tap; APK is 2026-compliant.
8. **+ US8** → all of the above stay fixed without another audit discovering they did not.

Each story adds value without invalidating the previous ones; every increment is independently demonstrable and ships behind its own green checkpoint.

### Parallel Team Strategy

With multiple contributors: finish Phases 1–2 together (the contract and gate harness are shared infrastructure), then split the four lanes above by file ownership, honouring the Serialisation Warnings table. `apps/desktop/src-tauri/src/lib.rs` and `aether/src/{quic.rs,netstack.rs,config.rs,cache.rs}` must each have exactly one active owner.

### Risk-Ordered Fallback

If capacity forces a cut line, take Phases 1–5 plus Phase 10's T229/T230/T239 (machine safety, trust, secrets, and the gate harness) — that removes every defect that can damage a host, destroy an identity, or silently mislead a future maintainer, and defers usability polish (US5/US6/US7's non-safety items) without weakening a single safety invariant.

---

## Notes

- `[P]` = different files, no incomplete dependency. Same-file tasks are serialised by the tables above regardless of priority.
- Every task states its own failing-then-passing evidence; the audit finding it closes is named inline so `scripts/audit-traceability.ps1` (T230) can parse it.
- Numeric constants in task text are contract values from `data-model.md` and `research.md` — do not re-derive them at implementation time: `TX_RING=256`, `enable_dgram(true,2048,2048)`, `45_000 ms` max idle, `15 s` keep-alive / `75 s` established abort, `MAX_UDP_PROXY=96`/`RESOLVER=32`, `MAX_TCP_PROXY=480`/`RESOLVER=32`, `128 MB` budget, `175 s` WG session cache TTL, junk clamp `[0,512]`, `MAX_SUCCESSES=1000`, `now+300 s` timestamp reject, `90 s` route lease / `30 s` refresh, `15 s` grace (from 5 s), teardown `< 500 ms`, `0x40000` revocation flag, `90 s` connect watchdog / `15 s` heartbeat / 3 misses, `3` restarts at `2/8/30 s`, `3×` keystore retry at `200/1000 ms`, `overscan: 8`, `SCAN_MAX = 500`, `minWidth 901`/`(max-width: 899px)`, `4.5:1`/`3:1`/`1.6:1` contrast, `11 px` type floor, `24 px`/`44 px` targets, `p_align ≥ 0x4000`, `targetSdk 36`.
- Commit after each task or logical group; stop at every checkpoint to validate independently.
- **Do not mark a task `[x]` without recording its step-3 guard-mutation result.** That single discipline is the difference between this feature and the fourteen that preceded it.

## Execution log (implement phase)

- **Reverted: root npm workspace manifest.** A root `package.json` with
  `workspaces: [packages/ui, apps/desktop, apps/android]` makes `npm ci` inside
  `apps/*` resolve to the workspace root, which then demands a root
  `package-lock.json`; CI's per-app installs (`cache-dependency-path:
  apps/desktop/package-lock.json`) failed with `EUSAGE`. The drift that actually
  hurts is duplicated *source*, which `packages/ui` + T188–T194 address by
  importing shared tokens, not by a shared install graph. Re-open only together
  with a committed root lockfile and CI changes in the same PR.
