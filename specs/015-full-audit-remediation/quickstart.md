# Quickstart: Validating the Full-System Audit Remediation

**Feature**: `015-full-audit-remediation` | **Date**: 2026-09-21
**Related**: [spec.md](spec.md) · [plan.md](plan.md) · [research.md](research.md) · [data-model.md](data-model.md) · [contracts/](contracts/)

This is a **validation** guide, not a build guide. Its purpose is to prove each remediated class of defect stays fixed — and, just as importantly, to prove that each check is capable of failing. A gate that cannot fail is the defect this feature exists to eliminate.

## Falsifiability protocol (applies to every section)

For each fix, run all three steps. A fix that passes only step 3 is **not done**:

1. **Red on old code** — run the new test against the pre-fix revision (or with the fix reverted) and observe failure.
2. **Green on new code** — run it against the remediated tree and observe pass.
3. **Guard reachable** — mutate or delete the *guard* (not the feature code) and confirm the test still fails. This is the step missing from the previous fourteen audit rounds: `specs/014/tasks.md` is 40/40 complete while its "fail-closed missing digest" check is unreachable, because `resources/*.exe` is gitignored so `build.rs:38-53` hashes nothing and emits no entry.

## Prerequisites

- Rust stable (the workspace builds on 1.88+), `cargo`, `cargo-clippy`, `cargo-deny`.
- Node 22+ and npm (workspaces require a single root `package.json` once `packages/ui` exists).
- Visual Studio Build Tools + WebView2 runtime for the Tauri shell; `windows-sdk` headers for `netioapi` bindings.
- Android Studio / SDK 36 platform, NDK r27d, JDK 21.
- **For real-environment validation (mandatory, not optional):** a Windows 11 VM with snapshot/restore, one ARM Android device with developer VPN logging, and a second third-party VPN installed (OpenVPN or Cisco AnyConnect) to act as the decoy whose routes must survive.
- A local fake MASQUE peer for hostile-input tests: the vendored fork exposes `test_utils::Pipe` through its `internal` feature (`quiche/quiche/src/test_utils.rs`) — enable it in dev builds only.
- Optional: a proxying network stack (mitmproxy/BPF) to inject 103s, off-stream 200s and oversized datagrams.

```bash
git clone <this repo> && cd Aether
cargo build -p aether && npm ci                       # root workspace, after packages/ui lands
cargo test -p aether --lib && cargo test -p aether --tests
cd apps/desktop && npm ci && npm test && cd -
cd apps/android && npm ci && npm test && cd -
cargo clippy -p aether -p aether-desktop --all-targets -- -D warnings
```

## 0. Prove the gates can fail (SC-013 — run this first)

```bash
scripts/verify-invariants --selftest-fail
```
**Expected:** exit **non-zero**, with one injected defect per invariant (BC-01…BC-22) and a message naming each. If this command exits 0, stop: every green check below is meaningless.

Then run the gates against the current tree to record the baseline of real failures:

```bash
scripts/verify-invariants            # expected today: FAIL
```
**Expected initial failures** (each one is a confirmed audit finding — their presence proves the checks are wired to the right things): `.metric-icon` unresolved (4 uses, 0 definitions), 8 `100vh`, 17 `transition: all`, 27 unguarded `:hover`, undefined `var(--x)` count 0 *(this one passes today)*, `std::env::var("AETHER_` found outside `runtime_env`, 5 registered-but-uninvoked Tauri commands, `Result<_, String>` in the shell command surface, `AETHER_WINTUN` read in the engine, `#[serde(default)]` on `EndpointsCache` absent.

---

## 1. Host network state (US1, FR-001…004, BC-05) — contracts/host-state-contract.md

```bash
cargo test -p aether --test route_journal_scoping -- --nocapture
cargo test -p aether --test route_teardown_budget
apps/desktop/src-tauri/tests: cargo test -p aether-desktop --test proxy_restore -- --nocapture
```

**Scenario A — decoy survival (INV-1).** Install OpenVPN, bring up its split tunnel, record `route print`. Start Aether in TUN, connect, disconnect.
**Expected:** OpenVPN's `0.0.0.0/1` and `128.0.0.0/1` present and byte-identical. **Today:** when Aether's journal indexes are 0 they are deleted from every interface.

**Scenario B — zeroed identifiers.** Truncate `%LOCALAPPDATA%\AetherNext\tun-routes.json` to `{}`, then disconnect.
**Expected:** only routes whose next-hop equals the recorded tunnel address are removed; decoy intact.

**Scenario C — hard kill + proxy-only repair (INV-3).** Connect in TUN, `taskkill /F /IM aether.exe`, restart Aether in **proxy-only** mode.
**Expected:** stale routes, adapter DNS and `InterfaceMetric` repaired before any connection attempt; a `RepairRecord` is logged. **Today:** repair is reachable only from `tun_win::spawn`, so this leaves the machine black-holed.

**Scenario D — teardown budget.** Remove `powershell.exe` from `PATH`, then disconnect.
**Expected:** in-session teardown < 500 ms (FFI path). **Today:** three PowerShell cold starts exceed the 5 s window and the child is killed mid-teardown.

**Scenario E — orphaned proxy.** Hand-set `ProxyEnable=1`, `ProxyServer=127.0.0.1:1820`, delete `proxy-recovery.json`, restart.
**Expected:** cleared and logged (journal mirrored to `HKCU\Software\AetherNext\ProxyJournal` + orphan sweep).

**Scenario F — soak (SC-002/003).** 200 cycles across: clean disconnect, GUI kill, engine kill, both killed, uninstall-while-connected.
**Expected:** 0 residual Aether routes / proxy settings after next start; 0 third-party routes removed.

---

## 2. Binary trust and release pipeline (US2, FR-005…008) — contracts/trust-verification-policy.md

```bash
cargo test -p aether --test trust_verification           # pinned-leaf acceptance/rejection
cargo test -p aether-desktop --test elevation_trust      # extended, non-tautological
powershell -File scripts/verify-installers.ps1 -DistPath dist-windows
```

**Scenario A — pin is reachable (T-A2/A3).** Build release signed with certificate **A**; run TUN with an engine re-signed by a different `CN=deathline94` certificate **B**.
**Expected:** refused. **Today:** the hash pin mirrors the shipped file so it always matches, and `WinVerifyTrust` against the machine store rejects the CI cert for *every* user, so release TUN never starts at all.

**Scenario B — verification is unconditional (T-A1).** Delete a `resources/aether.exe`, leave a foreign binary with the same name, connect in **system-proxy** mode.
**Expected:** refused before spawn. **Today:** verification only runs when `routing_mode == "tun"`, and the resource/portable fallbacks return unchecked paths.

**Scenario C — DLL hijack (wintun rule).** `setx AETHER_WINTUN C:\temp\trojan.dll`, connect in TUN.
**Expected:** connect fails **and** the trojan's `DllMain` marker file is never created. **Today:** the elevated child `LoadLibrary`s it directly.

**Scenario D — no bypass in release (T-A6, BC-03).** Compile-fail test naming `VerifyPolicy::Insecure`; string-grep the built binary for a dev-trust branch.
**Expected:** unnameable in release, absent from the binary.

**Scenario E — sign-before-bundle (T-A8/A9).** Build once with signing disabled and run the verifier.
**Expected:** `verify-installers.ps1` exits non-zero, and also exits non-zero if it extracts **zero** binaries. **Today:** the outer `setup.exe` is signed and verified while the embedded GUI exe is unsigned, so the step records a pass.

---

## 3. Secrets and learned state (US3, FR-009…014) — contracts/secret-envelope-format.md

```bash
cargo test -p aether --test atomic_write_test -- --nocapture      # extended: AAD + path binding
cargo test -p aether --test envelope_v2 -- --nocapture
cargo test -p aether --test cache_validation
cd apps/android/android && ./gradlew testDebugUnitTest --tests "*ConfigKeyStoreTest*"
```

**Scenario A — no plaintext, path-bound (S-A1/A2).** Delete `AETHER_CONFIG_KEY`, provision an identity, inspect the file.
**Expected:** no secret present; a magic header only if non-secret config was written. Copy `aether-masque.toml` over `aether.toml`.
**Expected:** authentication failure. **Today:** encryption is opt-in (plaintext by default) and the key is path-unbound, so the blob replays verbatim.

**Scenario B — no trusted backup (S-A4).** Plant `<path>.bak` containing a foreign identity, restart.
**Expected:** ignored/quarantined. **Today:** `load()` copies it over the live file with the error ignored.

**Scenario C — cache poisoning (S-B2/B3/B4).** Write a cache entry with a timestamp 1 year ahead, `successes: 2^31`, and an address outside the allowlist.
**Expected:** all three rejected and counted; ordering unaffected. **Today:** the future timestamp never decays and permanently earns the freshness bonus; `trust_score` is the sole ordering input to connection selection.

**Scenario D — lock cannot be stolen (S-B6).** Two processes writing concurrently for 10 000 iterations.
**Expected:** no lost update. **Today:** `mtime > 5 s` steals a live holder's lock and `Drop` unlinks whoever's file is present.

**Scenario E — transient keystore failure (S-A8).** Fault-inject `UnrecoverableKeyException` twice then succeed; separately inject `BadPaddingException`.
**Expected:** alias survives / config intact in case 1; quarantine occurs in case 2. **Today:** any exception deletes the master key and quarantines the config — one flaky boot costs the identity.

---

## 4. Transport truth (US4, FR-015…019) — research R1–R6

```bash
cargo test -p aether --lib quic::tests::drain_survives_undersized_reader
cargo test -p aether --lib quic::tests::classify_status
cargo test -p aether --lib quic::tests::recv_reports_protocol_error_as_fatal
cargo test -p aether --lib quic::tests::dead_peer_tears_down_within_idle_timeout
cargo test -p aether --test scanner_cancellation_test
```

| Assertion | Expected | Today |
|---|---|---|
| 4 000-byte then 64-byte datagram both reach `inbound_tx` | pass | **partially:** one datagram is lost (a *length* failure — but note the audit's "wedge" claim was wrong: `dgram_recv` pops before comparing, see spec §Clarifications) |
| `enable_dgram(true, 2048, 2048)` (entry counts) | pass | fails: `65536, 65536` admits ~65 k queued datagrams |
| 103 then 200 on the request stream ⇒ established | pass | fails: any non-2xx is fatal |
| 200 on a non-request stream ⇒ readiness does not latch | pass | fails: positive check is not stream-scoped |
| Peer-initiated close ⇒ `run()` is `Err` and a failure is recorded | pass | fails: returns `Ok(())` and `session.rs` records a **success** |
| Data-plane proof requires a reply to our own probe | pass | fails: any datagram (even ICMP errors) counts; the real validator is `#[cfg(test)]`-only |
| H2 gateway survives smart-reconnect verification | pass | fails: verified over QUIC, evicted after 3 strikes |
| 8 concurrent probes, max `on_timeout()` gap < 20 ms with the cache lock held | pass | fails: ≥1 500 ms of `thread::sleep` on workers |
| UI renders `—` for every unmeasured field | pass | fails: `< 45 ms`, `0.0%`, hardcoded sparkline, `SOCKS5 READY` beside `DORMANT` |

---

## 5. Netstack and proxies (US5, FR-020…024) — research R7–R13

```bash
cargo test -p aether --lib netstack::tests::flush_tx_mixed_sizes_fifo
cargo test -p aether --lib netstack::tests::idle_established_survives
cargo test -p aether --lib netstack::tests::tx_ring_is_bounded
cargo test -p aether --lib netstack::tests::cmd_not_starved_by_inbound
cargo test -p aether --lib netstack::tests::stale_handle_does_not_panic
cargo test -p aether --test socks_udp_associate
```

| Assertion | Expected | Today |
|---|---|---|
| Established, 60 s idle both directions ⇒ still open **and** ≥1 egress keep-alive frame observed | pass | fails: aborted at 10 s (`set_timeout` is also the inactivity timer) |
| `[1448, 52, 1448, 60, 1448]` through `mpsc(1)` drains in exact order | pass | fails: ≤128 B frames jump the queue; the existing FIFO test uses four identical 200-byte packets and can never catch it |
| Saturated `outbound_tx` ⇒ `device.tx` ≤ 256+ε with `tx_deferred > 0` | pass | fails: unbounded `VecDeque<Vec<u8>>` |
| 5× batch budget inbound ⇒ concurrent `OpenTcp` completes in ≤10 iterations | pass | fails: `biased` select starves opens/uploads |
| Stale socket handle ⇒ no panic escapes, task survives | pass | fails: `handle_cmd`/`handle_data` are outside the guard and `get::<T>()` panics (0.12 has no non-panicking accessor) |
| 100 proxy UDP associations ⇒ DNS still resolves | pass | fails: one shared 128-slot pool breaks all domain CONNECTs |
| `CONNECT 169.254.169.254:80` via 1819/1820 ⇒ refused | pass | fails: no destination policy |
| Bare-LF request line ⇒ forwarded request keeps `Host:` | pass | fails: parse/rewrite boundary divergence |
| ECH reply with mismatched TX ID ⇒ ignored | pass | fails: `parse_https_ech` checks ID, QR, name and `TC` none of |
| Scan at max load ⇒ proxied transfer ≥80 % of unscanned rate; cancel < 50 ms | pass | fails: shared quotas, no candidate-derived budget |

---

## 6. Contract and UI (US6, FR-025…037) — contracts/ipc-contract.md, ui-design-contract.md

```bash
cd apps/desktop && npm run build            # tsc && vite build
npx tsc --noEmit                            # strict, with noUncheckedIndexedAccess
npm test                                    # vitest
cargo run -p aether-desktop --bin export-bindings -- --out src/bindings.ts
git diff --exit-code apps/desktop/src/bindings.ts
scripts/verify-invariants --ui
```

| Assertion | Expected | Today |
|---|---|---|
| Regenerate bindings, no diff | pass | no generated file exists |
| Add a Rust field, don't update TS ⇒ build fails | fails correctly | nothing catches it |
| Every `invoke`d command exists **and** every registered command is invoked/listed | pass | fails: `get_settings`, `get_state`, `is_admin`, `app_info`, `test_connection` unused |
| Settings "Dual-Stack" ⇒ connect succeeds and persists | pass | fails: `"both"` rejected by `validate_settings`, save silently never lands, Connect hard-fails |
| Concurrency slider max equals the shell clamp | pass | fails: 2000 vs `clamp(1,500)` |
| Scan H3, then scan WireGuard ⇒ only current-run rows | pass | fails: 40 stale H3 rows interleave |
| `run_id: 1` event after scan #2 ⇒ row count unchanged | pass | fails: no run id exists |
| Save rejection ⇒ inline field error | pass | fails: "Auto-Saving" forever |
| `className` extraction ⇒ all resolve | pass | fails: `.metric-icon`, `.btn-secondary`, `.retry-btn`, … |
| Contrast from measured pixels at 100/125/150 % | ≥4.5:1 text, ≥3:1 state edges | fails: 2.4-2.6:1 informational tier, 1.05-1.47:1 borders |
| Zero non-`ipc:`/`localhost` network requests from the packaged build | pass | fails: Google Fonts blocked by CSP at best, exfiltrated in dev at worst |
| `.spin` animates while connecting; `prefers-reduced-motion` kills all 7 loops | pass | fails: spinners only defined inside the reduced-motion block |
| 2 000 rows ⇒ per-event frame < 16 ms p95 | pass | fails: unvirtualised list re-sorts and re-renders per event |
| Keyboard: focus visible, log console scrollable, no mouse-only steppers | pass | fails |
| axe per tab, 0 role violations | pass | fails: chips as `role="tab"`, `role="radio"` per-Tab-stop |

---

## 7. Android (US7, FR-038…042) — research R37–R41

```bash
cd apps/android && npm test
cd android && ./gradlew testDebugUnitTest --tests "*SessionControllerTest*" --tests "*ConfigKeyStoreTest*"
./gradlew assembleRelease && ./gradlew lint
scripts/verify-native-payloads        # sha256 + readelf p_align
```

| Assertion | Expected | Today |
|---|---|---|
| Fake builder whose `addDisallowedApplication` throws ⇒ `establish()` never called, state `error` | pass | fails: exception swallowed, tunnel established with no loop avoidance |
| `decideLiveness(rx↑/tx=0, 15 s)` ⇒ Dead; all-zero ⇒ Dead only after a failed probe; exhausted ⇒ terminal error | pass | fails: `TProxyGetStats()` declared and never called |
| Wi-Fi → cellular handoff ⇒ data restored ≤ 30 s or terminal "reconnect required" | pass | fails: blackhole behind a green badge on every handoff |
| `markConnected()` revocable after a liveness failure | pass | fails: one-shot compare-and-set |
| `invoke()` returns < 50 ms while a 12 s stub blocks; every request id resolved exactly once | pass | fails: synchronous bridge freezes the WebView |
| VPN consent sheet appears from a fresh install (bridge-triggered path) | pass | fails: `startActivityForResult` called on the JavaBridge thread |
| `onStop` of activity A leaves activity B receiving events | pass | fails: process-singleton emitter blanked to no-op |
| Status derived from structured events only | pass | fails: `line.contains("handshake successful")` — a string absent from the Rust source |
| `targetSdk >= 36`, every `.so` `p_align >= 0x4000`, digests match `hev-lock.json` | pass | fails: SDK 34; `test -s` only; provenance untraceable (committed blobs carry a `void TProxyStartService` and no `TProxyIsRunning`) |
| Engine killed by LowMemoryKiller ⇒ supervised restart | pass | fails: `START_NOT_STICKY`, no retry, silent |

---

## 8. Regression of prior audit rounds (US8, FR-046)

The prior fourteen specs are not trusted and not discarded: re-verify the ones that shipped working code, and re-open the ones that did not.

```bash
cargo test -p aether --test provision_lock_test --test http_header_test --test atomic_write_test
cargo test -p aether --lib -- --nocapture            # parsers: skip_name, DNS answers, CIDR
```
**Expected pass today** (verified clean in the audit — keep them passing): DNS compression/pointer-loop guards, `rdlen` bounds, question-name echo, `TC` handling in the proxy resolver, all SOCKS ATYP bounds, 16 KB header cap with read timeout, absolute-URI query preservation, no `blocking_send`, bounded channels everywhere, `Instant` arithmetic via `checked_*`/`saturating_*`, no shell-injection surface in the TUN command layer, no secret in any log, `allowBackup="false"`, Android GCM with a fresh random IV per record, every component explicitly `exported`, WebView host-locked with `allowFileAccess=false`, minimal Tauri capabilities, no private key material committed.

**Traceability check (SC-001).** Generate the map and review it as part of completion:
```bash
scripts/audit-traceability --spec specs/015-full-audit-remediation/spec.md
```
**Expected:** every finding in the 2026-09-21 audit resolves to ≥1 invariant, ≥1 task and ≥1 test; **any unmapped finding blocks completion** (FR-046).

## 9. What "done" means

All of: `scripts/verify-invariants` exits 0 · `--selftest-fail` exits non-zero · the §0 baseline failures are each individually closed with a red→green→guard-reachable triple recorded · SC-002…SC-015 measured in real environments with artifacts attached · the traceability table is complete · and FR-045's constitution is ratified so the next feature can be gated rather than re-audited.
