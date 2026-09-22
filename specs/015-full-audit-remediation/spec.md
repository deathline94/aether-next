# Feature Specification: Full-System Audit Remediation & Structural Regression Prevention

**Feature Branch**: `015-full-audit-remediation`

**Created**: 2026-09-21

**Status**: Draft

**Input**: User description: "you need to plan the ultimate plan to fix alllllll and i mean absolutely all of these problem . everything you found . the whole system ."

**Source of truth**: The 2026-09-21 full-codebase audit (6 parallel layer audits, ~200 findings). This spec supersedes the remediation scope of `specs/001`–`specs/014`. Those specs remain as history; their task checkboxes are **not** evidence of fixed behaviour — a material number of `// L6 fix` / `// M1 fix` / `// S4 fix rollback` guards in the current code are unreachable or inverted, and `specs/014/tasks.md` is 40/40 `[x]` while several of its claimed fixes are demonstrably inert.

---

## Clarifications

### Session-corrected audit premises

Two original audit findings were **disproved** during Phase 0 research against the vendored `quiche` 0.29.2 source and are restated correctly here. Recording them is mandatory: the project's failure mode is false-positive "fixed" claims, and this spec must not repeat it.

1. **Rejected finding — "a single oversized inbound datagram permanently wedges the receive loop."** `Connection::dgram_recv` (`quiche/quiche/src/lib.rs:6802-6816`) calls `dgram_recv_queue.pop()` **before** the length comparison, so `Error::BufferTooShort` consumes (loses) exactly one datagram and cannot block the queue.
   *The real defect, retained:* `Config::enable_dgram(enabled, recv_queue_len, send_queue_len)` (`quiche/quiche/src/lib.rs:1198-1208`) takes **queue entry counts**, not byte sizes — `max_datagram_frame_size` is a fixed `MAX_DGRAM_FRAME_SIZE = 65536` (`lib.rs:474`). Aether passes `enable_dgram(true, 65536, 65536)` (`aether/src/tls.rs:182`), permitting ~65 536 queued datagrams (tens of MB) of unacknowledged inbound. Combined with `Err(_) => break` at `aether/src/quic.rs:844-873`, which silently discards genuinely fatal receive errors, the exposure is memory growth plus loss of error visibility — not a wedge.
2. **Corrected attribution — "Windows signing was fixed by the recent CI commits."** It was made worse. `npm run tauri build` embeds the unsigned main exe into the NSIS container; the later step signs only a standalone copy plus the outer installer, and the verification step inspects only the outer installer (`.github/workflows/build.yml:142-207`).

### Additional findings surfaced during planning (now in scope)

3. **`dwProvFlags: 0x00000080` is mislabelled** as `WTD_REVOCATION_CHECK_NONE` at `apps/desktop/src-tauri/src/lib.rs:936`. `0x80` is `WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT`; the value for "none" is `0x40000`. The comment, the flag, and the intended CI behaviour disagree.
4. **5 of 10 registered Tauri commands are never invoked** by either frontend (`get_settings`, `get_state`, `is_admin`, `app_info`, `test_connection` per `lib.rs:2234-2245` vs the `invoke("…")` call sites). Only one direction of the IPC contract is currently exercised, so drift in the other direction is invisible.
5. **No pre-execution verification step exists in CI**: the engine is signed, staged, hashed into `build.rs`, bundled, and signed again — with no check that the staged file still matches the file the release digests will claim.

---

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Host Network State Is Never Left Damaged (Priority: P1) 🎯 MVP

A Windows user connects and disconnects — by button, by crash, by force-kill, or by uninstalling — and the machine's routing table, adapter DNS, interface metrics and system proxy are always returned to their pre-Aether state. Coexisting VPNs (whose split-default routes are byte-for-byte the same prefixes Aether installs) are never touched.

**Why this priority**: This is the only defect class in the audit that damages a user's machine outside the application boundary and the only one the user cannot repair from inside the app. `remove_routes()` deletes `0.0.0.0/1`, `128.0.0.0/1`, `::/1`, `8000::/1` from **every** interface whenever the recorded interface indexes are 0 (`aether/src/tun_win.rs:334-368`) — which includes every legacy, hand-edited or truncated state file, because the struct is `#[serde(default)]`. Teardown work runs only in `Drop`, inside a 5-second grace window that three `powershell.exe` cold starts reliably exceed, after which the shell calls `child.kill()` and destructors never run (`tun_win.rs:515-531`; `lib.rs:1551-1571`). The repair path is reachable only from `tun_win::spawn`, so proxy-only users and uninstalls never repair at all.

**Independent Test**: Plant a decoy `0.0.0.0/1` route on a second interface, zero the journal's interface identifiers, then disconnect: the decoy must survive and Aether's own routes must clear. `taskkill /F` the engine mid-session: the decoy survives and Aether's routes clear on next start. Full teardown completes in <500 ms with `powershell.exe` removed from `PATH`.

**Acceptance Scenarios**:
1. **Given** a route journal with missing or zeroed interface identifiers, **When** route removal runs, **Then** removal is restricted to prefixes whose next-hop equals the recorded tunnel address and no global prefix deletion is attempted.
2. **Given** an engine process terminated by `TerminateProcess`, **When** the host next starts Aether in any routing mode, **Then** stale Aether routes, adapter DNS, interface metrics and proxy settings are detected and repaired before any connection attempt.
3. **Given** a route mutation in progress, **When** any step fails, **Then** the journal records partial state and the repair path can complete or roll back idempotently.
4. **Given** a system proxy left enabled with Aether's listener address and no journal, **When** Aether starts, **Then** the orphaned proxy setting is cleared and logged.

---

### User Story 2 - The Application Proves Binary and Peer Trust Before Executing Anything (Priority: P1)

A user obtains an official Aether build. It runs with a valid signature on every installed binary, its TUN mode passes the application's own trust check on a real end-user machine, and the trust decision cannot be bypassed by placing a file where the app will find it.

**Why this priority**: Every current trust control is conditional, self-referential, or mislabelled, and the combination makes the flagship feature unusable while leaving the non-flagship paths unguarded. Verification runs only when `routing_mode == "tun"` (`lib.rs:1373-1379`); the resource, portable and repo-build fallbacks return unchecked binaries (`lib.rs:1046-1094`); `build.rs:38-53` computes the pinned release hashes from the very file that is shipped, so the check cannot fail; and `WinVerifyTrust` validates against the machine root store while CI mints an ephemeral self-signed certificate per run (`build.yml:88-111`), so release TUN mode fails for every end user. The elevated engine then loads `wintun.dll` from `AETHER_WINTUN` or the current directory with no validation (`tun_win.rs:25-47`) — arbitrary code as administrator.

**Independent Test**: Build release with certificate A, then attempt TUN with a binary signed by a different `CN=deathline94` certificate B: it must be rejected (proving the pin is reachable). Set `AETHER_WINTUN` to a trojan DLL: the connection must fail **and** the DLL's `DllMain` must never execute. String-grep the release binary for the developer trust bypass: it must be absent.

**Acceptance Scenarios**:
1. **Given** any resolved engine or helper binary in any routing mode, **When** it is about to be spawned, **Then** it has passed the trust check; verification is never conditional on routing mode.
2. **Given** a pinned trust anchor distributed with the source, **When** a build is signed by any other key, **Then** verification fails.
3. **Given** an elevated child, **When** it loads a native helper, **Then** the path is supplied by the verified parent, the file is verified before load, and the DLL search path is restricted to system directories.
4. **Given** a release build, **When** any environment-based verification bypass is present, **Then** it has no effect, because no such code path is compiled in.
5. **Given** every artifact in a published installer, **When** CI verifies the package, **Then** it inspects the extracted inner binaries, not the outer container.

---

### User Story 3 - Secrets and Learned State Are Authentic, Authoritative and Unclonable (Priority: P1)

A user's identity (WireGuard private key, access token, certificate) is never written unencrypted, cannot be lifted to another path or machine, and cannot be destroyed by a transient platform error. The endpoint cache the app learns is validated so that a poisoned file cannot redirect future connections.

**Why this priority**: Identity loss is unrecoverable for the user, and the endpoint cache is an *input to connection ordering* — so a writable file is currently a steering primitive. `encode()` returns plaintext when `AETHER_CONFIG_KEY` is unset (`config.rs:107-108`); `.bak` copies are produced outside the ACL-restricted writer and are then *trusted* by `load()` (`config.rs:232-275`); ACLs are granted to the `%USERNAME%` of a process that runs elevated (`config.rs:131-148`), so the next ordinary launch re-provisions a new device. The cache accepts a schema-less JSON with unchecked `successes + failures`, and its freshness term is a wall clock, so a future `timestamp` never decays and permanently pins an attacker-chosen endpoint to the top of ordering (`cache.rs:36-107`). On Android, `loadOrCreate` runs on every start and routes **any** keystore exception into `rotateAndRecover()`, which deletes the master key alias and quarantines the config (`ConfigKeyStore.kt:31-52`) — one transient `keystore2` failure permanently costs the identity.

**Independent Test**: Move a config ciphertext written for path A onto path B: authentication must fail. Set a cache entry's timestamp 1 year ahead with 2^31 successes: the loader must reject the entry and never order it first. Make `getKey` throw `UnrecoverableKeyException` twice then succeed: the alias must survive and `aether.toml` must be untouched; make it throw `BadPaddingException`: quarantine must occur.

**Acceptance Scenarios**:
1. **Given** no available OS key source, **When** identity is persisted, **Then** secrets are refused and only non-secret configuration is written.
2. **Given** an encrypted envelope, **When** it is read from any path other than the one it was written for, **Then** authentication fails.
3. **Given** a transient platform crypto failure, **When** secrets are loaded, **Then** the system retries and then fails loudly, and never deletes key material.
4. **Given** a restored or hand-edited cache or route journal, **When** the app reads it, **Then** every field is range-, schema- and provenance-validated, and invalid entries are dropped rather than fatal.

---

### User Story 4 - The Tunnel Reports What It Actually Did (Priority: P2)

A user sees connection status, latency, byte counters and scan results that are measurements, never defaults or decorations. A transport that failed is reported as failed. A status the application cannot observe is not displayed.

**Why this priority**: Every remaining severe bug is a *false positive*: they poison the trust cache, suppress rescans, and teach users to distrust the one signal that matters. A fatal connection close returns `Ok(())` (`quic.rs:627-680`) and the caller records it as a **success** (`session.rs:222-226`). `h3_ready` is set by a `:status: 200` on **any** stream, while the negative check is stream-scoped (`quic.rs:709-724`). Data-plane proof accepts any datagram — the real validator `dns.rs:222 is_dns_reply` is `#[cfg(test)]`-only. On Android, connectivity is inferred by matching English log prose (`SessionController.kt:314-326`). Meanwhile the UI renders `< 45 ms` from a regex that can never match the real string (`ConnectionTab.tsx:89-94` vs `lib.rs:1623`), `PACKET LOSS 0.0%`, a hardcoded sparkline array, and `SOCKS5 READY` inside a card reading `DORMANT`.

**Independent Test**: Feed a post-handshake packet that fails authentication into the tunnel loop: `run()` must return an error with the connection closed (today it returns `Ok(())` after a debug log). Send `:status: 103` then `200` on the request stream: the tunnel must establish. Send `200` on a different stream: readiness must not latch. Grep the shipped frontend for the fabricated metric strings: none may remain.

**Acceptance Scenarios**:
1. **Given** a transport teardown not initiated locally, **When** the session ends, **Then** the outcome is an error, failure is recorded against the endpoint, and the exit status is non-zero.
2. **Given** any status, counter or gauge in the UI, **When** it cannot be sourced from an engine measurement, **Then** it renders `—`/unavailable rather than a plausible value.
3. **Given** interim, wrong-stream and duplicate final responses, **When** MASQUE readiness is evaluated, **Then** only a single 2xx on the request stream establishes, and 1xx is ignored.
4. **Given** cached and freshly-scanned endpoints, **When** the best endpoint is chosen, **Then** a cache hit may be re-verified but never preferred over a fresh verification, and verification uses the transport actually in use.

---

### User Story 5 - Idle and Long-Lived Connections Survive; Dead Ones Are Reaped (Priority: P2)

A user leaves an SSH session, mail client or database connection idle and it is still open. A user whose peer crashes is cleaned up within a bounded time. The scanner's cancellation is honoured, its progress numbers are true, and its queue budget cannot starve the live tunnel.

**Why this priority**: `socket.set_timeout(Some(10s))` is applied at connect and never revised (`netstack.rs:562`); in smoltcp 0.12 that same field is the **inactivity** abort (`tcp.rs:2118-2122`, refreshed by `remote_last_ts` at `:1932`), so the connect-timeout fix silently became a 10-second idle killer. `device.tx` is unbounded (`netstack.rs:31,822-851`), `biased` select starves opens and uploads behind a saturating download (`netstack.rs:498-534`), and `flush_tx` sends every frame ≤128 B ahead of deferred larger frames (`netstack.rs:817-851`), inverting same-flow order — the existing FIFO test uses four identical 200-byte packets and cannot observe it. Scanner probes share the proxy's netstack socket budget (`netstack.rs:23`; `socks.rs:562-662`), so a heavy scan degrades the live tunnel.

**Independent Test**: Drive a loopback pair to Established, advance the simulated clock 60 s with zero inbound traffic: the connection must remain Established **and** at least one egress keep-alive frame must have been observed. Preload the inbound path with 5× the batch budget: a concurrent `OpenTcp` must complete within a bounded number of loop iterations. Flush `[1448, 52, 1448, 60, 1448]` through an `mpsc(1)`: pop order must equal push order.

**Acceptance Scenarios**:
1. **Given** an established connection idle in both directions, **When** it exceeds the connect timeout, **Then** it survives keep-alive probing and is aborted only after the peer stops answering.
2. **Given** sustained egress congestion, **When** the device transmit ring is full, **Then** frames are refused at a bounded depth with a visible counter, and smoltcp retries rather than losing data.
3. **Given** a same-flow mix of large and small segments, **When** the queue drains, **Then** order is preserved.
4. **Given** scanner load, **When** the user's proxied traffic needs sockets or worker time, **Then** proxy capacity is reserved and scan cancellation aborts within its documented budget.

---

### User Story 6 - One Contract, Two Platforms, Zero Drift (Priority: P2)

A developer changes an engine event, a settings field or a limit value, and every consumer — shell, desktop UI, Android UI — is updated or the build fails. The visual system renders identically at every Windows display scale and on Android.

**Why this priority**: Every UI defect in the audit is downstream of four missing invariants. The Settings "Dual-Stack" option sends `"both"`, which `validate_settings` rejects (`lib.rs:533-537`), so Connect hard-fails while the save dock lies "Auto-Saving" forever — and the *Scanner's* identical label works. `scan_failed` and `scan_done.working` exist only in TypeScript (`types.ts:111-112`; `session_event.rs:48-52` has no failure variant). `max={2000}` meets `clamp(1, 500)` (`ScannerTab.tsx:236` vs `lib.rs:1647`). `.metric-icon` is used four times and defined **zero** times; `.spin` exists only inside a `prefers-reduced-motion` block, so both spinners are frozen; the Google Fonts `<link>` is blocked by the app's own CSP with no `@font-face` anywhere, so the entire typographic identity silently falls back; border tokens at `rgba(255,255,255,.05/.07)` measure 1.05-1.18:1 and vanish at Windows fractional scaling; `color-scheme` is never declared, so `<select>` option lists are near-invisible. The scanner never clears the previous run (`useScanner.ts:106` filters only same-protocol rows), so results mix. `apps/android/src` is a ~3,000-line fork with its own 3,291-line stylesheet, and the two copies differ in *behaviour* — only Android has the connect watchdog.

**Independent Test**: Add a field to the Rust `Settings` struct without updating TypeScript: CI fails. Extract every `className` token from the frontend and require a matching selector: `.metric-icon` fails today. Render a profile card at 125 %/150 % scaling and assert its measured edge contrast ≥3:1. Start scan H3, then scan WireGuard: the result count reflects only the current run.

**Acceptance Scenarios**:
1. **Given** a Rust type, command, event or numeric limit, **When** any consumer's expectation diverges, **Then** generation or a CI check fails the build.
2. **Given** both platforms, **When** a behaviour exists on one (watchdog, default-merge hydration, scan completion wording), **Then** it exists on both from shared source.
3. **Given** a status, control or boundary that is the sole affordance, **When** rendered at any OS scale factor, **Then** it is perceivable (≥3:1) and every rendered class has a rule.
4. **Given** an interactive control, **When** used by keyboard or touch, **Then** focus is visible, targets meet the minimum, hover styling does not persist on touch, and composite widgets match their ARIA role.
5. **Given** thousands of streamed results, **When** the list updates per event, **Then** frame time stays within budget.

---

### User Story 7 - Android Keeps Working When the Network Changes (Priority: P2)

A phone user walks out of Wi-Fi range mid-session; the tunnel re-establishes on cellular within seconds, or tells the user it needs a tap. The UI never freezes, and the system's own VPN controls stay truthful.

**Why this priority**: The single most damaging Android failure is an interface that is up with no data path, and it is reachable on **every** handoff. `TProxyGetStats()` is declared and never called (`AetherVpnService.kt:384`), `onLost` only calls `setUnderlyingNetworks` (`:143-171`), and `markConnected()` is a one-shot compare-and-set that can never be revoked (`SessionController.kt:403-411`). Loop avoidance depends solely on `addDisallowedApplication`, whose exception is swallowed (`AetherVpnService.kt:130-134`). The bridge additionally blocks the single-threaded JS runtime for up to 12 s (`AetherBridge.kt:14` → `SessionController.kt:233-254`) and starts the VPN consent sheet from the JavaBridge thread (`MainActivity.kt:188-197`).

**Independent Test**: With a fake builder whose `addDisallowedApplication` throws, assert `establish()` is never called and the state becomes an error. Table-drive the liveness decision on `rx` advancing with `tx` frozen, all-zero, healthy, and attempts-exhausted. Assert `invoke()` returns in under 50 ms while a 12-second stub blocks behind it, and that every request id is resolved exactly once.

**Acceptance Scenarios**:
1. **Given** a network change or stalled data path, **When** the watchdog detects it, **Then** the tunnel restarts under a bounded backoff and reaches a terminal user-visible state rather than a false "connected".
2. **Given** loop-avoidance setup failure, **When** the interface is about to be established, **Then** establishment is refused.
3. **Given** any bridge call, **When** the underlying work may block, **Then** it is dispatched off the bridge thread and resolved asynchronously.
4. **Given** the target-API and 16 KB page-size requirements in force in 2026, **When** the APK is built, **Then** it is compliant and CI fails otherwise.

---

### User Story 8 - Every Claim of "Fixed" Is Mechanically Refutable (Priority: P3)

A maintainer adds a guard, and CI proves the guard can be reached — or the merge fails.

**Why this priority**: This is the meta-fix. The audit's dominant pattern was a fix whose enabling condition is unreachable, verified by a test that cannot observe it. `.gitignore` line 44 excludes `apps/desktop/src-tauri/resources/*.exe`, so `build.rs:38-53`'s "missing digest is an error" guard can **never** fire on a clean checkout — it hashes nothing, emits no entry, and CI passes. `AetherVpnServiceTest.kt:12-33` asserts on an `AtomicLong`, not on the class under test. The CI signing verification inspects the wrong artifact. `.github/workflows/ci.yml` has no `permissions:` block.
**Independent Test**: `scripts/verify-invariants` runs with `--selftest-fail` and must exit non-zero, having injected each defect it claims to detect.
**Acceptance Scenarios**:
1. **Given** a new invariant gate, **When** it ships, **Then** it also ships a mode that injects its own defect and fails.
2. **Given** a build-time check over staged artifacts, **When** the artifact is absent, **Then** the build errors rather than silently emitting an empty set.
3. **Given** a workflow, **When** it is triggered by a fork PR, **Then** it holds no write token and sees no secrets.
4. **Given** the project constitution, **When** any of these gates is evaluated, **Then** it is a ratified rule rather than an unpopulated template.

---

## Entities *(mandatory)*

- **Identity** — WireGuard private key, access token, client ID, MASQUE key PEM. Currently plaintext-by-default, path-unbound, cloned into `.bak`. *(see Clarifications §3, US3)*
- **ConfigEnvelope** — versioned, path-bound authenticated file: magic, schema version, nonce, ciphertext+tag, AAD over canonical path + version.
- **EndpointRegistry** — sole owner of learned endpoints; monotonic-ordered entries; local-learned only, never signed, never preferred over fresh verification; file is a write-behind snapshot.
- **RouteJournal** — versioned intent record written **before** mutation: LUIDs, alias, tunnel address, per-prefix next-hop and family, before-values, creator PID + process start time.
- **ProxySnapshot** — all five raw proxy values (`ProxyEnable`, `ProxyServer`, `ProxyOverride`, `AutoConfigURL`, per-connection PAC) plus a mirrored registry copy and an orphan sweep.
- **TrustAnchorSet** — committed, reviewed pins: file SHA-256, certificate SHA-256, SPKI SHA-256, per-host pin sets with expiry, generated by a release-time step and *never* by the same build that consumes it.
- **PinSet / VerifyPolicy** — per-host SPKI pins with expiry; `VerifyPolicy` is either `Pinned` or a debug-only `Insecure` that does not exist in a release binary.
- **Settings** — the single Rust definition; TypeScript is generated; enums replace allowlist strings; `IpVersion` makes `"both"` non-representable; `scan_mode`'s `"thorogh"` typo removed.
- **ScanRun** — carries `run_id`; every event echoes it; non-matching events are dropped by shell and UI; terminal events are typed.
- **RuntimeMetrics** — optional measured fields (`handshake_rtt_ms`, per-direction byte counters) where `null` renders as unavailable.
- **DesignTokenSet** — the shared token/component package used by both UIs, including two edge tokens (decorative ≥1.6:1, interactive ≥3:1).
- **TunnelLiveness** — Android `TProxyGetStats` deltas mapped to alive / rx-only / silent, driving a bounded supervised restart.
- **NetStackReservation** — per-consumer socket/port quotas (proxy vs resolver) and a global memory admission budget.

## Validation & Invariants *(mandatory)*

| ID | Invariant (mechanically checkable) | US |
|---|---|---|
| BC-01 | No plaintext identity is ever written; every persisted secret is inside a versioned envelope bound to its path. | US3 |
| BC-02 | Every engine or helper binary is trust-verified immediately before spawn, in every routing mode. | US2 |
| BC-03 | No verification-bypass code path exists in a release binary (`cargo clippy -- -D warnings` + compile-fail test). | US2, US3 |
| BC-04 | `std::env::var` is never used to read `AETHER_*` outside the runtime-config accessor; the accessor has exactly one reader. | US6 |
| BC-05 | No unwrap/expect on lock acquisition in shell or engine paths that own process, job, or proxy-restore state. | US1, US2 |
| BC-06 | No `unwrap`/`expect`/indexing/`as`-truncation on network- or file-sourced data in the engine. | US4, US5 |
| BC-07 | Every non-`Done` transport error is either handled or fatal; `Ok(())` is unreachable for a non-local teardown. | US4 |
| BC-08 | Every generated TS type equals the Rust type (regenerated in CI, `git diff --exit-code`). | US6 |
| BC-09 | IPC parity holds **both ways**: every invoked command exists, and every registered command is invoked or explicitly allow-listed. | US6 |
| BC-10 | Every `className` token in TSX resolves to a selector in CSS or Tailwind source. | US6 |
| BC-11 | No `100vh`, `transition: all`, unguarded bare `:hover`, or `border: 1px solid rgba(255,255,255,<0.10)`; no `var(--x)` without a definition. | US6 |
| BC-12 | All text ≥4.5:1 (≥3:1 large); all state-bearing non-text ≥3:1; no label below 11 px; no state signalled by colour alone. | US6 |
| BC-13 | Every new guard ships a paired `--selftest-fail` mode; a build step never silently produces an empty input for a later check. | US8 |
| BC-14 | Every status/counter in the UI is sourced from a measured field; no hardcoded metric arrays or placeholder values. | US4 |
| BC-15 | No blocking call, and no main-thread-only API, executes on the JS bridge thread. | US7 |
| BC-16 | Every scan event carries a `run_id`; consumers drop non-matching events. | US4, US6 |
| BC-17 | Every cache/route/settings file has a schema version and range-, timestamp- and provenance-validated fields. | US3 |
| BC-18 | The vendored dependency tree is pinned by checksum with recorded provenance and a patch manifest. | US2, US8 |
| BC-19 | Scanner concurrency and probe deadlines derive from the candidate-set size within the scan budget. | US5 |
| BC-20 | Every `#[tauri::command]` returns a typed error; no `Result<_, String>`. | US6 |
| BC-21 | Android APK meets the enforced target-API and 16 KB page-size requirements, and every native lib's digest is verified. | US7, US8 |
| BC-22 | The mobile and desktop UIs share one component/token/type source; platform differences are props, not forks. | US6 |

**Test First (NON-NEGOTIABLE)**: For each invariant above, tests are written and observed to **fail** against the current code before implementation. Acceptance scenarios under US1–US7 are the test specifications. Each fix carries a regression test that fails if the guard is removed.

## Observability & Failure Policy *(mandatory)*

- **Fail loud at boundaries.** A swallowed error becomes an actionable one: transport errors surface as `SessionEvent::Error`; save rejections surface as an inline field error, not a log line; a route repair that cannot run reports why to the user.
- **`debug!` is not a user-facing signal.** Any condition that changes what the user should do is `error!`-level or an event. This closes the current anti-pattern where a disabled security control, a lost pin, or a recovered-from-panic netstack is visible only at `debug`.
- **Silent-drop paths get counters.** Dropped datagrams, refused transmit frames, discarded proxy packets, dropped log lines and rejected cache entries are counted and exposed in diagnostics.
- **Diagnostics are exportable.** A single action produces engine version, resolved binary paths and digests, trust decision outcomes, effective runtime-config snapshot, route/proxy journal state, counters above.
- **Failure policy for state transitions**: any failure while leaving the host in a mutated state (routes installed, proxy enabled, adapter configured) MUST block or reverse, never proceed.
- **Assumptions**: The Cloudflare MASQUE edges remain the only production peers, so per-host pin sets are small and their rotation cadence is handled by expiry-plus-secondary-pin rather than online fetch. A single user account per device on desktop; multi-account elevation is handled by SID-derived ACLs rather than separate profiles.
- **Scope guard**: `quiche/` is patched in place at a pinned commit with a patch manifest; upstreaming is explicitly out of scope for this feature. Recorded in `quiche/PATCHES.md` (base `cloudflare/quiche@c4c0b978461aa153399a90217d85bebd1800f84d`, 6 deviating files in 3 classes) and enforced by `packaging/trust/quiche-vendor.json` + `scripts/verify-quiche-vendor.mjs`, both run by the `supply-chain` job in `ci.yml`. "Pinned commit", not "pinned tag": the tree's declared `version = "0.29.2"` is three commits stale relative to its actual content, so a tag-based pin would have been a false record — see the manifest.

### Edge Cases

- State file absent, zero-length, schema-version-mismatched, or a future version → treated as absent, repaired, never fatal to startup.
- Engine exits with no terminal event (killed, panicked, OOM) → shell emits a typed synthetic terminal event carrying the run id.
- Two Aether instances, one holding routes → the second refuses to mutate rather than overwriting the shared journal.
- Clock skew: wall clock ahead/behind by hours → decay uses monotonic progression; future timestamps rejected.
- Peer sends `100`/`103`, a second final response, or headers on a control stream.
- A peer advertises datagram support and then never sends one; a peer sends only ICMP-shaped datagrams.
- User force-kills the GUI (not the engine), the engine (not the GUI), or both; uninstall while connected.
- Elevated and non-elevated launches interleaved on the same account.
- Keystore temporarily unavailable (screen locked during background start), GCM tag mismatch, truncated wrapping.
- Wi-Fi and cellular both present with the same SSID handoff mid-handshake; task swipe; doze.
- WebView page reloads mid-request leaving an unresolved bridge request id.
- 2,000+ scan rows arriving while the window is minimised to tray (throttled timers).
- Windows display scaling 100/125/150/175 %, and a light-mode OS with a forced-dark app.

---

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: System MUST return host routing, adapter DNS/metrics and system-proxy state to its pre-session condition after any termination path, including `TerminateProcess`. (US1)
- **FR-002**: System MUST scope every route removal to identifiers recorded in a journal written before mutation, and MUST NOT perform unscoped prefix deletion. (US1)
- **FR-003**: System MUST run state repair unconditionally at startup in all modes, and MUST provide a CLI repair for the uninstall path. (US1)
- **FR-004**: System MUST perform host network mutations through in-API calls with a bounded, measurable teardown time, not per-process shell startups. (US1)
- **FR-005**: System MUST trust-verify every engine/helper binary before spawn in every mode, against an anchor set independent of the build being verified. (US2)
- **FR-006**: The elevated child MUST NOT resolve native helpers from environment variables or the working directory; the verified parent supplies an absolute canonical path and verification precedes load. (US2)
- **FR-007**: No verification-bypass path MUST be compiled into a release binary; developer bypass is compile-time absent, not runtime-gated. (US2, US3)
- **FR-008**: CI MUST sign every bundled binary before it is embedded, and MUST verify signatures on the extracted inner payloads of each package. (US2)
- **FR-009**: System MUST persist identity only inside a versioned, path-bound, authenticated envelope, and MUST refuse to persist secrets absent a key source. (US3)
- **FR-010**: File replacement MUST NOT leave an unencrypted or un-ACL'd secondary copy, and MUST NOT auto-restore an untrusted backup. (US3)
- **FR-011**: File ACLs MUST be derived from the token/console user's SID with an explicit protective descriptor. (US3)
- **FR-012**: Endpoint cache MUST be schema-versioned with range-, timestamp- and provenance-validated entries; untrustworthy entries are dropped without fataling. (US3)
- **FR-013**: Cross-process locks MUST be OS-lifecycle-backed, MUST NOT fail open, and MUST NOT delete a lock the holder did not create. (US3)
- **FR-014**: Transient platform crypto failures MUST be retried and then surfaced; key material is destroyed only on explicit, evidenced data corruption, and MUST be dual-wrapped for recovery. (US3)
- **FR-015**: Transport teardown that the local side did not request MUST produce an error, a recorded failure, and a non-zero engine exit status. (US4)
- **FR-016**: MASQUE readiness MUST latch on exactly one 2xx on the request stream; interim and off-stream responses MUST NOT establish or abort. (US4)
- **FR-017**: Data-plane proof MUST validate that an inner IP packet corresponding to the session's own query was received. (US4)
- **FR-018**: Endpoint verification MUST use the transport in use, and cached endpoints MUST NOT be preferred over fresh verification. (US4)
- **FR-019**: UI MUST NOT display a metric that lacks a measured source; unavailable renders as unavailable. (US4)
- **FR-020**: Idle established connections MUST be kept alive by probing and reaped only after the peer stops responding, within a bounded time. (US5)
- **FR-021**: The device transmit path MUST be bounded with refusal-and-count at capacity; per-flow ordering MUST be preserved; ingest batching MUST be bounded and MUST NOT starve the timer or outbound path. (US5)
- **FR-022**: Socket and port quotas MUST be partitioned per consumer, and scan load MUST NOT starve proxy or resolver capacity. (US5)
- **FR-023**: Scanner budgets MUST derive from candidate count, verify cost and concurrency; progress MUST reflect candidates examined. (US5)
- **FR-024**: Blocking persistence MUST run on a dedicated thread so QUIC timers stay prompt; cancellation MUST interrupt in-flight work. (US5)
- **FR-025**: A single Rust definition MUST generate the TypeScript contract for settings, runtime state, commands and events, verified in CI both directions. (US6)
- **FR-026**: Settings, transport options and numeric limits MUST be enums/typed constants shared with the engine, not string allowlists. (US6)
- **FR-027**: A rejected settings save MUST surface as an inline field error and MUST clear optimistic "saved" state. (US6)
- **FR-028**: Each new scan MUST clear prior results, counters and best-selection; result identity MUST key on address and protocol; stale events MUST be dropped. (US6)
- **FR-029**: The desktop UI MUST share the connect watchdog and default-merge hydration with mobile, from shared source. (US6)
- **FR-030**: Fonts MUST be self-hosted and same-origin; a blocked or missing font MUST NOT be load-bearing. (US6)
- **FR-031**: Every rendered class MUST have a rule; the class vocabulary MUST be single-generation; design tokens MUST be the sole colour source. (US6)
- **FR-032**: Edges that carry meaning MUST meet ≥3:1 at every OS scale factor; alpha-over-surface hairlines are prohibited for them. (US6)
- **FR-033**: Informational text MUST meet ≥4.5:1 and be ≥11 px; no state MAY be signalled by colour alone. (US6)
- **FR-034**: Hover styling MUST be pointer-guarded; touch targets MUST meet the enforced minimum; keyboard focus MUST be visible and scroll regions reachable. (US6)
- **FR-035**: Large streamed lists MUST be windowed or budgeted so per-event frame time stays within budget. (US6)
- **FR-036**: Viewport sizing MUST use dynamic units and honour safe-area insets on mobile. (US6)
- **FR-037**: Both UIs MUST consume one shared token/component source; behavioural differences are props. (US6)
- **FR-038**: Loop avoidance MUST fail closed: an exclusion error aborts interface establishment. (US7)
- **FR-039**: Data-path liveness MUST be measured and MUST drive a bounded supervised restart to a terminal state. (US7)
- **FR-040**: Bridge calls MUST be asynchronous with correlated request ids and MUST NOT block the bridge thread; main-thread APIs MUST be posted. (US7)
- **FR-041**: Engine status MUST be derived from structured events, never log-text matching. (US7)
- **FR-042**: The APK MUST meet the enforced target-API and 16 KB page-size requirements, with third-party native payloads pinned by digest and CI-verified. (US7, US8)
- **FR-043**: Every invariant gate MUST ship with a self-test that injects its defect and fails. (US8)
- **FR-044**: CI MUST run static/supply-chain analysis, and workflows MUST hold least-privilege tokens with no secret interpolation into shells. (US8)
- **FR-045**: The project constitution MUST be ratified before implementation completes, encoding BC-01…BC-22. (US8)
- **FR-046**: Every finding in the 2026-09-21 audit MUST be mapped to a task and to a test that fails against current code; unmapped findings block completion. (US8)
- **FR-047**: The engine binary MUST be a thin consumer of the library the integration tests exercise. (US8)

### Key Entities
See **Entities** above; each maps to a model in `data-model.md`.

### Technology Stack *(mandatory)*

**Languages/Frameworks**: Rust 2021 (engine, shell; `windows-sys` 0.61 for netio/WinTrust/DPAPI/ACL), Kotlin (Android shell), TypeScript 5.8 + React 19 (both UIs); Vite 7; Tailwind v4 reduced to tokens. **Runtime**: tokio 1.52+, `smoltcp` 0.12, vendored `quiche` 0.29.2 + `boring` 4.22, `boringtun` 0.6.0 (reviewed), `parking_lot`, `serde`, `chacha20poly1305` with AAD. **Contract layer**: `tauri-specta` 2.0.0-rc.x + `specta` + `specta-typescript` + `thiserror` (generated `bindings.ts`). **Virtualisation**: `@tanstack/react-virtual` 3.x. **Fonts**: `@fontsource-variable/geist` + `geist-mono` (OFL-1.1), bundled same-origin. **Quality gates**: `cargo clippy` with a `disallowed-methods` config, `cargo deny`, `osv-scanner`, `zizmor`, `actionlint`, `stylelint`, `axe`, `vitest`, Robolectric. **No new runtime services**: no updater backend, no paid signing dependency, no remote config.

**Accessibility requirements**: WCAG 2.2 AA as the enforced floor (BC-12, BC-14, FR-033/034), including 1.4.11 for state-bearing non-text and 2.5.8 target minimums.
**Localization**: `llm`-free — locale-independent formats required for all machine-read data; timestamps rendered 24-hour in fixed tracks.

### Platform Realities *(mandatory)*

**Deployment targets**: Windows 10/11 x64 (Tauri NSIS, perMachine or portable), Android 8.0+ arm64/armv7/x86_64, and the engine standalone from a CLI on all three. **Offline/airgapped**: the app MUST fully function with no network beyond its tunnel path — no CDN fonts, no GitHub API for status, no remote config. **Resource limits**: a 4 GB Android device and an 8 GB desktop must survive worst-case scan and download load (drives FR-021, netstack memory budget). **Security/privacy boundaries**: engine MUST NOT write secrets unless handed a key source; local proxy MUST be loopback-only by default with a destination deny-list; the elevated process MUST receive configuration over a private channel, not the environment. **Failure handling**: any failure that would leave the host mutated MUST reverse or block. **Audit/logging**: journal everything host-mutating; retain the audit trail across restart. **App lifecycle**: GUI and engine can die independently in either direction, on desktop and mobile (drives FR-001/003/039). **Manual review gates**: pin-set rotation, keystore destruction, patch-manifest changes to `quiche/`, and allowlist shrinkage in `cargo deny` require human review in the release environment.

---

## Success Criteria *(mandatory)*

**Measurable Outcomes**:
- **SC-001**: 100 % of the audit findings are mapped to a task with a failing-then-passing test; a written traceability table shows none skipped.
- **SC-002**: Across 200 scripted disconnect/crash/force-kill cycles, zero residual Aether routes, adapter overrides or proxy settings remain after the next start; zero third-party routes removed (verified by decoy-route differential).
- **SC-003**: Route/proxy teardown after `TerminateProcess` is fully repaired by the next start within 3 s; the normal in-session teardown path completes in <500 ms with PowerShell absent from `PATH`.
- **SC-004**: Release TUN mode starts successfully on a clean machine using the CI-produced package, and refuses to start for a binary signed by a different key — both outcomes demonstrated in CI.
- **SC-005**: Zero plaintext secrets on disk in any supported flow; moving a ciphertext to another path fails authentication; a transient keystore failure never deletes a key.
- **SC-006**: A peer-forced teardown is reported as an error 100 % of the time; injecting a 103 then 200 establishes; a 200 on another stream never latches readiness.
- **SC-007**: TCP connections idle 60 s survive at a 100 % rate; a dead peer is reaped within 90 s; 2 000 mixed-size frames drain in exact order under a saturated outbound channel.
- **SC-008**: During a maximum-load scan, a real proxied transfer sustains ≥80 % of its unscanned rate and scan cancellation completes in <50 ms.
- **SC-009**: Zero frontend↔Rust contract mismatches detected by the generated-binding diff; the previously broken cases (`"both"`, `scan_failed`, 2000-vs-500) each fail the build when reintroduced.
- **SC-010**: Every `className` in the shipped UI resolves to a rule; zero remote font or API requests leave the packaged app; every text element ≥4.5:1 and every state-bearing edge ≥3:1 measured at 100/125/150 % scaling.
- **SC-011**: A 2 000-row scan result keeps per-event frame time under 16 ms p95 on desktop.
- **SC-012**: On a device, a Wi-Fi→cellular handoff restores data within 30 s or presents a terminal "reconnect required" state — never a silent green badge with no traffic; bridge calls return in <50 ms.
- **SC-013**: `scripts/verify-invariants --selftest-fail` exits non-zero, proving each new gate can actually fire.
- **SC-014**: The APK satisfies the 2026 enforced target-API and 16 KB page-size requirements; every native payload digest is verified in CI, and corrupting the lock file fails the build.
- **SC-015**: The mobile and desktop UIs render from one shared component/token source; the deliberate-behaviour-difference list is empty or explicitly justified.

**Measurement方法**: CI runs the automated gates (SC-004…SC-015 mechanically); SC-002/003/008/012 are scripted soak runs in a Windows VM and on one ARM device, recorded as CI artifacts; SC-001 is a reviewed traceability table generated from the audit list; SC-013 is a build-time property.

## Out of Scope

- Any change to the MASQUE/QUIC **wire behaviour** toward Cloudflare edges beyond what correctness requires (no new transports, no new obfuscation profiles).
- Redesigning the visual language (the "hardware terminal" look is retained; only defects are fixed).
- Introducing a paid certificate, a hosted updater backend, or any new remote service.
- Upstreaming the `quiche` fork; converting it to a submodule is allowed but not required.
- Feature work: no new UI screens, no per-app split tunneling, no multi-user profiles.
- Rewriting the engine in-process on Android (explicit deferred behind a phase-2 decision).
- Historical `git` size remediation (working-tree cleanup only).

## Assumptions

- The only production peers are the pinned MASQUE/WARP edges, so per-host pin sets are tiny and rotation is handled by expiry + secondary pin.
- One human operator maintains release key material; therefore the trust anchor must be a committed, reviewable file, not infrastructure they cannot run.
- The user accepts a one-time OS-level import of a long-lived self-signed code-signing certificate if that is the cheapest path that keeps release TUN working.
- Android `libhev-socks5-tunnel` can be rebuilt from an upstream tag with the project's JNI package/class names; its current committed blobs came from a source tree not in this repo and are traceable only by strings.
- The 14 prior specs stay as history; this feature re-verifies rather than inherits their claims.
- `specs/014`'s open items are subsumed; nothing new in this spec depends on any prior spec's completion claim.
