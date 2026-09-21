# Implementation Plan: Full-System Audit Remediation & Structural Regression Prevention

**Branch**: `015-full-audit-remediation` | **Date**: 2026-09-21 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `specs/015-full-audit-remediation/spec.md`

## Summary

Remediate every finding from the 2026-09-21 full-codebase audit (~200 findings across 7 layers) in a way that makes the *pattern* — not just the instance — structurally impossible to repeat. The audit's dominant failure mode is self-cancelling fixes: guards whose enabling condition is unreachable, verification steps that inspect the wrong artifact, and tests that cannot observe the behaviour they claim to prove. This plan therefore treats **falsifiability as a requirement, not a practice**: every remediated item carries a test that fails against today's code, and every new invariant gate carries a `--selftest-fail` mode that injects its own defect.

Seven workstreams map to the spec's user stories: (1) host network state is never left damaged, (2) binary and peer trust are proven before execution, (3) secrets and learned state are authentic and unclonable, (4) the tunnel reports what it actually did, (5) idle connections survive and dead ones are reaped, (6) one contract across two platforms with zero drift, (7) Android survives network change. An eighth, cross-cutting workstream installs the mechanical gates that keep all of the above from regressing.

Two audit premises were disproved during research and are corrected in `spec.md` §Clarifications before any work is scheduled. Technical approach per defect: see [research.md](research.md) (R1–R42).

## Technical Context

**Language/Version**: Rust 2021 (engine `aether/`, Tauri shell `apps/desktop/src-tauri/`, Kotlin 2.0/JVM 21 for `apps/android/`), TypeScript 5.8 strict + React 19

**Primary Dependencies**: `tokio` 1.52+ · vendored `quiche` **0.29.2** (patched, `boringssl-boring-crate` + `qlog`) · `boring`/`tokio-boring` 4.22 · `smoltcp` 0.12 · `boringtun` 0.6.0 · `windows-sys` 0.61 (WinTrust, Cryptography, NetioApi, Security/ACL, Job Objects) · Tauri 2 · **added**: `tauri-specta` 2.0.0-rc.x + `specta` + `specta-typescript` + `thiserror` 2, `@tanstack/react-virtual` 3.x, `parking_lot`, `chacha20poly1305` with AAD, `@fontsource-variable/geist` + `geist-mono` · **removed**: two TLS kill-switches, `preshred_key` plumbing, Google Fonts `<link>`, `AETHER_WINTUN` env resolution, `useLegacyPackaging`, fabricated telemetry markup

**Storage**: Versioned authenticated envelope `AETHERCFG2 ‖ nonce(12) ‖ ct+tag` (ChaCha20-Poly1305, AAD = canonical path + schema version) with the data key from DPAPI (Windows, SID-scoped, app entropy) or AndroidKeyStore (dual-wrapped `…-v1`/`…-v2`); `routes.journal.json` (pre-mutation intent journal with LUIDs); proxy journal mirrored to `HKCU\Software\AetherNext\ProxyJournal`; endpoint cache is a write-behind snapshot of an in-process `EndpointRegistry`, never read directly

**Testing**: `cargo test` + new `#[cfg(test)]` Pipe-based transport tests and `aether/tests/` system tests · `cargo clippy -- -D warnings` with `clippy.toml` `disallowed-methods` · `vitest` (both UIs) · Robolectric + `ShadowVpnService` argument capture · `tsc --noEmit` with `noUncheckedIndexedAccess` · stylelint + a `className`→selector resolution script + an axe scan per tab · `scripts/verify-invariants` (with `--selftest-fail`) · `zizmor` + `actionlint` + `cargo deny` + `osv-scanner` · soak runs: 200 connect/force-kill cycles (Windows VM), Wi-Fi↔cellular handoff (ARM device)

**Target Platform**: Windows 10/11 x64 (Tauri NSIS perMachine + portable; WebView2), Android 8.0+/API 26+ with **target/compileSdk 36**, engine standalone from CLI on all three

**Project Type**: Multi-platform native + webview hybrid: Rust core engine (library + thin binary), Tauri desktop shell (Rust), React/TS web UI shared with an Android WebView shell (Kotlin)

**Performance Goals**: Scanner cancellation abort < 50 ms · route/proxy teardown in-session < 500 ms and post-`TerminateProcess` repair < 3 s · per-event frame time < 16 ms p95 with 2 000 streamed scan rows · QUIC `on_timeout()` promptness < 20 ms maximum gap under 8 concurrent probes · bridge call returns < 50 ms · netstack TX ring ≤ 256 frames · total netstack memory ≤ 128 MB admission budget

**Constraints**: Never leave host network state mutated · never write an unencrypted secret · no verification-bypass path compiled into a release binary · no runtime network request from the UI outside the tunnel path (offline/airgapped capable) · **no paid signing dependency** (an unaffordable control is a skipped control) · no new remote service, no hosted updater · every guard must have a test that fails if the guard is removed · `quiche` fork stays patched-in-place (no upstreaming)

**Scale/Scope**: ~200 audit findings · 21 behavioural invariants (BC-01…BC-22) · 47 functional requirements · 7 user stories · 8 workstreams · **37 first-party source files** (~21.3 k LOC audited: 31 engine modules, 2 248-line shell, ~3.1 k+3.3 k lines of CSS in two diverged copies, 9 Kotlin files, 12 TS modules) + 2 CI workflows + build scripts

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

**Status: BLOCKED-BY-GOVERNANCE, evaluated and passed with a recorded governance gap.**

`.specify/memory/constitution.md` is an **unpopulated template** — every principle is still a placeholder (`[PRINCIPLE_1_NAME]`, `[CONSTITUTION_VERSION]`), so the project has **zero ratified principles** to gate against. This is itself a finding, and a load-bearing one: fourteen prior audit specs (001–014) each declared remediation complete while several claimed fixes shipped inert, because there was no ratified rule that a "fix" must be falsifiable, no governance record defining what "verified" means, and no principle that a self-cancelling guard is a defect.

Because the gate is vacuous rather than satisfied, it cannot be "passed" silently. Resolution:

| Item | Determination |
|---|---|
| Violations of ratified principles | **None** — none exist. |
| Consequence for this plan | No complexity is unjustifiable on constitutional grounds; `Complexity Tracking` is therefore **not** required by a gate failure. |
| Required action | **FR-045**: ratify a constitution encoding BC-01…BC-22 via `/speckit-constitution` **before** `tasks.md` is executed to completion, so that `speckit-converge`/`review` have rules to audit against. This plan proceeds; it does not treat the empty template as approval. |
| Standing rule adopted in the interim | Every decision in `research.md` is written as *Decision / Rationale / Alternatives considered / Verification test*, and no decision is accepted without a test that fails if its guard is unreachable. This is the de-facto constitution for this feature and the seed for the ratified one. |

**Post-Phase-1 re-check (after research.md, data-model.md, contracts/)**: ✅ No gates introduced a violation. Two design choices were **rejected on simplicity grounds** before they could become violations: a signed auto-updater (no key custody → would be configured wrong or skipped) and an in-process Android engine rewrite (destroys the existing W^X workaround for no defect-fixing benefit). Both are recorded as deferred with defaults, not open questions. The vendored-`quiche` decision chose pinned-checksum-plus-patch-manifest over submodule conversion for the same reason: minimum churn, full audit property.

## Project Structure

### Documentation (this feature)

```text
specs/015-full-audit-remediation/
├── spec.md              # 7 user stories, 47 FRs, 21 invariants, corrections to the audit
├── plan.md              # this file
├── research.md          # Phase 0 — R1…R42, Decision/Rationale/Alternatives/Verification
├── data-model.md        # Phase 1 — entities, field rules, state machines, migration
├── quickstart.md        # Phase 1 — validation guide incl. the falsifiability protocol
├── contracts/           # Phase 1
│   ├── ipc-contract.md              # shell commands + events, typed error enum
│   ├── engine-event-protocol.md     # engine → shell NDJSON, run_id/generation rules
│   ├── host-state-contract.md       # route journal + proxy journal + repair semantics
│   ├── trust-verification-policy.md # anchor set, verify-before-spawn, release signing order
│   ├── secret-envelope-format.md    # AETHERCFG2 layout, key sources, migration
│   └── ui-design-contract.md        # tokens, classes, contrast, a11y acceptance
└── tasks.md             # Phase 2 (/speckit-tasks — NOT created by /speckit-plan)
```

### Source Code (repository root)

```text
aether/                                    # Rust engine (library + thin binary)
├── src/
│   ├── lib.rs            # single module owner; main.rs becomes a thin binary (R42)
│   ├── runtime_env.rs    # SOLE config reader: var/set/remove/Snapshot + one truthiness helper
│   ├── quic.rs masque.rs masque_h2.rs h3_probe.rs   # drain loop, readiness FSM, error taxonomy, teardown reason
│   ├── session.rs        # success/failure recording, verification-by-transport, registry client
│   ├── prober.rs         # per-probe tasks, timer-first select, budget math, drill-down fix
│   ├── netstack.rs       # keep-alive+abort, bounded TX ring, strict FIFO, fair loop, port randomisation
│   ├── socks.rs http_proxy.rs dns.rs       # origin-map TTL, CRLF parsing, ECH reply validation, policy
│   ├── tun_win.rs        # → netio FFI mutations, LUID scoping, parent-handle teardown
│   ├── route_repair.rs   # NEW: unconditional startup repair + --repair-routes
│   ├── trust.rs          # NEW: VerifyPolicy, PinSet, chain-anchored-at-pinned-leaf verification
│   ├── config.rs cache.rs account.rs       # envelope + AAD, EndpointRegistry actor, ZeroizeOnDrop
│   ├── wireguard.rs obfuscation.rs aethernoize.rs noize.rs   # PSK removal, keepalive threading, bounds
│   └── error.rs consts.rs mtu.rs engine_config.rs lastconn.rs routing_plane.rs
├── tests/                # system-level: teardown, FIFO, UDP associate, trust rejection
└── examples/trust/       # NEW: signed-elsewhere fixtures for trust tests

apps/desktop/
├── src-tauri/
│   ├── src/lib.rs        # engine_supervisor thread, per-child Job, typed CommandError, 90s watchdog
│   ├── build.rs          # embeds the pinned ANCHOR FILE; never hashes the file it ships
│   ├── tests/            # dpapi_key / elevation_trust / proxy_restore (extended, non-tautological)
│   └── tauri.conf.json   # minWidth off the breakpoint collision; CSP stays 'self'-only
├── src/
│   ├── bindings.ts       # GENERATED from Rust (R25); never hand-edited
│   ├── components/ hooks/ types.ts        # per-tab boundary, virtualised rows, honest stats
│   └── App.css           # token-driven; classes all resolve; fonts self-hosted
└── index.html            # remote font <link>s deleted

packages/ui/              # NEW: @aether/ui shared token + component package (R35)
├── tokens.css            # single token source: --edge / --edge-interactive / type scale
└── src/                  # shared components; platform differences become props

apps/android/
├── android/app/src/main/java/app/aethernext/
│   ├── AetherBridge.kt       # async requestId protocol, nothing blocking on the bridge thread
│   ├── AetherVpnService.kt   # fail-closed exclusion, TProxyGetStats watchdog, off-main teardown
│   ├── SessionController.kt  # coroutine scope, listener registry, event-driven status
│   ├── EngineRunner.kt MainActivity.kt ConfigKeyStore.kt SettingsStore.kt BootReceiver.kt
│   └── Liveness.kt           # NEW: pure decideLiveness(prev, now, elapsed, attempt)
├── android/app/src/test/     # Robolectric builder capture; tautological test deleted
├── hev-lock.json             # NEW: upstream tag + per-ABI sha256 + build recipe
└── src/                      # consumes @aether/ui; own watchdog/hydration merged into shared source

.github/
├── workflows/{ci.yml,build.yml}   # sign-before-bundle, extract-and-verify, permissions, env secrets
└── scripts/sign-windows.ps1

scripts/
├── verify-invariants.(sh|ps1)     # NEW: all BC-* gates + mandatory --selftest-fail mode
└── verify-installers.ps1          # NEW: 7z-extract, check every inner binary, fail on 0 found
```

**Structure Decision**: The repository is already a polyglot monorepo with a clean layer split, so no restructuring is proposed; the audit's structural failures are *contract* failures, not *directory* failures. Three additions are structural and deliberate: (1) `packages/ui/` is the minimum change that ends the two-fork drift, which is currently a *behavioural* divergence (only Android has the connect watchdog), not merely visual; (2) `aether/src/trust.rs` and `aether/src/route_repair.rs` extract two cross-cutting policies that today are smeared across `tls.rs`/`masque_h2.rs` and `tun_win.rs` respectively, which is precisely how two copies of the same rule drifted apart; (3) `scripts/verify-invariants` is the deliverable that makes this feature's completion durable — without it the next audit finds the same classes again. `main.rs`'s private copy of all 30 modules is removed so integration tests exercise shipped code.

## Workstreams & Sequencing

| WS | Scope | Spec stories | Research | Depends on |
|----|-------|--------------|----------|------------|
| **A. Host-state safety** | routes/proxy journal, netio FFI, unconditional repair, teardown handshake | US1 | R14,R15 | — (start first) |
| **B. Trust & secrets** | verify-before-spawn, wintun, pin+chain, envelope, ACLs, registry, Android keystore | US2, US3 | R16-R24, R39 | A (journal shape) |
| **C. Transport truth** | drain loop, readiness FSM, error taxonomy, teardown reason, liveness, scanner timers | US4 | R1-R6 | — |
| **D. Netstack & proxies** | keep-alive, bounded ring, FIFO, fairness, ports, quotas, proxy policy | US5 | R7-R13 | C (shared loop idioms) |
| **E. Contract & gates** | generated IPC, typed errors, run_id, invariants, constitution | US6, US8 | R25-R31, R42 | B/C/D surfaces |
| **F. Visual system** | fonts, borders, tokens, colour, spinners, a11y, virtualisation, shared package | US6 | R32-R36 | E (bindings.ts), packages/ui |
| **G. Android platform** | liveness+restart, async bridge, events-not-prose, SDK/16KB/native payloads | US7 | R37-R41 | A (journal), E (event types) |
| **H. Release pipeline** | sign-before-bundle, anchor custody, provenance, supply-chain tooling | US2, US8 | R24, R29-R31 | B |

E is deliberately early: `bindings.ts` must exist before F rewrites components, or F's fixes land in types that E then regenerates. C precedes D because both touch the same select/loop idioms and a shared "fatal vs retryable" convention.

## Post-Implementation Verification Requirements *(mandatory)*

- **Constitution Alignment**: re-check after `tasks.md` completes; requires FR-045's ratified constitution to exist. Absent it, verification uses this plan's de-facto rule (every guard has a can-fail test).
- **Real-Environment Validation** (not a substitute for unit tests; required before claiming any success criterion met):
  - SC-002/SC-003: Windows VM — 200 scripted cycles of clean disconnect, GUI kill, engine `taskkill /F`, uninstall-while-connected, with a decoy third-party split route present each time; diff the routing table and proxy registry before/after.
  - SC-004: clean Windows 11 machine, install the CI-produced package, connect in TUN, then attempt with a differently-signed engine.
  - SC-005/SC-012: ARM device with developer VPN logging — Wi-Fi→cellular handoff ×20, task swipe, doze, screen-lock keystore access, first-install consent.
  - SC-006/SC-007: against a real edge **and** a local fake H3/MASQUE peer that sends 103s, off-stream 200s, oversized datagrams, and then stops answering.
  - SC-010: Windows at 100/125/150/175 % and Android in light mode; measure rendered contrast rather than computing it from tokens.
- **Contract Compliance**: `scripts/verify-invariants --selftest-fail` exits non-zero (SC-013) — proof that the gates can fire; `git diff --exit-code` on regenerated bindings; installer-contents verification with a deliberately unsigned fixture build.
- **Traceability (FR-046, SC-001)**: a generated table mapping every audit finding → invariant → task → failing-then-passing test, reviewed as part of completion. An unmapped finding blocks completion.
- **Regression**: after each workstream, run the full prior-audit quickstart set (US8) to confirm 001–014's genuinely-working fixes still work.

## Complexity Tracking

> No constitutional violations exist to justify (the constitution is unratified). Two items are recorded here because they are the design's only non-obvious expansions, and both were **constrained** rather than accepted at face value.

| Item | Why needed | Simpler alternative rejected because |
|---|---|---|
| `packages/ui/` shared workspace (new top-level dir) | The two UI forks differ in *behaviour*, not just styling — desktop lacks the connect watchdog that prevents a permanent "Connecting" state with Settings locked. A shared package is the only structure where that class of drift is impossible. | Cherry-pick the missing behaviours into the desktop fork — rejected: 42 findings of visual drift plus a 359-line stylesheet delta would still re-divergence, and the next audit would report the same item. |
| Two new engine modules (`trust.rs`, `route_repair.rs`) | Both encode a *policy* currently duplicated with drift: pin verification lives twice (`tls.rs`, `masque_h2.rs`) with different behaviours, and route cleanup is split between Drop-driven teardown and an unreachable spawn-time repair. Two policies that live in three places is the defect. | Fix both copies in place — rejected: the copies are exactly what disagreed; there is no invariant that keeps them equal. |

## Phase 0 → Phase 1 Traceability

- All Technical Context fields are populated; **no NEEDS CLARIFICATION remains** in the spec, this plan or `research.md`.
- Deferred items are decisions-with-defaults, listed in `research.md` §NEEDS CLARIFICATION: Android in-process engine, Windows service trust boundary, signed updater, submodule conversion.
- Phase 1 outputs: [data-model.md](data-model.md), [contracts/](contracts/), [quickstart.md](quickstart.md).
