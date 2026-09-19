# Implementation Tasks: Comprehensive Codebase Bug Audit & Precision Remediation

**Feature Branch**: `004-codebase-bug-audit-remediation`
**Spec**: [spec.md](spec.md) | **Plan**: [plan.md](plan.md)
**Status**: Completed

---

## Phase 1: Setup & Foundations

**Purpose**: Establish test helpers and verify shared contract types before implementing user story changes.

- [x] T001 Define and verify queue FIFO ordering test harness in aether/src/netstack.rs
- [x] T002 [P] Define resolver entry test cases for IPv4 and IPv6 in aether/src/socks.rs
- [x] T003 [P] Define query-preservation test cases for URI rewriting in aether/src/http_proxy.rs

---

## Phase 2: User Story 1 - Core Networking, Transport & Netstack Bug Remediation (Priority: P1) 🎯 MVP

**Goal**: Guarantee lossless in-order packet queueing under congestion, robust IPv6 DNS server configuration, multi-socket UDP associate routing, and query string preservation.

**Independent Test**: Run `cargo test --bin aether` verifying all new queue ordering, DNS parsing, and URI rewrite unit tests pass alongside the existing 49 tests.

- [x] T004 [US1] Fix `flush_tx` queue packet inversion on `outbound_tx` backpressure in aether/src/netstack.rs
- [x] T005 [P] [US1] Add unit test `netstack_queue_preserves_fifo_order_on_congestion` in aether/src/netstack.rs
- [x] T006 [US1] Fix `configured_dns_servers` to parse bare and bracketed IPv6 resolver addresses into `SocketAddr` with default port 53 in aether/src/socks.rs
- [x] T007 [P] [US1] Add unit tests `configured_dns_servers_handles_bare_and_bracketed_ipv6` in aether/src/socks.rs
- [x] T008 [US1] Multiplex UDP Associate replies by mapping client endpoints to remote targets in aether/src/socks.rs
- [x] T009 [US1] Preserve query strings and parameters in `rewrite_absolute_uri` in aether/src/http_proxy.rs
- [x] T010 [P] [US1] Add unit test `rewrite_absolute_uri_preserves_query_string` in aether/src/http_proxy.rs
- [x] T011 [US1] Switch `std::env::var` peer lookups to `runtime_env::var` in `select_peer` in aether/src/session.rs

**Checkpoint**: Core networking engine guarantees lossless in-order delivery, robust IPv6 DNS resolution, and query preservation.

---

## Phase 3: User Story 2 - Windows Routing & System Proxy Safety (Priority: P2)

**Goal**: Prevent destruction of coexisting third-party VPN routes during Aether TUN setup and ensure clean route and registry restoration.

**Independent Test**: Connect via TUN mode and verify route installation scopes `Remove-NetRoute` strictly to `ADAPTER_NAME` and `physical_if_index`.

- [x] T012 [US2] Scope `Remove-NetRoute` in `install_routes()` to `tunIf` and `physIf` interface indices in aether/src/tun_win.rs
- [x] T013 [US2] Verify `reset_adapter_config` and `remove_routes` teardown cleanliness in aether/src/tun_win.rs

**Checkpoint**: Host routing integrity is safeguarded; third-party VPN routes remain unaffected when Aether TUN connects.

---

## Phase 4: User Story 3 - Desktop UI, Telemetry, and State Machine Precision (Priority: P3)

**Goal**: Eliminate UI spinning lockups on connection error, prevent spurious auto-save error logs during port editing, align obfuscation select controls, and ensure log readiness parsing parity.

**Independent Test**: Test direct connection failure from Scanner tab, test port collision auto-save blocking in Settings tab, and verify Scanner obfuscation options match Settings.

- [x] T014 [US3] Catch connection failure in `connectToPeer` and transition runtime state to `status: "error"` in apps/desktop/src/hooks/useRuntime.ts
- [x] T015 [P] [US3] Filter auto-save in `persistSettings` to abort when ports collide or fall outside 1024..=65535 in apps/desktop/src/hooks/useRuntime.ts
- [x] T016 [P] [US3] Synchronize obfuscation dropdown `<option>` values with canonical profiles (`off`, `light`, `medium`, `high`, `max`, `custom`) in apps/desktop/src/components/ScannerTab.tsx
- [x] T017 [P] [US3] Update line 459 in apps/desktop/src-tauri/src/lib.rs to match `"socks5 listening on"` and `"http proxy listening on"`

**Checkpoint**: Desktop frontend state machine is resilient, free of infinite spinners, and quiet during settings configuration.

---

## Phase 5: User Story 4 - Android Client Security & Handshake Reliability (Priority: P4)

**Goal**: Re-enable SPKI certificate pinning on Android production builds and prevent premature scanner handshake timeouts over cellular connections.

**Independent Test**: Verify `EngineRunner.kt` does not unconditionally pass `AETHER_DANGEROUS_DISABLE_TLS_VERIFY = "1"`, and verify `AetherBridge.kt` defaults scanner timeout to 6000ms.

- [x] T018 [US4] Remove hardcoded `AETHER_DANGEROUS_DISABLE_TLS_VERIFY = "1"` in apps/android/android/app/src/main/java/app/aethernext/EngineRunner.kt
- [x] T019 [P] [US4] Update default standalone scan timeout in `AetherBridge.kt` from 3000ms to 6000ms in apps/android/android/app/src/main/java/app/aethernext/AetherBridge.kt

**Checkpoint**: Android client operates with full SPKI pinning security and sufficient probe timeout for cellular QUIC handshakes.

---

## Phase 6: Polish & Cross-Cutting Concerns

**Purpose**: Full workspace build verification and end-to-end testing.

- [x] T020 Run `cargo test --bin aether` to verify all existing and newly added engine tests pass
- [x] T021 Run `cargo check` in apps/desktop/src-tauri to ensure desktop backend compiles cleanly
- [x] T022 Run `npm run build` in apps/desktop to verify TypeScript and UI bundling
- [x] T023 Run validation scenarios per specs/004-codebase-bug-audit-remediation/quickstart.md

---

## Dependencies & Execution Order

### Phase Dependencies
- **Phase 1 (Setup)**: Can start immediately.
- **Phase 2 (US1 - MVP)**: Depends on Phase 1.
- **Phase 3 (US2)**: Can run after Phase 1 / concurrently with US1.
- **Phase 4 (US3)**: Can run after Phase 1 / concurrently with US1/US2.
- **Phase 5 (US4)**: Can run after Phase 1 / concurrently with US1/US2/US3.
- **Phase 6 (Polish)**: Depends on completion of all user stories.

### Parallel Opportunities
- T002, T003 can run in parallel during Phase 1.
- T005, T007, T010 can be developed in parallel once foundational fixes are staged.
- T014, T015, T016, T017 target different files and can be worked on concurrently.
- T018, T019 can be implemented independently on the Android codebase.

---

## Implementation Strategy (MVP First)

1. **Sprint 1 (MVP)**: Implement Phase 1 and Phase 2 (US1). Validate netstack queue preservation, IPv6 DNS resolution, and query string preservation with unit tests.
2. **Sprint 2 (Host & Routing)**: Implement Phase 3 (US2) and Phase 4 (US3). Validate Windows route scoping, direct connect error transitions, and auto-save filtering.
3. **Sprint 3 (Mobile & Polish)**: Implement Phase 5 (US4) and Phase 6. Re-enable SPKI pinning on Android, run full workspace verification suites, and validate against quickstart.
