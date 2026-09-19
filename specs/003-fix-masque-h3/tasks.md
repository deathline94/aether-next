# Implementation Tasks: Fix MASQUE H3 Connectivity and Upstream Alignment + Bug Remediation

**Feature Branch**: `003-fix-masque-h3`
**Spec**: [spec.md](spec.md) | **Plan**: [plan.md](plan.md)
**Status**: Ready for Implementation

---

## Phase 1: Setup & Constants

**Purpose**: Define protocol constants and test harness for pre-handshake baiting.

- [x] T001 Define `QUIC_V2_VERSION` constant (`0x6b33_43cf`) in aether/src/consts.rs
- [x] T002 [P] Implement unit tests for QUIC v2 version negotiation packet generator in aether/src/quic.rs

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Core transport, cryptographic, and header infrastructure required before MASQUE connections can proceed.

**⚠️ CRITICAL**: Must complete before starting User Story phases.

- [x] T003 Implement `build_version_bait()` and `send_version_bait()` with `AETHER_QUIC_V2` environment toggle in aether/src/quic.rs
- [x] T004 [P] Align Quiche transport parameters (strictly `b"h3"` ALPN, remove unvalidated early data, set `disable_active_migration(true)`) in aether/src/tls.rs
- [x] T005 [P] Standardize CONNECT-IP request headers to clean RFC 9220 / RFC 9484 format and remove obsolete `H3HeaderMode` in aether/src/masque.rs

**Checkpoint**: Core packet formats, headers, and transport configuration ready.

---

## Phase 3: User Story 1 - MASQUE H3 Connection Establishment (Priority: P1) 🎯 MVP

**Goal**: Deliver reliable MASQUE H3 tunnel connections that punch through DPI middleboxes on restricted networks.

**Independent Test**: Connect via MASQUE H3 profile, verify 1200-byte version bait is sent, QUIC v1 handshake succeeds, and tunnel connects.

- [x] T006 [US1] Wire `send_version_bait()` before Quiche connection creation in aether/src/quic.rs
- [x] T007 [US1] Integrate version baiting into standalone MASQUE prober candidate checks in aether/src/prober.rs
- [x] T008 [US1] Validate MASQUE H3 tunnel session establishment and datagram budget in aether/src/session.rs

**Checkpoint**: MASQUE H3 handshakes successfully pass through DPI firewalls without being dropped.

---

## Phase 4: User Story 2 - Proxy Stream Health, Stream Reset & Data Plane Probing (Priority: P2)

**Goal**: Eliminate hung states on rejected streams and guarantee verified bidirectional data flow before declaring connection active.

**Independent Test**: Connect to a rejected/unauthorized endpoint and verify immediate failure; connect to a valid endpoint and verify 2 consecutive DNS probes over H3 datagrams.

- [x] T009 [US2] Implement fail-fast HTTP status code validation (abort on non-2xx) and stream reset/finish event handling in aether/src/masque.rs
- [x] T010 [US2] Update `verify_masque()` in aether/src/quic.rs to probe data plane requiring 2 consecutive DNS replies over encapsulated H3 datagrams
- [x] T011 [US2] Update quick verification logic in aether/src/session.rs to handle stream rejection and fail fast

**Checkpoint**: Silent connection hangs and unverified proxy tunnels are completely prevented.

---

## Phase 5: User Story 3 - Visual, Scanner & Ergonomic Bug Remediation (Priority: P3)

**Goal**: Fix all cataloged UI, layout, telemetry, and settings bugs across the desktop application.

**Independent Test**: Run a standalone scan, test "Connect Direct" tab transition, clear forced peer on preset click, test connection in TUN mode, and verify layout containment.

- [x] T012 [P] [US3] Switch view to `"home"` (`setView("home")`) when "Connect Direct" is clicked in apps/desktop/src/App.tsx
- [x] T013 [US3] Clear pinned `peer` when clicking presets or primary Connect button, and display forced peer indicator badge in apps/desktop/src/components/ConnectionTab.tsx
- [x] T014 [P] [US3] Retain scanner progress bar and summary metrics after scan completes or stops (`active || scanned > 0`) in apps/desktop/src/components/ScannerTab.tsx
- [x] T015 [P] [US3] Set phase to `"Completed (0 found)"` on zero hits and suppress empty log strings in apps/desktop/src/hooks/useScanner.ts
- [x] T016 [P] [US3] Update `test_connection()` to conduct direct HTTPS trace in TUN mode without failing on port 1820 in apps/desktop/src-tauri/src/lib.rs
- [x] T017 [P] [US3] Update Process metric subtitle to show "Starting" / "Connecting" during startup, update obsolete preset notes, and add test result color accents in apps/desktop/src/components/ConnectionTab.tsx
- [x] T018 [P] [US3] Add `max-height: 380px; overflow-y: auto;` to `.discovered-list` and add overflow wrap containment in apps/desktop/src/App.css
- [x] T019 [P] [US3] Add advisory for UDP noise inapplicability under H2, and reflect blocked save state on sticky save bar when port collision occurs in apps/desktop/src/components/SettingsTab.tsx
- [x] T020 [P] [US3] Filter probe candidate timeouts out of the "Milestones" filter predicate in apps/desktop/src/hooks/useLogs.ts

**Checkpoint**: All desktop UI visual inconsistencies, telemetry glitches, layout overflows, and settings edge cases are fully resolved.

---

## Phase 6: Polish & Cross-Cutting Concerns

**Purpose**: Full workspace build verification and end-to-end testing.

- [x] T021 Run `cargo test --package aether --lib` to verify all engine unit and bait generation tests
- [x] T022 Run `cargo check --workspace` to ensure all workspace crates (engine, tauri host, android) compile cleanly
- [x] T023 Run `npm run build` in apps/desktop to verify TypeScript compilation and UI bundle generation
- [x] T024 Validate end-to-end verification scenarios per specs/003-fix-masque-h3/quickstart.md

---

## Dependencies & Execution Order

### Phase Dependencies
- **Setup & Constants (Phase 1)**: Can start immediately.
- **Foundational (Phase 2)**: Depends on Phase 1 completion — BLOCKS all user stories.
- **User Story 1 (Phase 3)**: Depends on Phase 2 completion.
- **User Story 2 (Phase 4)**: Depends on Phase 2 & Phase 3 completion.
- **User Story 3 (Phase 5)**: Depends on Phase 2 completion (can proceed in parallel with US1/US2).
- **Polish & Cross-Cutting (Phase 6)**: Depends on all user stories being complete.

### Parallel Opportunities
- T001, T002 can be completed together.
- T004, T005 can be implemented in parallel.
- All desktop frontend tasks in Phase 5 (T012, T014, T015, T016, T017, T018, T019, T020) target separate files and components and can run concurrently.

---

## Implementation Strategy (MVP First)

1. **Sprint 1 (MVP)**: Implement Phase 1, Phase 2, and Phase 3. Validate that MASQUE H3 handshakes and connects over the network.
2. **Sprint 2 (Robustness)**: Implement Phase 4. Validate fail-fast stream rejection and 2-probe data plane verification.
3. **Sprint 3 (UI & Polish)**: Implement Phase 5 and Phase 6. Fix all desktop bugs, verify builds, and run full test suites.
