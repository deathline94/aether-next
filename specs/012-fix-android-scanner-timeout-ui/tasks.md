# Implementation Tasks: Unbounded Scanner Execution & Mobile Terminal Header UI Fixes

**Feature**: `012-fix-android-scanner-timeout-ui`
**Spec**: [`specs/012-fix-android-scanner-timeout-ui/spec.md`](./spec.md)
**Plan**: [`specs/012-fix-android-scanner-timeout-ui/plan.md`](./plan.md)

---

## Phase 1: Setup & Foundational Prerequisites

**Purpose**: Verify existing environment, build toolchains, and setup baseline structure.

- [x] T001 Verify Rust engine toolchain and run baseline check in `aether/Cargo.toml`
- [x] T002 [P] Verify Android Kotlin build environment and gradle configuration in `apps/android/android/app/build.gradle.kts`
- [x] T003 [P] Verify Android frontend web build environment in `apps/android/package.json`

**Checkpoint**: Development toolchains verified; core engine, native Android, and webview layers compile cleanly.

---

## Phase 2: User Story 1 - Unbounded Endpoint Pool Scanning (Priority: P1) 🎯 MVP

**Goal**: Standalone scans run continuously without being cut off by connection flow watchdogs (90s) or engine deadline caps (600s).

**Independent Test**: Start a standalone scan with 20,000 candidates. Observe the scan progress past 90 seconds and past 300 seconds without any premature termination, connection watchdog trigger, or false-positive error alerts.

### Implementation Tasks

- [x] T004 [US1] Remove 10-minute overall deadline cap for exhaustive scans (`st.overall_deadline = Duration::MAX`) in `aether/src/prober.rs`
- [x] T005 [US1] Ensure prober candidate stream loop in `aether/src/prober.rs` only exits on candidate pool exhaustion or explicit cancellation when `exhaustive` is active
- [x] T006 [P] [US1] Expose public `isScanMode(): Boolean` inspection helper on `EngineRunner` in `apps/android/android/app/src/main/java/app/aethernext/EngineRunner.kt`
- [x] T007 [US1] Remove `setRuntime("connecting", ...)` from `scan()` method in `apps/android/android/app/src/main/java/app/aethernext/SessionController.kt` so standalone scans do not mutate tunnel connection state
- [x] T008 [US1] Update `onExit` handler in `apps/android/android/app/src/main/java/app/aethernext/SessionController.kt` to prevent setting `runtime.status = "error"` when a standalone scan process completes or cancels

**Checkpoint**: Standalone scans run with unlimited duration, never mutating the tunnel state to "connecting" and never triggering the connection watchdog.

---

## Phase 3: User Story 2 - Responsive, Bound-Safe Mobile Terminal Window Header (Priority: P1)

**Goal**: Redesign the live engine terminal console header on mobile viewports so window controls, telemetry text, and action buttons fit within the chassis without horizontal clipping or vertical word fragmentation.

**Independent Test**: Load the Activity tab on a mobile viewport (360px–412px). Confirm that window dots and session title remain on one line with ellipsis protection, the buffer stream counter displays on a single line without multi-line wrapping, and action buttons (`Follow`, `Copy Buffer`, `Clear`) are fully visible and comfortable to tap.

### Implementation Tasks

- [x] T009 [US2] Implement responsive 2-tier CSS Grid layout (`controls telemetry` / `actions actions`) for `.terminal-header-chrome` under `@media (max-width: 680px)` in `apps/android/src/App.css`
- [x] T010 [P] [US2] Apply `white-space: nowrap; overflow: hidden; text-overflow: ellipsis;` to `.terminal-title-text`, `.terminal-center-telemetry`, and `.stream-count` in `apps/android/src/App.css`
- [x] T011 [P] [US2] Configure `.terminal-action-buttons` under mobile breakpoint to span full width with `justify-content: flex-end` and min 30px touch height in `apps/android/src/App.css`
- [x] T012 [US2] Ensure terminal action button markup and state feedback (e.g. "Copied") render seamlessly in `apps/android/src/components/ActivityTab.tsx`
- [x] T013 [P] [US2] Apply cross-platform mobile nowrap and overflow safeguards to terminal header classes in `apps/desktop/src/App.css`

**Checkpoint**: Terminal window header displays without clipping, text wrapping, or out-of-bounds overflow across all mobile screen sizes.

---

## Phase 4: User Story 3 - Separation of Scanner & Connection Lifecycles (Priority: P2)

**Goal**: Guarantee clean state transitions between exploratory scanning and tunnel connection flows, preventing false status badges and enabling seamless direct gateway connections.

**Independent Test**: Run a scan, stop it, and click "Connect Direct" on a discovered gateway. Confirm the scan stops cleanly, the connection transitions to "connecting", and the connection watchdog is correctly armed for the tunnel attempt.

### Implementation Tasks

- [x] T014 [US3] Verify `stop_scan` command handling in `apps/android/android/app/src/main/java/app/aethernext/SessionController.kt` gracefully sends `cancel\n` without leaving zombie processes
- [x] T015 [US3] Verify direct connection transition from scanner hits to tunnel connection in `apps/android/src/hooks/useScanner.ts` and `apps/android/src/App.tsx`

**Checkpoint**: Scanning and connecting lifecycles operate independently without state interference or watchdog leaks.

---

## Phase 5: Verification, Build & Polish

**Purpose**: End-to-end compilation, bundle verification, and quickstart scenario validation.

- [x] T016 Verify Rust core engine builds without warnings via `cargo check` in `aether/`
- [x] T017 [P] Verify Android frontend bundle builds with 0 errors via `npm run build` in `apps/android/`
- [x] T018 [P] Verify Android Kotlin compilation passes with 0 errors via `./gradlew compileDebugKotlin` in `apps/android/android/`
- [x] T019 Execute validation scenarios from `specs/012-fix-android-scanner-timeout-ui/quickstart.md`

---

## Dependencies & Execution Order

```mermaid
flowchart TD
    subgraph Phase 1: Setup
        T001[T001 Toolchain Verify]
        T002[T002 Android Verify]
        T003[T003 Web Verify]
    end

    subgraph Phase 2: US1 Unbounded Scanner
        T004[T004 Prober Deadline MAX]
        T005[T005 Prober Loop Unbounded]
        T006[T006 EngineRunner isScanMode]
        T007[T007 SessionController scan state]
        T008[T008 SessionController onExit clean]
    end

    subgraph Phase 3: US2 Mobile Terminal Header
        T009[T009 Terminal Header CSS Grid]
        T010[T010 Text Nowrap & Ellipsis]
        T011[T011 Action Buttons Mobile Width]
        T012[T012 ActivityTab Markup Check]
        T013[T013 Desktop CSS Parity]
    end

    subgraph Phase 4: US3 Lifecycle Separation
        T014[T014 Stop Scan Handling]
        T015[T015 Connect Direct Transition]
    end

    subgraph Phase 5: Build & Polish
        T016[T016 Cargo Check]
        T017[T017 Frontend Build]
        T018[T018 Kotlin Compile]
        T019[T019 Quickstart Validation]
    end

    Phase 1 --> Phase 2
    Phase 1 --> Phase 3
    Phase 2 --> Phase 4
    Phase 3 --> Phase 5
    Phase 4 --> Phase 5
```

---

## Parallel Execution Opportunities

- **Phase 1**: T001, T002, T003 can execute in parallel.
- **Phase 2 & Phase 3**: Can execute concurrently as Phase 2 touches Rust/Kotlin backend while Phase 3 touches React/CSS frontend.
- **Within Phase 3**: T010, T011, and T013 can execute in parallel.
- **Phase 5**: T016, T017, and T018 can execute in parallel.

---

## Implementation Strategy: MVP First

1. **MVP (Phase 1 + Phase 2)**:
   - Implement T004–T008. Standalone scans can immediately run for hours across entire pools without 90s connection watchdog aborts or 600s engine deadlines.
2. **Visual Ergonomics (Phase 3)**:
   - Implement T009–T013. Fixes mobile terminal header clipping, word fragmentation, and out-of-bounds action buttons.
3. **Integration & Lifecycle Polish (Phase 4 & 5)**:
   - Implement T014–T019. Guarantees clean handoff between scanning and tunnel connection, verified by full builds across all 3 layers.
