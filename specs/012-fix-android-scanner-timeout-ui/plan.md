# Implementation Plan: Unbounded Scanner Execution & Mobile Terminal Header UI Fixes

**Branch**: `012-fix-android-scanner-timeout-ui` | **Date**: 2026-09-19 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from [`specs/012-fix-android-scanner-timeout-ui/spec.md`](./spec.md)

## Summary

This plan addresses two critical Android defects:
1. **Unbounded Standalone Scanning**: Decouple standalone scanner execution from the VPN connection handshake lifecycle by:
   - Ensuring `SessionController.scan()` does not set `runtime.status = "connecting"` (which erroneously displayed a connecting badge and armed the 90-second connection watchdog in `useRuntime.ts`).
   - Removing the arbitrary 10-minute cap in `aether/src/prober.rs` when `AETHER_SCAN_EXHAUSTIVE=1` so scans run until the candidate pool is fully probed or the user stops it.
   - Preventing `SessionController.kt` exit handlers from reporting connection gateway errors when a scan terminates.
2. **Responsive Mobile Terminal Window Header**: Redesign `.terminal-header-chrome` using a mobile-optimized CSS Grid layout (`@media (max-width: 680px)`) that stacks into two clean tiers:
   - Tier 1: Window controls and session title on the left; single-line stream counter telemetry (`X shown / Y buffer`) on the right.
   - Tier 2: Action buttons (`Follow`, `Copy Buffer`, `Clear`) right-aligned across full width, eliminating clipped text (`Copy Buffe`) and multi-line vertical word fragmentation.

---

## Technical Context

**Language/Version**: TypeScript 5.6 / React 18.3, Kotlin 1.9 (Android SDK 34, minSdk 26), Rust 1.88 (Edition 2021)

**Primary Dependencies**: Vite, Lucide React, OkHttp, Tokio, Quiche, BoringSSL

**Storage**: Android `SharedPreferences`, `aether.toml` configuration files, in-memory stream buffer

**Testing**:
- Frontend: `npm run build` (TypeScript + Vite)
- Android: `./gradlew compileDebugKotlin`
- Rust Engine: `cargo check`

**Target Platform**: Android (API 26+) mobile devices, with desktop parity for shared CSS

**Project Type**: Multi-platform VPN & Probing Client (Android Native + Webview UI + Rust Core Engine)

**Performance Goals**:
- Standalone scans run past 300+ seconds without interruption until pool completion or user cancel.
- Terminal console header renders cleanly on mobile viewports down to 320px with zero clipping.

**Constraints**:
- Connection watchdog (90s) MUST remain active for actual VPN connection attempts (`connect()`).
- No regression on desktop window chrome styling (> 680px).

---

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle | Assessment | Status |
|---|---|---|
| **Simplicity & YAGNI** | Direct CSS Grid responsive breakpoint + removing improper state mutations; no heavy external libraries | Pass |
| **Separation of Concerns** | Standalone scanner lifecycle cleanly separated from VPN tunnel handshake lifecycle | Pass |
| **Observability & Ergonomics** | Retains full structured scan telemetry while fixing clipped action controls | Pass |
| **Test-First & Verifiable** | Clear runnable verification scenarios covering endurance and responsive layout | Pass |

---

## Project Structure

### Documentation (this feature)

```text
specs/012-fix-android-scanner-timeout-ui/
├── spec.md                  # Feature requirements and user scenarios
├── plan.md                  # This implementation plan
├── research.md              # Phase 0 findings: state lifecycle & CSS Grid layout
├── data-model.md            # Phase 1 data entities and state transitions
├── contracts/
│   ├── scanner-session-contract.md   # Lifecycle separation contract
│   └── terminal-header-ui-contract.md# Mobile terminal header UI contract
├── quickstart.md            # Runnable validation scenarios
└── checklists/
    └── requirements.md      # Specification quality checklist
```

### Source Code (affected paths)

```text
aether/
└── src/
    └── prober.rs            # Set overall_deadline = Duration::MAX when exhaustive is active

apps/android/
├── android/app/src/main/java/app/aethernext/
│   ├── SessionController.kt # Remove setRuntime("connecting") during scan; handle scan exit cleanly
│   └── EngineRunner.kt      # Expose isScanMode() helper
└── src/
    ├── App.css              # Responsive grid layout for .terminal-header-chrome
    └── components/
        └── ActivityTab.tsx  # Bounds-safe terminal header markup
```

**Structure Decision**: Multi-layer implementation addressing the UI presentation bug in `apps/android/src/App.css`, the session lifecycle conflict in `SessionController.kt`, and the prober deadline cap in `aether/src/prober.rs`.

---

## Planned Implementation Steps

1. **Rust Core Engine (`aether/src/prober.rs`)**:
   - Update `hunt_best` under `if exhaustive`: set `st.overall_deadline = Duration::MAX` and ensure `remaining` does not terminate the loop when exhaustive scanning is active.
2. **Android Native Lifecycle (`SessionController.kt` & `EngineRunner.kt`)**:
   - In `EngineRunner.kt`: expose `isScanMode(): Boolean`.
   - In `SessionController.kt`:
     - In `scan()`: remove `setRuntime("connecting", ...)` so `runtime.status` stays disconnected / idle.
     - In `onExit`: check `runner.isScanMode()`; if true, do not emit error state or change tunnel status. Cleanly emit `scan_done` if needed.
3. **Android UI & Styling (`App.css` & `ActivityTab.tsx`)**:
   - Add responsive CSS Grid rules for `.terminal-header-chrome` under `@media (max-width: 680px)`.
   - Ensure `.terminal-title-text`, `.terminal-center-telemetry`, and `.stream-count` use `white-space: nowrap` and ellipsis overflow handling.
   - Position `.terminal-action-buttons` on row 2 with `justify-content: flex-end` so `Follow`, `Copy Buffer`, and `Clear` are 100% visible and unclipped.
   - Mirror relevant CSS improvements to `apps/desktop/src/App.css` for cross-platform visual consistency.
4. **Verification**:
   - Build frontend: `npm run build` in `apps/android`.
   - Build Kotlin: `./gradlew compileDebugKotlin` in `apps/android/android`.
   - Check Rust: `cargo check` in `aether`.
