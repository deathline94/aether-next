# Implementation Plan: Speed Profile & Scanner Tab Visual Polish & Spatial Architecture

**Branch**: `005-fix-profile-scanner-ui` | **Date**: 2026-09-16 | **Spec**: [Feature Specification](spec.md)

**Input**: Feature specification from `/specs/005-fix-profile-scanner-ui/spec.md`

---

## Summary

The Speed Profiles preset section and Scanner Tab in both desktop (`apps/desktop`) and Android (`apps/android`) suffered from severe spatial disorganization, misplaced DOM hierarchy, and missing CSS styling:
1. **Speed Profiles**: In `ConnectionTab.tsx`, `<section className="profiles-panel">` was mistakenly placed beneath the 12-column Telemetry Bento Grid. Furthermore, `.profiles-panel`, `.profile-grid`, and `.profile-card` styling rules were completely missing from `App.css`, causing preset buttons to render as unstyled, misaligned standard HTML buttons.
2. **Scanner Tab**: `ScannerTab.tsx` crammed the live radar scope reticle, telemetry, parameters, unstyled stepper inputs, and primary action buttons into a single monolithic card. Concurrency and Timeout inputs lacked structured container blocks, causing labels and stepper controls to collide, while Handshake Obfuscation lacked `.tactical-select` styling.

The technical approach restructures `ConnectionTab.tsx` to elevate Speed Profiles directly beneath the Hero Connection stage, implements complete obsidian/emerald tactical styling in `App.css` across both platforms, partitions `ScannerTab.tsx` into two dedicated cards (Radar HUD Card and Scan Parameters Card), structures numeric fields inside `.param-field-block`, and introduces responsive breakpoints (`<=680px` for mobile, `<=380px` for narrow screens).

---

## Technical Context

**Language/Version**: TypeScript 5.6+, React 18, CSS3  
**Primary Dependencies**: React 18, Lucide React (`lucide-react`), Vite 5  
**Storage**: Tauri Store / Android LocalStorage for persisted user configuration  
**Testing**: TypeScript compiler type-check (`tsc --noEmit`), Vite production build (`npm run build`), Android asset sync (`npm run sync-www`)  
**Target Platform**: Windows 10/11 (Tauri v2 Desktop) & Android 10+ (Capacitor / Android Studio)  
**Project Type**: Cross-platform desktop & mobile application GUI  
**Performance Goals**: 60 fps transitions, 0 layout shifts (Cumulative Layout Shift < 0.01), sub-16ms tactile feedback  
**Constraints**:
- Zero breaking changes to Tauri IPC commands (`bridge.ts`, `connectToPeer`, `patchSettings`, `runTest`) or Android `AetherBridge`.
- Complete preservation of React state, hooks, and props (`useRuntime`, `useScanner`, `useLogs`, `useOnline`).
- Zero unstyled button artifacts; all touch targets must maintain `>= 44px` with clear focus/active states.
- Monospace font and `tabular-nums` enforced on all numbers and metrics.  
**Scale/Scope**: 6 source files across `apps/desktop` and `apps/android` (2 CSS files, 4 React TSX components).

---

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

- [x] **Contract Integrity**: No modification to underlying backend IPC, bridge schemas, or data contracts. All changes are strictly presentation and spatial layout.
- [x] **Functional Parity**: Both desktop and Android applications receive identical visual and behavioral fixes.
- [x] **Testability & Verifiability**: Static type validation, production bundle compilation, and explicit end-to-end verification scenarios defined in `quickstart.md`.
- [x] **Visual Design System Compliance**: Strictly adheres to the obsidian cyber-tactical theme (`var(--panel)`, `var(--emerald)`, `var(--font-mono)`, `tabular-nums`).

---

## Project Structure

### Documentation (this feature)

```text
specs/005-fix-profile-scanner-ui/
├── plan.md              # Implementation Plan (this file)
├── research.md          # Phase 0: Architectural decisions & research findings
├── data-model.md        # Phase 1: Entity definitions, state transitions, validation rules
├── quickstart.md        # Phase 1: Validation & run guide across desktop & Android
├── contracts/           # Phase 1: Layout, DOM hierarchy, and CSS contracts
│   └── ui-layout-contracts.md
├── checklists/
│   └── requirements.md  # Quality checklist for requirements
└── tasks.md             # Phase 2: Actionable task list (generated via /speckit-tasks)
```

### Source Code (repository root)

```text
apps/
├── desktop/
│   └── src/
│       ├── App.css                      # Desktop CSS stylesheet (profiles & scanner rules)
│       └── components/
│           ├── ConnectionTab.tsx        # Connection tab (relocate speed profiles above bento)
│           └── ScannerTab.tsx           # Scanner tab (two-card HUD & parameters partitioning)
└── android/
    └── src/
        ├── App.css                      # Android CSS stylesheet (profiles & scanner rules)
        └── components/
            ├── ConnectionTab.tsx        # Android Connection tab (relocate speed profiles)
            └── ScannerTab.tsx           # Android Scanner tab (two-card partitioning)
```

**Structure Decision**: Both desktop and Android share identical component hierarchy and visual patterns. Source changes are applied symmetrically to both application packages.

---

## Complexity Tracking

*No violations identified. All proposed changes strictly align with existing project conventions and architecture.*

| Item | Assessment | Notes |
|---|---|---|
| Architecture | Minimal complexity | Pure layout reordering and missing CSS rule completion |
| Dependencies | Zero added dependencies | Reuses existing Lucide icons, UI primitives (`NumberField`, `Segmented`), and CSS variables |
| State Management | Unchanged | Reuses existing React state and callback hooks |
