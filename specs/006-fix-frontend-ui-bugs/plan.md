# Implementation Plan: Frontend & UI Visual Polish & State Remediation

**Branch**: `006-fix-frontend-ui-bugs` | **Date**: 2026-09-17 | **Spec**: [Feature Specification](spec.md)

**Input**: Feature specification from `/specs/006-fix-frontend-ui-bugs/spec.md`

---

## Summary

This plan remediates critical UI defects and state lifecycle issues across both **Aether Desktop** (`apps/desktop`) and **Aether Android** (`apps/android`):
1. **Speed Profile Presets Styling**: Replace borderless, low-contrast, colliding text elements with distinct high-contrast tactile hardware cards (`#0d131a` surface, `1px solid rgba(255, 255, 255, 0.14)` border, glowing emerald active state, and separate header/hint layout).
2. **Activity Tab Session Flush**: Automatically flush and reset session logs when initiating a scan, toggling tunnel connection, or executing a direct-connect action, ensuring the log console displays only current action traces.
3. **Activity Tab Auto-Scroll Following**: Implement a reliable container scroll lock mechanism (`consoleRef.current.scrollTop = scrollHeight`) with programmatic scroll feedback guards, ensuring the log viewer reliably follows the latest incoming message.
4. **Strict "Hits" Filter**: Re-architect `isHit` in `useLogs.ts` to strictly validate IPv4/IPv6 socket addresses with discovery confirmation, eliminating generic false-positive status lines (such as lines containing "gateway").
5. **Scanner Tab Protocol Organization & Overwrite**: Automatically wipe previous scan results upon launching a new scan, and provide protocol-aware filtering/grouping (`All`, `MASQUE H3`, `MASQUE H2`, `WireGuard`) sorted by lowest latency.

---

## Technical Context

**Language/Version**: TypeScript 5.6+, React 18, CSS3  
**Primary Dependencies**: React 18, Lucide React (`lucide-react`), Vite 5  
**Storage**: Tauri Store / Android LocalStorage  
**Testing**: TypeScript compiler check (`tsc --noEmit`), Vite production build (`npm run build`), Android asset sync (`npm run sync-www`)  
**Target Platform**: Windows 10/11 (Tauri v2 Desktop) & Android 10+ (Capacitor)  
**Project Type**: Cross-platform desktop & mobile client UI  
**Performance Goals**: 60 fps transitions, CLS < 0.01, instantaneous (<16ms) feedback on card clicks and filter switches  
**Constraints**:
- Zero breaking changes to Tauri IPC commands or Android `AetherBridge`.
- Complete preservation of React state and callback hooks.
- All touch targets maintained at `>= 44px` on mobile.
- `tabular-nums` and monospace font enforced on all IP addresses, timers, and latencies.  
**Scale/Scope**: 8 key files across `apps/desktop` and `apps/android` (2 CSS files, 2 `useLogs` hooks, 2 `ScannerTab` components, 2 `ActivityTab` / `App` components).

---

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

- [x] **Contract Integrity**: Presentation, filtering, and state cleanup only. Zero modification to underlying IPC schemas.
- [x] **Functional Parity**: Both desktop and Android applications receive identical visual, lifecycle, and filtering fixes.
- [x] **Testability & Verifiability**: TypeScript compile validation, Vite production builds, and documented scenarios in `quickstart.md`.
- [x] **Visual Design System Compliance**: Strictly adheres to the obsidian cyber-tactical theme with enhanced card contrast and illumination.

---

## Project Structure

### Documentation (this feature)

```text
specs/006-fix-frontend-ui-bugs/
├── plan.md              # Implementation Plan (this file)
├── research.md          # Phase 0: Architectural decisions & research findings
├── data-model.md        # Phase 1: Entity definitions, state transitions, validation rules
├── quickstart.md        # Phase 1: Validation & run guide across desktop & Android
├── contracts/           # Phase 1: UI layout and state contracts
│   └── ui-state-contracts.md
├── checklists/
│   └── requirements.md  # Quality checklist for requirements
└── tasks.md             # Phase 2: Actionable task list (generated via /speckit-tasks)
```

### Source Code (repository root)

```text
apps/
├── desktop/
│   └── src/
│       ├── App.css                      # Desktop high-contrast card & scanner styling
│       ├── App.tsx                      # Flush logs on toggleConnection & connectDirect
│       ├── hooks/
│       │   ├── useLogs.ts               # Strict isHit filter & clearLogs export
│       │   └── useScanner.ts            # Flush logs on startScan
│       └── components/
│           ├── ConnectionTab.tsx        # High-contrast preset cards layout
│           ├── ActivityTab.tsx          # Auto-follow scroll lock & guard
│           └── ScannerTab.tsx           # Protocol tabs/grouping & clean overwrite
└── android/
    └── src/
        ├── App.css                      # Android high-contrast card & scanner styling
        ├── App.tsx                      # Android log flush on actions
        ├── hooks/
        │   ├── useLogs.ts               # Android strict isHit filter
        │   └── useScanner.ts            # Android log flush on startScan
        └── components/
            ├── ConnectionTab.tsx        # Android high-contrast preset cards
            ├── ActivityTab.tsx          # Android auto-follow scroll lock
            └── ScannerTab.tsx           # Android protocol tabs & overwrite
```

---

## Complexity Tracking

*No violations identified. All proposed changes strictly align with existing project conventions and architecture.*
