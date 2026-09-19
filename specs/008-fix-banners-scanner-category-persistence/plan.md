# Implementation Plan: Connection Banners, Scanner Inputs & Category Persistence

**Branch**: `008-fix-banners-scanner-category-persistence` | **Date**: 2026-09-18 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `specs/008-fix-banners-scanner-category-persistence/spec.md`

## Summary

This plan addresses:
1. **Connection Tab Banners Layout & Styling**: Styles `.error-banner`, `.pinned-peer-bar`, and `.update-banner` with cyber-tactical CSS, preventing plain unstyled text and collision between addresses and action buttons (`443Clear`).
2. **Scanner Tab Stepper Inputs Sizing & Step Validation**: Fixes the HTML5 step validation mismatch on `concurrency` (eliminating the "enter between 231 to 241" browser popup by setting `step="any"` on the underlying input), and resizes `.stepper-input-wrapper` to compact content dimensions (~130–140px) to eliminate awkward empty dead space and the vertical divider artifact.
3. **Category-Isolated Discovered Endpoints**: Refactors `useScanner` to scope endpoint resetting per protocol category when starting a scan, preserving previously discovered endpoints from other protocols.
4. **MASQUE H3 Anti-DPI Scan Wire-up & Probe Leniency**: Passes `AETHER_QUIC_INITIAL_FRAG` to standalone scans in `src-tauri/src/lib.rs`, and relaxes `verify_masque` in `aether/src/quic.rs` to accept 1 confirmed data-plane roundtrip within a 3.5s window to prevent false negative timeouts on lossy/high-jitter networks.

---

## Technical Context

**Language/Version**: Rust 1.88+ (Engine), TypeScript 5.8+ / React 19 (Desktop & Android UI), Kotlin / Android SDK 26-35  
**Primary Dependencies**: `quiche`, `boring`, `tokio`, `lucide-react`, Tauri v2  
**Target Platform**: Windows 10/11 x64, Android (arm64-v8a, armeabi-v7a, x86_64)  
**Project Type**: Multi-platform VPN & Proxy Engine with native Android and Tauri desktop frontends  
**Performance Goals**: Stepper inputs respond with zero latency; scan endpoints partition cleanly with instant dock tab switching  
**Constraints**: Maintain full visual and functional parity between Desktop and Android frontends  

---

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

- **Principle 1 (Library-First)**: Passed. Core protocol logic remains inside `aether/`.
- **Principle 2 (Observability)**: Passed. Diagnostic logging preserved.
- **Principle 3 (Simplicity & YAGNI)**: Passed. Minimal, targeted CSS and state changes without introducing extraneous libraries.

---

## Project Structure

### Documentation (this feature)

```text
specs/008-fix-banners-scanner-category-persistence/
├── spec.md              # Feature specification
├── plan.md              # This plan
├── research.md          # Phase 0 technical research
├── data-model.md        # Phase 1 data & configuration model
├── quickstart.md        # Phase 1 verification guide
├── contracts/           # Phase 1 interface contracts
│   ├── banners-contract.md
│   └── scanner-inputs-contract.md
└── checklists/
    └── requirements.md  # Spec quality validation checklist
```

### Source Code Paths

```text
apps/desktop/
├── src/
│   ├── App.css                     # Banner CSS (.error-banner, .pinned-peer-bar, .update-banner) & stepper wrapper sizing
│   ├── components/
│   │   ├── ConnectionTab.tsx       # Banner structure & icon spacing
│   │   ├── ScannerTab.tsx          # Concurrency/timeout hint & input configuration
│   │   └── ui.tsx                  # NumberField step="any" constraint fix
│   └── hooks/
│       └── useScanner.ts           # Category-isolated endpoint filtering on startScan
└── src-tauri/
    └── src/
        └── lib.rs                  # Pass AETHER_QUIC_INITIAL_FRAG during scan command

apps/android/
├── src/
│   ├── App.css                     # Symmetrical banner CSS & stepper wrapper sizing
│   ├── components/
│   │   ├── ConnectionTab.tsx       # Symmetrical banner structure
│   │   ├── ScannerTab.tsx          # Symmetrical scanner inputs
│   │   └── ui.tsx                  # Symmetrical NumberField step fix
│   └── hooks/
│       └── useScanner.ts           # Symmetrical category-isolated endpoint filtering

aether/
└── src/
    └── quic.rs                     # verify_masque leniency (1 roundtrip floor, 3.5s window)
```

---

## Implementation Phases

### Phase 1: Frontend UI & CSS Remediation
1. **Connection Tab Banners**:
   - In `apps/desktop/src/App.css` and `apps/android/src/App.css`, implement `.error-banner`, `.pinned-peer-bar`, and `.update-banner` per `banners-contract.md`.
   - In `apps/desktop/src/components/ConnectionTab.tsx` and `apps/android/src/components/ConnectionTab.tsx`, ensure clear spacing between forced endpoint code and the "Clear" action button.
2. **Scanner Tab Stepper Inputs**:
   - In `apps/desktop/src/components/ui.tsx` and `apps/android/src/components/ui.tsx`, update `NumberField` input element with `step="any"` to eliminate HTML5 step validation mismatch errors.
   - In `apps/desktop/src/App.css` and `apps/android/src/App.css`, constrain `.stepper-input-wrapper` width to ~130–140px, center the input between `−` and `+` buttons.

### Phase 2: Category Isolation & Protocol Persistence
1. **Per-Protocol Endpoint Filtering**:
   - In `apps/desktop/src/hooks/useScanner.ts` and `apps/android/src/hooks/useScanner.ts`:
     - Implement `isProtocolMatch` helper.
     - On `startScan`, filter out only endpoints belonging to the actively scanned protocol instead of wiping `endpoints` entirely.
     - Update dock hit counters to reflect preserved endpoints.

### Phase 3: MASQUE H3 Anti-DPI Scan Wire-up & Probe Leniency
1. **QUIC Fragmentation in Standalone Scan**:
   - In `apps/desktop/src-tauri/src/lib.rs`, pass `AETHER_QUIC_INITIAL_FRAG` matching `settings.quic_initial_frag` and `settings.quic_initial_frag_size` to the scan child command.
2. **Quic Prober Leniency**:
   - In `aether/src/quic.rs`, adjust `verify_masque` data-plane probe validation to accept 1 confirmed reply and extend the deadline to 3.5s.

### Phase 4: Verification & Build
1. Run `cargo test` in `aether/`.
2. Run `npm run build` in `apps/desktop/`.
3. Run `npm run sync-www` in `apps/android/`.
