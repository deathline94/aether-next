# Implementation Plan: Reset Connect State on Discovery Failure and Modernize Noise Profiles

**Branch**: `001-fix-scan-fail-noise` | **Date**: 2026-09-15 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `specs/001-fix-scan-fail-noise/spec.md`

## Summary

This feature resolves two critical operational issues in Aether Next:
1. **Connect Button State Hang on Scan Failure**: When endpoint scanning fails (notably on MASQUE H3), the engine previously fell back to a blocked anycast VIP causing two 20-second connection timeouts, and subsequently hung on process exit due to Tokio's background stdin reader thread on Windows. This left the UI in a perpetual "connecting" state with the power button stuck in "DISCONNECT". The fix eliminates the blocked anycast fallback, forces immediate error propagation, emits a structured error event, and exits the child process cleanly with `std::process::exit(1)`, allowing Tauri and Android shells to revert the button to the idle "CONNECT" state immediately.
2. **Unified Modernized Noise Profiles**: Replaces legacy, varied noise parameters across WireGuard, WARP-in-WARP (Gool), MASQUE H2, and MASQUE H3 with the proven anti-DPI profile (`Jc=5`, `Jmin=50`, `Jmax=128`, `0ms` delay), matching AmneziaWG interface headers and v2rayN finalmask UDP burst configurations.

## Technical Context

**Language/Version**: Rust 2021 (engine & Tauri backend), TypeScript 5.x / React 18 (desktop & mobile frontends), Kotlin (Android native bridge).

**Primary Dependencies**: `tokio`, `quiche`, `boringtun`, `smoltcp`, `@tauri-apps/api`.

**Storage**: Local JSON / TOML files (`settings.json`, `aether.toml`, `aether-masque.toml`).

**Testing**: `cargo test` for unit tests and protocol packet generation; Tauri dev test for end-to-end UI state reversion.

**Target Platform**: Windows 10/11 (desktop Tauri app) and Android (Capacitor/native bridge).

**Project Type**: Multi-platform hybrid desktop/mobile app with compiled native Rust engine.

**Performance Goals**: State reversion on scan failure within <100ms of scan completion; 5-packet pre-handshake burst dispatched in <2ms with zero artificial sleep.

**Constraints**: Must not leave orphan background processes or lingering port bindings on 1819/1820; noise packets must never exceed minimum path MTU (1280 bytes).

**Scale/Scope**: Impacts engine session supervisor, noise generators, desktop Tauri shell, and settings models.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

- **Principle 1 (Library-First & Modularity)**: PASS. Engine modifications are contained within protocol and obfuscation modules (`session.rs`, `noize.rs`, `aethernoize.rs`, `main.rs`).
- **Principle 2 (Clean Separation of Concerns)**: PASS. Engine owns tunnel execution and emits structured `AETHER_EVENT` lines; UI shells handle presentation, user notifications, and button state.
- **Principle 3 (Observability & Fail-Fast)**: PASS. Replaces 40-second timeout hangs with immediate `NoCleanEndpoint` failure emission and clean exit code propagation.

## Project Structure

### Documentation (this feature)

```text
specs/001-fix-scan-fail-noise/
├── plan.md              # This file (/speckit-plan output)
├── research.md          # Phase 0 output
├── data-model.md        # Phase 1 output
├── quickstart.md        # Phase 1 output
├── contracts/           # Phase 1 interface contracts
│   ├── engine-events.md
│   ├── obfuscation-profiles.md
│   └── settings-schema.md
├── checklists/
│   └── requirements.md
└── tasks.md             # Phase 2 output (/speckit-tasks command)
```

### Source Code

```text
aether/src/
├── session.rs          # Remove dead anycast fallback on H3 scan fail; fail immediately
├── main.rs             # Emit error event and std::process::exit(1) on session failure
├── noize.rs            # Update MASQUE noise profile to Jc=5, Jmin=50, Jmax=128, delay 0ms
├── aethernoize.rs      # Update WireGuard/Gool noise profile to Jc=5, Jmin=50, Jmax=128, delay 0ms
└── obfuscation.rs      # Update profile definitions and env parameter defaults

apps/desktop/
├── src/types.ts        # Update Settings defaults (noizeJc: 5, noizeJmin: 50, noizeJmax: 128, noizeIntervalMs: 0)
└── src-tauri/src/lib.rs # Update default Settings struct and ensure error state triggers button reset

apps/android/
├── src/types.ts        # Update Settings defaults for mobile
└── android/app/src/main/java/app/aethernext/SessionController.kt # Ensure error events transition runtime state
```

**Structure Decision**: Retains the established multi-platform architecture, updating engine protocol logic and UI configuration contracts symmetrically across desktop and Android.

## Complexity Tracking

| Violation | Why Needed | Simpler Alternative Rejected Because |
|---|---|---|
| None | N/A | Implementation uses existing event and profile mechanisms without adding new frameworks or layers. |
