# Feature Specification: Speed Profile & Scanner Tab Visual Polish & Spatial Architecture

**Feature Branch**: `005-fix-profile-scanner-ui`

**Created**: 2026-09-16

**Status**: Draft

**Input**: User description: "the speed profile section in both desktop and android app is very broken out of order with weird spacings . so is the scanner tab"

---

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Speed Profiles Visual Polish, Spatial Order, and Tactile Feedback (Priority: P1) 🎯 MVP

A user opening Aether on desktop or mobile wants to immediately see and choose their desired routing preset (MASQUE H3, MASQUE H2, WireGuard, Gool) right alongside the connection stage, with clear tactile card styling, balanced spacing, and obvious active indicators—rather than having presets buried below lengthy telemetry cards or rendered as unstyled, misaligned buttons.

**Why this priority**: Speed profiles represent the primary decision users make before connecting. Misplaced, unstyled, or weirdly spaced preset buttons destroy visual hierarchy, make preset selection unintuitive, and undermine the cyber-tactical design quality.

**Independent Test**:
1. Open the Connection tab on both desktop and mobile; verify the Speed Profiles panel appears immediately beneath the hero Connection stage.
2. Verify profile cards render in a symmetrical, well-proportioned grid with dark obsidian panels, micro-borders, and tactile hover feedback.
3. Tap each profile preset; verify the active profile highlights immediately with a phosphor emerald border and "ACTIVE" badge.

**Acceptance Scenarios**:
1. **Given** a user viewing the Connection tab on desktop or mobile, **When** the page renders, **Then** the Speed Profiles panel is positioned directly below the connection master switch stage and above the detailed telemetry bento grid.
2. **Given** the Speed Profiles section, **When** rendered on screen, **Then** all four profile cards (`MASQUE H3`, `MASQUE H2`, `WireGuard`, `Gool`) display inside an organized grid with consistent card heights, internal padding, crisp typography, and subtitle hints.
3. **Given** an active profile matching current settings, **When** viewed, **Then** the corresponding card displays an illuminated emerald border, ambient glow, and an `ACTIVE` tag pill.
4. **Given** a user clicking a profile card, **When** clicked, **Then** the settings patch applies, the card enters the active state, and a tactile scale feedback occurs without UI jitter.

---

### User Story 2 - Scanner Tab Architecture, Parameter Panel Separation & Input Alignment (Priority: P2)

A user navigating to the Scanner tab requires a logical, orderly layout where the Radar HUD (monitoring & scan trigger) and the Scan Configuration parameters (protocol, IP family, concurrency, timeout, obfuscation) are organized into clean, dedicated tactical panels with properly aligned input blocks—eliminating cramped horizontal text wrapping, unstyled dropdowns, and awkward spacing.

**Why this priority**: The Scanner tab currently combines the radar scope, telemetry, parameter buttons, inline inputs, and action buttons into a single monolithic card without proper input layout styling, causing labels and stepper controls to warp and collide.

**Independent Test**:
1. Navigate to the Scanner tab; verify the Radar HUD (sweep scope, status line, progress bar, master scan button) and the Scan Configuration (protocol, IP family, concurrency, timeout, noise) are cleanly partitioned into distinct tactical panels.
2. Inspect concurrency and timeout numeric fields; verify they sit in structured input blocks with clear labels, metadata hints, and stepper controls without awkward text wrapping.
3. Verify the Handshake Obfuscation selector adopts the uniform tactical select style matching the rest of the application.

**Acceptance Scenarios**:
1. **Given** the Scanner tab view, **When** loaded, **Then** the radar engine scope and scan action button are housed in a dedicated Radar HUD Card, while parameter adjustments are grouped in a dedicated Scan Parameters Card.
2. **Given** the Concurrency and Timeout inputs, **When** rendered, **Then** each input occupies a structured field block containing a bold title, range hint, and stepper control with balanced horizontal and vertical spacing.
3. **Given** the Handshake Obfuscation dropdown, **When** displayed, **Then** it renders using the styled tactical select component rather than a generic unstyled browser select.
4. **Given** an active scan, **When** probes are in progress, **Then** the progress bar, live worker count, healthy gateway counter, and best RTT badge render within the HUD area without displacing configuration controls.

---

### User Story 3 - Mobile Screen Flow & Multi-Density Responsive Spacing (Priority: P3)

An Android mobile user requires that both the Speed Profiles grid and the Scanner tab scale gracefully to phone viewports (360px–430px wide) without horizontal scrollbars, squished buttons, overlapping text, or awkward whitespace gaps.

**Why this priority**: Mobile screens have strict spatial constraints. What looks fine on a wide desktop screen will break on mobile if grid templates, input widths, and padding do not adapt to narrow widths.

**Independent Test**:
1. Load the mobile app or resize the viewport to 360px width; verify profile cards collapse gracefully into an ergonomic 2x2 or 1-column layout with minimum 44px touch targets.
2. Verify Scanner tab inputs and segmented controls flex to full container width on mobile without horizontal clipping or label overflow.

**Acceptance Scenarios**:
1. **Given** a mobile viewport (<=680px), **When** viewing Speed Profiles, **Then** cards arrange in an ergonomic 2-column or stacked grid where labels, badges, and hints remain comfortably readable.
2. **Given** a mobile viewport, **When** viewing the Scanner tab, **Then** segmented controls flex to 100% width, number input wrappers expand cleanly across the available width, and the radar scope centers with balanced margins.
3. **Given** any screen size, **When** navigating between tabs, **Then** consistent outer padding (16px–24px) and element vertical gaps (12px–16px) are maintained across both platforms.

---

## Edge Cases

- **Narrow Mobile Widths (down to 320px)**: What happens on very small phone screens? Profile cards and input rows stack into a single column with full-width controls to prevent truncation.
- **Dynamic Profile Matching**: What happens when a user customizes a parameter that doesn't match any preset? None of the profile cards display the `ACTIVE` tag, and card borders return to the standard subtle border state.
- **Active Scan Lockdown**: What happens when a scan is currently active? Scan parameter controls (protocol, IP family, concurrency, timeout, obfuscation) disable cleanly with dimmed opacity, while the radar HUD displays the active sweep animation and "Halt Active Probe" button.
- **Extreme Latency Values**: What happens when discovered endpoints have long IPv6 addresses or high latency? The discovered row uses `overflow-wrap: anywhere`, tabular numbers, and tiered color badges without breaking the row layout.

---

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The Speed Profiles section MUST be positioned immediately beneath the primary Connection hero stage and above the telemetry bento grid in `ConnectionTab.tsx` on both desktop and Android applications.
- **FR-002**: The Speed Profiles panel MUST be styled with a dedicated `.profiles-panel` container, `.profile-grid` CSS grid layout, and `.profile-card` tactile hardware cards in `App.css`.
- **FR-003**: Each profile card MUST feature a top header row with bold title and active status indicator, accompanied by a secondary subtitle hint describing the preset configuration.
- **FR-004**: The active profile card MUST display an illuminated phosphor emerald border (`--emerald-border`), ambient glow, and an `ACTIVE` badge.
- **FR-005**: In `ScannerTab.tsx`, the Radar HUD (scope, status, progress bar, action button) MUST be visually separated from the Scan Parameters (protocol, IP family, concurrency, timeout, obfuscation) into distinct architectural cards.
- **FR-006**: Scanner numeric parameters (concurrency and probe timeout) MUST be structured with dedicated field blocks (`.port-field-block` / `.param-field-block`) containing label metadata, range hints, and stepper `NumberField` controls.
- **FR-007**: The Handshake Obfuscation selector in `ScannerTab.tsx` MUST use `.tactical-select` styling for complete visual consistency with `SettingsTab.tsx`.
- **FR-008**: The Speed Profiles grid MUST render as 4 columns on desktop/tablet viewports and adapt to 2 columns (or 1 column on narrow screens) on mobile viewports.
- **FR-009**: All interactive elements in both tabs MUST adhere to accessibility standards with touch targets >= 44px and visible focus rings.
- **FR-010**: All numerical readouts (workers, timeouts, latencies, percentages) MUST enforce `tabular-nums` and monospace font styling.

---

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Speed profile cards display in a symmetrical, evenly-spaced grid (4 columns desktop, 2 columns mobile) with zero unstyled button artifacts or missing CSS classes.
- **SC-002**: In the Connection tab, speed profiles are positioned directly under the hero stage, reducing user eye-travel distance by >60% compared to bottom placement.
- **SC-003**: In the Scanner tab, scan parameters and live radar HUD are separated into two distinct cards with zero cramped, misaligned, or overflowing input rows.
- **SC-004**: Zero layout breakage, horizontal overflow, or clipped text across mobile (320px–430px), tablet (768px–1024px), and desktop (1200px+) viewports.
- **SC-005**: Both `apps/desktop` and `apps/android` build cleanly with `npm run build` and zero TypeScript or bundling errors.

---

## Assumptions

- The 4 core speed profiles (`MASQUE H3`, `MASQUE H2`, `WireGuard`, `Gool`) and their underlying settings patches remain identical.
- Backend Tauri IPC and Android Kotlin bridge contracts are unchanged; this is a pure visual hierarchy, spatial architecture, and CSS styling overhaul.
- Existing functionality (connect direct, auto-scroll, scan cancelation, test verification) must be 100% preserved without regression.
