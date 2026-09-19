# Feature Specification: Android UI Spacing & Mobile Density Overhaul

**Feature Directory**: `specs/009-fix-android-spacing`

**Created**: 2026-09-18

**Status**: Draft

**Input**: User description: "only in android app . in scanner and setting tab literaly every section has bad spacing . cant attach all the screenshots but literaly all the tabs and sections have bad spacing . with a lot of extra unused space"

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Compact, Proportionate Settings Rows & Panels (Priority: P1)

As an Android mobile user configuring network options in the Settings tab, I want every setting section and row to display with tight, mobile-native vertical spacing so that controls (dropdowns, segmented tabs, number steppers) sit immediately adjacent to their descriptions without massive empty black voids separating them.

**Why this priority**: Currently on Android portrait viewports, setting rows stretch across hundreds of pixels of blank dead space (up to 400px per card), forcing the user to scroll endlessly across bloated single-control screens.

**Independent Test**: Open the Settings tab on Android mobile. Verify that each section (Transport Engine, Topology Scanner, Android Routing, Proxy Endpoints) displays its label and interactive controls in a compact, natural vertical stack without dead space gaps.

**Acceptance Scenarios**:
1. **Given** an Android mobile device viewing the Settings tab, **When** examining the "Topology Scanner" and "Android Routing" cards, **Then** the dropdown controls appear directly beneath their respective label and hint text with comfortable mobile padding (8px–12px gap) instead of a 400px empty chasm.
2. **Given** the "Proxy Endpoints" card in the Settings tab, **When** viewing the HTTP and SOCKS5 port configuration fields, **Then** both fields appear together within the card in a clean, compact layout with no runaway vertical expansion.
3. **Given** the "IP Pool Family" card in the Settings tab, **When** viewing the segmented options (`IPv4 Only`, `IPv6 Only`, `Dual-Stack`), **Then** the segmented control button group sits directly under the explanation text and spans the width comfortably.

---

### User Story 2 - Compact, Balanced Scanner Controls & Telemetry Layout (Priority: P1)

As an Android user searching for clean Cloudflare edge endpoints in the Scanner tab, I want the probe parameters (Target Protocol, IP Family, Concurrency Workers, Probe Timeout) and the radar telemetry card to have compact mobile padding so I can see the scanner controls, start button, and progress metrics on a single screen without unnecessary scrolling.

**Why this priority**: The Scanner tab is the primary discovery tool for mobile connectivity. Excessive card padding and stretched input rows currently push critical actions and telemetry results far off-screen.

**Independent Test**: Navigate to the Scanner tab on Android. Verify that the Radar HUD, probe parameters, and action buttons fit comfortably within the viewport, and parameter rows do not have stretched vertical dead space.

**Acceptance Scenarios**:
1. **Given** an Android user on the Scanner tab, **When** inspecting "Engine Handshake Configuration", **Then** the protocol segmented buttons, IP family segmented buttons, and numeric steppers sit cleanly stacked with compact 8px–10px spacing.
2. **Given** a scan is in progress or completed, **When** viewing discovered endpoints in the results list, **Then** endpoint rows render with balanced touch targets (36px–42px) without inflating surrounding card heights.

---

### User Story 3 - Sticky Header & Bottom Navigation Chrome Cleanliness (Priority: P2)

As an Android user scrolling through long configuration or log lists, I want the sticky topbar to have a solid opaque background so scrolled content does not bleed through or collide with the "Settings" / "Scanner" title text.

**Why this priority**: When scrolling on mobile Android WebView, semi-transparent blur backdrops bleed text through, creating unreadable doubled text (e.g. "Settings" clashing directly over "CONFIGURATION LOCAL LISTENERS Proxy Endpoints").

**Independent Test**: Scroll the Settings and Scanner tabs vertically on Android. Verify that the top header remains crisp, legible, and completely obscures scrolled cards passing underneath it.

**Acceptance Scenarios**:
1. **Given** the user scrolls down on any tab, **When** card content reaches the topbar, **Then** the topbar renders with an opaque background (`#07090b` / `var(--bg-app)`), cleanly masking underlying content without ghosting.
2. **Given** the bottom navigation bar is fixed at the bottom of the screen, **When** the sticky auto-save dock appears in the Settings tab, **Then** it docks comfortably above the bottom navigation bar without clipping or obscuring interactive controls.

---

### Edge Cases

- **Small Screen Displays (width <= 360px)**: Labels and segmented button text must wrap or scale gracefully without overlapping or horizontal overflow.
- **Large Font / Accessibility Scaling**: When the user's Android system font size is set to Large or Largest, setting rows must expand to fit text dynamically while maintaining tight vertical grouping.
- **Orientation Changes (Portrait vs. Landscape)**: In landscape mode on a phone or tablet, layouts should transition smoothly to balanced multi-column or horizontal layouts without vertical stretching.

---

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: Setting rows (`.setting-row`) on mobile screens (width <= 768px) MUST reset vertical `flex-basis` and `flex-grow` on text containers so that titles and descriptions take only their natural content height.
- **FR-002**: Mobile setting rows MUST use `gap: 10px` (or 12px) with `justify-content: flex-start` (not `space-between`) when in column orientation, ensuring controls immediately follow their labels.
- **FR-003**: Form controls on mobile (dropdown selects, segmented buttons, input wrappers) MUST expand to full container width (`width: 100%`) rather than sitting at rigid desktop minimum widths (180px) with dead horizontal margins.
- **FR-004**: Multi-input rows such as `.port-field-block` MUST reset `flex-basis` from `200px` to `auto` / `100%` on mobile viewports so individual input blocks do not claim arbitrary vertical heights.
- **FR-005**: All container view wrappers (`.settings-view`, `.scanner-view`, `.home-view`, `.logs-view`) on mobile MUST use compact horizontal and vertical padding (14px–16px horizontal, 16px–20px vertical) instead of desktop desktop-scale padding (32px–48px).
- **FR-006**: Card sections (`.settings-section`, `.tactical-panel`, `.radar-hud-container`) MUST eliminate redundant stacked margins and reduce internal padding from 16px/22px to 14px/16px on mobile viewports.
- **FR-007**: The mobile topbar (`.topbar`) MUST have a fully opaque background matching the application theme (`#07090b`) to prevent content bleed-through when scrolling.
- **FR-008**: The sticky save dock (`.tactical-save-dock`) MUST adjust its bottom offset and padding on mobile to account for the 60px fixed bottom navigation bar, preventing overlap.

---

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Vertical height of single-row setting cards (such as "Android Routing") on mobile decreases by at least 50% (from ~400px down to ~120px–150px).
- **SC-002**: 100% of setting cards on a standard portrait mobile screen (390px x 844px) display labels and controls within immediate proximity (< 16px gap), eliminating all blank void spaces.
- **SC-003**: The entire Settings tab fits within approximately 2 to 2.5 full scroll viewports instead of 6+ viewports of empty space.
- **SC-004**: Zero text collision or bleed-through occurs behind the sticky topbar during vertical scrolling across all four tabs.

---

## Assumptions

- The fixes are strictly targeted at mobile viewports (width <= 768px / Android app) and will preserve desktop layout intact.
- Both `apps/android` and any mobile-responsive CSS in `apps/desktop` will be updated with identical mobile rules to ensure parity when desktop windows are resized to mobile widths.
- No functional behavior, IPC methods, or state management logic needs to be altered; this is a pure layout, spacing, and CSS density correction.
