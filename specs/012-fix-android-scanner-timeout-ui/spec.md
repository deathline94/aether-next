# Feature Specification: Unbounded Scanner Execution & Mobile Terminal Header UI Fixes

**Feature Branch**: `012-fix-android-scanner-timeout-ui`

**Created**: 2026-09-19

**Status**: Reconciled & Hardened (Superseded by `specs/013-security-reliability-remediation/spec.md`)

> [!NOTE]
> Scanner timeout isolation, unbounded background execution, and mobile layout fixes are integrated and hardened under `specs/013-security-reliability-remediation/spec.md`, enforcing responsive CancellationToken aborts (<10ms) and unified 6000ms default / 3000ms minimum floors across all platforms.

**Input**: User description: "only on android . that banner on scanner tab that i circle has out of bounds and frankly is a ui bug . messed up texts , out of place bounds etc etc. also i noticed . in the scanner tab when we start scanning , we are still bound by connecting flows timeout ! cause when we hit connect we may have 300 seconds then the operation gets cut , it seems that logic and timeout is getting applied to the scanner tab scans too . which is a bad implementation ! in scanner tab there should be no timeouts ! timeouts are only suitable for the connecting flow !"

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Unbounded Endpoint Pool Scanning Without Connection Timeouts (Priority: P1)

As a network administrator or mobile user running an endpoint discovery scan from the Scanner tab, when I initiate a scan across a large pool of candidate addresses, the scan must proceed continuously without being prematurely terminated by tunnel connection timeouts or watchdog countdowns, allowing the scanner to probe all candidates until completion or until I choose to stop it.

**Why this priority**: Standalone endpoint scanning is an exploratory diagnostic process across thousands of potential gateways. If connection watchdog timeouts are applied to scanning, long-running scans are abruptly killed mid-discovery, preventing users from discovering viable endpoints on slow, high-latency, or restrictive networks.

**Independent Test**: Initiate an endpoint pool scan with a large candidate count (e.g. 20,000 candidates). Observe the scan progress past typical connection timeout thresholds (e.g., beyond 90 to 300 seconds). Verify that the scan continues actively running, streaming discoveries, and reporting progress until all candidates are probed or the user presses Stop, without any timeout-induced interruption.

**Acceptance Scenarios**:

1. **Given** the user is on the Scanner screen and starts an endpoint scan, **When** the scan duration exceeds standard connection timeout thresholds, **Then** the scanner continues probing without interruption and never aborts due to a connection watchdog timer.
2. **Given** an active standalone scan in progress, **When** the user monitors the application state, **Then** the application does not arm connection timeout watchdogs and does not report a connection failure while the scanner is doing its work.
3. **Given** an active standalone scan, **When** the user explicitly taps the Stop button, **Then** the scan cleanly terminates immediately and retains all discovered working endpoints.

---

### User Story 2 - Responsive, Bound-Safe Mobile Terminal Window Header (Priority: P1)

As a mobile user viewing live engine telemetry and scan logs on an Android phone, when I view the terminal console header, all window controls, log titles, stream counter telemetry, and action buttons must fit neatly within the card chassis without text fragmentation, vertical word stacking, clipping, or out-of-bounds overflow.

**Why this priority**: Severe visual layout distortions—such as single-word multi-line wrapping and clipped action buttons ("Copy Buffe")—compromise user trust, degrade usability, and make vital telemetry unreadable on standard mobile screens.

**Independent Test**: Open the application on an Android device (or viewport with 360px–412px width). View the live session log terminal console while scanning or idling. Verify that the window controls, title text, stream counter metrics, and action buttons fit comfortably inside the container boundaries, text remains on designated lines without awkward fragmentation, and the Copy button is fully visible and comfortably tappable.

**Acceptance Scenarios**:

1. **Given** an Android mobile device with a narrow screen viewport (360px to 420px), **When** viewing the live terminal log header, **Then** the window header elements adapt to the screen width and all text labels remain fully legible without vertical single-word wrapping.
2. **Given** the live terminal log header on mobile, **When** examining the buffer counter and action buttons, **Then** the counter displays compactly without breaking across multiple fragmented lines, and the action button (e.g. Copy Buffer) remains completely within the chassis without horizontal clipping.
3. **Given** a user tapping the action button in the terminal header on a touchscreen, **When** the button is pressed, **Then** it provides clear tactile or visual feedback (e.g. state change to "Copied") without shifting neighboring elements out of bounds.

---

### User Story 3 - Strict Separation of Scanner and Connection Lifecycles (Priority: P2)

As a user navigating between the Connection, Scanner, and Activity screens, starting a scan must be recognized as an independent diagnostic action and must not alter the primary tunnel state to "Connecting", preventing spurious connection failure notifications or erroneous status badges.

**Why this priority**: Blurring the line between scanning and connecting creates confusing UX where the top navigation bar falsely announces an active tunnel handshake, misinforming the user about their device's actual network protection state.

**Independent Test**: Navigate to the Scanner tab while the VPN is disconnected. Start a scan and observe the global status indicators (e.g., top status pill/header). Verify that the primary tunnel connection state remains distinct from scanning and does not display an active tunnel connection in progress.

**Acceptance Scenarios**:

1. **Given** the VPN is currently disconnected, **When** the user initiates an endpoint scan from the Scanner tab, **Then** the system marks the scanner as actively probing while maintaining the primary VPN tunnel state as disconnected or idle.
2. **Given** an active scan running in the background, **When** the user switches to other tabs (Activity, Connection), **Then** the user can observe scan telemetry without receiving erroneous connection timeout dialogs or alerts.

---

### Edge Cases

- What happens when a scan finishes probing every candidate in the pool? The scanner must cleanly mark the scan as complete, present the final discovered list ordered by latency, and remain in an idle state without triggering connection error states.
- What happens if the user triggers a direct connection to a discovered gateway while a scan is running? The system must gracefully stop the scan first before initiating the tunnel connection handshake, at which point connection timeouts and watchdogs are appropriately armed.
- What happens on extremely narrow mobile screens (e.g., 320px width) or when device accessibility font scaling is set to large/extra-large? The terminal header must either wrap into clean, balanced tiers or truncate gracefully with ellipsis rather than breaking words character-by-character or overflowing offscreen.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The system MUST NOT apply connection flow timeouts or connection watchdog limits to standalone scans initiated from the Scanner interface.
- **FR-002**: Standalone endpoint scans MUST run continuously until the entire candidate endpoint pool has been evaluated or until the user explicitly requests cancellation.
- **FR-003**: The system MUST strictly isolate the standalone scanner lifecycle from the VPN tunnel connection lifecycle so that starting a scan does not transition the primary tunnel state into an in-flight connection handshake.
- **FR-004**: The terminal log console header MUST fit entirely within the visual chassis boundaries on mobile viewports without horizontal overflowing or clipping of action buttons.
- **FR-005**: Text labels and telemetry counters within the terminal console header MUST NOT fragment into single-word vertical wrapping on mobile screens.
- **FR-006**: Action buttons within the terminal console header (including copy buffer and auto-scroll follow) MUST remain fully visible, intact, and accessible with comfortable touch target dimensions on mobile touchscreens.
- **FR-007**: When an active scan is stopped by the user, the scanner MUST promptly cease probing, finalize all discoveries collected up to that moment, and transition to a stopped state without error banners.

### Key Entities

- **Endpoint Scan Session**: An exploratory probing operation that tests network reachability and latency across candidate gateway addresses, independent of tunnel routing.
- **Connection Handshake Session**: The stateful negotiation of an encrypted VPN tunnel, which requires strict time bounds to fail fast if an endpoint is unreachable.
- **Terminal Console Header**: The top chrome banner of the live engine output panel containing window status indicators, log buffer metrics, and console management actions.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Standalone endpoint scans can run without interruption past 300 seconds (and up to full pool completion) with 0% premature timeout terminations.
- **SC-002**: On mobile viewports ranging from 320px to 480px width, 100% of terminal console header elements remain within the visible chassis with zero horizontal clipping.
- **SC-003**: 100% of text and telemetry elements in the terminal console header maintain coherent formatting without single-word line wrapping on mobile displays.
- **SC-004**: Touch action buttons in the terminal console header maintain a minimum touch target height of at least 32px and are fully clickable on touchscreen devices without overlap.
- **SC-005**: Zero false-positive "Connection Timed Out" error alerts appear when running standalone scans.

## Assumptions

- The user initiates standalone scans explicitly from the Scanner tab.
- Connection flow timeouts remain active and enforced during intentional VPN connection attempts initiated from the Connection tab or via direct gateway selection.
- Mobile screen viewports adhere to standard responsive Android display widths (typically 360px–412px, down to 320px minimum).
