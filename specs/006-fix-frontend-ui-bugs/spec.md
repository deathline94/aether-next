# Feature Specification: Frontend & UI Visual Polish & State Remediation

**Feature Branch**: `006-fix-frontend-ui-bugs`

**Created**: 2026-09-17

**Status**: Draft

**Input**: User description: "i wanna address and fix some frontend and ui visual bugs in both desktop and android version . i attach screenshots. first one speed profiles that as you can see are boarderless , weird and out of place and order . please fix this one. the next one in activity tab . after every scan , connect and action please clear all the logs . auto follow the scroll with the last message . hits tab must only show the valid ips . thats it. scanner tab must be more much more orginized . every ip found for every protocol must be in their respected fields . next scan must override the previous ones. but the results must be more optimized and organized with more order. fix these ui bugs in both desktop and android app"

---

## User Scenarios & Testing *(mandatory)*

### User Story 1 - High-Contrast Tactile Speed Profile Cards (Priority: P1) 🎯 MVP

A user on desktop or mobile opening the Connection stage expects Speed Profile presets (MASQUE H3, MASQUE H2, WireGuard, Gool) to display as crisp, individually framed tactile hardware cards with strong visible borders, noticeable dark card surfaces contrasting against the panel background, and clear internal padding—completely eliminating the borderless, floating-text appearance where titles and descriptions ran together into an unreadable mess.

**Why this priority**: Speed profiles represent the primary quick-selection interface before initiating a tunnel. In the current build (as captured in the user's screenshot), buttons render without distinct visual borders or surface contrast, causing labels to run directly into each other and making preset selection feel broken and unstyled.

**Independent Test**:
1. Open the Connection tab on both desktop and mobile; observe the Speed Profiles panel.
2. Verify each profile preset (`MASQUE H3`, `MASQUE H2`, `WireGuard`, `Gool`) is rendered within a distinct, high-contrast bordered card with clear separation, internal padding, and distinct typography for title vs hint.
3. Verify the currently active profile displays a radiant phosphor emerald border (`--emerald-border`), emerald ambient glow, and an illuminated `ACTIVE` tag pill.
4. Hover and tap cards; verify interactive tactile states (brightening border, scale feedback) operate smoothly without layout shifting.

**Acceptance Scenarios**:
1. **Given** a user viewing the Speed Profiles panel, **When** rendered on screen, **Then** all four profile options appear inside clearly defined hardware cards with high-contrast visible borders (`rgba(255, 255, 255, 0.12)` default, `rgba(255, 255, 255, 0.22)` on hover) and distinct card background surfaces (`#0d131a` / `--panel-nested`) set against the surrounding panel.
2. **Given** a profile card, **When** inspected, **Then** the card title is separated on its own header line from the secondary hint text, and adjacent cards are separated by a minimum 10px–12px gutter.
3. **Given** an active profile matching current settings, **When** displayed, **Then** it renders with an emerald-illuminated border (`var(--emerald-border)`), subtle inner glow, and an `ACTIVE` badge.
4. **Given** a user clicking a profile card, **When** clicked, **Then** the settings patch applies, the card enters the active state immediately, and visual feedback is instantaneous (<16ms).

---

### User Story 2 - Activity Tab Log Lifecycle, Auto-Scroll Following & Strict Hits Filter (Priority: P2)

A user navigating to the Activity tab requires that logs stay relevant and legible: previous log buffers must automatically flush whenever a new scan, connection, or primary verification action is initiated; the log console must reliably follow and stay locked to the newest incoming message; and the "Hits" filter tab must strictly display verified IP addresses rather than generic status logs.

**Why this priority**: Activity logs currently accumulate endlessly across multiple sessions and scans. Furthermore, the log window does not consistently follow the scroll stream, and the "Hits" filter includes irrelevant log lines simply because they contain the word "gateway".

**Independent Test**:
1. Run a scan or connect the tunnel; observe logs streaming in the Activity tab; verify the log viewer automatically follows and keeps the last message in view.
2. Stop the scan or disconnect; start a new scan or new connection action; verify previous logs are cleared automatically so only the current action's logs appear.
3. Select the "Hits" filter pill in the Activity tab; verify that every single entry listed contains a verified IP endpoint, with zero generic status or informational lines displayed.

**Acceptance Scenarios**:
1. **Given** the user initiating a new action (starting a scanner run, toggling tunnel connection, or clicking Connect Direct), **When** the action is triggered, **Then** the existing log buffer is automatically flushed and reset to start fresh for the new action.
2. **Given** active streaming logs in the console, **When** new entries arrive and auto-scroll is enabled, **Then** the console smoothly follows the stream so the most recent log line remains fully visible at the bottom.
3. **Given** the user viewing the Activity tab, **When** the "Hits" filter tab is active, **Then** only log entries that contain a valid, verified IP address (IPv4 or IPv6 with or without port) are displayed in the list and counted in the badge.
4. **Given** manual log management, **When** the user clicks "Clear", **Then** the log buffer flushes to 0 immediately.

---

### User Story 3 - Organized Scanner Results by Protocol & Automatic Scan Overwrite (Priority: P3)

A user performing edge discovery in the Scanner tab expects results to be clean, organized, and segmented by protocol (MASQUE H3, MASQUE H2, WireGuard), with every new scan completely overriding the previous scan's results so that stale endpoints never linger or mix with fresh discoveries.

**Why this priority**: Edge scanning is used to benchmark and find the fastest route. If previous scan results mix with new ones or if endpoints across different protocols are dumped into an unorganized flat list, the user cannot easily compare or select the optimal endpoint for their preferred protocol.

**Independent Test**:
1. Navigate to Scanner tab and launch a scan for `MASQUE H3`; verify discovered endpoints appear in an organized protocol section/filter.
2. Change protocol or rerun the scan; verify previous results are immediately cleared and replaced by the new scan's findings.
3. Inspect discovered endpoint rows; verify results are ordered by latency (lowest RTT first) with distinct protocol tags, clear IP copy buttons, and one-click "Connect Direct" actions.

**Acceptance Scenarios**:
1. **Given** a user starting a new scan in the Scanner tab, **When** the scan starts, **Then** all previous discovered endpoints are immediately cleared from state and UI.
2. **Given** discovered endpoints returned from the scan, **When** rendered in the Telemetry Results panel, **Then** they are cleanly grouped or filterable by protocol (MASQUE H3, MASQUE H2, WireGuard) with dedicated count chips and latency sorting.
3. **Given** each discovered endpoint item, **When** rendered, **Then** it presents the socket address in monospace font, protocol badge, RTT latency tier badge (green <20ms, cyan <=60ms, amber <=100ms, coral >100ms), and a responsive "Connect Direct" button.

---

### User Story 4 - Cross-Platform Parity across Desktop & Android (Priority: P4)

A user on Android requires the identical visual hierarchy, high-contrast speed profile cards, auto-cleared activity logs, strict hits filtering, and protocol-organized scanner results as the Desktop client, tailored to touch screens.

**Why this priority**: Both platforms share the same core features. Discrepancies between mobile and desktop create frustration and inconsistent experiences.

**Independent Test**:
1. Build and launch `apps/android`; verify speed profile cards have clear visible borders, padding, and responsive 2-column layout.
2. Test Activity tab and Scanner tab on mobile; verify identical log clearing, auto-follow, and protocol organization behaviors.

**Acceptance Scenarios**:
1. **Given** Android viewport widths (360px–430px), **When** viewing Speed Profiles, **Then** cards render with visible high-contrast borders and touch targets >= 44px.
2. **Given** Android Activity tab, **When** actions trigger, **Then** logs clear automatically and follow the scroll smoothly.
3. **Given** Android Scanner tab, **When** scanning, **Then** results overwrite previous runs and display in clean protocol-organized layouts.

---

## Edge Cases

- **Fast Successive Actions**: If a user quickly starts and stops a scan, or toggles connection rapidly, log clearing must not cause race conditions or unhandled rejections.
- **Empty Hits Filter**: When no valid IP addresses have been discovered yet, the "Hits" filter must display a clear empty state ("No Verified Endpoint Hits") rather than an empty blank screen.
- **Scroll Away Behavior**: If the user deliberately scrolls up to read earlier logs during an active stream, auto-follow must pause and display a "Follow" resume pill; clicking "Follow" or scrolling back to the bottom must re-engage auto-follow.
- **Narrow Mobile Screens (<=380px)**: Profile cards must stack cleanly in a single column so text and hints never clip or wrap awkwardly.
- **Long IPv6 Addresses**: IPv6 endpoints in scanner results must wrap cleanly or truncate with ellipsis while keeping copy button and latency badges aligned.

---

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: Speed profile preset cards in `ConnectionTab` MUST render with high-contrast visible borders (`1px solid rgba(255, 255, 255, 0.12)` minimum) and a distinct dark card surface (`#0d131a`) on both desktop and Android clients.
- **FR-002**: Each speed profile card MUST enforce clear internal padding (minimum 14px), vertical flex layout, and separated header and hint text blocks to prevent text collisions.
- **FR-003**: The active speed profile card MUST display an illuminated phosphor emerald border (`var(--emerald-border)`), ambient glow, and an `ACTIVE` tag pill.
- **FR-004**: In `useLogs`, the session log buffer MUST automatically clear and reset whenever a user starts a scan, toggles a tunnel connection (connect/disconnect), or executes a direct endpoint connection.
- **FR-005**: In `ActivityTab`, the log console MUST reliably auto-scroll to keep the latest message visible when auto-scroll is enabled, and provide a clear "Follow" action when paused.
- **FR-006**: In `useLogs`, the `isHit` filter predicate MUST strictly match log entries containing valid IP endpoints (IPv4 or IPv6 socket addresses), completely excluding generic status messages (e.g. status lines merely containing the substring "gateway").
- **FR-007**: In `useScanner`, starting a new scan MUST completely clear and overwrite all previously discovered endpoints from state and UI.
- **FR-008**: In `ScannerTab`, discovered endpoints MUST be organized with protocol-aware categorization (protocol tabs or distinct protocol groupings for MASQUE H3, MASQUE H2, WireGuard) and sorted by lowest latency.
- **FR-009**: All UI updates and styling MUST be applied symmetrically to both `apps/desktop` and `apps/android`.
- **FR-010**: All numerical readouts (latencies, counts, IP addresses) MUST enforce `tabular-nums` and monospace typography.

---

## Key Entities *(include if feature involves data)*

- **SpeedProfile**: Preset definition with `id`, `label`, `hint`, and `patch` configuration for protocol, transport, noise, scanMode, and routingMode.
- **LogEntry**: Diagnostic event with `id`, `ts`, `level` ("info" | "warn" | "error"), and `message`.
- **LogFilter**: View filter mode ("milestones" | "hits" | "errors" | "raw"), where "hits" strictly denotes entries containing verified IP addresses.
- **DiscoveredEndpoint**: Discovered edge node with `addr` (IP:port), `rtt` string, `rttMs` numeric latency, and `protocol` string.

---

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: 100% of Speed Profile preset cards render with clearly visible borders and contrast on both desktop and mobile screens, matching the cyber-tactical design system with zero borderless/glued text defects.
- **SC-002**: 100% of scan, connect, and direct-connect actions trigger an automatic log buffer reset, ensuring logs only reflect the current operation.
- **SC-003**: The Activity log console maintains auto-scroll following during active streaming, keeping the latest log line visible without user intervention.
- **SC-004**: 100% of entries shown under the "Hits" filter tab contain a verified IP address, with 0 generic status/informational false positives.
- **SC-005**: 100% of new scanner runs completely overwrite previous results, and discovered endpoints are organized by protocol and sorted by latency.
- **SC-006**: Both `apps/desktop` and `apps/android` pass production builds (`npm run build`, `npm run sync-www`) with zero compiler or bundling errors.

---

## Assumptions

- Auto-clearing logs on action is user-desired to reduce clutter during frequent test cycles; the manual "Copy Buffer" allows exporting before actions if desired.
- Valid IP detection in logs can be reliably performed using regex matching standard IPv4 (`\b(?:\d{1,3}\.){3}\d{1,3}\b`) and IPv6 patterns in combination with hit confirmation events.
- Discovered endpoints in the scanner can be filtered/switched via protocol segmented pills or grouped headers without altering backend scanner event payloads.
- Existing Tauri IPC commands and Android bridge contracts remain unchanged.
