# Feature Specification: Connection Banners, Scanner Inputs & Category Persistence

**Feature Branch**: `008-fix-banners-scanner-category-persistence`

**Created**: 2026-09-18

**Status**: Draft

**Input**: User description: "ok two more visual bugs so far . both attached screenshots. first one the messages under the main tab top banner are just weird shaped , out of place and out of bounds and order ! no boarder no marker no nothing ! just plain text dead in the middle ! needs attention and fixing. second one in scanner tab both cuncurrency worker and timeout fields are bigger than nessecary ! and have a weird half baked shape . with a devider in the middle of each ! needs fixing. other none ui issues are : masque h3 wont find ip and connect (mostly the cause is that my network has blocked it) needs more investigating tho. now masque has a ip pool of about 1300 and wireguard has 20000 which im assuming is what it should be ??? also when scanning for h2 ips if we already have found wireguard ips it should not remove those . new scans only overwrite the previous scans in their own categories ! scanner tab concurrency field tells me to enter a value between 231 to 241 !! whyyyy ?? why so random ? why not between 1 and 500 ??"

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Tactical Status & Notification Banners (Priority: P1)

Users viewing the Connection Tab (Home) need status notifications (error banners, forced endpoint notices, update alerts) to be visually contained, styled with cyber-tactical design standards, and cleanly separated from neighboring layout elements so text never collides or floats without context.

**Why this priority**: Directly addresses user screenshot `media_1789681616167.jpg` and `media_1789681688601.jpg` where error notices and forced-peer indicators appear as plain unstyled text colliding directly with action buttons (`443Clear`) with zero visual structure.

**Independent Test**:
- Trigger an error state (e.g. scan failure or failed connection) and verify the error banner displays inside a styled card with warning icon, bounded width, border, padded text, and a distinct dismiss button.
- Pin a peer endpoint and verify the "Targeting forced endpoint" bar renders as a high-contrast tactical pill/card with clear spacing between the endpoint address and the "Clear" button.

**Acceptance Scenarios**:
1. **Given** the runtime transitions to `error` status, **When** the Connection Tab renders, **Then** an `.error-banner` is displayed with a tactical red/amber background (`var(--coral-dim)`), 1px solid border (`var(--coral-border)`), rounded corners, an alert icon on the left, clear typography, and a distinct dismiss close button on the right.
2. **Given** a forced endpoint is configured (`settings.peer`), **When** the Connection Tab renders, **Then** the `.pinned-peer-bar` displays a styled pill with an informational icon, a formatted monospace code block for the IP:port, and a separate, padded action button labeled "Clear (Scan dynamically)" separated by adequate whitespace.
3. **Given** an update notification is active, **When** rendered, **Then** the `.update-banner` displays with emerald accents, distinct primary action button, and a separate dismiss icon.

---

### User Story 2 - Scanner Tab Stepper Field Sizing & Validation Fix (Priority: P1)

Users configuring scanner concurrency and timeout values need proportional, compact stepper input fields that fit the parameters naturally without sprawling empty space, without confusing dividers, and without erratic browser validation popups (e.g. "enter a value between 231 to 241").

**Why this priority**: Directly addresses user screenshot `media_1789681616168.jpg` where stepper inputs span the entire container width with 80% dead space, leaving the `+` button in the center resembling a divider, and fixes the HTML5 `min=1`/`step=10` constraint bug that blocked entering standard values like 240 or 500.

**Independent Test**:
- Inspect the Scanner Tab Concurrency and Timeout inputs on both Desktop and Android: verify they have compact, well-proportioned dimensions matching the numbers they contain.
- Enter any number between 1 and 500 (such as `240`, `250`, `500`) and verify no browser validation errors occur.

**Acceptance Scenarios**:
1. **Given** the Scanner Tab is open, **When** viewing Concurrency and Timeout inputs, **Then** the `.stepper-input-wrapper` is compactly sized to fit the stepper buttons and number input without awkward dead space to the right.
2. **Given** the concurrency input has a value of 240, **When** the user types or adjusts the value, **Then** HTML5 input step constraints allow all integers between 1 and 2000 (with recommended range 1–500), completely eliminating browser step-mismatch errors.
3. **Given** the user clicks the `+` or `−` stepper buttons, **When** clicked, **Then** the value increments or decrements cleanly by 10 (or 100 for timeout) while manual text input permits any integer in the allowed range.

---

### User Story 3 - Category-Isolated Discovered Endpoints Persistence (Priority: P2)

Users scanning for endpoints across different protocols (MASQUE H3, MASQUE H2, WireGuard) need new scans to only overwrite endpoints belonging to the category currently being scanned, preserving endpoints discovered under other protocols.

**Why this priority**: Solves workflow destruction where discovering endpoints for one protocol previously wiped out valid endpoints already found for other protocols.

**Independent Test**:
- Run a WireGuard scan to discover WireGuard endpoints.
- Switch to MASQUE H2 and run a scan.
- Verify WireGuard endpoints remain saved in the endpoints list and visible under the WireGuard filter tab, while only the MASQUE H2 list is updated.

**Acceptance Scenarios**:
1. **Given** the user has previously discovered WireGuard endpoints, **When** the user starts a new scan for MASQUE H2, **Then** only existing MASQUE H2 endpoints are cleared and replaced, while existing WireGuard endpoints remain in the endpoint cache and UI.
2. **Given** endpoints exist for multiple protocols, **When** the user views the Scanner Tab, **Then** the protocol dock tabs (`All`, `MASQUE H3`, `MASQUE H2`, `WireGuard`) display accurate counts reflecting the preserved endpoints for each protocol.
3. **Given** the user clicks "Clear Endpoints" (or resets cache), **Then** an explicit option or confirmation allows clearing all or clearing the active category.

---

### User Story 4 - MASQUE H3 Failure Guidance & Pool Size Transparency (Priority: P3)

Users need clear visibility into why candidate pool sizes differ between protocols (e.g. ~1,300 for MASQUE vs ~20,000 for WireGuard) and actionable assistance when MASQUE H3 handshakes fail due to ISP-level QUIC/UDP blocking.

**Why this priority**: Explains the technical pool architecture and provides instant failover to MASQUE H2 when UDP/443 is filtered by the user's ISP.

**Independent Test**:
- Trigger a MASQUE H3 scan failure.
- Verify the failure notification or Activity log provides a direct prompt to switch to MASQUE H2 or WireGuard.

**Acceptance Scenarios**:
1. **Given** a MASQUE H3 scan completes with 0 hits, **When** the error/completion message displays, **Then** it clearly indicates that UDP/QUIC may be filtered on the current network and recommends switching to MASQUE H2 (TCP).
2. **Given** candidate generation starts, **When** logged or displayed in telemetry, **Then** the pool counter clarifies the candidate formula (MASQUE sweeps port 443 across 14 subnets plus multi-port seeds ~1,300 pairs; WireGuard sweeps 54 ports across 7 subnets ~20,000 pairs).

---

### Edge Cases

- What happens if the user enters a concurrency value outside 1–2000? Values below 1 are clamped to 1; values above 2000 are clamped to 2000 upon commit/blur.
- What happens if a scan discovers an endpoint with an IP:port that already exists under a different protocol? Endpoints are unique by `(addr, protocol)`.
- What happens on very small mobile screens for banners? `.error-banner` and `.pinned-peer-bar` wrap cleanly with `flex-wrap: wrap` and `gap: 8px` so text and buttons do not clip.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: System MUST style `.error-banner` in both desktop and mobile CSS with a cyber-tactical card container (`background: rgba(255, 92, 92, 0.08)`, `border: 1px solid var(--coral-border)`, padding, icon alignment, and hoverable dismiss button).
- **FR-002**: System MUST style `.pinned-peer-bar` with a tactical pill layout, separating `Targeting forced endpoint: [IP]` and `Clear (Scan dynamically)` with adequate spacing and distinct button styling.
- **FR-003**: System MUST style `.update-banner` with emerald tactical styling and clear primary action button separation.
- **FR-004**: System MUST resize `.stepper-input-wrapper` to compact, content-fitted dimensions (max width ~160px) so buttons and input occupy the entire wrapper without empty space.
- **FR-005**: System MUST configure the Concurrency `NumberField` so that HTML5 step validation does not reject valid integers (allowing any integer in 1–2000 without "231 to 241" step mismatch warnings).
- **FR-006**: System MUST isolate scan endpoint state updates so that initiating a scan for protocol $P$ only clears/replaces endpoints matching protocol $P$, retaining endpoints from other protocols.
- **FR-007**: Scanner Tab protocol dock tabs MUST accurately reflect the count of active endpoints per protocol category.
- **FR-008**: System MUST display actionable diagnostic messages when MASQUE H3 fails, recommending MASQUE H2 (TCP) or WireGuard.

### Key Entities

- **DiscoveredEndpoint**: Represents a probed and responsive gateway, containing `addr` (IP:port), `rtt` (human-readable latency string), `rttMs` (numeric latency), and `protocol` (`masque-h3`, `masque-h2`, or `wireguard`).
- **ScanState**: Represents current scanning progress, including `active`, `mode`, `phase`, `scanned`, `total`, `working`, `concurrency`, and `bestRtt`.
- **RuntimeState**: Represents engine tunnel state (`status`, `peer`, `protocol`, `detail`).

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: 100% of banner elements (`.error-banner`, `.pinned-peer-bar`, `.update-banner`) display within styled cards with dedicated borders, padding, and zero text/button collisions.
- **SC-002**: Concurrency input accepts any user-entered integer from 1 to 500 without triggering browser step-validation popups.
- **SC-003**: Stepper input wrapper width is constrained to its interactive content, eliminating the visual "divider" artifact.
- **SC-004**: Running a scan for one protocol preserves 100% of previously discovered endpoints from other protocols.
- **SC-005**: Both Desktop and Android applications maintain parity in banner styling, stepper controls, and category persistence.

## Assumptions

- The primary cause of MASQUE H3 timeouts on the user's connection is ISP-level censorship blocking UDP port 443 (QUIC), which is resolved by using MASQUE H2 (TCP) or WireGuard.
- Concurrency workers between 1 and 500 provide optimal performance for domestic and restricted connections; capping at 2000 handles enterprise/high-bandwidth testing.
- Preserving endpoints per protocol category in memory/state aligns with user expectations while switching between protocols.
