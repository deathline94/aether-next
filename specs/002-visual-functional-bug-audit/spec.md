# Feature Specification: Visual & Functional Bug Remediation

**Feature Branch**: `002-visual-functional-bug-audit`

**Created**: 2026-09-16

**Status**: Draft

**Input**: User description: "this app still has a lot of visual and functional bugs . haunt and find all of them"

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Direct Connection Navigation & Pinned Peer State Freedom (Priority: P1)

When a user discovers a healthy gateway in the Standalone Scanner and clicks "Connect Direct", the app must immediately navigate to the Connection view, initiate the connection with feedback, and keep the user informed. Subsequent normal connections or preset selections must never be locked to this forced peer indefinitely; clicking the primary Connect button or choosing a profile preset must automatically clear any pinned peer so the engine performs a fresh discovery scan.

**Why this priority**: Currently on desktop, clicking "Connect Direct" does not switch tabs, leaving the user on the scanner with no visible indication that connection started. Worse, saving `peer` into `settings.json` permanently locks all future connections to that single IP forever with no UI method to clear it.

**Independent Test**:
1. Scan for endpoints in the Scanner tab and click "Connect Direct" on any discovered endpoint.
2. Verify the UI switches to the Connection view and displays connecting/connected status.
3. Disconnect, select a speed preset (e.g. MASQUE H2) or click Connect again, and verify the connection performs a dynamic gateway scan rather than reusing the forced peer.

**Acceptance Scenarios**:
1. **Given** a list of discovered endpoints in the Scanner tab, **When** the user clicks "Connect Direct" on an endpoint, **Then** the view switches to the Connection view, connection status transitions to "connecting" for that gateway, and logs record the direct connection.
2. **Given** a previous direct connection that set a forced peer, **When** the user clicks the primary "Connect" button or chooses a speed profile preset, **Then** any pinned peer is cleared to empty and a normal multi-endpoint discovery scan occurs.

---

### User Story 2 - Scanner Progress Retention & Accurate Result Telemetry (Priority: P1)

When a standalone scan completes, stops, or fails, the scanner progress card (probed count, working count, progress bar percentage, and best RTT badge) must remain visible on screen so the user can inspect the final outcome. If a scan completes with 0 working endpoints, the UI must accurately indicate "No Endpoints Found" or "Completed" rather than claiming "Verified", and the activity log must not output broken placeholder lines like `Scan complete — best:  ()`.

**Why this priority**: Currently, `scanState.active && (...)` unmounts the entire progress bar and summary the millisecond a scan finishes, causing the stats to vanish abruptly. Furthermore, empty results emit a false "Verified" phase and a corrupted log string.

**Independent Test**:
1. Start a standalone scan and let it complete (or click "Stop Scan").
2. Verify that the progress bar (at 100% or stopped position), candidate counters, and summary stats stay displayed until a new scan is started.
3. Verify that on 0 hits, the phase reads "Completed (0 found)" rather than "Verified", and the log entry is formatted properly or suppressed when no endpoint was found.

**Acceptance Scenarios**:
1. **Given** an active standalone scan, **When** the scan completes or is cancelled, **Then** the progress bar and summary stats remain visible in the completed state.
2. **Given** a scan that discovers 0 working endpoints, **When** it finishes, **Then** the scan phase reports 0 discovered endpoints without claiming "Verified", and no empty `()` log line is generated.

---

### User Story 3 - TUN Mode Verification & Process Metric Accuracy (Priority: P1)

In the hero metrics grid and test verification section, state indicators must reflect technical truth. The Process metric card must show "Connecting" or "Starting" while an engine child process is launching, rather than showing a valid PID accompanied by a contradictory "Not running" subtitle. Furthermore, the "Test connection" feature must be capable of validating connectivity when in TUN mode (which routes system-wide without binding local loopback proxy ports).

**Why this priority**: Users see "PID 12345" + "Not running" simultaneously during startup, and clicking "Test connection" in TUN mode always produces a false-negative "connection refused" error because it blindly targets `127.0.0.1:1820` where no proxy listener exists in TUN mode.

**Independent Test**:
1. Initiate connection and observe the Process metric card during the "connecting" phase. Verify it displays "Connecting" / "Starting" instead of "Not running".
2. In TUN mode (when connected), click "Test connection". Verify it either runs a direct internet trace or clearly displays a TUN-specific validation status without erroring on an absent proxy port.

**Acceptance Scenarios**:
1. **Given** the tunnel is in the "connecting" state, **When** the user views the Process metric card, **Then** it indicates "Starting" or "Connecting" alongside the active PID.
2. **Given** an active TUN mode connection, **When** the user clicks "Test connection", **Then** the verification performs a direct egress test or correctly confirms full-tunnel routing.
3. **Given** a test result in the Connection view, **When** the test succeeds or fails, **Then** visual feedback distinguishes success (green accent) from failure (coral/red accent).

---

### User Story 4 - Responsive Layout, Overflow Containment & Discovered Gateway Scrolling (Priority: P2)

The application workspace across desktop and mobile platforms must constrain content gracefully under varying screen sizes and display scale factors (100% to 175%). Discovered endpoint lists in the Scanner view must be contained within a scrollable region with a reasonable height limit, preventing long lists from expanding the window indefinitely. On narrow mobile screens, gateway rows must wrap elements without overflowing the viewport.

**Why this priority**: Finding dozens or hundreds of gateways causes the desktop window to stretch downwards indefinitely. On small screens or high DPI scaling, text and buttons overflow horizontally or get cut off.

**Independent Test**:
1. Run a scan that finds 20+ endpoints. Verify the discovered list scrolls internally without blowing out the page footer.
2. Resize the desktop window or inspect mobile view at 360px width. Verify no elements produce unintended horizontal scrollbars or truncated buttons.

**Acceptance Scenarios**:
1. **Given** many discovered gateways, **When** rendered in the Scanner tab, **Then** the list scrolls cleanly within a maximum bounded height container.
2. **Given** narrow viewports or display scaling, **When** viewing the connection cards or scanner rows, **Then** text wraps safely and action buttons remain accessible.

---

### User Story 5 - Settings Invariants, Transport Awareness & Log Hygiene (Priority: P2)

Settings and log presentation must be transparent and consistent with underlying network protocols. When MASQUE H2 (TCP/TLS) is selected, obfuscation noise controls must indicate that UDP noise is not applicable rather than implying it takes effect. Port collision warnings must propagate to the sticky save indicator when auto-save is blocked. Obsolete references to legacy profile names ("Max (TUN)", "Speed") must be updated. The activity log "Milestones" filter must suppress repetitive probe timeout errors so real milestones stand out.

**Why this priority**: Users are confused by noise options that do nothing in H2, misleading save bars that say "Auto-save on" while an error blocks saving, out-of-date documentation strings, and a "Milestones" log tab flooded with hundreds of probe errors.

**Independent Test**:
1. In Settings, switch to MASQUE H2. Verify the Obfuscation noise dropdown indicates that UDP noise is not applicable for TCP.
2. Set HTTP port equal to SOCKS5 port. Verify the sticky save indicator shows an error or blocked state instead of "Auto-save on".
3. Check the Connection view notes for updated profile guidance.
4. During a scan, switch to the "Milestones" log filter. Verify that individual probe failure lines are filtered out, leaving high-level phase changes.

**Acceptance Scenarios**:
1. **Given** MASQUE H2 is active, **When** viewing obfuscation settings, **Then** the UI clearly denotes UDP noise is inapplicable for TCP TLS.
2. **Given** conflicting port settings, **When** viewing the bottom save bar, **Then** the bar reflects that changes cannot be saved due to validation errors.
3. **Given** active engine logging during a scan, **When** filtered by "Milestones", **Then** probe timeout errors are excluded while session state transitions remain visible.

---

### Edge Cases

- What happens if the user rapidly clicks "Connect Direct" while a connection is already being established? The action must be guarded by `busy` / `connectBusy` to prevent duplicate spawns.
- What happens if the user manually enters an invalid number into a `NumberField`? The draft state safely clamps to `[min, max]` on blur and resets on invalid input.
- What happens if the network is disconnected during a scan? The scanner detects the condition, stops cleanly, and preserves any endpoints found prior to the drop.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: Clicking "Connect Direct" in the desktop Scanner view MUST automatically transition the active view to "home" (Connection tab).
- **FR-002**: Triggering a standard connection via the primary Power button or clicking any speed profile preset MUST clear any previously pinned `peer` to allow normal gateway discovery scanning.
- **FR-003**: The standalone scanner progress card MUST remain rendered in a completed/stopped state after a scan finishes, until a new scan is initiated.
- **FR-004**: When a standalone scan completes with 0 endpoints, the phase status MUST indicate that 0 endpoints were found (not "Verified"), and empty `Scan complete — best:  ()` log messages MUST be suppressed.
- **FR-005**: The Process metric card MUST display "Connecting" / "Starting" while an engine process is in the connecting phase with an active PID.
- **FR-006**: The "Test connection" action MUST properly handle TUN mode by conducting a direct network test or reporting TUN verification rather than attempting to connect to a nonexistent local proxy.
- **FR-007**: The connection test result element MUST visually distinguish success messages (positive/green accent) from error messages (negative/coral accent).
- **FR-008**: In the Settings view, when MASQUE H2 is selected, the obfuscation noise option MUST be disabled or marked with an advisory that UDP noise packets are not transmitted over TCP TLS.
- **FR-009**: When port validation errors exist (such as HTTP and SOCKS5 port collision), the sticky save bar MUST display an error indicator instead of "Auto-save on".
- **FR-010**: The discovered endpoints list in the Scanner tab MUST have a maximum bounded height with an internal scrollbar to prevent unbounded vertical page expansion.
- **FR-011**: Global CSS overflow containment rules (`min-width: 0`, `overflow-wrap: anywhere`) MUST be added to desktop styling to prevent text and button clipping under high DPI scaling.
- **FR-012**: The "Milestones" log filter predicate MUST filter out probe failure and candidate rejection noise so that user-meaningful milestones remain prominent.

### Key Entities

- **Settings**: Configuration entity containing tunnel protocol, transport, routing mode, ports, obfuscation parameters, and optional temporary peer override.
- **ScanState**: Telemetry entity tracking whether a scan is active, current phase, total candidate count, probed count, working count, and best measured RTT.
- **DiscoveredEndpoint**: Network gateway record storing IP:port address, measured RTT string, numeric RTT milliseconds, and protocol identification.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: 100% of "Connect Direct" user interactions on both desktop and mobile transition the active view to Connection without requiring manual tab switching.
- **SC-002**: Reconnecting after a direct connect restores dynamic multi-endpoint scanning in 100% of cases unless the user deliberately targets a forced gateway.
- **SC-003**: Scan progress summary metrics remain visible on 100% of completed or stopped scans until the next scan run.
- **SC-004**: Zero instances of contradictory metric display (e.g. "PID [N]" paired with "Not running") occur during connection startup.
- **SC-005**: Zero false-negative "connection refused" errors occur during live connection tests in TUN mode when internet routing is healthy.
- **SC-006**: 100% of discovered endpoints lists scroll within a bounded viewport regardless of whether 5 or 500 gateways are found.

## Assumptions

- Both desktop (Tauri) and mobile (Android) codebases share identical semantic contracts for engine telemetry and settings fields.
- WinTUN adapter setup requires administrative privileges on Windows; non-admin users default to system-proxy mode.
- Amnezia and v2rayN noise parameters (`Jc=5, Jmin=50, Jmax=128, 0ms delay`) remain the system-wide standard for UDP-based obfuscation.
