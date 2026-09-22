# Feature Specification: Reset Connect State on Discovery Failure and Modernize Noise Profiles

> **Superseded by `specs/015-full-audit-remediation`.** Every "fixed" statement
> below describes the tree as it was when this document was written. 015
> re-audited these claims against source and found that several of the guards
> they record were unreachable, inverted, or never wired into CI. Read the code
> before quoting this file as evidence that something is done.


**Feature Branch**: `001-fix-scan-fail-noise`

**Created**: 2026-09-15

**Status**: Draft

**Input**: User description: "hey this app i developed ,i wanna fix some bugs . first one when protocol is set on masque h3 , start , the scan to find endpoints , when it fails to find anything , it says its failed in the logs but the start button is still hangs on until we click it to disengage manualy . when failed the button should revert too othe bug/feature is the way we use use fragment/noise/junk here . i use wireguard noise in two formats . one is the wireguard amnezia format Jc=5 Jmin=50 Jmax=128 these values under the privatekey part the second format that works is the v2rayn format in the finalmask { \"udp\": [ { \"type\": \"noise\", \"settings\": { \"reset\": \"1-2\", \"noise\": [ { \"rand\": \"50-128\", \"delay\": \"0\" }, { \"rand\": \"50-128\", \"delay\": \"0\" }, { \"rand\": \"50-128\", \"delay\": \"0\" }, { \"rand\": \"50-128\", \"delay\": \"0\" }, { \"rand\": \"50-128\", \"delay\": \"0\" } ] } } ] } cause in the past and now the masque h3 just wont connect for me . i thought to myself that we should try these junk/noise/fragments i found that actualy work in other wireguards . so im gonna need u to replace em in wg , wg over wg , masque h2 , masque h3"

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Auto-Revert Connect Button on Endpoint Discovery Failure (Priority: P1)

When a user initiates a connection (particularly in MASQUE H3 mode, or any supported protocol) and the automated endpoint discovery fails to find any reachable gateway, the system must recognize the failure immediately, log the diagnostic error, display a prominent error banner to the user, and automatically revert the primary Start/Connect button from the engaged "DISCONNECT" state back to the idle "CONNECT" state without requiring the user to click it manually to clear the hung state.

**Why this priority**: A hung connection button prevents users from making subsequent connection attempts or changing protocols without manual, confusing intervention. The app appears frozen or unresponsive when the button state diverges from the actual engine state.

**Independent Test**: Can be tested independently by launching the application, selecting MASQUE H3 (or simulating blocked endpoints), clicking "CONNECT", and observing that upon discovery failure the button automatically reverts to "CONNECT" and displays the failure reason.

**Acceptance Scenarios**:

1. **Given** the user selects MASQUE H3 and initiates a connection, **When** the endpoint discovery scan completes with 0 reachable endpoints found, **Then** the application logs the failure, presents an error banner, and automatically resets the power button state to idle "CONNECT" without user clicking.
2. **Given** the application has returned to the idle state after a failed discovery attempt, **When** the user clicks "CONNECT" again (or selects another protocol preset), **Then** the application initiates a new connection cycle cleanly without needing manual recovery or process termination.

---

### User Story 2 - Modernized Noise Profiles Across All Supported Protocols (Priority: P1)

Users operating in high-censorship environments require effective traffic obfuscation to prevent Deep Packet Inspection (DPI) systems from identifying and dropping tunnel handshakes. The application must update its default noise/junk injection across all four core protocols—WireGuard (WG), WARP-in-WARP / Gool (WG over WG), MASQUE over HTTP/2, and MASQUE over HTTP/3—to use the proven noise profile consisting of 5 junk packets with payload sizes randomized between 50 and 128 bytes and zero delay between packets.

**Why this priority**: Without effective noise and packet shape masking, handshakes (especially QUIC/H3 and WireGuard) are actively dropped by network firewalls. Aligning all protocols with proven working noise patterns enables successful connections where standard handshakes fail.

**Independent Test**: Can be tested independently by establishing connections under WireGuard, WARP-in-WARP, MASQUE H2, and MASQUE H3, capturing outbound pre-handshake datagrams, and verifying that 5 noise packets with lengths in the [50, 128] byte range are dispatched with zero inter-packet delay.

**Acceptance Scenarios**:

1. **Given** any protocol mode (WireGuard, WARP-in-WARP, MASQUE H2, or MASQUE H3) is selected, **When** the tunnel initiates connection to an endpoint, **Then** 5 junk packets within the 50–128 byte size range are transmitted before/during the handshake.
2. **Given** standard noise settings are active, **When** junk packets are transmitted, **Then** the inter-packet delay is set to 0 milliseconds to match the proven fast-burst pattern.

---

### User Story 3 - WireGuard Amnezia and Finalmask Noise Compatibility (Priority: P2)

Technical users need confidence that obfuscation parameters conform to established and proven standards from other tools such as Amnezia WireGuard (`Jc=5`, `Jmin=50`, `Jmax=128` under the private key section) and v2rayN finalmask format (5 UDP noise bursts of `50-128` bytes, delay `0`, reset `1-2`). The application configuration system and settings defaults must represent and store these parameters consistently.

**Why this priority**: Ensuring parameter definitions conform to recognized formats allows consistent behavior, easy auditing, and transparent cross-client compatibility for users configuring anti-censorship tunnels.

**Independent Test**: Can be tested independently by inspecting the configuration outputs and custom settings defaults, verifying that parameters reflect Jc=5, Jmin=50, Jmax=128, and zero delay.

**Acceptance Scenarios**:

1. **Given** default settings or custom obfuscation is selected, **When** viewing or inspecting settings, **Then** the default junk count displays as 5, min size as 50, max size as 128, and delay as 0 ms.
2. **Given** WireGuard configuration generation, **When** generating client configurations, **Then** Amnezia noise parameters `Jc = 5`, `Jmin = 50`, `Jmax = 128` are properly formatted under the interface section.

---

### Edge Cases

- **Immediate Cancellation During Scan**: What happens if the user manually clicks Disconnect while endpoint discovery is still actively probing? The system must cleanly cancel the in-flight scan tasks, avoid race conditions with error emission, and return to the idle state promptly.
- **Flapping or Intermittent Network**: What happens if the network drops entirely during endpoint discovery? The scan must detect the network unreachable state, emit a clean failure event, reset the button state, and log the network issue without freezing the UI.
- **Zero Viable Endpoints in Custom Scan**: What happens if the user runs a standalone scan in the Scanner tab that yields no working endpoints? The scan must report "Scan complete: 0 endpoints found" and stop smoothly without hanging the scanner state or connection state.
- **Non-Standard MTU / Packet Clamping**: What happens when network intermediate nodes have a restricted MTU? The 50–128 byte junk packet range is strictly well below any standard Internet MTU (minimum IPv4 MTU 576, IPv6 1280), ensuring no fragmentation occurs on the noise packets themselves.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The system MUST automatically transition the connection UI state from connecting/active back to disconnected/idle whenever endpoint discovery or connection negotiation fails to find or establish a working gateway.
- **FR-002**: The system MUST guarantee that the background tunnel engine child process exits or terminates cleanly upon discovery failure, preventing orphan processes from holding network ports or proxy configurations.
- **FR-003**: The user interface MUST display a clear and actionable error message whenever endpoint scanning fails, while enabling the Start/Connect button to be clicked immediately for a new connection attempt.
- **FR-004**: The system MUST replace existing default and active obfuscation noise profiles across WireGuard, WARP-in-WARP (Gool), MASQUE H2, and MASQUE H3 with the unified 5-packet profile (`Jc=5`, `Jmin=50`, `Jmax=128`, `delay=0ms`).
- **FR-005**: For WireGuard and WARP-in-WARP tunnels, the obfuscator MUST transmit 5 junk packets of randomized size between 50 and 128 bytes prior to completing the cryptographic handshake.
- **FR-006**: For MASQUE H2 and MASQUE H3 tunnels, the pre-handshake obfuscator MUST transmit 5 junk packets of randomized size between 50 and 128 bytes before sending the HTTP/QUIC connection initiation.
- **FR-007**: The system MUST set the inter-packet delay between junk packets in the modernized noise profiles to 0 milliseconds by default (fast burst).
- **FR-008**: WireGuard configuration data models MUST support Amnezia WireGuard noise headers (`Jc = 5`, `Jmin = 50`, `Jmax = 128`) placed beneath the private key in the interface section.
- **FR-009**: Default values in desktop and mobile settings schemas MUST be updated to reflect the new standard defaults (`noizeJc: 5`, `noizeJmin: 50`, `noizeJmax: 128`, `noizeIntervalMs: 0`).

### Key Entities

- **Connection State**: Represents the active lifecycle of the client tunnel (`disconnected`, `connecting`, `connected`, `error`). Governs UI controls including the Connect/Disconnect power button and status badges.
- **Noise Profile**: Defines the obfuscation parameters applied to outbound datagrams, including packet count (`Jc`), minimum packet size (`Jmin`), maximum packet size (`Jmax`), inter-packet delay (`interval_ms`), and reset cadence.
- **Endpoint Discovery Result**: Represents the outcome of an edge discovery probe across candidate addresses, returning either a set of reachable gateways with latency metrics or a terminal failure indicating zero reachable endpoints.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: 100% of failed endpoint discovery or connection attempts automatically return the Start/Connect button to the idle "CONNECT" state within 1 second of failure without requiring user interaction.
- **SC-002**: 0% of failed connection attempts leave orphaned background processes or occupied local proxy ports (1819/1820).
- **SC-003**: All four tunnel protocols (WireGuard, WARP-in-WARP, MASQUE H2, MASQUE H3) transmit exactly 5 pre-handshake junk packets sized between 50 and 128 bytes with 0 ms delay when noise is active.
- **SC-004**: Users can initiate a new connection attempt immediately after a failed scan with a single click, eliminating the need to click "Disconnect" first to clear a hung state.
- **SC-005**: Obfuscation settings and generated configuration headers display and persist `Jc=5`, `Jmin=50`, `Jmax=128` across application sessions.

## Assumptions

- Restrictive networks (such as GFW or severe national firewalls) drop standard WireGuard and QUIC Initial packets, but allow through traffic preceded by 5 small random noise datagrams in the 50–128 byte range as observed in working Amnezia and v2rayN configurations.
- When an endpoint scan in MASQUE H3 finds 0 valid endpoints, falling back to an unresponsive hardcoded address is undesirable if it causes the session to hang indefinitely; instead, failure must promptly surface to the user and release the UI state.
- Custom obfuscation settings will still allow users to customize Jc, Jmin, and Jmax if needed, but the default/recommended values will be aligned to Jc=5, Jmin=50, Jmax=128, and 0 ms delay.
