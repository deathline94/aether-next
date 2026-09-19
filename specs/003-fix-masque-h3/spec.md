# Feature Specification: Fix MASQUE H3 Connectivity and Upstream Alignment

**Feature Branch**: `003-fix-masque-h3`

**Created**: 2026-09-16

**Status**: Draft

**Input**: User description: "this is the main core that i based my project on https://github.com/CluvexStudio/Aether https://github.com/CluvexStudio/Aether/releases/tag/v2.0.0 and in my project , masque h3 still dont work . check this project and its code of the latest changes and latest versions , to see how they handle their masque h3 protocol"

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Reliable MASQUE H3 Connection Establishment (Priority: P1)

As a user on a restricted network, I want to connect to a MASQUE HTTP/3 proxy tunnel so that my internet traffic is securely tunneled without being blocked or dropped by stateful censorship firewalls and deep packet inspection (DPI) middleboxes.

**Why this priority**: MASQUE H3 is currently completely non-functional on censored networks due to protocol header mismatches and DPI middleboxes dropping initial handshake packets. Making it successfully connect is the core value of this feature.

**Independent Test**: Configure a MASQUE H3 profile, initiate a connection, and verify that the tunnel connects and successfully carries bidirectional traffic to the internet.

**Acceptance Scenarios**:

1. **Given** a valid MASQUE H3 configuration and an active network connection behind a restrictive firewall, **When** the user clicks "Start", **Then** the application negotiates bidirectional reachability with the server edge, completes the secure handshake, and transitions to the connected state.
2. **Given** a network where initial protocol handshake packets are scrutinized or dropped by DPI, **When** the connection begins, **Then** the application sends standard protocol negotiation bait to trigger middlebox state-tracking and verify edge UDP reachability before completing the primary tunnel handshake.
3. **Given** an active MASQUE H3 tunnel, **When** the user accesses web resources, **Then** IP datagrams flow bidirectionally with consistent throughput and low packet loss.

---

### User Story 2 - Accurate Proxy Health & Stream Verification (Priority: P2)

As a user connecting via MASQUE H3, I want the system to actively verify that the proxy stream and underlying datagram transport are healthy and operational before marking the connection as ready, so that I never get stuck with a "connected" status that cannot transmit data.

**Why this priority**: Users experience silent failures and hanging connections when a proxy stream accepts the initial connection but fails HTTP CONNECT authorization or drops datagram capsules. Active verification guarantees real data flow.

**Independent Test**: Connect to both valid and rejected/unreachable endpoints, verifying that healthy endpoints are promptly approved while rejected endpoints immediately report clear failure status.

**Acceptance Scenarios**:

1. **Given** an established transport connection to a proxy edge, **When** the proxy responds with an error code (such as HTTP 400 or HTTP 403) on the tunnel stream, **Then** the system immediately aborts the connection attempt, marks the session failed, and reverts UI connection controls.
2. **Given** a successful stream establishment, **When** verifying the data plane, **Then** the system requires confirmed bidirectional data exchange (e.g. verified test responses over encapsulated datagrams) before reporting the connection as fully established.

---

### User Story 3 - Robust Protocol Configuration & Anti-Censorship Toggles (Priority: P3)

As an advanced user or mobile user, I want the application to offer clean configuration defaults and environment controls for anti-censorship features (such as QUIC v2 version baiting) so that I can adapt the connection behavior to specific regional network characteristics.

**Why this priority**: Network conditions and middlebox behavior vary across regions and internet service providers; having standardized defaults matching upstream behavior ensures optimal out-of-the-box performance while retaining control.

**Independent Test**: Toggle the anti-censorship negotiation bait setting via configuration or environment variable, and verify that the client respects the toggle during connection initiation.

**Acceptance Scenarios**:

1. **Given** default application settings, **When** MASQUE H3 connects, **Then** anti-censorship version negotiation bait is enabled automatically.
2. **Given** a user or environment specifying that negotiation bait should be disabled, **When** MASQUE H3 connects, **Then** the connection proceeds directly to the standard handshake without pre-handshake baiting packets.

---

### Edge Cases

- What happens when a network completely blocks UDP on the configured port?
  The client times out cleanly according to configured probe/connection deadlines and reverts UI controls without hanging.
- What happens when an edge proxy resets the CONNECT-IP stream immediately after handshake?
  The system detects the reset event on the request stream and terminates the session with an explicit error rather than staying hung waiting for traffic.
- What happens when the server does not support datagram capsules?
  The connection fails fast during capability negotiation and logs the reason clearly.
- What happens when noise/junk packet parameters are also configured?
  The connection correctly layers noise/junk packets without disrupting or corrupting the MASQUE H3 protocol negotiation bait or transport handshake.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: System MUST send standard 1200-byte protocol version negotiation bait prior to initiating MASQUE H3 connections to prime middleboxes and confirm UDP reachability.
- **FR-002**: System MUST allow anti-censorship version negotiation bait to be controlled via configuration and environment settings, with enabled as the default.
- **FR-003**: System MUST format MASQUE HTTP/3 CONNECT-IP request headers adhering strictly to standard specification recipes (`:method`, `:protocol` as `cf-connect-ip`, `:scheme`, `:authority`, `:path`, empty `user-agent`, and `capsule-protocol: ?1`).
- **FR-004**: System MUST NOT send extraneous custom headers that trigger HTTP 400 rejection on standard edge nodes.
- **FR-005**: System MUST configure transport parameters adhering to standard ALPN (`h3`), appropriate flow control limits, and disabled active migration to match upstream edge expectations.
- **FR-006**: System MUST verify bidirectional data plane capability using end-to-end data probes through encapsulated datagrams before declaring MASQUE H3 connections verified.
- **FR-007**: System MUST detect HTTP non-2xx status codes, stream resets, and premature stream finishes on the CONNECT-IP control stream and fail fast with clear diagnostics.
- **FR-008**: System MUST revert UI controls and trigger proper disconnection state when a MASQUE H3 handshake or stream fails.

### Key Entities

- **MASQUE Session**: Represents an active HTTP/3 tunnel session, encapsulating the underlying transport state, the CONNECT-IP control stream, datagram flow states, and negotiated parameters.
- **Version Bait Packet**: A targeted pre-handshake UDP packet designed to elicit a version negotiation response from the edge server, validating path reachability and opening stateful middlebox NAT bindings.
- **Data Probe**: A lightweight end-to-end verification request routed through encapsulated datagrams to confirm functional bidirectional packet routing prior to handing the tunnel over to the system network interface.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: MASQUE H3 connections successfully achieve bidirectional data throughput on networks where standard direct handshakes are dropped by DPI middleboxes.
- **SC-002**: 100% of failed connection attempts (due to bad credentials, unreachable endpoints, or edge stream resets) fail fast within the configured timeout window without causing UI state lockups.
- **SC-003**: Data plane reachability is verified with 2 consecutive successful encapsulated data exchanges before user traffic routing begins.
- **SC-004**: Compatibility with existing noise/obfuscation configurations (Amnezia Jc/Jmin/Jmax and noise arrays) is preserved with zero regression.

## Assumptions

- The remote server or edge supports HTTP/3 MASQUE CONNECT-IP (such as Cloudflare Zero Trust WARP / MASQUE endpoints).
- The network allows UDP packets, or allows UDP once bidirectional state has been negotiated via version baiting.
- Upstream CluvexStudio Aether v2.0.0 protocol implementation serves as the canonical reference implementation for wire behavior and header formatting.
