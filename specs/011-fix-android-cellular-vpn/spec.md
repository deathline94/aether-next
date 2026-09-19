# Feature Specification: Full Tunnel Protection on Android Cellular Networks

**Feature Branch**: `011-fix-android-cellular-vpn`

**Created**: 2026-09-19

**Status**: Ready for Planning

**Input**: User description: "ok i still had issues where the vpn would connect but the data would skip the tunnel and connect from outside on my android phone until i noticed that i only have this problem on mobile data . its absolutely fine on wifi so there ! heres another clue . please fix"

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Full-Device Tunnel Protection on Cellular Data (Priority: P1)

As a mobile user browsing the internet using mobile data (cellular LTE/5G), when I connect to the VPN, all device internet traffic must route exclusively through the secure tunnel so that my carrier cannot inspect or throttle my activity and external websites see my secure VPN address rather than my mobile carrier IP.

**Why this priority**: This is the core purpose of the VPN. If data bypasses the tunnel when connected to cellular data, the user has zero privacy and security despite the application showing an active VPN connection.

**Independent Test**: Connect an Android device to cellular data (turn off Wi-Fi). Launch the VPN and verify the connection is active. Open a browser and visit an IP verification service. The reported IP address must match the secure VPN gateway, and no device traffic may bypass the tunnel.

**Acceptance Scenarios**:

1. **Given** an Android device with Wi-Fi disabled and mobile data enabled, **When** the user activates the VPN connection, **Then** all browser and application traffic routes through the secure tunnel and public IP detection shows the VPN gateway address.
2. **Given** an active VPN connection on mobile data, **When** applications make network requests, **Then** zero network requests escape the tunnel or connect directly to the mobile carrier network.

---

### User Story 2 - Dual-Stack Network Leak Prevention (Priority: P1)

As a user on a mobile carrier network that provides both modern IPv6 and legacy IPv4 addresses, when the VPN is active, applications must not bypass the tunnel via alternative network routes, ensuring complete leak-free protection regardless of carrier network configurations.

**Why this priority**: Modern mobile carriers assign native IPv6 addresses by default. When applications attempt dual-stack connections, incomplete tunnel routing causes traffic to silently bypass the tunnel over the carrier's direct connection while the VPN interface remains visibly connected.

**Independent Test**: Run standard leak detection tests (such as IP and DNS leak checks) on a cellular network that supports both IPv4 and IPv6. Verify that neither the carrier's IPv4 nor IPv6 address is exposed and that DNS lookups do not leak to carrier servers.

**Acceptance Scenarios**:

1. **Given** a mobile carrier network assigning both IPv4 and IPv6 connectivity, **When** an application initiates a dual-stack connection, **Then** all traffic remains inside the secure tunnel without falling back to unencrypted carrier routes.
2. **Given** an active VPN connection on cellular data, **When** an application attempts a domain resolution request, **Then** the request is resolved strictly through the secure tunnel DNS and carrier DNS servers are never queried directly.

---

### User Story 3 - Seamless Network Interface Transition (Priority: P2)

As a mobile user moving between Wi-Fi and cellular networks, when my network connectivity switches while the VPN is active, the secure tunnel must maintain continuous protection without briefly exposing traffic to the carrier network during handover.

**Why this priority**: Users frequently move between Wi-Fi and mobile networks. Network switches must not cause traffic to spill onto the carrier connection outside the tunnel.

**Independent Test**: Connect to Wi-Fi with the VPN active, verify secure tunnel traffic, then toggle Wi-Fi off so the device switches to mobile data. Verify that traffic continues to route through the secure tunnel without any unencrypted leak.

**Acceptance Scenarios**:

1. **Given** an active VPN session established on Wi-Fi, **When** the user disconnects from Wi-Fi and the device switches to cellular mobile data, **Then** the VPN maintains full encapsulation and does not expose data outside the tunnel.
2. **Given** an active VPN session established on cellular data, **When** the user connects to a Wi-Fi network, **Then** traffic smoothly migrates to the Wi-Fi route while maintaining unbroken VPN protection.

---

### Edge Cases

- What happens when a mobile carrier operates on an IPv6-only network with carrier-side translation? The system must ensure that all application connections are encapsulated through the secure tunnel without failing or falling back to the raw interface.
- What happens when the cellular signal drops momentarily and reconnects? The VPN interface must rebind cleanly and prevent any opportunistic network requests from escaping during network re-establishment.
- What happens when multiple applications generate high-throughput traffic simultaneously on mobile data? The tunnel must handle concurrent application demands without dropping routing integrity.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The system MUST route 100% of outbound user-space and background application network traffic through the established VPN tunnel when connected over any cellular mobile data network.
- **FR-002**: The system MUST prevent any device application or system component from establishing direct internet connections outside the VPN tunnel while the VPN state is active on cellular networks.
- **FR-003**: The system MUST ensure that external network verification services detect exclusively the VPN tunnel address and never expose the carrier-assigned cellular IP address.
- **FR-004**: The system MUST prevent traffic leaks on dual-stack carrier networks, ensuring that protocol queries not supported end-to-end by the tunnel are safely contained and never fall back to the unencrypted cellular interface.
- **FR-005**: The system MUST route all domain name system (DNS) resolution queries strictly through the secure tunnel when connected via cellular networks, preventing carrier DNS snooping.
- **FR-006**: The system MUST provide identical, consistent protection across both Wi-Fi and cellular network connections without requiring manual configuration changes from the user.
- **FR-007**: The system MUST maintain full tunnel encapsulation during network handovers between Wi-Fi and cellular connections.

### Key Entities

- **VPN Tunnel Session**: The active encrypted communication session established between the mobile device and the secure remote gateway.
- **Network Interface Route**: The operating system routing configuration dictating how outbound application traffic is directed to physical or virtual network interfaces.
- **Carrier Connection**: The cellular data link provided by the mobile network operator (LTE/5G), which must be strictly used as the transport underlay for the encrypted tunnel and never for direct application traffic.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: 100% of tested web browsers and applications reflect the VPN gateway IP address instead of the carrier IP address when the device operates solely on mobile data.
- **SC-002**: Zero packets leak directly to the cellular carrier interface while the VPN state is active, verified by public leak detection tests (including IP and DNS leak checks).
- **SC-003**: Feature provides equivalent, unbroken privacy on both Wi-Fi and cellular connections without user intervention.
- **SC-004**: Network transition between Wi-Fi and cellular completes within 3 seconds while maintaining complete tunnel encapsulation.

## Assumptions

- The Android operating system provides standard VPN interface creation and permission management.
- The user has an active cellular mobile data subscription with working internet connectivity.
- The remote VPN gateway is reachable over cellular networks and has functional internet egress routing.
- Device applications adhere to standard operating system network routing.
