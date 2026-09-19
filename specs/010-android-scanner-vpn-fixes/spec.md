# Feature Specification: Android Scanner Gateway Display & VPN Tunnel Leak Fixes

**Feature Branch**: `010-android-scanner-vpn-fixes`

**Created**: 2026-09-18

**Status**: Ready for Planning

**Input**: User description: "two problems only in android: first a ui bug that you can see in the screenshot . in scanner tab under scanned and found ips for each protocol . as you can see it all messed up and out of order . needs fixing; second in android . it connects . vpn service gets connected but the data run pass the tunnel outside of it still as it was before . its not fixed yet"

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Readable and Actionable Discovered Gateways on Mobile (Priority: P1)

When a mobile user runs the scanner to discover available gateway endpoints, the discovered gateway list must display each result in a clean, legible, and organized layout. The endpoint address, protocol badge, latency indicator, and action buttons (copying the address and connecting directly) must render with clear visual hierarchy, without text wrapping character-by-character into vertical columns or elements colliding and overlapping.

**Why this priority**: Discovered endpoints are the primary operational output of the scanner. If the user cannot read the IP/port or tap the action buttons due to distorted overlapping elements, the mobile scanning feature is unusable.

**Independent Test**: Perform a gateway scan on a mobile device or portrait viewport (~360px–420px width). Verify that each discovered gateway card presents the endpoint address on one unbroken line, protocol badge, latency metrics, and interactive action buttons cleanly arranged and fully accessible.

**Acceptance Scenarios**:

1. **Given** the mobile user is on the Scanner tab and completes an endpoint scan, **When** discovered endpoints are displayed in the results list, **Then** each endpoint item displays its full host and port cleanly without vertical character-by-character splitting or line break distortion.
2. **Given** a displayed gateway result on a narrow mobile screen, **When** viewing the card layout, **Then** the protocol label, round-trip latency badge, copy action, and direct connection action are clearly separated and easily tappable without visual collision or overlap.
3. **Given** a discovered gateway card, **When** the user taps the copy button or the direct connect button, **Then** the corresponding action executes cleanly without triggering accidental touches on neighboring elements.

---

### User Story 2 - Complete Mobile Device Traffic Encapsulation Through VPN (Priority: P1)

When a mobile user establishes a VPN connection, all internet data and DNS queries from all applications on the device must be directed through the encrypted proxy tunnel. Network traffic must not leak or bypass the active tunnel over the physical network interface (cellular data or Wi-Fi).

**Why this priority**: A VPN that leaks data or permits traffic to bypass the tunnel fails its fundamental privacy, anti-censorship, and security guarantees. Users rely on the tunnel to access restricted services and protect their traffic.

**Independent Test**: Connect the mobile application to a verified endpoint on both cellular data and Wi-Fi. Verify using independent external IP/DNS checker services that all outbound HTTP/HTTPS traffic, streaming requests, and domain name resolutions originate from the proxy egress IP and zero traffic routes over the physical carrier network.

**Acceptance Scenarios**:

1. **Given** the user connects to a gateway endpoint via the mobile VPN service, **When** applications on the device generate network traffic (browsing, streaming, messaging), **Then** all outbound traffic routes strictly through the VPN tunnel, reflecting the gateway's egress IP.
2. **Given** an active VPN connection on mobile data (cellular LTE/5G) or Wi-Fi, **When** domain names are resolved by the system or applications, **Then** DNS requests are securely resolved through the tunnel without leaking to local carrier or local Wi-Fi resolvers.
3. **Given** a device with dual-stack (IPv4 and IPv6) cellular connectivity, **When** the VPN connection is active, **Then** IPv6 and IPv4 traffic are both handled securely by the tunnel so that traffic cannot slip past the tunnel via unhandled network routes.
4. **Given** the VPN connection is established, **When** network quality fluctuates or the device transitions between networks, **Then** device applications maintain continuous tunnel routing without silently dropping back to unencrypted physical network paths.

---

### Edge Cases

- **Narrow / Small Mobile Screens**: Screens with viewport widths below 360px (or high display scaling settings) must maintain readable endpoint text and wrapped button rows without truncation or horizontal clipping.
- **Very Long Hostnames / IPv6 Endpoints**: When discovered endpoints contain longer domain names or bracketed IPv6 addresses with port numbers, the text must maintain readable font sizing and truncate gracefully or wrap predictably rather than breaking word stems arbitrarily.
- **Android Private DNS (DoT) Enabled**: When the mobile system has "Private DNS" set to Automatic or Strict mode, DNS queries must still be handled reliably through the tunnel rather than stalling or forcing the operating system to route app traffic outside the VPN.
- **Cellular Dual-Stack (IPv4/IPv6 / 464XLAT)**: On mobile networks that assign IPv6 alongside IPv4 (or IPv6-only with 464XLAT), the VPN routing must prevent any IPv6 traffic from bypassing the tunnel or stalling connectivity.
- **Reconnection and Roaming**: Transitioning from cellular data to Wi-Fi (or vice versa) while the VPN is active must not expose unencrypted packets outside the tunnel.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The mobile interface MUST render discovered gateway items in a responsive card structure optimized for narrow viewports (320px–480px width).
- **FR-002**: The endpoint address (host and port) in each discovered gateway card MUST NOT break into vertical single-character columns.
- **FR-003**: The mobile interface MUST provide dedicated, accessible touch targets for copying the gateway address and initiating a direct connection without spatial collision.
- **FR-004**: The mobile VPN service MUST intercept and route all device IPv4 network traffic into the tunnel.
- **FR-005**: The mobile VPN service MUST handle IPv6 routing so that IPv6-capable carrier networks do not leak traffic outside the tunnel.
- **FR-006**: The mobile VPN service MUST route all domain name system (DNS) lookups through the tunnel, preventing DNS leakage to underlying physical network adapters.
- **FR-007**: The mobile VPN service MUST remain compatible with system Private DNS settings so network validation completes and the operating system recognizes the tunnel as the primary internet pathway.
- **FR-008**: The mobile interface MUST display real-time connection status accurately reflecting whether tunnel routing is actively protecting device traffic.

### Key Entities

- **Discovered Gateway**: An endpoint detected by the scanning engine, characterized by host address, port, protocol type (MASQUE H3, Shadowsocks, VLESS, etc.), measured round-trip time (latency), and operational actions (Copy, Connect Direct).
- **VPN Tunnel Session**: The active operating-system-level network interface and routing state that encapsulates outbound device traffic and forwards it through the local proxy client to the remote gateway.
- **DNS Resolution Path**: The configured route and resolver used by the operating system and applications to resolve domain names while the tunnel session is active.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Discovered gateway cards render cleanly on mobile viewports down to 320px width, with 0 instances of character-by-character vertical text splitting or overlapping buttons.
- **SC-002**: 100% of outbound device application traffic (HTTP/HTTPS/TCP/UDP) routes through the VPN tunnel when connected, confirmed by external IP verification showing the proxy egress IP.
- **SC-003**: 0 DNS queries leak to local carrier or local Wi-Fi DNS servers while the VPN is connected, as verified by standard DNS leak test tools.
- **SC-004**: Users can tap copy and connect buttons on discovered gateway cards on touchscreens on the first attempt without mis-clicking adjacent buttons.
- **SC-005**: Device internet access remains functional and fully tunneled across both Wi-Fi and cellular connections (including dual-stack IPv4/IPv6 networks).

## Assumptions

- The target platform for this feature is the Android mobile client (`apps/android`).
- The underlying proxy core protocols (MASQUE H3, Shadowsocks, VLESS) and desktop application layouts are operating as intended; adjustments are scoped to mobile UI presentation and Android VPN service routing configuration.
- Standard Android devices running Android 8.0 through Android 15 are supported.
- Standard user flow involves scanning for endpoints, viewing the discovered list, and initiating a VPN connection either directly from the scanner or from the home tab.
