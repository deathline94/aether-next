
> **Superseded by `specs/015-full-audit-remediation`.** Every "fixed" statement
> below describes the tree as it was when this document was written. 015
> re-audited these claims against source and found that several of the guards
> they record were unreachable, inverted, or never wired into CI. Read the code
> before quoting this file as evidence that something is done.

﻿# Feature Specification: Backend & Technical Bug Fixes (MASQUE H3 Pool, SPKI Pins, Android VPN Traffic, IP/Port Sync, Activity Header Spacing)

**Feature Branch**: `007-fix-backend-vpn-masque-bugs`

**Created**: 2026-09-18

**Status**: Draft

**Input**: User description: "1.first the masque h3 protocol . i think it only accept 2 or 3 ips with multiple ports while our ip pool is over 12000 ips right ?? thats weird ! needs to be addressed . find out why and also how the main repo handles this situation https://github.com/CluvexStudio/Aether 2.this error is getting repeated [2026-09-17T20:32:34.493Z WARN aether::tls] [tls] SPKI pin mismatch: [19, ce, e4, 42, 63, 3f, 9b, 40] — refusing connection. If Cloudflare rotated their edge certificate, update consts::MASQUE_PINS. Debug-only escape hatch: set AETHER_MASQUE_DISABLE_SPKI_PINS=1 find out why and also how the main repo handles this situation https://github.com/CluvexStudio/Aether 3.also one more ui bug left from last pass . i attach the screenshot . activity tab top banner is getting too crowded and malformed . needs proper spacing 4.please synce my ip port pool with the main repo . exactly like what they have https://github.com/CluvexStudio/Aether use whatever they use in my project 5.in android app only when connects , android vpn service also connects but no traffic gets thro the vpn . all the traffic still exist outside the tunnel . needs fixing"

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Android VpnService Full-Device Traffic Capture (Priority: P1)

As an Android user, when I connect to an Aether tunnel (via MASQUE or WireGuard) with TUN routing enabled, all device network traffic (browser, social apps, DNS lookups) must be captured and routed through the tunnel so that my real public IP is protected and no data leaks unencrypted outside the tunnel.

**Why this priority**: A VPN that connects successfully but allows all traffic to bypass the tunnel outside of it fails its primary purpose of privacy, security, and censorship circumvention.

**Independent Test**: Can be tested independently on an Android device: connect to tunnel, open a browser, navigate to a public IP checker (e.g. `icanhazip.com` or `cloudflare.com/cdn-cgi/trace`), and verify that the egress IP matches the Cloudflare WARP Anycast IP rather than the cellular/Wi-Fi ISP IP.

**Acceptance Scenarios**:
1. **Given** Aether Android is running and connected with TUN routing mode, **When** external applications (e.g. Chrome) make HTTP/HTTPS connections or DNS queries, **Then** all traffic is routed into the TUN interface and forwarded through the local proxy to the Cloudflare gateway.
2. **Given** the Android `VpnService` is established, **When** applications issue DNS queries, **Then** queries are resolved via the mapped fake DNS address within a valid, routeable unicast address space (`198.18.0.0/15`) and mapped to SOCKS5, rather than dropping or falling back to local ISP resolvers.
3. **Given** Android `VpnService` is initialized, **When** system routing tables are populated, **Then** underlying networks are explicitly set (`setUnderlyingNetworks(null)`) and route coverage prevents bypass leaks.

---

### User Story 2 - Upstream IP & Port Pool Synchronization & MASQUE H3 Candidate Optimization (Priority: P1)

As an Aether user on Desktop or Android, when I run a standalone scan or connect via MASQUE H3, the prober must test real, active Cloudflare Anycast CIDRs and ports synchronized exactly with upstream `CluvexStudio/Aether`, eliminating invalid non-Cloudflare address ranges (such as `8.x.x.x` Level3/Google subnets) and prioritizing high-probability seed IPs across all known gateway ports.

**Why this priority**: Testing over 12,000 invalid or non-WARP IPs wastes system resources, triggers probe timeouts, and creates confusion when only 2 or 3 actual WARP anycast gateways answer MASQUE HTTP/3 extended CONNECT handshakes.

**Independent Test**: Can be tested by initiating a scan or MASQUE H3 connection and inspecting the candidate list: candidate pools must mirror upstream `MASQUE_CIDRS_V4`, `MASQUE_SEEDS`, `MASQUE_PORTS`, `WG_PREFIXES_V4`, and `WG_PORTS`, generating focused, high-yield gateway candidates.

**Acceptance Scenarios**:
1. **Given** the prober generates candidates for MASQUE, **When** candidate IP pools are compiled, **Then** they strictly use the upstream Cloudflare CIDRs (`162.159.192.0/24` through `162.159.198.0/24`, `172.65.251.0/24`, `188.114.96-99.0/24`, `162.159.36/46.0/24`) and known seeds (`162.159.198.2`, `162.159.198.1`, `162.159.197.3`, etc.), omitting foreign `8.x.x.x` subnets.
2. **Given** the prober generates candidates for WireGuard, **When** candidate IP pools and ports are compiled, **Then** they strictly use upstream `WG_PREFIXES_V4`, `WG_PREFIXES_V6`, `WG_SEEDS_V4`, `WG_SEEDS_V6`, and the full 54-port upstream `WG_PORTS` list.
3. **Given** MASQUE H3 candidate assembly, **When** building probe queues, **Then** the prober probes the high-priority seed VIPs across all tiered ports first before sweeping CIDRs, guaranteeing immediate hit discovery.

---

### User Story 3 - TLS Certificate Pinning & Diagnostic Demotion (Priority: P2)

As a user inspecting the Activity log, when the scanner probes edge IP addresses during network discovery, non-matching TLS edge certificates presented by general Cloudflare web/CDN servers must fail silently at debug level (mirroring upstream behavior) rather than flooding the user-facing log with repetitive `WARN [tls] SPKI pin mismatch` warnings.

**Why this priority**: Cloudflare anycast IPs serve diverse edge certificates per SNI. When testing general CIDR addresses, non-WARP edges return default CDN certificates. Surface-level warnings scare users into thinking the application is broken or certificates have expired.

**Independent Test**: Run a standalone scan on Desktop or Android and monitor the live Activity tab: verify that no repetitive `SPKI pin mismatch` warnings appear under the default "Milestones" filter.

**Acceptance Scenarios**:
1. **Given** a TLS probe encounters an edge presenting a certificate that does not match `MASQUE_PINS`, **When** the custom verify callback evaluates the certificate, **Then** the probe is rejected and logged at `debug` level (not `warn`), matching upstream `CluvexStudio/Aether`.
2. **Given** a valid Cloudflare MASQUE endpoint presenting an authorized certificate (e.g. self-signed root or Google Trust Services), **When** verifying the SPKI SHA-256 hash, **Then** the connection succeeds without error.
3. **Given** an operator sets `AETHER_MASQUE_DISABLE_SPKI_PINS=1`, **When** connecting in debug or test environments, **Then** pin verification is bypassed gracefully.

---

### User Story 4 - Activity Tab Top Scan Banner Layout & Spacing (Priority: P3)

As a Desktop or Android user viewing the Activity Tab during an active scan, the progress banner at the top of the terminal chassis must display title, status pill, worker badge counters, progress bar, and percentage with clean spacing, flexible alignment, and no overlapping or colliding text strings.

**Why this priority**: In the current UI, missing layout CSS classes cause `(BALANCED)Probing Pool`, `16 workers0 working`, and `candidates1%` to concatenate into unreadable, malformed strings.

**Independent Test**: Trigger a scan, switch to the Activity tab, and visually confirm that the scan card header, badge pills, progress bar, and footer numbers are separated by clear margins and flex gaps.

**Acceptance Scenarios**:
1. **Given** an engine scan is active, **When** the Activity Tab renders the scan banner, **Then** `.scan-card-header` displays the mode and phase pill with clear gap separation (`gap: 10px`).
2. **Given** worker count and working gateway statistics are displayed, **When** rendered in `.scan-badges`, **Then** each metric is styled as a distinct tactile badge with padding and horizontal spacing.
3. **Given** probe count and progress percentage are rendered in `.scan-card-footer`, **When** displayed beneath the progress bar, **Then** the probe count is left-aligned and the percentage is right-aligned (`justify-content: space-between`).

---

### Edge Cases

- **Private DNS / DNS-over-TLS (DoT)**: On Android 9+, if Private DNS is set to "Automatic" or an explicit DoT hostname (e.g., `dns.google`), Android probes port 853 over TLS. If the VPN route captures all traffic, DoT queries to external resolvers could fail unless routed properly or mapped DNS handles queries without timeout loops.
- **IPv6 Tunnel Blackholing**: Since full IPv6 tunneling is not supported on Android, `AetherVpnService` routes IPv6 to a blackhole address (`fd00:ae::1/128`, `::/0`) so that IPv6 traffic does not bypass the VPN over physical mobile data.
- **Direct Peer Pinning**: If a user selects "Connect Direct" on an endpoint discovered in the Scanner tab, that specific IP and port must be passed directly to the engine without re-running the full discovery sweep.

---

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: Android `AetherVpnService` MUST configure TUN address within a routeable unicast CIDR (`198.18.0.1/16` or `/24`) so mapped DNS at `198.18.0.2` is within the interface subnet.
- **FR-002**: Android `AetherVpnService` MUST configure `hev-socks5-tunnel` `mapdns` network to `198.18.0.0` with netmask `255.255.0.0` (RFC 2544 benchmark space), replacing unsupported Class E `240.0.0.0/4`.
- **FR-003**: Android `AetherVpnService` MUST add routes covering `0.0.0.0/0` and `198.18.0.0/15`, and call `setUnderlyingNetworks(null)` to ensure the system default network transitions fully to the VPN.
- **FR-004**: System MUST synchronize MASQUE IPv4 CIDRs in `consts.rs` and `prober.rs` exactly with upstream: `162.159.196.0/24`, `162.159.195.0/24`, `162.159.192.0/24`, `162.159.193.0/24`, `162.159.204.0/24`, `162.159.197.0/24`, `162.159.198.0/24`, `172.65.251.0/24`, `188.114.96-99.0/24`, `162.159.36.0/24`, `162.159.46.0/24`.
- **FR-005**: System MUST synchronize MASQUE IPv4 seeds with upstream: `162.159.196.1`, `162.159.195.1`, `162.159.192.1`, `162.159.197.3`, `162.159.197.1`, `162.159.198.2`, `162.159.198.1`, `162.159.193.1`.
- **FR-006**: System MUST synchronize MASQUE ports with upstream: `443, 500, 1701, 4500, 4443, 8443, 8095`.
- **FR-007**: System MUST synchronize WireGuard IPv4 prefixes with upstream: `162.159.192.0/24`, `162.159.195.0/24`, `188.114.96.0/24`, `188.114.97.0/24`, `188.114.98.0/24`, `188.114.99.0/24`, `162.159.193.0/24`.
- **FR-008**: System MUST synchronize WireGuard ports with upstream 54-port list (`WG_PORTS`).
- **FR-009**: System MUST remove all non-Cloudflare `8.x.x.x` CIDRs and seeds from `prober.rs` and `wireguard.rs`.
- **FR-010**: MASQUE H3 candidate builder MUST probe known seed VIPs across all candidate ports first, and only sweep CIDR blocks on primary ports or structured sample intervals, eliminating redundant dead candidate explosion.
- **FR-011**: In `tls.rs`, SPKI pin mismatch log level MUST be changed from `warn` to `debug` during probe handshakes, matching upstream `CluvexStudio/Aether` behavior.
- **FR-012**: `MASQUE_PINS` in `consts.rs` MUST include Cloudflare's valid SPKI hashes and handle certificate pinning consistently across H2 and H3 transports.
- **FR-013**: Desktop and Android `App.css` MUST define CSS rules for `.scan-card-header`, `.scan-title`, `.scan-badges`, `.scan-card-footer`, `.phase-pill`, and `.badge` with flex layout and spacing.
- **FR-014**: Both `apps/desktop` and `apps/android` MUST compile without errors (`npm run build`).
- **FR-015**: Android web assets MUST be synchronized to `android/app/src/main/assets/www` (`npm run sync-www`).

---

### Key Entities

- **ProbeCandidate**: A tuple of `(IpAddr, u16)` evaluated during network scans.
- **MasquePin**: A 32-byte SHA-256 digest of the SubjectPublicKeyInfo from authorized Cloudflare edge certificates.
- **HevTunnelConfig**: YAML configuration feeding the native `libhev-socks5-tunnel.so` tun2socks engine on Android.

---

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: On Android, 100% of external web requests and DNS queries originate through the VPN tunnel when connected, confirmed by public IP verification tools showing the Cloudflare WARP egress IP.
- **SC-002**: Scanner candidate generation matches upstream definitions and eliminates all 8.x.x.x foreign prefixes, reducing futile probe attempts by over 70%.
- **SC-003**: The Activity tab log contains 0 false-positive `SPKI pin mismatch` warning entries during standard scans under the default "Milestones" log filter.
- **SC-004**: The Activity tab scan banner renders all title, status, badge, and progress text with zero character collisions or overlapping text.
- **SC-005**: Both Desktop and Android applications compile cleanly with 0 TypeScript and 0 Rust compilation errors.

---

## Assumptions

- Cloudflare WARP Anycast infrastructure terminates extended CONNECT HTTP/3 on its designated seed VIPs and specific edge POPs; standard website CDN IPs do not offer MASQUE termination.
- Android devices running Android 8.0 through Android 15 support standard `VpnService` with `addDisallowedApplication(packageName)`.
- The upstream repository `https://github.com/CluvexStudio/Aether` is the authoritative source for Cloudflare edge CIDRs, seeds, and port configurations.
