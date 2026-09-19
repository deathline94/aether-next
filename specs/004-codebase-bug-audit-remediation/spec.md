# Feature Specification: Comprehensive Codebase Bug Audit & Precision Remediation

**Feature Branch**: `004-codebase-bug-audit-remediation`

**Created**: 2026-09-16

**Status**: Reconciled & Hardened (Superseded by `specs/013-security-reliability-remediation/spec.md`)

> [!NOTE]
> All findings from this audit are fully remediated and hardened under `specs/013-security-reliability-remediation/spec.md`, establishing strict single-instance supervisors, Authenticode/SHA256 elevation trust, DPAPI/AndroidKeyStore encryption, atomic file replacements, and unified scanner timeout boundaries.

**Input**: User description: "this project is massive and has a huge code base . so its only natural that it has a lot of bugs , missed edge cases and bad implementation both in backend , function and also visual bugs in the frontend . so please very carefully find all the remaining bugs in detail with very high percision"

---

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Core Networking, Transport & Netstack Bug Remediation (Priority: P1) 🎯 MVP

A user connecting via SOCKS5, HTTP proxy, or Windows TUN mode requires reliable, lossless data transmission without silent socket stalls, packet reordering, or DNS lookup failures on IPv6/dual-stack networks.

**Why this priority**: Core networking bugs in the netstack and proxy protocol handlers compromise connection stability, corrupt TCP streams, and cause unrecoverable failures under high throughput or multi-client workloads.

**Independent Test**:
1. Run high-concurrency downloads through SOCKS5 and HTTP proxies; verify no packet inversion or reordering occurs in `flush_tx` under backpressure.
2. Configure `AETHER_DNS` with standard IPv6 literals (e.g., `2606:4700:4700::1111`) and verify DNS resolution succeeds without unparseable address errors.
3. Test concurrent UDP associate datagrams from multiple ephemeral ports and verify each socket receives its corresponding replies.
4. Test absolute URIs with query parameters in HTTP proxy and verify queries are preserved.

**Acceptance Scenarios**:
1. **Given** network congestion where `outbound_tx` queue fills, **When** `flush_tx` deferral occurs, **Then** all deferred packets maintain strict FIFO ordering without inversion upon re-queueing.
2. **Given** IPv6 DNS addresses supplied in `AETHER_DNS`, **When** `configured_dns_servers()` parses the entries, **Then** standard bare IPv6 addresses parse cleanly into `SocketAddr` with default port 53.
3. **Given** multiple local applications or threads sending UDP datagrams through a single SOCKS5 UDP association, **When** upstream responses arrive, **Then** replies are routed back to the correct originating client port rather than being misdirected to the last active sender.
4. **Given** an HTTP request with query parameters (e.g. `GET http://example.com?query=1`), **When** rewritten by the HTTP proxy, **Then** query parameters are preserved in the request path.
5. **Given** a connection initiated with `EngineConfig`, **When** `select_peer` resolves endpoint overrides, **Then** it reads from `runtime_env` rather than un-synchronized `std::env::var`.

---

### User Story 2 - Windows Routing & System Proxy Safety (Priority: P2)

A user running on Windows requires that activating TUN mode or system proxy does not tamper with or destroy coexisting network routes (such as secondary corporate or private VPNs), and restores all system settings cleanly upon disconnect or termination.

**Why this priority**: Route corruption and improper system proxy registry states break internet connectivity for the entire host and disrupt coexisting network adapters.

**Independent Test**:
1. Activate TUN mode with simulated coexisting routes on secondary adapters; verify `install_routes` only modifies routes on the Aether adapter and physical default interface without ripping routes from other interfaces.
2. Test disconnect and crash recovery; verify registry proxy settings and adapter metrics are fully restored.

**Acceptance Scenarios**:
1. **Given** active split-default routes (`0.0.0.0/1` and `128.0.0.0/1`) on third-party network interfaces, **When** `install_routes()` prepares the Aether TUN adapter, **Then** route cleanup is strictly scoped to the Aether adapter and physical gateway interface without deleting third-party VPN routes.
2. **Given** a user disconnecting from TUN mode, **When** `remove_routes()` and `reset_adapter_config()` run, **Then** adapter DNS, metric, and interface routes are cleanly restored to their pre-connection state.

---

### User Story 3 - Desktop UI, Telemetry, and State Machine Precision (Priority: P3)

A desktop user navigating between Scanner, Connection, Settings, and Activity tabs requires consistent visual controls, synchronized configuration options, resilient error handling, and quiet background auto-save without UI freezes.

**Why this priority**: Visual inconsistencies, desynchronized dropdowns, and UI state hangs degrade user trust and create confusing edge cases.

**Independent Test**:
1. Trigger a direct connection to a discovered peer that fails; verify the Connection tab displays an error banner and returns the Power button to idle instead of hanging in "Connecting".
2. Edit port numbers in Settings; verify no error alerts appear in the logs while typing intermediate invalid numbers until valid values are committed.
3. Verify that obfuscation dropdown options across SettingsTab and ScannerTab are fully synchronized with canonical profile names (`off`, `light`, `medium`, `high`, `max`, `custom`).
4. Verify that the desktop log pump correctly recognizes `"socks5 listening on"` as a readiness signal.

**Acceptance Scenarios**:
1. **Given** a direct connect attempt from the Scanner tab to an unreachable endpoint, **When** `connect` encounters a connection error, **Then** `useRuntime` sets `status: "error"` with the error detail so the user can retry or dismiss.
2. **Given** a user adjusting port numbers in Settings, **When** ports temporarily collide or fall outside the valid range (1024–65535), **Then** background debounced persistence is paused and no spurious error logs are written.
3. **Given** any active obfuscation setting, **When** navigating between Settings and Scanner tabs, **Then** the obfuscation select displays the correct canonical profile and does not render blank.
4. **Given** engine startup, **When** log lines are streamed to Tauri, **Then** both structured events and legacy log fallbacks (`socks5 listening on`) correctly trigger the ready state.

---

### User Story 4 - Android Client Security & Handshake Reliability (Priority: P4)

An Android user running Aether mobile requires that TLS connections enforce valid cryptographic verification by default and that scanner handshakes are budgeted sufficient time to succeed on mobile cellular networks.

**Why this priority**: Unconditionally disabling TLS verification exposes users to machine-in-the-middle attacks on untrusted public/mobile networks, and undersized probe timeouts cause false-negative scans.

**Independent Test**:
1. Inspect Android engine startup parameters; verify `AETHER_DANGEROUS_DISABLE_TLS_VERIFY` is not hardcoded to `"1"` in production builds.
2. Trigger an endpoint scan on Android; verify the per-probe timeout defaults to a minimum of 6000ms for expensive H3/BoringSSL probes.

**Acceptance Scenarios**:
1. **Given** standard Android app execution, **When** `EngineRunner` launches `libaether.so`, **Then** TLS verification and SPKI pinning remain active unless explicitly enabled by a debug configuration.
2. **Given** a mobile standalone scan, **When** `AetherBridge.kt` dispatches probe parameters, **Then** the probe timeout defaults to at least 6000ms to allow QUIC handshakes over cellular latency.

---

## Edge Cases

- **Port Collision During Typing**: What happens when the user types in the port inputs and the numbers temporarily match? Auto-save is suspended until both fields are valid and distinct.
- **Unbracketed IPv6 Literals in Config**: What happens when an IPv6 address without brackets is supplied to DNS configuration? The parser identifies it as an IP address, adds brackets, and pairs it with the standard port.
- **Interleaved UDP Streams from Loopback**: What happens when local processes rapidly switch ephemeral ports to the SOCKS UDP relay? The relay tracks client sessions per source port so answers are routed back to the exact socket.
- **Scanner Direct Connect Failure**: What happens when "Connect Direct" is clicked for an endpoint that has just gone offline? The UI catches the connect error and displays the error state instead of hanging in "Connecting".

---

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The netstack TX flush routine MUST preserve FIFO packet order during congestion and queue-full retries without inverting deferred packets.
- **FR-002**: The DNS configuration parser in SOCKS MUST parse both IPv4 and IPv6 addresses (with or without port specifications) without discarding unbracketed IPv6 strings.
- **FR-003**: SOCKS5 UDP Associate MUST multiplex and route incoming UDP replies back to the exact originating client address/port that sent the request.
- **FR-004**: The HTTP proxy URI rewriter MUST preserve query strings and fragments when rewriting absolute URIs without slashes before query parameters.
- **FR-005**: Windows TUN route installation MUST scope route removals to the designated Aether and physical interface indexes, preventing destruction of third-party VPN routes.
- **FR-006**: `select_peer` in `session.rs` MUST read configuration overrides from the thread-safe `runtime_env` store rather than `std::env::var`.
- **FR-007**: The desktop runtime hook (`useRuntime.ts`) MUST transition `runtime.status` to `"error"` when `connectToPeer` fails, preventing the UI from remaining stuck in `"connecting"`.
- **FR-008**: The desktop runtime hook MUST suppress background persistence when settings fail validation (e.g. port collision or out-of-range ports).
- **FR-009**: The Scanner tab obfuscation selector MUST match canonical profile tokens (`off`, `light`, `medium`, `high`, `max`, `custom`) and never display a blank option.
- **FR-010**: The desktop host (`lib.rs`) MUST recognize `"socks5 listening on"` in log parsing to ensure fallback readiness detection succeeds.
- **FR-011**: Android `EngineRunner.kt` MUST NOT hardcode `AETHER_DANGEROUS_DISABLE_TLS_VERIFY = "1"`, ensuring SPKI pinning protects mobile users.
- **FR-012**: Android `AetherBridge.kt` MUST provide a minimum probe timeout of 6000ms for expensive H3 scans.

---

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: 100% of unit tests pass across `aether` crate with zero compiler warnings.
- **SC-002**: Desktop application builds cleanly with `npm run build` (TypeScript and Vite) with zero errors.
- **SC-003**: Tauri backend compiles cleanly with `cargo check` in `apps/desktop/src-tauri` with zero warnings.
- **SC-004**: Zero UI lockups or unhandled connection errors occur when direct connecting to offline or invalid peers.
- **SC-005**: All DNS servers specified as IPv6 literals are recognized and utilized without unparseable entry warnings.
- **SC-006**: Coexisting network routes on secondary Windows adapters remain intact when Aether TUN starts and stops.

---

## Assumptions

- Users may configure custom IPv6 DNS resolvers without wrapping them in brackets (e.g. `2606:4700:4700::1111`).
- SOCKS clients on loopback may send UDP packets from multiple local ports concurrently.
- Settings auto-save should only trigger when the active settings represent a valid, persistable state.
- Android production builds should enforce TLS verification and SPKI pinning identically to desktop.
