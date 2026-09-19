# Phase 0 Research: MASQUE H3 Engine Alignment & Bug Remediation

**Feature**: Fix MASQUE H3 Connectivity and Upstream Alignment + Visual & Functional Bugs
**Status**: Completed

---

## 1. QUIC v2 Version Negotiation Bait (`AETHER_QUIC_V2`)

- **Decision**: Implement a 1200-byte pre-handshake UDP packet with header byte `0xc3` (Long Header, fixed bit 1, Initial packet for QUIC v2) and version `0x6b33_43cf` (`QUIC_V2_VERSION`) in `aether/src/quic.rs`. Wire through `send_version_bait()` before creating the `quiche::Connection`. Control via `AETHER_QUIC_V2` (enabled by default unless explicitly `"0"`, `"off"`, or `"false"`).
- **Rationale**: Restrictive DPI firewalls (e.g. in Iran, Russia, and China) detect and drop QUIC v1 (`0x00000001`) ClientHello packets unconditionally across all ports. Sending a QUIC v2 bait packet causes Cloudflare edges to respond with an RFC 9000 Version Negotiation packet (`0xc0000000`). This bidirectional exchange punches middlebox NAT state and establishes stateful flow allowance before the primary QUIC v1 tunnel handshake begins. This matches the proven mechanism implemented in CluvexStudio Aether v2.0.0.
- **Alternatives Considered**:
  - *Standard QUIC v1 directly*: Rejected; completely blocked by DPI middleboxes on censored networks.
  - *Random unpadded UDP packets*: Rejected; does not trigger RFC 9000 Version Negotiation at the Cloudflare edge, failing to prove edge reachability.
  - *Unconditional 0-RTT early data*: Rejected; causes edge handshake rejection when valid session tokens are not present.

---

## 2. Strict RFC 9220 / RFC 9484 CONNECT-IP Headers

- **Decision**: Remove legacy `H3HeaderMode` enum and proprietary headers (`cf-connect-proto`, `cf-pq-enabled`) from `aether/src/masque.rs`. Format CONNECT-IP stream headers strictly to the standard recipe:
  ```rust
  vec![
      h3::Header::new(b":method", b"CONNECT"),
      h3::Header::new(b":protocol", consts::CF_CONNECT_PROTOCOL.as_bytes()), // "cf-connect-ip"
      h3::Header::new(b":scheme", b"https"),
      h3::Header::new(b":authority", authority.as_bytes()),
      h3::Header::new(b":path", path.as_bytes()),
      h3::Header::new(b"user-agent", b""),
      h3::Header::new(b"capsule-protocol", b"?1"),
  ]
  ```
- **Rationale**: Cloudflare and standard RFC 9484 MASQUE proxies reject requests containing unexpected custom pseudo-headers or headers with HTTP 400 Bad Request. Upstream v2.0.0 eliminated custom headers for reliable compatibility.
- **Alternatives Considered**:
  - *Header fallback retry logic*: Rejected; introduces unnecessary latency and complexity when the standard recipe works universally.

---

## 3. Quiche Transport Parameter Configuration

- **Decision**: In `aether/src/tls.rs` and `aether/src/quic.rs`:
  - Restrict application ALPN strictly to `&[consts::ALPN_H3]` (`b"h3"`), removing `b"h3-29"`.
  - Remove unconditional `config.enable_early_data()`.
  - Set `config.set_disable_active_migration(true)`.
  - Use balanced flow control: `10_000_000` max data, `2_000_000` initial stream data.
  - Budget datagram limits to `1200..=1350` bytes.
- **Rationale**: Modern Cloudflare edges have discontinued draft-29 support; offering draft-29 can cause edge protocol downgrade or handshake aborts. Early data without resumption tokens causes handshake mismatches. Disabling active migration prevents middlebox connection drops during interface transitions.
- **Alternatives Considered**:
  - *Keep h3-29 for fallback*: Rejected; draft-29 is obsolete and unsupported on modern edge deployments.

---

## 4. Fail-Fast CONNECT-IP Stream Polling & Data Plane Verification

- **Decision**:
  - In `aether/src/masque.rs` `poll_h3()`, inspect response headers on `req_stream`. If `:status` is not 2xx, parse the code and immediately return `Err(AetherError::Masque(format!("CONNECT rejected by proxy: HTTP {status}")))`.
  - Listen for `h3::Event::Reset` or `h3::Event::Finished` on `req_stream` and terminate immediately.
  - In `aether/src/quic.rs` `verify_masque()`, probe the data plane using DNS queries over H3 datagrams (`masque::encode_ip_datagram`), requiring `DATA_PROBE_REQUIRED_SUCCESSES = 2` consecutive successful replies before declaring the endpoint verified.
- **Rationale**: Prevents infinite polling loops or hanging connection buttons when the edge rejects authorization or resets the CONNECT-IP stream. Verifying 2 consecutive datagram exchanges ensures the tunnel is capable of bidirectional IP forwarding before user traffic is routed.
- **Alternatives Considered**:
  - *Single probe verification*: Rejected; can produce false positives on network hiccups or packet reflections. 2 consecutive responses confirm stable end-to-end routing.

---

## 5. UI Direct Connect Navigation & Pinned Peer State

- **Decision**:
  - In `apps/desktop/src/App.tsx`, `connectDirect` calls `setView("home")` immediately.
  - In `apps/desktop/src/hooks/useRuntime.ts` and `components/ConnectionTab.tsx`:
    - Clicking the primary Connect button or choosing any speed profile preset clears any temporarily pinned `peer`.
    - When a forced peer is active, render an indicator badge in ConnectionTab: `Targeting [peer] (Clear)` allowing the user to reset to dynamic scanning with one click.
- **Rationale**: Clicking "Connect Direct" gave no visual feedback that connection had begun. Persisting `peer` in `settings.json` permanently hijacked all subsequent connections, disabling edge discovery scans without the user realizing it.
- **Alternatives Considered**:
  - *Prompt confirmation dialog on every connect*: Rejected; adds unnecessary friction. Clearing on preset selection / providing a clear button is intuitive and clean.

---

## 6. Scanner Progress Retention & Telemetry Hygiene

- **Decision**:
  - In `apps/desktop/src/components/ScannerTab.tsx`, keep the progress card visible when `scanState.active || scanState.scanned > 0`.
  - In `apps/desktop/src/hooks/useScanner.ts`, when `scan_done` fires with 0 working endpoints, set `phase: "Completed (0 found)"` (not "Verified") and log `Scan complete — no working endpoints found.` instead of `Scan complete — best:  ()`.
- **Rationale**: Prevents the progress bar and probed counts from abruptly disappearing upon scan completion. Avoids contradictory "Verified" states and malformed log entries when no endpoints answer.
- **Alternatives Considered**:
  - *Reset scan state immediately on completion*: Rejected; destroys the user's view of how many candidates were scanned.

---

## 7. TUN Mode Live Connection Test & Metric Accuracy

- **Decision**:
  - In `apps/desktop/src-tauri/src/lib.rs` `test_connection()`: check `settings.routing_mode == "tun"`. For TUN mode, issue a direct HTTP request to `https://www.cloudflare.com/cdn-cgi/trace` without setting a proxy, verifying that Windows system-level TUN routing works. Return `format!("OK via TUN · ip={ip} loc={loc}")`.
  - In `apps/desktop/src/components/ConnectionTab.tsx`:
    - Update Process metric subtitle to show `{connected ? "Healthy" : running ? "Starting" : "Not running"}` so that `PID 12345` is not paired with `"Not running"`.
    - Update profile note to reference modern presets instead of obsolete "Max (TUN)" and "Speed".
    - Add color accent classes (`ok` vs `error`) to `.test-result` based on whether the result starts with `OK`.
- **Rationale**: TUN mode routes Layer 3 packets directly into the WinTUN virtual adapter and does not bind a local loopback proxy port. Testing via `127.0.0.1:1820` in TUN mode produced a 100% false-negative error. Displaying "PID 12345" + "Not running" was factually contradictory.
- **Alternatives Considered**:
  - *Spinning up a dummy proxy during TUN mode*: Rejected; wastes system ports and fails to validate the actual TUN adapter route.

---

## 8. Desktop Overflow Containment & Discovered Gateway Scrolling

- **Decision**:
  - In `apps/desktop/src/App.css`, add `max-height: 380px; overflow-y: auto;` to `.discovered-list`.
  - Add `min-width: 0; overflow-wrap: anywhere;` to container elements and discovered rows.
- **Rationale**: When scanning discovers 50+ endpoints, the list expands the Tauri window infinitely downwards and off-screen. High-DPI scaling caused text clipping without overflow wraps.
- **Alternatives Considered**:
  - *Pagination*: Rejected; vertical scrolling inside a bounded card is smoother and faster for desktop users.

---

## 9. Settings Invariants & Noise Guidance

- **Decision**:
  - In `apps/desktop/src/components/SettingsTab.tsx`, show an advisory that UDP noise is inactive when MASQUE H2 (TCP) is active.
  - When `portsCollide` is true, update the save bar to display `Save blocked: fix port collision` with error styling.
  - In `apps/desktop/src/hooks/useLogs.ts`, refine `isMilestone` to exclude probe failures (`probe failed`, `timeout`, `candidate rejected`) so that milestones display only significant connection phases.
- **Rationale**: Clarifies protocol capabilities, prevents misleading "Auto-save on" indicators when saves are blocked by validation, and keeps the milestones log readable.
