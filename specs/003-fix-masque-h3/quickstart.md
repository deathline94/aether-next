# Quickstart & Verification Guide: MASQUE H3 & Bug Remediation

**Feature**: Fix MASQUE H3 Connectivity and Upstream Alignment + Visual & Functional Bugs
**Status**: Ready for Implementation

---

## 1. Prerequisites

- Rust toolchain: `cargo`, `rustc` (stable 2021 edition)
- Node.js & npm (for desktop frontend)
- Git repository: `c:\Users\SLiM\Desktop\Project\Aether`

---

## 2. Core Engine Verification

### A. Build and Unit Tests
Run the core engine test suite to ensure all cryptographic, QUIC bait, and packet parsing routines pass:

```powershell
# In repo root:
cargo test --package aether --lib
```

### B. QUIC v2 Bait Unit Test
Verify that the `build_version_bait` function produces exact 1200-byte packets with correct headers:

```powershell
cargo test --package aether --lib quic::tests::test_build_version_bait
```

### C. Check Compilation of Full Workspace
Verify that the Tauri host and Android bridge bindings compile cleanly:

```powershell
cargo check --workspace
```

---

## 3. Desktop Frontend Verification

### A. Type Check and Production Build
Verify that TypeScript compilation and Tailwind/Vite bundling pass with zero errors:

```powershell
cd apps/desktop
npm run build
```

---

## 4. Manual End-to-End Verification Scenarios

### Scenario 1: MASQUE H3 Anti-Censorship Connection
1. Launch Aether Next desktop application.
2. Under **Presets**, click **Fastest MASQUE (H3)**.
3. Click the primary **Connect** button.
4. **Expected**:
   - Engine sends 1200-byte QUIC v2 version bait to edge gateway.
   - Version negotiation packet received or timeout handled cleanly.
   - QUIC v1 handshake succeeds without DPI drop.
   - 2 consecutive DNS probes over H3 datagrams verify data plane.
   - Status updates to **Protected**; Process card displays active PID and **Healthy**.

### Scenario 2: Standalone Scanner & "Connect Direct" Navigation
1. Navigate to the **Scanner** tab.
2. Click **Start Standalone Scan**.
3. Allow scan to complete (or click **Stop Scan**).
4. **Expected**:
   - Progress bar and summary metrics (e.g. `250 / 250 probed · 12 working · best 42ms`) remain displayed after scan completion.
   - Discovered gateways scroll cleanly within a bounded card without expanding the window vertically.
5. Click **Connect Direct** on a discovered gateway.
6. **Expected**:
   - Active view automatically switches to **Connection** tab.
   - Subtitle indicates `Connecting to <gateway>`.
   - Connection succeeds to that specific gateway.
7. Disconnect and click any Preset (e.g. **Fastest MASQUE (H3)**).
8. **Expected**:
   - Pinned peer is cleared and normal multi-endpoint discovery is restored.

### Scenario 3: Live Connection Test in TUN Mode
1. In **Settings**, change Routing Mode to **TUN (admin)**.
2. Connect the tunnel.
3. On the **Connection** tab, click **Test connection**.
4. **Expected**:
   - Test performs a direct trace via system stack (captured by WinTUN).
   - Test result displays with green/success accent: `OK via TUN · ip=<ip> loc=<loc>` without proxy connection refused errors.

### Scenario 4: Settings Invariant & Port Collision
1. In **Settings**, choose **MASQUE H2**.
2. **Expected**:
   - Obfuscation noise displays an advisory: `Not applicable for H2 (TCP)`.
3. Set HTTP port equal to SOCKS5 port (e.g. 1820).
4. **Expected**:
   - Port collision error alert appears.
   - Sticky save bar alerts `Save blocked: fix port collision`.
