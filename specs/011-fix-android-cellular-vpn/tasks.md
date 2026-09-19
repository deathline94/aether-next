# Implementation Tasks: Full Tunnel Protection on Android Cellular Networks

**Branch**: `011-fix-android-cellular-vpn` | **Date**: 2026-09-19 | **Spec**: [spec.md](./spec.md) | **Plan**: [plan.md](./plan.md)

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Verify development environment, build tools, and baseline compilation.

- [X] T001 Verify Android build environment and Gradle project compilation state in `apps/android/android/`
- [X] T002 [P] Verify Rust engine compilation and clippy clean state in `aether/`

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Core engine and tun2socks routing fixes that MUST be in place before user story validation.

**⚠️ CRITICAL**: Both User Story 1 and User Story 2 rely on fast failure / rejection for unrouted traffic to prevent connection hanging.

- [X] T003 Update `writeHevConfig` in `apps/android/android/app/src/main/java/app/aethernext/AetherVpnService.kt` to set `icmp: 'reject'` and reduce `connect-timeout` to 5000ms
- [X] T004 [P] Implement fast refusal for `ATYP_V6` targets when no valid IPv6 gateway route exists in `aether/src/socks.rs` to eliminate 20-second connection timeouts

**Checkpoint**: Foundation ready — tun2socks and SOCKS5 reject unrouteable flows immediately.

---

## Phase 3: User Story 1 - Full-Device Cellular Tunnel Protection (Priority: P1) 🎯 MVP

**Goal**: Ensure 100% of outbound device network traffic routes through the secure VPN tunnel when on cellular mobile data (LTE/5G), preventing traffic from connecting directly via carrier IP.

**Independent Test**: Connect an Android phone on mobile data (Wi-Fi off). Visit `https://ipinfo.io` in Chrome. IP address MUST show Cloudflare VPN exit node, and carrier IP must never appear.

### Implementation for User Story 1

- [X] T005 [US1] Reconfigure `VpnService.Builder` DNS in `apps/android/android/app/src/main/java/app/aethernext/AetherVpnService.kt` to advertise strictly `198.18.0.2` (`MAPPED_DNS`) and remove `1.1.1.1`, `8.8.8.8`, and `2606:4700:4700::1111`
- [X] T006 [US1] Verify and lock IPv4 routing configuration in `apps/android/android/app/src/main/java/app/aethernext/AetherVpnService.kt` with `addAddress("198.18.0.1", 24)`, `addRoute("0.0.0.0", 0)`, and `addRoute("198.18.0.0", 15)`
- [X] T007 [US1] Validate full cellular traffic encapsulation per Scenario 1 in `specs/011-fix-android-cellular-vpn/quickstart.md`

**Checkpoint**: User Story 1 MVP fully functional and verified on mobile data.

---

## Phase 4: User Story 2 - Dual-Stack Network Leak Prevention (Priority: P1)

**Goal**: Prevent dual-stack (IPv4/IPv6) cellular carriers from leaking traffic outside the tunnel when applications perform IPv6 lookups or connections.

**Independent Test**: Run leak tests on `https://browserleaks.com/ip` and `https://test-ipv6.com` while connected over cellular data. Zero carrier IPv6 or carrier DNS addresses detected.

### Implementation for User Story 2

- [X] T008 [US2] Reconfigure IPv6 tunnel binding in `apps/android/android/app/src/main/java/app/aethernext/AetherVpnService.kt` to use point-to-point host prefix `128` (`addAddress("fd00:ae::1", 128)`) with `addRoute("::", 0)`
- [X] T009 [US2] Ensure `hev-socks5-tunnel` `mapdns` returns `NODATA` for `AAAA` queries over `198.18.0.2:53` without forwarding queries to carrier resolvers in `apps/android/android/app/src/main/java/app/aethernext/AetherVpnService.kt`
- [X] T010 [US2] Validate zero IPv6 carrier leaks and zero DNS leaks per Scenario 2 in `specs/011-fix-android-cellular-vpn/quickstart.md`

**Checkpoint**: Dual-stack leak prevention verified — device operates leak-free across all cellular carriers.

---

## Phase 5: User Story 3 - Seamless Network Interface Transition (Priority: P2)

**Goal**: Maintain continuous tunnel encapsulation when the device transitions between Wi-Fi and cellular networks.

**Independent Test**: Connect over Wi-Fi with VPN active, then toggle Wi-Fi off. Tunnel must seamlessly update underlying networks without dropping traffic into the carrier link.

### Implementation for User Story 3

- [X] T011 [US3] Register `ConnectivityManager.NetworkCallback` in `apps/android/android/app/src/main/java/app/aethernext/AetherVpnService.kt` to track active physical network availability (Cellular and Wi-Fi)
- [X] T012 [US3] Dynamically invoke `setUnderlyingNetworks(arrayOf(network))` on network transitions and clean up callback unregistration in `stopTunnel()` in `apps/android/android/app/src/main/java/app/aethernext/AetherVpnService.kt`
- [X] T013 [US3] Validate handover behavior by toggling Wi-Fi during an active session per Scenario 3 in `specs/011-fix-android-cellular-vpn/quickstart.md`

**Checkpoint**: All three user stories completed and independently validated.

---

## Phase 6: Polish & Cross-Cutting Concerns

**Purpose**: Compilation verification, code cleanliness, and release readiness.

- [X] T014 Run full Android build `./gradlew compileDebugKotlin` in `apps/android/android/` to ensure clean compilation
- [X] T015 [P] Run Rust engine check in `aether/` to verify backend engine cleanliness
- [X] T016 Document final verification results in `specs/011-fix-android-cellular-vpn/quickstart.md`

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies — can start immediately.
- **Foundational (Phase 2)**: Depends on Setup completion — BLOCKS all user stories.
- **User Story 1 (Phase 3)**: Depends on Foundational completion. Delivers core MVP.
- **User Story 2 (Phase 4)**: Depends on Foundational and User Story 1. Delivers dual-stack containment.
- **User Story 3 (Phase 5)**: Depends on User Story 1 & 2. Delivers dynamic network handover.
- **Polish (Phase 6)**: Depends on all user stories being complete.

### Parallel Opportunities

- T001 and T002 can run concurrently.
- T003 (`AetherVpnService.kt`) and T004 (`socks.rs`) touch different files and can be prepared in parallel.
- T014 (Android build) and T015 (Rust clippy) can run in parallel during the polish phase.

---

## Implementation Strategy

### MVP First (User Story 1 Only)
1. Complete Phase 1 (Setup) and Phase 2 (Foundational).
2. Implement Phase 3 (User Story 1): DNS isolation to `198.18.0.2` and IPv4 routing lock.
3. Validate on cellular mobile data — confirm carrier IP bypass is eliminated.

### Incremental Delivery
1. Foundation + US1 -> MVP: Cellular mobile data routes 100% through the tunnel.
2. US2 -> IPv6 leak-proof: `fd00:ae::1/128`, `::/0`, `NODATA` for AAAA, and `icmp: 'reject'`.
3. US3 -> Handover resilience: `NetworkCallback` tracking underlying Wi-Fi and Cellular networks.
4. Polish -> Compilation, packaging, and release verification.
