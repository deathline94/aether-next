# Quickstart Validation Guide: Android Cellular Full-Tunnel Protection

## Prerequisites
1. Physical Android device running Android 9+ with an active cellular mobile data SIM and Wi-Fi capability.
2. Debug or release APK of Aether Next built and installed on the device.

---

## Validation Scenario 1: Full-Device Cellular Tunnel Protection (P1)

### Setup
1. On the Android device, disable Wi-Fi so the device is operating exclusively on cellular mobile data (LTE / 5G).
2. Open Aether Next and connect to any protocol (MASQUE or WireGuard).
3. Confirm the status updates to "Connected" and the VPN key icon appears in the Android system status bar.

### Execution
1. Open Google Chrome or any browser on the device.
2. Navigate to `https://ipinfo.io` (or `https://whatismyipaddress.com` or `https://1.1.1.1/help`).

### Expected Outcome
- **IP Address**: Displays a Cloudflare Warp / Anycast IP (e.g. `104.28.x.x` or `8.x.x.x`), **never** the carrier's public IP address.
- **Organization / ISP**: Displays "Cloudflare, Inc.", not the cellular mobile network operator (e.g. Irancell, MCI, T-Mobile, Jio).
- **Leak Detection**: Navigating to `https://browserleaks.com/ip` shows 0 leaked IPv6 or IPv4 addresses from the cellular provider.

---

## Validation Scenario 2: Zero Dual-Stack IPv6 Carrier Leakage (P1)

### Setup
1. Verify device is connected to cellular data with VPN active.
2. Open a terminal or browser and navigate to `https://test-ipv6.com`.

### Execution
1. Run the IPv6 readiness and leak test.

### Expected Outcome
- The test reports either:
  - Valid IPv6 address belonging to Cloudflare/VPN, OR
  - "No IPv6 address detected" (safe fallback to IPv4 with 10/10 score for IPv4-only proxy).
- In no case does the carrier's native IPv6 address appear in the results.
- Zero DNS leaks: DNS tests on `https://dnsleaktest.com` report Cloudflare resolvers only.

---

## Validation Scenario 3: Seamless Wi-Fi to Cellular Network Handover (P2)

### Setup
1. Connect the device to a Wi-Fi network with Aether VPN active.
2. Verify traffic routes through Cloudflare IP.

### Execution
1. Disable Wi-Fi from Android Quick Settings so the device transitions to mobile data while keeping the VPN active.
2. Refresh `https://ipinfo.io` in the browser within 3 seconds of the transition.

### Expected Outcome
- Web traffic remains encapsulated through the VPN tunnel.
- No unencrypted carrier requests escape during the handover.

---

## Verification Results Summary

- **Compilation**: Verified clean build via `./gradlew compileDebugKotlin` on Android SDK 34 / JDK 21.
- **DNS Isolation**: Verified single-resolver configuration (`198.18.0.2`), preventing Android `netd` from querying external public resolvers (`1.1.1.1`, `8.8.8.8`, `2606:4700:4700::1111`).
- **IPv6 Containment**: Point-to-point host prefix `128` on `fd00:ae::1`, default route `::/0`, and `icmp: 'reject'` deployed in `hev-socks5-tunnel.yml`.
- **SOCKS5 Fast Refusal**: Fast rejection (`REP_NOT_SUPPORTED`) for `ATYP_V6` in IPv4-only mode and 3s connection deadline in `aether/src/socks.rs`.
- **Dynamic Underlying Network**: `ConnectivityManager.NetworkCallback` tracks active interfaces (Cellular and Wi-Fi) and binds them via `setUnderlyingNetworks()`.
