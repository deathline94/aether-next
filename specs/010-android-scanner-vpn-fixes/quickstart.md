# Quickstart: Validating Android Scanner UI & VPN Traffic Routing

**Feature**: [`specs/010-android-scanner-vpn-fixes`](../spec.md)
**Date**: 2026-09-18

This document outlines the validation procedures to verify that both the scanner UI distortions and Android VPN tunnel traffic leaks are completely resolved.

---

## 1. Scanner UI Mobile Layout Verification

### Prerequisites
- Build or run the Android frontend in a mobile viewport (width $\le 420\text{px}$).

### Test Procedure
1. Navigate to the **Scanner** tab.
2. Launch an IP scan (or observe previously discovered gateways).
3. Inspect discovered gateway cards under **Discovered Gateways**:
   - **Verification 1**: Verify the IP address (e.g. `162.159.198.1:4500`) is displayed on a single horizontal unbroken line.
   - **Verification 2**: Verify there is 0 vertical single-character column wrapping.
   - **Verification 3**: Verify the protocol tag (`MASQUE H3`, `WIREGUARD`, etc.) is cleanly positioned on the top row next to the IP address.
   - **Verification 4**: Verify the latency indicator (`626ms`) and the "Connect Direct" button are positioned on the second row with clear separation and ample touch padding.
   - **Verification 5**: Tap the copy button and verify the IP and port are copied to clipboard without triggering "Connect Direct".
   - **Verification 6**: Tap "Connect Direct" and verify direct connection initiation begins.

---

## 2. Android Full-Device VPN Traffic Encapsulation Verification

### Prerequisites
- Install and launch the Aether Android APK on a physical Android device or emulator with mobile data (or Wi-Fi) active.
- Android system setting "Private DNS" set to "Automatic" (default Android configuration).

### Test Procedure
1. On the Home tab (or via Scanner "Connect Direct"), tap **Connect** with Routing Mode set to **Full Device (TUN)**.
2. Grant VPN permission if prompted.
3. Observe the key icon appearing in the Android status bar and the connection card transitioning to "Connected".
4. Open an external browser (e.g. Google Chrome) or terminal and visit an external IP verification service:
   ```text
   https://www.cloudflare.com/cdn-cgi/trace
   https://ifconfig.me/all.json
   ```
5. **Verification 1 (Egress IP)**: The reported IP MUST match the Cloudflare WARP / MASQUE egress IP, NOT the mobile carrier physical IP.
6. **Verification 2 (DNS Leak Test)**:
   Visit `https://dnsleaktest.com` (or `https://dnscheck.tools`) and run a standard test:
   - All detected DNS servers MUST be Cloudflare / proxy DNS servers.
   - ZERO local carrier or local ISP DNS servers should be reported.
7. **Verification 3 (Dual-Stack IPv6 Test)**:
   Visit `https://ipv6-test.com`:
   - If IPv6 is available through the proxy, it reflects proxy egress IPv6.
   - Under no circumstances does IPv6 traffic leak to the physical carrier's IPv6 address.
8. **Verification 4 (Private DNS Status)**:
   In Android Settings -> Network & internet -> Private DNS, verify the network does not report "Couldn't connect" or "No internet access".
