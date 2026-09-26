<div align="center">

<img src="packages/ui/brand/aether-mark.svg" alt="Aether Next Logo" width="80" height="80">

# Aether Next

**Fast, resilient multi-protocol tunnel client for Windows and Android.**

[![Release](https://img.shields.io/github/v/release/deathline94/aether-next?style=flat&color=3388ff)](https://github.com/deathline94/aether-next/releases/latest)
[![CI](https://img.shields.io/github/actions/workflow/status/deathline94/aether-next/ci.yml?branch=main&label=CI&style=flat)](https://github.com/deathline94/aether-next/actions/workflows/ci.yml)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg?style=flat)](LICENSE)

[Downloads](#downloads) • [Quick Start](#quick-start) • [Protocols & Routing](#protocols--routing) • [User Guide](Docs/GUIDE.en.md) • [Building](#building-from-source)

</div>

---

Aether Next automatically finds working endpoints and establishes encrypted tunnels through restrictive networks. Designed for both desktop and mobile, it offers one-click connection presets alongside granular protocol and obfuscation controls.

## Downloads

Grab the latest release from the [Releases page](https://github.com/deathline94/aether-next/releases/latest):

| Platform | Package | Description |
| :--- | :--- | :--- |
| **Windows** | [`Setup (.exe)`](https://github.com/deathline94/aether-next/releases/latest) | Full Windows installer (x64) |
| **Windows** | [`Portable (.zip)`](https://github.com/deathline94/aether-next/releases/latest) | Standalone portable bundle, no installation needed |
| **Android** | [`arm64-v8a (.apk)`](https://github.com/deathline94/aether-next/releases/latest) | Modern Android devices (64-bit ARM) |
| **Android** | [`armeabi-v7a (.apk)`](https://github.com/deathline94/aether-next/releases/latest) | Older 32-bit Android phones |
| **Android** | [`x86_64 (.apk)`](https://github.com/deathline94/aether-next/releases/latest) | Emulators, Chromebooks & Intel/AMD tablets |
| **Android** | [`Universal (.apk)`](https://github.com/deathline94/aether-next/releases/latest) | All-in-one APK for any architecture |

## Features

- **Multiple Protocols**: MASQUE (HTTP/2 & HTTP/3 via QUIC), WireGuard, nested WireGuard (Gool), and MASQUE-in-MASQUE (a second MASQUE hop tunneled through the first).
- **Automated Endpoint Discovery**: High-concurrency scanner with Turbo, Balanced, Thorough, and Stealth discovery modes.
- **Flexible Routing**:
  - **Full Tunnel**: Device-wide TUN interface using WinTUN on Windows and native VpnService on Android.
  - **System Proxy**: Automatic Windows system proxy configuration.
  - **Local Inbound Proxies**: Standard SOCKS5 and HTTP CONNECT proxies for per-app routing.
- **Connection Insights**: Real-time throughput metrics, latency monitoring, verbose logs, and an integrated connection tester.
- **Security by Design**: Hardware-backed or DPAPI-encrypted secrets, strict origin validation, and cryptographic build provenance.

## Quick Start

1. **Install and Launch**: Download the package for your platform and open Aether Next.
2. **Select a Preset**: Choose a connection preset from the dashboard (e.g. *Balanced* or *Stealth*).
3. **Connect**: Click **Connect**. The built-in prober will test available endpoints and activate the tunnel.

If a route is throttled or blocked, switch to another transport mode (such as MASQUE over HTTP/2) or run a scan from the **Scanner** tab to discover optimal candidates.

### Using Local Inbound Proxies

When connected, Aether Next exposes local proxies on localhost:

- **SOCKS5 Proxy**: `127.0.0.1:1819`
- **HTTP Proxy**: `127.0.0.1:1820`

You can test the active tunnel directly from your terminal:

```bash
# Test through the SOCKS5 proxy
curl -x socks5h://127.0.0.1:1819 https://www.cloudflare.com/cdn-cgi/trace

# Test through the HTTP proxy
curl -x http://127.0.0.1:1820 https://www.cloudflare.com/cdn-cgi/trace
```

Configure your browser, package manager, or CLI tools to use these endpoints to route individual applications through the tunnel without altering system-wide network routing.

## Protocols & Routing

| Routing Mode | Windows | Android | Privileges Required |
| :--- | :---: | :---: | :--- |
| **Local Proxies** | Yes | Yes | None (standard user) |
| **System Proxy** | Yes | — | None |
| **Device Tunnel (TUN)** | Yes | Yes | Administrator (Windows) / VPN Permission (Android) |

## Verification & Integrity

Every official build publishes SHA-256 digests and GitHub build provenance attestations.

To verify a downloaded binary with the GitHub CLI:

```bash
gh attestation verify <path-to-file> --repo deathline94/aether-next
```

You can also verify checksums manually against `SHA256SUMS.txt` or the individual `.sha256` files attached to each release.

## Building from Source

### Prerequisites
- **Rust** 1.88.0+
- **Node.js** 22+ & npm
- **Go** 1.22+ & **CMake** / **NASM** (for BoringSSL / quiche)
- *Windows*: Visual Studio C++ Build Tools
- *Android*: Android SDK, NDK r27+, JDK 21+

### Build Commands

```bash
# 1. Build the Rust core engine
cd aether
cargo build --release
cd ..

# 2. Build the Desktop application (Tauri + React)
cd apps/desktop
npm ci
npm run stage-engine
npm run build
npm run tauri build
cd ../..

# 3. Build the Android application
cd apps/android
npm ci
npm run build
cd android
./gradlew assembleRelease
```

## Architecture

```
aether-next/
├── aether/             # Core tunnel engine (Rust, quiche, BoringSSL, wintun, MASQUE)
├── apps/
│   ├── desktop/        # Desktop application (Tauri v2, React, TypeScript, Tailwind)
│   └── android/        # Android application (Kotlin, VpnService, Capacitor WebView)
├── packages/
│   └── ui/             # Shared UI components, theme tokens, and typography
├── packaging/          # WinTUN driver and cryptographic trust anchors
└── scripts/            # Release integrity gates, policy enforcement, and verification tools
```

## License

Aether Next is licensed under the [GNU Affero General Public License v3.0](LICENSE).  
Maintained by [deathline94](https://github.com/deathline94). Upstream tunnel foundation based on the open-source [Aether](https://github.com/CluvexStudio/Aether) project.
