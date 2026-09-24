<img src="packages/ui/brand/aether-mark.svg" alt="Aether Next mark" width="72">

# Aether Next

**A tunnel client for Windows and Android.** Find a working connection, then route your apps through a local proxy or a device-wide tunnel.

[Download releases](https://github.com/deathline94/aether-next/releases) · [User guide](Docs/GUIDE.en.md) · [Report an issue](https://github.com/deathline94/aether-next/issues)

## What it does

Aether Next scans for a reachable endpoint and opens an encrypted tunnel. You can choose a preset and connect without tuning every transport setting, or adjust the protocol and scanning options yourself.

- **Multiple routes:** MASQUE over HTTP/2 or HTTP/3, WireGuard, and nested WireGuard (gool).
- **Endpoint discovery:** turbo, balanced, thorough, and stealth scan modes.
- **Network controls:** connection presets, obfuscation profiles, live status, logs, and a connection test.
- **Local proxies:** SOCKS5 at `127.0.0.1:1819` and HTTP CONNECT at `127.0.0.1:1820` by default.

| Platform | Routing options |
| --- | --- |
| Windows | Local proxies, system proxy, or an optional WinTUN device-wide tunnel (administrator access required). |
| Android | Local proxies or an optional Android VPN connection (VPN permission required). |

## Get started

1. Download the appropriate Windows installer, portable package, or Android APK from [Releases](https://github.com/deathline94/aether-next/releases).
2. Open Aether Next, choose a preset, and press **Connect**.
3. If the first route does not work, try MASQUE over HTTP/2 or a different scan mode. The [user guide](Docs/GUIDE.en.md) explains the transport and obfuscation settings.
4. To check a local proxy on Windows, run:

```powershell
curl.exe -x socks5h://127.0.0.1:1819 https://www.cloudflare.com/cdn-cgi/trace
```

The system proxy and VPN options route traffic from compatible apps without configuring each app's proxy separately. Apps that ignore the system proxy may need the device-wide tunnel.

## Verify a download

Each release includes SHA-256 checksums. Compare a downloaded file with its matching `.sha256` file or `SHA256SUMS.txt`. Where an attestation is available, you can also check its build provenance with the GitHub CLI:

```sh
gh attestation verify <downloaded-file> --repo deathline94/aether-next
```

Windows packages are not Authenticode-signed, so Windows may show **Unknown publisher**. Verify the checksum and build attestation before running them. Details are in the [user guide](Docs/GUIDE.en.md#verify-a-download).

## Build from source

The tunnel engine is written in Rust; the Windows desktop app uses Tauri and React, and the Android app has a native shell around its web interface. The CI workflows show the complete platform toolchains and packaging steps.

| Component | Build entry point |
| --- | --- |
| Engine | `cd aether; cargo build --release` |
| Windows interface | `cd apps/desktop; npm ci; npm run build` |
| Android interface | `cd apps/android; npm ci; npm run build` |

Building a distributable Windows package requires a reviewed engine digest in the trust anchor. See [engine trust and release preparation](packaging/trust/README.md) before packaging. The Android APK also requires its native engine libraries and Android SDK/NDK; see [the Android app](apps/android/README.md).

## Project and license

Aether Next is maintained by [deathline94](https://github.com/deathline94) and builds on the open-source [Aether](https://github.com/CluvexStudio/Aether) tunnel project. It also uses other open-source components whose notices are kept in the repository.

Licensed under the [GNU Affero General Public License v3.0](LICENSE).
