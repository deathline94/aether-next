# Aether Next

Tunnel client for restricted networks. Opens an encrypted path and gives you a local SOCKS5 / HTTP proxy so apps can get out.

By [deathline94](https://github.com/deathline94).

## Get it

[Releases](https://github.com/deathline94/aether-next/releases) — Windows installer / portable, Android APK.

Default proxy: `127.0.0.1:1819` (SOCKS5), HTTP CONNECT on `1820` when using the app defaults.

## What it supports

- MASQUE (HTTP/2 and HTTP/3)
- WireGuard and nested WireGuard (gool)
- Scan modes and obfuscation profiles
- Windows desktop app (system proxy, optional full tunnel)
- Android app (optional VPN)

## Build (Windows)

```text
cd aether
cargo build --release

cd ..\apps\desktop
npm install
npm run stage-engine
npm run tauri build
```

## Build (Android)

```text
cd apps\android
npm install
npm run sync-www
cd android
gradlew assembleDebug
```

(You need an arm64 engine binary staged under `jniLibs` / `assets/engine` before Connect works.)

## License

See [LICENSE](LICENSE).
