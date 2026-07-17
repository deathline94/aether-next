# Aether Next guide

Aether Next is a tunnel client. It opens an encrypted path out of a restricted network and exposes a local proxy so your browser or other apps can send traffic through it.

Default SOCKS5: `127.0.0.1:1819`  
Default HTTP proxy (app): `127.0.0.1:1820`

## Apps

- **Windows** — desktop UI (installer or portable from Releases)
- **Android** — APK from Releases (Connect may ask for VPN permission in full-tunnel mode)

The tunnel engine itself can also be run as a CLI binary on Windows if you prefer env vars and a terminal.

## Transports

### MASQUE (default)

Traffic is carried inside an HTTPS-looking connection. Best starting point on hard networks.

- **h3** — HTTP/3 over QUIC/UDP (faster when UDP is fine)
- **h2** — HTTP/2 over TCP (use when UDP/QUIC is blocked or flaky)

In the app: transport setting / speed presets.  
CLI: `AETHER_MASQUE_HTTP2=1` forces h2.

### WireGuard

Lean and fast when the path allows classic WG packets.

### gool (nested WireGuard)

WG inside WG. Heavier, sometimes more stable when single-layer WG is not enough.

## Scan

Endpoints are discovered at runtime (not hard-coded forever). Modes:

| Mode | Notes |
|------|--------|
| turbo | quick pick |
| balanced | default |
| thorough | slower, better pick |
| stealth | quieter, slower |

IPv4 / IPv6 / both can be selected in the app or via `AETHER_IP`.

## Obfuscation (“noise”)

Junk / timing tricks before and around the handshake so the connection does not look like a textbook protocol start.

Typical profiles: **firewall** / **balanced** (good defaults), **gfw** / **aggressive** (heavier), **light**, **off**.

Start default. If it fails or drops, go heavier. On open networks, light/off for speed.

## Speed presets (desktop / Android UI)

Presets map protocol + transport + noise + scan so you do not have to hand-tune every time. Custom mode still exposes full settings.

## Environment variables (CLI / advanced)

| Variable | Purpose |
|----------|---------|
| `AETHER_PROTOCOL` | `masque`, `wg`, `gool` |
| `AETHER_SOCKS` | SOCKS listen addr (default `127.0.0.1:1819`) |
| `AETHER_HTTP` | HTTP CONNECT listen (when used) |
| `AETHER_NOIZE` | obfuscation profile |
| `AETHER_SCAN` | `turbo` / `balanced` / `thorough` / `stealth` |
| `AETHER_IP` | IPv4 / IPv6 / both |
| `AETHER_MASQUE_HTTP2` | `1` = force MASQUE over h2 |
| `AETHER_PEER` | force endpoint, skip scan |
| `AETHER_CONFIG` | config file path |
| `AETHER_TUN` | enable full-tunnel path where supported |
| `AETHER_WG_NO_PROFILE_RETRY` | skip extra WG profile retries |

## Quick check

With the tunnel up:

```text
curl -x socks5h://127.0.0.1:1819 https://www.cloudflare.com/cdn-cgi/trace
```

If you get a response, the proxy path is working.

## Troubleshooting

- No connect: try h2 MASQUE, then WG / gool, then heavier noise.
- Connects then dies: heavier noise; check that the network is not killing long-lived UDP.
- Slow scan: use turbo.
- Slow throughput: prefer MASQUE h2 or single WG over gool when the path allows it.

## Build notes

Windows desktop: Rust + Node, then `npm run tauri build` under `apps/desktop` after a release engine build.

Android: Node UI (`npm run sync-www`), Gradle APK under `apps/android/android`, with engine binaries staged into `jniLibs` as `libaether.so`.
