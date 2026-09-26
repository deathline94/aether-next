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

### MASQUE-in-MASQUE (mim)

A second, independent MASQUE tunnel established *through* the first one: the outer
hop reaches Cloudflare's edge as usual, and the inner hop dials its own edge over
the outer tunnel. Heavier than plain MASQUE (two layers of encapsulation), but the
inner leg's traffic pattern is decoupled from the local network's view of the
outer hop.

- The outer hop follows the transport setting (h3/h2) like plain MASQUE; the inner
  hop follows the same choice (h3 rides the outer tunnel as UDP datagrams, h2 as
  TCP through a local forwarder).
- The inner edge is discovered automatically from the designed MASQUE H3 pool
  (3 permitted VIPs across every MASQUE port). You can pin both hops instead —
  see the environment variables below.
- The **Scanner** tab deliberately does not list mim: a standalone scan can only
  probe the outer hop, which is the same pool MASQUE H3/H2 already cover, so a mim
  row would claim a certainty about the inner leg it cannot have. Connect-time
  scanning verifies the outer hop and the data plane proves the inner one.
- An inner hop that shares its address with the outer edge is refused: the inner
  tunnel would pinch through the edge it is nested in.

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
| `AETHER_SCAN` | `turbo` / `balanced` / `thorough` / `stealth` / `ironclad` |
| `AETHER_IP` | IPv4 / IPv6 / both |
| `AETHER_MASQUE_HTTP2` | `1` = force MASQUE over h2 |
| `AETHER_PEER` | force endpoint, skip scan |
| `AETHER_MIM_PEERS` | pin both mim hops: `outer:port,inner:port`. `auto` / `off` / `false` / `0` = discover the inner edge automatically |
| `AETHER_MIM_OUTER_PEER` | pin the mim outer hop only (overrides the outer half of `AETHER_MIM_PEERS`) |
| `AETHER_MIM_INNER_PEER` | pin the mim inner hop only; must land on a different edge than the outer hop |

CLI flags (manual runs): `--mim` selects the transport, `--mim-outer <addr>`,
`--mim-inner <addr>`, `--mim-peers <list>` pin the hops, `--protocol <name>`
matches `AETHER_PROTOCOL`. Unknown flags, missing values and conflicting
protocol choices are refused, not silently ignored.
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

## Verify a download

Every Windows installer, portable zip and Android APK is attested by the CI run that
built it, so provenance is checkable without trusting the file itself:

```sh
gh attestation verify AetherNext-windows-x64-setup.exe --repo deathline94/aether-next
gh attestation verify AetherNext-android-arm64-v8a.apk  --repo deathline94/aether-next
```

A pass means these exact bytes were produced by this repository's build workflow at the
recorded commit. Aether's Windows packages are not Authenticode-signed, so Windows may
show **Unknown publisher**. Compare the downloaded SHA-256 checksum as well. The shell
refuses to launch an engine whose digest is not committed in
`packaging/trust/engine-trust.json`; a separate reviewed workflow records that digest
before a release build uses it. The bundled WinTUN driver keeps its vendor signature.

## Repairing leftover state

A crash or a killed process can leave host state behind: routes that still point at
a tunnel that is gone, or a system proxy still set to the local port. Both are
repairable without opening a tunnel:

```sh
aether --repair-routes          # drop routes this app installed and no longer owns
AetherNext.exe --repair-proxy   # restore the system proxy integration
```

Repair is scoped to what the journal says this app created. Where ownership cannot be
established it reports and changes nothing — deleting someone else's route is not a
cleanup. If a proxy points at a port another program now holds, the repair says so
instead of guessing at a value.

## Rotating the engine trust anchor

The desktop shell refuses to launch an engine whose bytes are not digested in
`packaging/trust/engine-trust.json`. That witness is authored by a separate, reviewed
step, so a release cannot vouch for whatever the runner happened to build:

1. `gh workflow run prepare-anchor.yml` (it requires the literal `PUBLISH` confirmation).
2. It builds the unsigned engine, uploads those exact bytes, then opens a pull
   request with the measured digest and artifact pointer.
3. Merge it, then tag. A tag build that finds no committed witness for the engine it
   staged fails, rather than rewriting its own anchor.

If an engine change produces no anchor diff, the pipeline is broken: a release that
silently reuses a stale witness is the failure this step exists to prevent.

## Updates

Aether Next tells you a newer version exists; it does not fetch and install one in
the background. An updater that downloads a new engine is a second trust path, and
the engine already has one that is auditable (the committed anchor above). Update by
downloading and verifying per [Verify a download](#verify-a-download).

## Invariants

The mechanical gates live in `scripts/verify-invariants.mjs` and run in CI. Every
gate ships a fixture that proves it can fail:

```sh
node scripts/verify-invariants.mjs                  # all gates must pass
node scripts/verify-invariants.mjs --selftest-fail  # every gate must be able to fail
```

The governing rules are ratified in `.specify/memory/constitution.md`. A change with
no check that would fail without it is not a fix.

## Build notes

Windows desktop needs Rust and Node. The engine alone builds with
`cd aether && cargo build --release`. The desktop interface builds with
`cd apps/desktop && npm ci && npm run build`.

A distributable `npm run tauri build` embeds the reviewed engine digest from
`packaging/trust/engine-trust.json`. On a fresh checkout with the placeholder
digest, run the **Prepare engine witness** workflow and merge its pull request
before tagging. `AETHER_ALLOW_UNWITNESSED=1` permits a development build only;
the release policy refuses to publish it.

Android: Node UI (`npm run sync-www`), Gradle APK under `apps/android/android`, with engine binaries staged into `jniLibs` as `libaether.so`.

### Android `versionCode` ↔ `versionName`

`apps/android/android/app/build.gradle.kts` pairs `versionCode = 52` with
`versionName = "1.3.0"`, and nothing recorded why 52. It is not derived and must not be
guessed at: **Android installs strictly greater `versionCode` only**, so a release that
bumps `versionName` and forgets `versionCode` publishes an APK that existing users cannot
update to — silently, with no build error.

The coupling, stated:

| Field | Lives in | Rule |
|---|---|---|
| `versionName` | `aether/Cargo.toml`, `apps/desktop/src-tauri/Cargo.toml` + `tauri.conf.json`, `apps/desktop/package.json`, `apps/android/android/app/build.gradle.kts` | user-facing semver, **must match across all five** |
| `versionCode` | `apps/android/android/app/build.gradle.kts` only | monotonic integer, `+1` per published APK, never reused, never derived from `versionName` |

52 is simply the count of published Android builds to date. When you bump `versionName`
to `1.3.1`, set `versionCode = 53` in the same commit; a `versionCode` that is not the
previous release's plus one is a release-blocking review comment.

