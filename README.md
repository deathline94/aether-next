# Aether Next

**Aether Next** is a full product build of the Aether tunnel idea - not a CLI-only drop, and not a thin wrapper on someone else's release zip.

By **[deathline94](https://github.com/deathline94)**.

It still does the core job: find a working path out of a restricted network, open an encrypted tunnel, and hand you a local proxy so browsers and apps can leave through it.

**Default SOCKS5:** `127.0.0.1:1819`  
**Default HTTP CONNECT (apps):** `127.0.0.1:1820`

---

## Why this exists

The original open-source **Aether** project (see [CluvexStudio/Aether](https://github.com/CluvexStudio/Aether)) shipped a capable **command-line** tunnel engine: MASQUE, WireGuard, nested WG (`gool`), scanning, obfuscation, Termux builds, etc. That engine lineage is real prior art and this tree still stands on that kind of tunnel stack (including quiche / BoringSSL under the hood).

**What was missing for day-to-day use** was a polished, shippable **client product** - something normal people can install, click Connect on, and trust to manage proxy / VPN without living in a terminal.

**Aether Next is that rework:** same class of tunnel, rebuilt into a **full Windows desktop app** and a **full Android app**, with engine-side fixes, packaging, and UX aimed at real use on hard networks.

---

## Apps

### Windows desktop (full GUI)

A proper **Windows application** (Tauri + React), not a console window:

- Connect / disconnect from the UI  
- **Speed presets** (one-click combos for protocol, transport, noise, scan, routing)  
- Protocol, MASQUE h2/h3, WireGuard, gool, scan, obfuscation, ports  
- **System proxy** mode so traffic can go through the tunnel without per-app config  
- Optional **WinTUN full-device tunnel** (admin)  
- Tray, session log, connection test  
- **Installer + portable** builds in Releases  

### Android (full app)

A real **Android client** with the same product surface as desktop:

- Same connection / settings / activity UI  
- Local SOCKS5 + HTTP proxies for apps that can use them  
- Optional **VpnService** path for device-wide routing  
- Multi-ABI engine inside the **APK** (phones + emulators)  
- Install from Releases like any other app  

If you only wanted a binary in PATH, the original CLI world was already enough. **If you want something you can hand to a user on Windows or Android, this is that.**

---

## What's better / different here

| Area | Aether Next |
|------|-------------|
| **Product form** | Full Windows GUI + full Android app, not CLI-only |
| **UX** | Speed presets, live status, logs, connection test |
| **Windows routing** | System proxy + optional WinTUN full tunnel |
| **Android routing** | App proxies + optional system VPN permission |
| **Engine work** | Reliability and performance pass (handshake/flush, hunt timeouts, scan turbo, MTU, HTTP CONNECT, structured session events, etc.) |
| **Shipping** | Versioned Windows installer/portable + Android APK from CI |

Transports and ideas (MASQUE / WG / gool / scan / noise) come from the same problem space as the original project. The **product layer and the rework around it** are what Aether Next is for.

---

## Features (engine + apps)

- Automatic endpoint discovery (turbo / balanced / thorough / stealth)  
- **MASQUE** over **HTTP/2** and **HTTP/3**  
- **WireGuard** and **nested WireGuard (gool)**  
- Obfuscation profiles (firewall, gfw, balanced, aggressive, light, off, ...)  
- Local **SOCKS5** + **HTTP CONNECT**  
- Windows: system proxy, optional TUN  
- Android: in-app control, optional VPN  
- Live session / engine event stream in the UI  

More detail: [Docs/GUIDE.en.md](Docs/GUIDE.en.md).

---

## Download

**Always grab the newest build here:**

-> **[Latest release](https://github.com/deathline94/aether-next/releases/tag/latest)**

Every push to `main` rebuilds and **overwrites** that page with:

- Windows installer + portable
- Android: arm64-v8a, armeabi-v7a, x86_64, and universal APKs

Version tags (`v1.0.0`, `v1.1.0`, ...) create/update a frozen release with the same file names.

| File | What |
|------|------|
| `AetherNext-windows-x64-setup.exe` | Windows installer |
| `AetherNext-portable-windows-x64.zip` | Windows portable |
| `AetherNext-android-arm64-v8a.apk` | Phones (recommended) |
| `AetherNext-android-armeabi-v7a.apk` | Older 32-bit ARM |
| `AetherNext-android-x86_64.apk` | Emulators / x86 |
| `AetherNext-android-universal.apk` | All ABIs in one APK |

---

## Build from source

### Windows desktop (GUI)

```powershell
# 1. engine - always builds, no witness involved
cd aether
cargo build --release

# 2. shell - needs a signed, witnessed engine or an explicit opt-out
cd ..\apps\desktop
npm install
npm run stage-engine
npm run tauri build
```

Step 2 **fails on a fresh clone**, and that is deliberate. `apps/desktop/src-tauri/build.rs`
embeds `packaging/trust/engine-trust.json`, and on `main` that file still carries the
all-zero witness for `aether.exe` — a signed engine only exists inside a release run — so
the build stops rather than producing a GUI that would refuse to launch the engine it
ships with. Pick one:

```powershell
# development only: build an unwitnessed shell that asserts nothing about release
# provenance. It can never be shipped; the build prints a warning saying so.
$env:AETHER_ALLOW_UNWITNESSED = "1"
npm run tauri build

# a real release: cut the witness first, in a reviewed separate run
gh workflow run prepare-anchor.yml -f confirm=PUBLISH -f ref=main
# ...merge the pull request it opens, then tag
```

Full sequence, and what each guard refuses: [`Docs/GUIDE.en.md`](Docs/GUIDE.en.md) § Build notes.

### Android app

```powershell
cd apps\android
npm install
npm run sync-www
# stage arm64/armv7/x86_64 engines as jniLibs/*/libaether.so
cd android
.\gradlew assembleRelease
```

Engine crate alone: `cd aether && cargo build --release`.

The three `libhev-socks5-tunnel.so` payloads under `jniLibs` are committed and
digest-pinned (`scripts/verify-hev-lock.mjs`); `libaether.so` is not — it is built by CI.
`versionName` and `versionCode` are coupled by hand, not derived; see the guide before
bumping either.

---

## Naming, and what is not here

**There is no imagery in this README, by observation rather than by choice.** Nothing in
`README.md` or `Docs/GUIDE.en.md` contains a single real `![...](...)`: every screenshot
would have to come from a running Windows or Android build with a tunnel established, and
no such capture exists in the tree. A "screenshot" here would be a placeholder or a mock,
which is the kind of claim this repository has been deleting. The Vite/Tauri scaffold art
is not available to use either: of the three files the stock templates ship, only
`apps/desktop/src/assets/react.svg` is in the index, and it is referenced by nothing and
already absent from the working tree (the deletion is uncommitted as of this writing -
`git status` will show it). `public/vite.svg` and `public/tauri.svg` are not in this
repository at all. Nothing was removed to write this paragraph; if the intent is a brand
mark rather than a screenshot, that is a design decision and belongs with the icons in
`apps/desktop/src-tauri/icons/`, not here.

**Four spellings of one product.** `Aether Next`, `AetherNext`, `app.aethernext`,
`aether-next`. They are not interchangeable and the split is load-bearing in some places:

| Spelling | Where it lives | Can it change? |
|---|---|---|
| `Aether Next` | README title, window/product name, `tauri.conf.json` productName | display only — renaming changes the installed-app identity and the path under `%PROGRAMFILES%` |
| `AetherNext` | artifact file names in Releases (`AetherNext-windows-x64-setup.exe`) | no — published file names are what users and scripts already downloaded |
| `app.aethernext` | Android `applicationId` | **never** — changing it means existing installs cannot update, and Play treats it as a different app |
| `aether-next` | git remote / repository name | cosmetic, but breaks every external link |

Recommendation, not a rename: fix `app.aethernext` and the Release file names as
immutable, document `Aether Next` as the only user-visible spelling, and let `aether-next`
stand as the repository slug. A future unification should change the display name and
nothing else.

**Three owner namespaces, all live.** `deathline94` is the Authenticode subject
(`CN=deathline94`, asserted by `.github/scripts/sign-windows.ps1` and both workflows) and
also appears in the release download URL — so it is not a stylistic choice, it is what the
signature check compares against. `CluvexStudio/Aether` is cited in
[Why this exists](#why-this-exists) as the upstream lineage of the original CLI, not as this
repository's remote. `aether-next` is where this code is actually pushed. Those three are
consistent with each other today; the failure mode to avoid is treating `CN=deathline94`
as a string to tidy up, because the trust anchor's `issued_cn` is derived from it and the
witness in `packaging/trust/engine-trust.json` would stop matching the binaries it
describes.

---

## Credits & lineage

- **Aether Next** product, apps, packaging, and engine rework: **deathline94**  
- Original open-source **Aether** CLI / tunnel project: [CluvexStudio/Aether](https://github.com/CluvexStudio/Aether) - thanks for the baseline idea and public engine work  
- MASQUE / QUIC path uses **Cloudflare quiche** and related open-source components (see their licenses in-tree)

---

## License

See [LICENSE](LICENSE).