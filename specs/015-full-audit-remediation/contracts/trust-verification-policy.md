# Contract: Trust Verification Policy

**Feature**: `015-full-audit-remediation` | Applies to: new `aether/src/trust.rs`, `aether/src/tls.rs`, `aether/src/masque_h2.rs`, `apps/desktop/src-tauri/src/{lib.rs,build.rs}`, `.github/workflows/build.yml`, `.github/scripts/sign-windows.ps1`, `packaging/trust/*`

## Scope

Two distinct trust decisions that today share an ad-hoc, partially-disabled implementation:

- **T-A: binary trust** — "is this executable the one we shipped?"
- **T-B: peer trust** — "is this TLS peer the edge we mean to talk to?"

## T-A: Binary trust

**T-A1 — Unconditional.** Verification runs on the resolved path in **every** branch (resource dir, portable loop, repo-build fallback, custom `enginePath`, `AETHER_ENGINE`) and **every** routing mode. Today it runs only when `routing_mode == "tun"` (`lib.rs:1373-1379`) and the fallbacks at `lib.rs:1046-1094` return unchecked binaries while the child is handed the DPAPI master key.

**T-A2 — Independent anchor.** `packaging/trust/engine-trust.json` is committed and human-reviewed, written by the **release job after signing**. `build.rs` embeds the anchor file's bytes and hash and never hashes the binary being verified: `build.rs:38-53` currently computes `EMBEDDED_RELEASE_HASHES` from `resources/aether.exe`, so the runtime comparison always matches, and because `resources/*.exe` is gitignored, a clean checkout hashes **nothing** — the "missing digest is an error" guard is unreachable.

**T-A3 — Order.** Resolve canonical path → file SHA-256 → leaf certificate hash + SPKI hash → chain anchored **at the pinned leaf** → `CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_AUTHENTICODE)` → only then spawn. `WinVerifyTrust` is used as a PE-digest check.

**T-A4 — Flags.** `WTD_UI_NONE`, `WTD_REVOCATION_CHECK_NONE` (`0x40000`), `dwStateAction = WTD_STATEACTION_CLOSE`. Today `dwProvFlags: 0x00000080` is **mislabelled** in a comment as `WTD_REVOCATION_CHECK_NONE` but is `WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT`, and the state action is `IGNORE` — a live revocation check against a per-run ephemeral CI certificate that can never satisfy it.

**T-A5 — Trust boundary is narrow.** The custom `enginePath` root is the exe directory **only**; `exe.parent().parent()` currently includes `C:\Program Files` for perMachine installs and a user-writable extraction directory for portable.

**T-A6 — No bypass in release.** `allow_unsigned_in_debug` is deleted; a developer bypass is `#[cfg(debug_assertions)]`-only so the code path does not exist in a shipped binary.

**T-A7 — Honest about certificates.** The project does not assume a purchased certificate. A long-lived (10 y) self-signed code-signing certificate is minted **once**, stored as CI secrets, with its public DER hash committed. Azure Artifact/Trusted Signing (~$9.99/mo per 5 000 signatures, legal-name CN requirement, no EV) and paid EV are recorded as alternatives — a plan requiring a control the maintainer cannot operate is a plan that gets skipped, which is itself the vulnerability.

## T-A release pipeline (sign-before-bundle)

```
import stable PFX → cargo build --release (engine) → sign aether.exe → verify signature
→ stage engine → verify staged file digest == engine-trust.json entry        [NEW GATE]
→ npm ci && npm run build → npm run tauri build --config '{"bundle":{"windows":
     {"certificateThumbprint": …, "digestAlgorithm":"sha256","timestampUrl": …}}}'
→ EXTRACT installer (7z) and verify EVERY embedded .exe/.dll we own          [NEW GATE]
→ write/refresh release digests (post-signing) → upload
```

Tauri's bundler performs the signing itself: it signs the main exe after `patch_binary` (`bundle.rs:155`), signs `externalBin` sidecars while skipping already-signed files (`:296-336`), signs NSIS plugins (`nsis/mod.rs:672-679`) and the uninstaller (`:306`), the outer installer (`:717`), and `resources/*` excluding already-signed files (`:792`) — so wintun's own WireGuard LLC signature survives. Authenticode and the Tauri **updater** signature are unrelated: `TAURI_SIGNING_PRIVATE_KEY`/`createUpdaterArtifacts` produce a minisign signature over the update archive and never sign the PE.

**T-A8 — Verification must inspect the shipped thing.** The current "Verify all packaged Windows binaries" step checks only the outer `setup.exe`, which is why "sign Windows outputs after Tauri build" left the installed GUI unsigned. A check that inspects the wrong artifact is worse than no check, because it records a pass.

**T-A9 — Fail closed on emptiness.** The verifier errors if it finds **zero** embedded binaries, so a changed NSIS layout cannot make the gate vacuous.

## T-B: Peer trust

**T-B1 — Pinning adds to verification; it never replaces it.** Inside the callback: `ctx.verify_cert()? && pin_matches(host, leaf)`. Today `set_verify_callback(SslVerifyMode::PEER, move |_ok, ctx| …)` discards `Ok`, so BoringSSL performs no chain building, no signature check, no validity-period check and no hostname check; `masque_h2.rs` additionally calls `set_verify_hostname(false)`.

**T-B2 — Pins are per-host and expiring.** `PinSet { host, require_hostname, pins: [Pin{spki_sha256, expires_unix}] }`, ≥2 pins per host (live key + next key). The current flat two-entry global set means either edge key authenticates **any** peer.

**T-B3 — SNI fronting preserved.** Dial the pinned host for verification and set the fronting SNI separately (`into_ssl(PIN_HOST)` then `set_hostname(front_sni)`); the fronted name gets its own `require_hostname: false` entry. The current global hostname-verification-off exists to work around a per-name problem.

**T-B4 — No ambient bypass.** `VerifyPolicy` is an explicit parameter of the TLS builders, never read from the environment. Both kill-switch variables are deleted. Today `h3_probe.rs:252` writes the switch via `runtime_env::set` while `tls.rs:128` reads `std::env::var` — simultaneously inert (the fingerprint probe's advertised mode never applies) and one accessor change away from being a live process-wide MITM switch.

**T-B5 — Empty or fully-expired pin set is an error**, not `SslVerifyMode::NONE` (`tls.rs:31-33` today).

**T-B6 — Failures are visible.** `error!` + `SessionEvent::Error` naming host, observed leaf SPKI in hex, the `X509VerifyResult`, and the pin expiry date. Today a lost pin is `log::debug!`.

**T-B7 — TLS floors.** TLS 1.3 on both H3 and H2 (H2 currently floors at 1.2). The "rotate client hello profile" control uses `set_ciphers13`/signature-algorithm permutation — `set_cipher_list` governs only pre-1.3 suites, and its `let _ =` currently hides failure.

**T-B8 — Read-only probe isolation.** `fingerprint_h3`'s no-pin mode is `VerifyPolicy::ReadOnlyProbe`: chain-verified, unpinned, and structurally unable to affect tunnel traffic.

**T-B9 — Diagnostics never mutate global trust state** (supersedes the sticky `runtime_env::set` of a verification switch).

## Verification

| Test | Falsifies |
|---|---|
| Release TUN with an engine signed by a **different** `CN=deathline94` certificate ⇒ refuse | T-A2/A3 (proves the pin is reachable, not tautological). |
| Build with signing disabled ⇒ `scripts/verify-installers.ps1` exits non-zero | T-A8/A9. |
| Delete the call to `ctx.verify_cert()` ⇒ the expired-pin test still passes | T-B1 — the test must fail, proving chain validation is load-bearing in the callback. |
| Compile-fail `VerifyPolicy::Insecure` in release; string-grep the binary | T-A6, T-B4. |
| `AETHER_MASQUE_DISABLE_SPKI_PINS=1` in release ⇒ no effect | T-B4. |
| `pins = []` ⇒ `Err` | T-B5. |
| CI recomputes the staged engine digest and diffs `engine-trust.json` | T-A2. |
| Overwrite `engine-trust.json` with a wrong digest in a throwaway job ⇒ runtime test goes red | T-A2 (anti-tautology). |
