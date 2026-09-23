# packaging/trust

Committed witnesses for two different questions. Keeping them separate is the
point: the bug this directory replaces was one file being used to validate
itself.

| File | Question it answers | Written by |
|---|---|---|
| `engine-trust.json` | "is this executable the one we published?" | `scripts/publish-engine-trust.mjs`, after signing, as a reviewable one-line diff |
| `masque-pins.json` | "is this TLS peer the edge we mean?" | a human, when Cloudflare rotates a key |

## `engine-trust.json`

`apps/desktop/src-tauri/build.rs` embeds this file's bytes and hash and derives
`EMBEDDED_RELEASE_HASHES` from it alone. It must **never** compute a digest from
`resources/aether.exe` — hashing the artifact you are about to ship makes the
runtime comparison a tautology, and because `resources/*.exe` is gitignored a
clean checkout hashed *nothing* and emitted no entry at all, so the "missing
digest is an error" guard was unreachable in CI.

An absent, truncated (< 256 bytes), unparseable, or incomplete anchor (no entry
for `aether.exe` or `wintun.dll`, or a digest that is not 64 hex characters) is a
**hard compile error**. That is deliberate: a check that cannot fail is worse than
no check, and every one of those shapes previously produced a silently empty
allow-list.

`file_sha256` is SHA-256 over the artifact's bytes; `cert_sha256` is SHA-256 over
the signing leaf certificate's DER (**not** the SHA-1 value
`Get-AuthenticodeSignature` prints as `Thumbprint`); `issued_cn` is what
Authenticode reports as the subject. Publish them with the script rather than by
hand — the anchor's `wintun.dll` entry was previously a hand-written digest that
had never been measured, and it did not describe the DLL in this repository.

### What an all-zero digest means

No witness has been published for that artifact. Nothing on disk can match it, so
a **release** build refuses with `anchor_not_published` — an error that names the
missing pipeline step instead of looking like a tampered install — and a debug
build, which asserts nothing about release provenance, continues. The committed
file keeps `aether.exe` at zero because a signed engine only exists inside a
release run.

### Who publishes it, and why that is not circular

`.github/workflows/prepare-anchor.yml` — a separate, manually-triggered,
environment-protected workflow — builds and signs the engine, rewrites the matching
`file_sha256`/`cert_sha256`, and opens a pull request. It never pushes to `main`.
`build.yml` does **not** publish: it only runs `publish-engine-trust.mjs --check` at two
points (after staging, after packaging), so a tag build that has no committed witness for
the engine it staged fails instead of rewriting its own anchor. That separation is the
whole point: the value is measured by a different run than the one that consumes it, and
`--check` re-measures the bytes that actually ship. Because the CI certificate is
ephemeral (self-signed per run), the run's anchor is uploaded with the artifacts
(`dist-windows/engine-trust.json`, and inside the portable zip) so the digests a build
will accept are always readable next to it.

To build a release yourself: run `publish-engine-trust.mjs` locally for both artifacts
against the engine you signed, then `npm run tauri build`. Without it, `build.rs` stops a
release build outright — see `Docs/GUIDE.en.md` § Build notes for the exact sequence and
for what `AETHER_ALLOW_UNWITNESSED` does and does not let you ship.

## `wintun.dll`: a pinned third-party binary whose certificate has already expired

`packaging/wintun.dll` is measured like everything else, and its entry is real:

| | |
|---|---|
| Provenance | WireGuard LLC (Jason A. Donenker), `FileInternalVersion`/`FileVersion` **0.14.1** |
| Authenticode | `Status = Valid` — verified on this checkout, 2026 |
| Leaf `NotAfter` | **2021-12-14** |
| Leaf SHA-1 (as printed by `Get-AuthenticodeSignature`) | `DF98E075A012ED8C86FBCF14854B8F9555CB3D45` |
| Anchor `cert_sha256` (SHA-256 over the leaf DER) | `c9e1b3127c2f1312056d49a93ac4bd700393fd323d2bf3b2235aff52bea8d136` |
| Anchor `file_sha256` | `e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce` |

The leaf expired four years ago and the signature is still `Valid`, because it carries an
RFC 3161 counter-signature: Authenticode judges the bytes as of the moment they were
signed. **That is a property of this one binary, not a general licence to accept expired
chains** — the moment the timestamp is stripped or a different copy is dropped in, the
status flips to `TimestampMismatch`/`NotTrusted` and `.github/scripts/sign-windows.ps1`
refuses it.

The cost of pinning both digests is that **the driver cannot be updated in place.**
Replacing `packaging/wintun.dll` — for a newer WireGuard release, a Windows compatibility
fix, or because a CVE lands on 0.14.1 — changes `file_sha256`, which changes the bytes
`build.rs` embeds, which invalidates the witness. There is no shortcut around re-cutting
it. Procedure:

1. Obtain the release from <https://www.wintun.net/> (in-tree builds are published by
   WireGuard LLC; anything else is not the same artifact).
2. Confirm the copy you are about to commit before you touch the anchor:
   ```powershell
   Get-AuthenticodeSignature packaging\wintun.dll | Format-List Status,StatusMessage
   (Get-Item packaging\wintun.dll).VersionInfo.FileVersion
   (Get-FileHash -Algorithm SHA256 packaging\wintun.dll).Hash.ToLower()
   ```
   `Status` must be `Valid` and the subject must still be `CN=WireGuard LLC`. A
   `NotTrusted` result means the chain no longer validates even at its own timestamp —
   stop.
3. Replace the file **and** re-publish its anchor entry in one commit, via the script
   rather than by hand (the previous `wintun.dll` digest in this repo was hand-written and
   never measured):
   ```powershell
   node scripts/publish-engine-trust.mjs --name wintun.dll `
     --file packaging/wintun.dll --cert-sha <sha256-of-leaf-der> --cn "CN=WireGuard LLC"
   node scripts/publish-engine-trust.mjs --check --name wintun.dll --file packaging/wintun.dll
   ```
   Update the table above in the same commit; a stale digest table in this file is how the
   next person re-introduces a hand-written one.
4. Land both `packaging/wintun.dll` and `packaging/trust/engine-trust.json` together. A
   commit containing one without the other is a build that refuses its own driver.
5. The engine's staged copy under `apps/desktop/src-tauri/resources/wintun.dll` is a build
   artifact (gitignored) — CI re-stages it, and `build.yml`'s "Verify all packaged Windows
   binaries" step re-checks the copy that ships.

Old and new cannot coexist in the anchor: `files[]` keys on `name`, so this is a
replacement, not a rotation with a dual-pin window like `masque-pins.json` gets below.
Ship the bump, and if TUN mode refuses to start on a user's machine, that is the witness
doing its job — the fallback is proxy mode, not a relaxed check.

## Authenticode and the updater signature are unrelated

`TAURI_SIGNING_PRIVATE_KEY` / `createUpdaterArtifacts` produce a **minisign**
signature over the update archive. It attests nothing about the PE files inside:
an update can carry the right minisign signature and an unsigned or replaced
`aether.exe`. Authenticode is the only thing that says who produced the binary
the OS is about to load, and the runtime checks above are the only thing that
binds the shipped engine to the shipped shell. Do not treat "the updater accepted
it" as "we verified it".

Rejected alternatives, with the reason each was rejected — a control the
maintainer cannot operate is a control that gets skipped:

- **Paid EV code signing**: requires a hardware token or cloud HSM and a
  legal-entity OV history; the organization check has no path for an unincorporated
  individual, and the multi-day issuance blocks the release cadence this repo uses.
- **Azure Artifact Signing** (~$9.99 / month per 5 000 operations): EV-grade
  certificates there still require a registered legal-name common name, which an
  unincorporated maintainer cannot obtain, and every release would additionally
  depend on a subscription staying paid and a quota staying unfilled.
- **Installer-run `certutil -addstore TrustedPublisher`**: adds the signing
  certificate to the machine's trusted-publisher store at install time. That
  permanently widens what the OS will load for *every* program on the box, to
  work around a check that is meant to be ours. It is the opposite of the control.

## `masque-pins.json`

Pins are per-host with an expiry. `trust::active_pins()` treats "every pin for
this host is expired" as a hard error and warns below two unexpired pins, so
rotation is a planned edit rather than a surprise outage. Expiry is capped at
180 days by policy (`trust::MAX_PIN_VALIDITY_SECS`).

Each active pin carries a `MEASURED <date> …` note and the digest of the leaf
it was measured from. `trust::active_pins()` refuses an unmeasured key, and
`node scripts/verify-masque-pins.mjs` checks the committed file. The old
`UNMEASURED FALLBACK` key was removed after the local measurement failed to
find it; its earlier presence would have allowed an unaudited key to authenticate
a peer. The standalone gate also refuses `require_chain`/
`require_hostname` set to `true` without a note recording a verifying chain or a
covering SAN).

The digests are no longer carried over blind. Measured on 2026-09-23 with
`openssl s_client -connect <ip>:443 -servername <sni> -showcerts` (TCP and
`-quic -alpn h3`) against the MASQUE VIPs `162.159.198.2` / `162.159.199.2` and
eight generic Cloudflare anycast edges. The findings, exact per-host result and
instructions for a second-vantage check are recorded in the file:

1. Both hostnames now have the measured key seen on both transports. The
   unmeasured second digest was removed; adding it back requires a real leaf
   measurement from the region that serves it.
2. `require_hostname` stays `false` on evidence — the live edge's SAN is
   `masque.cloudflareclient.com`, which names neither dialled SNI — and
   `require_chain` stays `false` on evidence too: that peer sends one
   certificate, issued by a Cloudflare-private self-signed root, so chain
   building cannot succeed. The earlier plan ("flip `require_chain` once the
   per-host split has moved the self-signed digest away") is now known to be
   unachievable by splitting: the leaf a peer presents is chosen by the IP
   dialled, not by the SNI. Turning either check on needs an endpoint-keyed
   policy, which is a code change, not a line in this file.

## Rotation procedure

1. Obtain the new leaf's SPKI: `openssl x509 -in leaf.pem -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256`.
2. Add it alongside the outgoing pin, with `note` starting `MEASURED <date>` and
   `cert_sha256` set to the leaf it was read from. Do not remove the old one yet.
3. Ship. Wait for the fleet to pass the boundary.
4. Delete the old pin, and only then bump `expires_unix` on the survivor.

A single-pin window is what turns a routine key rotation into an outage.
