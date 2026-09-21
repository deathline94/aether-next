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

`.github/workflows/build.yml` runs the publish step between *engine staged* and
*app compiled*, so the shell is compiled against the digest of the engine that
run produced and signature-verified. It is still a separate witness from the
comparison: the value is read from the staged file before the checker exists, and
`--check` re-measures the bytes that ship at the end of the pipeline. Because the
CI certificate is ephemeral (self-signed per run), the run's anchor is uploaded
with the artifacts (`dist-windows/engine-trust.json`, and inside the portable
zip) so the digests a build will accept are always readable next to it.

To build a release yourself: run the publish step locally for both artifacts
against the engine you signed, then `npm run tauri build`. Without it, TUN mode
refuses to launch the engine and proxy mode is unaffected.

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

The digests are carried over from `aether/src/consts.rs::MASQUE_PINS` unchanged.
Two deliberate non-changes are recorded inline in the file, because guessing at
them would trade a fixed bug for an outage:

1. both digests remain listed under both hostnames — which digest belongs to
   which SNI must be observed from a live handshake, not inferred;
2. `require_hostname` stays `false` — the peer is dialled by IP address, so
   tightening it needs the same live pass.

## Rotation procedure

1. Obtain the new leaf's SPKI: `openssl x509 -in leaf.pem -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256`.
2. Add it alongside the outgoing pin. Do not remove the old one yet.
3. Ship. Wait for the fleet to pass the boundary.
4. Delete the old pin, and only then bump `expires_unix` on the survivor.

A single-pin window is what turns a routine key rotation into an outage.
