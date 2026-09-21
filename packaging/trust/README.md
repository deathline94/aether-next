# packaging/trust

Committed witnesses for two different questions. Keeping them separate is the
point: the bug this directory replaces was one file being used to validate
itself.

| File | Question it answers | Written by |
|---|---|---|
| `engine-trust.json` | "is this executable the one we published?" | the release job, **after** signing, as a reviewable one-line diff |
| `masque-pins.json` | "is this TLS peer the edge we mean?" | a human, when Cloudflare rotates a key |

## `engine-trust.json`

`build.rs` embeds this file's bytes and hash. It must **never** compute a digest
from `resources/aether.exe` — hashing the artifact you are about to ship makes
the runtime comparison a tautology, and because `resources/*.exe` is gitignored
a clean checkout hashed *nothing* and emitted no entry at all, so the
"missing digest is an error" guard was unreachable in CI.

Placeholder digests are all-zero on purpose. `trust::load_anchors()` accepts the
shape and rejects an empty file list, so a build with no release digests fails
at the digest comparison rather than passing on an empty allow-list.

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
