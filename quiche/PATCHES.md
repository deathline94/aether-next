# Vendored `quiche/` — provenance and patch manifest

`quiche/` in this repository is **not a git submodule and not a git subtree**. There is
no `.gitmodules`, and no `git submodule status` output exists for it. It is a plain copy
of Cloudflare's quiche tree, imported whole in commit `3c4fb69` ("Aether Next",
`quiche/` = 2 147 tracked files) and edited in place.

`specs/015-full-audit-remediation/spec.md` §Scope guards claimed the tree is "patched in
place at a pinned tag with a patch manifest", and `plan.md` recorded the decision as
"pinned-checksum-plus-patch-manifest". Until this file and
`packaging/trust/quiche-vendor.json` existed, neither half of that claim was true. Both
halves are true now, and this file is the record they refer to.

## Base commit

| | |
|---|---|
| Upstream | <https://github.com/cloudflare/quiche> |
| **Base commit** | `c4c0b978461aa153399a90217d85bebd1800f84d` — *"tokio-quiche: ensure ConnectionMap is updated regularly"* |
| Position | 3 commits after tag `0.29.2`, 12 commits before tag `0.29.3` |
| Tag `0.29.2` | annotated tag `f77fdc75bf58807321e59fda3996b8373728fadd` → commit `839b23d0edcc98aa1cf90c2cf0797b8cc56d4f15` |
| Declared version | `quiche/quiche/Cargo.toml` = `0.29.2`, `quiche/tokio-quiche/Cargo.toml` = `0.19.0`, `quiche/octets` = `0.3.5` |

**The declared version is not the provenance.** `aether/Cargo.lock` and
`quiche/quiche/Cargo.toml` both say `0.29.2` only because quiche bumps `version` at
release time; the *content* is from an unreleased commit on `main` between `0.29.2` and
`0.29.3`. A future auditor who pins this tree to tag `0.29.2` will get 17 mismatched
files and conclude the vendor copy is corrupt. It is not — `0.29.2` is simply the wrong
answer, which is exactly why the base commit is recorded above.

### How the base was determined

`c4c0b97` is the only commit in `0.29.2..0.29.3` whose tree matches this one outside the
six files listed below. Method: partial clone of upstream, then for each commit in the
range compare the CR-stripped content of every file the two trees disagree on
(`git show <c>:<path> | tr -d '\r' | git hash-object --stdin`). 16 of the 20 candidate
commits in the range produce ≥4 mismatches; `c4c0b97` produces exactly the 6 documented
deviations, and every other file in `quiche/` is byte-identical to it.

### Line endings — read this before diffing against upstream

The vendored tree was committed with **CRLF** line endings; upstream is **LF**. A plain
`diff -r quiche /path/to/upstream` therefore reports 329 differing files and hides the
real patch surface completely. Every comparison in this file uses CR-stripped content,
and so does `scripts/verify-quiche-vendor.mjs`. There is no `.gitattributes` normalising
this yet; adding one would rewrite all 2 147 files, so it is deliberately left alone and
documented instead.

## Deviations from the base

33 hunks across 6 files, +173 / −27 lines. Reproduce with:

```sh
git clone --filter=blob:none https://github.com/cloudflare/quiche /tmp/quiche
cd /tmp/quiche && git checkout c4c0b978461aa153399a90217d85bebd1800f84d
diff -r --strip-trailing-cr -p /tmp/quiche <repo>/quiche
```

### A. Aether-original: anti-DPI Initial CRYPTO fragmentation

`quiche/quiche/src/lib.rs` — 9 hunks, +42 / −2. The only Aether-authored Rust code in the
vendor tree. One feature, `Config::set_initial_crypto_fragment(usize)`, threaded through
`Config` → `Connection` → the packet writer, which splits the client Initial's
ClientHello so the first Initial carries only N CRYPTO bytes and the remainder is forced
into a separate datagram. This defeats DPI that reads SNI from the first Initial only;
each Initial is still padded to the 1200-byte minimum, and multi-packet CRYPTO with
offsets is standard QUIC, so a spec-compliant server reassembles transparently.

| Line (HEAD) | Site |
|---|---|
| `lib.rs:598` | `Config { initial_crypto_frag: Option<usize> }` field |
| `lib.rs:934` | `pub fn set_initial_crypto_fragment(&mut self, v: usize)` (0 disables) |
| `lib.rs:1377` | `Connection { initial_crypto_frag }` field |
| `lib.rs:4081` | `send_on_path`: stop coalescing after an Initial with CRYPTO left buffered |
| `lib.rs:4147` | `do_write`: copy the fragment size out before the field borrows below |
| `lib.rs:5074` | CRYPTO frame writer: cap the **first** Initial fragment (`crypto_off == 0`) |

Every hunk is marked `Aether anti-DPI` in place, so `grep -rn "Aether" quiche/` finds the
whole of class A — and nothing else, which is the point of enumerating classes B and C
here.

### B. Aether-original: dependency pin

`quiche/Cargo.toml` — 1 hunk, +1 / −1: workspace `boring` `4.3` → `4.22`. This is what
`aether/Cargo.toml`'s direct `boring = "4.22"` resolves against, so it is load-bearing
for the `boringssl-boring-crate` feature the engine uses.

### C. Verbatim forward-port of an upstream security fix — NOT an Aether change

4 files, 23 hunks, +130 / −24, byte-identical (CR-stripped) to upstream commit
**`8215ecdd74a809f1389784c5cd694fa1603d8da7`** — *"qpack: fix size calculation when
decoding"*, part of the QPACK/HPACK header-bomb hardening series that landed after our
base and before `0.29.3`:

| File | Upstream blob at `8215ecdd` |
|---|---|
| `quiche/octets/src/lib.rs` | `get_huffman_decoded_with_max_length`, bounds decoded output before allocation |
| `quiche/quiche/src/h3/qpack/decoder.rs` | charges name+value+32 B overhead against the remaining `HeaderListTooLarge` budget |
| `quiche/quiche/src/h3/qpack/mod.rs` | tests for the above |
| `quiche/quiche/src/h3/stream.rs` | `PRIORITY_UPDATE_FRAME_PAYLOAD_MAX_SIZE = 256` (RFC 9218 §7.2) → `Error::ExcessiveLoad` |

These carry **no** local marker, so nothing in the tree distinguishes them from class A.
Anyone re-running the anti-DPI grep will conclude quiche is otherwise pristine and
silently drop the header-bomb fix on the next re-vendor — the exact "an upgrade cannot
silently change semantics" failure `tasks.md` T236 was written to prevent. Recording the
upstream commit here is what closes it.

Not deviations, though an earlier task said they were: `tasks.md` T236 named
`dgram_recv`'s pop-before-length-check, `to_wire()`'s non-standard
`BufferTooShort -> 0x999`, and the `h3::Error != quiche::Error` distinction as things the
*fork* did. All three files are byte-identical (CR-stripped) to the base commit, so they
are upstream 0.29.x behaviour, not local patches. They are still real hazards - they are
why the engine has to know `h3::Error` and `quiche::Error` apart - but they belong in the
engine's comments, not in a patch manifest. Recording them as patches would have made the
next re-vendor "re-apply" a bug that was never ours.

### A-prime. The same feature, at its other five call sites

`Config::set_initial_crypto_fragment` is only half of class A — the other half is the
engine's consumer side in `aether/src/tls.rs` (`config.set_initial_crypto_fragment(frag)`,
`tls.rs:321`), which is not part of the vendor tree and is
therefore outside this manifest's scope. It is listed here only so that the 6 marker hits
and the 1 setter are not mistaken for 6 independent patches: they are one feature, threaded
`Config` (598) → setter (934) → `Connection` field (1377) → coalescing break (4081) →
local copy (4147) → frame cap (5074).

### D. Upstream paths dropped at import

Present upstream at the base, absent here: `AGENTS.md` and `fuzz/mayhem/*/testsuite`.
Neither is reachable by the engine (the `fuzz` crate is `exclude`d from the workspace),
but they were removed without a note, so a re-vendor must not treat their absence as
intentional content trimming.

## The checksum

```
packaging/trust/quiche-vendor.json
  tree       = sha256 over "sha256(CR-stripped bytes)  <path>" for every tracked file
               under quiche/, sorted, UTF-8, LF-joined
  files      = per-file digests, so a failure names the file instead of the tree
```

Regenerate and re-pin after a deliberate re-vendor or a new recorded patch:

```sh
node scripts/verify-quiche-vendor.mjs --write      # re-records the pin
node scripts/verify-quiche-vendor.mjs              # checks it
node scripts/verify-quiche-vendor.mjs --selftest-fail  # proves a tamper goes red
```

`quiche/PATCHES.md` is excluded from its own digest; the pin lives outside `quiche/`.
A re-pin is a human-review event per `spec.md` §User Story 8 — patch-manifest changes to
`quiche/` are on the manual-review-gate list, so this file and the pin must move in the
same commit as the bytes they describe.

## Upgrade rules

1. Re-vendor onto a **tag**, not a loose `main` commit, and update the base commit above.
2. Re-apply class A by hand (it is 42 lines) and re-apply class B; class C should
   disappear on its own once the base is ≥ `8215ecdd`.
3. Re-run `node scripts/verify-quiche-vendor.mjs --write`, then the diff of
   `packaging/trust/quiche-vendor.json` is the reviewable evidence of what moved.
4. Do **not** convert to a submodule to fix this: `spec.md` §Out of scope allows it but a
   submodule cannot carry classes A and B, so it would need a fork remote anyway.
