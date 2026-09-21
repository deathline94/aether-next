# Contract: Secret Envelope, Learned State & Local Proxy Policy

**Feature**: `015-full-audit-remediation` | Applies to: `aether/src/{config.rs,cache.rs,account.rs,socks.rs,http_proxy.rs,netstack.rs,dns.rs}`, `apps/desktop/src-tauri/src/lib.rs` (DPAPI), `apps/android/.../{ConfigKeyStore.kt,SettingsStore.kt}`

## S-A: Secrets at rest

**S-A1 — Mandatory encryption.** Identity (access token, WG private key, client id, MASQUE key PEM) is persisted only inside `ConfigEnvelope` (layout in `data-model.md` §2). With no key source, `save()` writes non-secret settings only and **refuses** secrets with an explicit message. Today `encode()` returns plaintext when `AETHER_CONFIG_KEY` is unset, so the identity sits in cleartext by default.

**S-A2 — Path-bound.** AAD = canonical absolute path + magic + schema version. Replaying one file's ciphertext onto another path is an authentication failure.

**S-A3 — Nonce discipline.** Fresh 12-byte random nonce per record under a given key, stored with the ciphertext; never derived, never reused (RFC 8439).

**S-A4 — No second copy.** `ReplaceFileW` with `lpBackupFileName = NULL`; the `std::fs::copy(path, &bak)` fallback and the `.bak`-trusting branch in `load()` are deleted. Today a leftover `.bak` — written outside the ACL-restricted writer — is copied back over the live file with its error ignored, so a planted file becomes the identity.

**S-A5 — Key custody is never ambient.** The data key is handed to the child over **stdin** once and removed from the environment; `AETHER_CONFIG_KEY` disappears from the child's env block. On non-Windows, DPAPI's stand-in is not "no-op": macOS uses Keychain, Linux uses `libsecret`, and an unavailable service means S-A1's refuse-secrets path. Today `encrypt`/`decrypt` are identity functions off-Windows, so `config_key.dpapi` holds the master key in plaintext.

**S-A6 — Zeroization.** `ZeroizeOnDrop` on `Identity`, `Zeroize` on key arrays, pass by reference instead of copying a private key by value once per scanned IP:port. `zeroize` is currently a declared dependency used nowhere in the engine. Key generation from `OsRng`, not `thread_rng`.

**S-A7 — ACL principal.** SID from the process token or active console session, never `%USERNAME%`, with a protective descriptor (see `host-state-contract.md` for who owns the file: the GUI, not the elevated child).

**S-A8 — Android: transient ≠ corrupt.** Retry 3× on `KeyStoreException|ProviderException|UnrecoverableKeyException`, then fail loudly. Only `BadPaddingException`/short-buffer may trigger rotation, and rotation writes the second wrapping (`…-v1`/`…-v2`, B last, both validated before promoting) before anything is discarded. Today `loadOrCreate` routes **any** exception into `rotateAndRecover()`, which deletes the alias and quarantines the config — one transient `keystore2` failure permanently costs the user's WARP identity.

**S-A9 — No secret material in logs, events or diagnostics.** Preserved (audited clean today); enforced by a CI grep on the log call sites.

## S-B: Learned state (endpoint cache)

**S-B1 — Actor-owned.** One `EndpointRegistry` task owns the data; reads and writes are messages. No lock-free read path renaming files (today's `get_*_sorted` calls `load_endpoints` without the lock).

**S-B2 — Versioned and validated.** `{version, written_at, entries[]}`; clamped counters; `saturating_add`; timestamps `(epoch_secs, monotonic_ticks)` with `epoch > now+300` rejected and **decay on the monotonic term only** — a future `SystemTime` currently makes an entry immortal and permanently earns its freshness bonus.

**S-B3 — Provenance-bounded.** Every address must fall inside the compiled MASQUE/WG allowlists; entries outside are dropped and counted. Today the cache is unvalidated persisted input that directly orders connections.

**S-B4 — Never authoritative.** Cached endpoints may be re-verified, never preferred over fresh verification, and verification uses the transport actually in use. Today `quick_verify_masque` always probes over QUIC, so a healthy H2 gateway accrues three failures and is evicted (`session.rs:483-607`, `cache.rs:505-521`).

**S-B5 — Non-destructive reads.** Corrupt files are preserved as `.corrupt.<seq>`; the rename must never clobber a prior `.corrupt`.

**S-B6 — Locks cannot be stolen.** `CreateMutexW` / permanent-fd `flock`; never delete a lock you did not create; never fail open after a timeout. `fs2` advisory locks are not a mutual-exclusion guarantee, and `PROVISION_LOCK_STALE` is dead code.

**S-B7 — Directory fsync** after rename on Unix (currently the file is fsynced and the directory is not, so the rename is not durable across power loss).

## S-C: Local proxy surface

**S-C1 — Loopback by default, one gate.** Remote listeners require `AETHER_ALLOW_REMOTE_PROXY`; `AETHER_UNSAFE_PUBLIC_PROXY` is deleted (two variables today gate one behaviour, and neither is checked by the other's consumer).

**S-C2 — Post-resolution destination deny-list**, enforced once in `netstack::handle_cmd`: `127.0.0.0/8`, `::1`, `0.0.0.0/8`, `169.254.0.0/16` (IMDS), `100.64.0.0/10`, `fc00::/7`; RFC1918 opt-in. Post-resolution because only then is the actual destination known — a pre-resolution check is defeated by DNS rebinding. Today any local process can `CONNECT 169.254.169.254` **into** the tunnel, i.e. at the exit provider's metadata service.

**S-C3 — Credentials when exposed.** A non-loopback listener requires a per-session token; there is no unauthenticated exit.

**S-C4 — UDP origin fidelity.** The association's origin map is TTL+LRU per entry (never `map.clear()`, which today hands other flows' datagrams to one pinned client on every subsequent miss), and datagrams whose origin is unknown are **dropped**, never fallback-forwarded.

**S-C5 — Resolver reply authentication.** The ECH/HTTPS bootstrap parser validates the transaction ID, the `QR` bit, the echoed question name and refuses `TC`. `parse_https_ech` (`dns.rs:35-103`) checks none of them, so one spoofed reply attributed to 1.1.1.1 installs an attacker-chosen ECHConfigList. The proxy resolver already does this correctly and is the model.

**S-C6 — Randomised ephemeral source ports** (odd stride over the 2^14 band), so a DNS spoofing attempt cannot be retried cheaply against a predictable port.

**S-C7 — Request-line parsing uses one boundary rule.** `\r\n` for the request line and the rewrite point — today `text.lines()` splits on bare `\n` while `rewrite_absolute_uri` splices to the first `\r\n`, so a bare-LF request **loses its `Host:` header** on forwarding: a parse/response divergence of request-smuggling shape.

**S-C8 — Session caps are policy, not surprises.** `MAX_SESSION`/`MAX_CLIENTS` saturation yields an explicit refusal the client can see, not an accepted socket dropped with no SOCKS reply (RST) after a hard 4-hour cap.

## Verification

| Test | Falsifies |
|---|---|
| Ciphertext from path A read at path B ⇒ auth failure | S-A2. |
| `KeySource::None` ⇒ save writes no secret; file has no magic+secret payload | S-A1. |
| Plant a `.bak` with a foreign identity ⇒ `load()` ignores it | S-A4. |
| Android: `UnrecoverableKeyException` ×2 then success ⇒ alias survives, config intact; `BadPaddingException` ⇒ quarantine | S-A8 (both directions prove reachability). |
| Cache with future timestamp + 2^31 successes + out-of-allowlist address ⇒ all three rejected, ordering unaffected | S-B2, S-B3. |
| Force a poison `Get-NetRoute`-style concurrent writer ⇒ no lost update under `CreateMutexW` | S-B6. |
| `CONNECT 169.254.169.254:80` via 1819/1820 ⇒ refused | S-C2. |
| `GET http://a/ HTTP/1.1\nHost: a\r\n\r\n` ⇒ forwarded request still has `Host:` | S-C7. |
| Fill the proxy UDP quota ⇒ DNS still resolves ⇒ domain CONNECTs still work | S-C4 / quota partitioning. |
| Malformed ECH reply with a mismatched TX ID ⇒ ignored | S-C5. |
