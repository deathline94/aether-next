# Phase 1 Data Model — Full-System Audit Remediation

**Feature**: `015-full-audit-remediation` | **Date**: 2026-09-21
**Sources**: `spec.md` §Entities · `research.md` R1–R42 · current shapes in `aether/src/{config,cache,session,session_event,netstack,tun_win,runtime_env}.rs`, `apps/desktop/src-tauri/src/lib.rs`, `apps/desktop/src/types.ts`, `apps/android/.../{ConfigKeyStore,SessionController,AetherVpnService}.kt`

Field rules below are **binding acceptance criteria**. A row is a defect if shipped code violates it. "Rejection behaviour" is what must happen on invalid input — `drop+count` means the item is discarded, counted in a diagnostic, and startup continues; `fail-closed` means the operation is refused with a user-visible error.

---

## 1. RuntimeConfig (replaces the ambient environment)

Sole owner of every `AETHER_*` knob. `std::env::var` is forbidden outside this module (BC-04). Closes R18, and the `h3_probe.rs:252` ↔ `tls.rs:128` split-brain.

| Field | Type | Rules |
|---|---|---|
| `values` | `HashMap<String, String>` behind `parking_lot::RwLock` | Reads never fall through to the process environment after initial snapshot. |
| `snapshot` | `Snapshot` (immutable clone) | Handed to per-operation code so a mid-operation write cannot change a decision already made. |

**Accessors**: `var(key) -> Option<&str>`, `set(key, v)`, `remove(key)`, `flag(key) -> bool`, `usize_or(key, default) -> (value, wasParseError)`, `snapshot()`.

**Validation rules**
- `flag()` uses exactly one truthiness helper (`1/true/yes/on` true; `0/false/no/off/empty` false). Presence alone never means true. This fixes `wireguard.rs:429` where `AETHER_WG_NO_DATA_CHECK=0` **disabled** the check.
- Numeric parse failure is **reported**, not silently defaulted: `AETHER_QUIC_MAX_UDP_PAYLOAD=abc` must surface "invalid value, using 1350" as a warning, not revert silently.
- Lock acquisition uses `unwrap_or_else(PoisonError::into_inner)`; a poisoned map must never drop writes.

**Rejected values / removals**: `AETHER_DANGEROUS_DISABLE_TLS_VERIFY` and `AETHER_MASQUE_DISABLE_SPKI_PINS` are deleted (R18). `AETHER_WINTUN` is deleted from the engine's read path (R16). `AETHER_UNSAFE_PUBLIC_PROXY` is deleted; `AETHER_ALLOW_REMOTE_PROXY` is the single gate (R13). `AETHER_LASTCONN_PATH` is no longer an arbitrary write target — the path must be inside the per-user data directory.

---

## 2. Identity & ConfigEnvelope

`Identity` (secrets) is separated from `UserConfig` (non-secret settings) so a machine without a key source can still persist settings.

### Identity

| Field | Type | Rules |
|---|---|---|
| `access_token` | `SecretString` (`ZeroizeOnDrop`) | Never persisted without a key source. |
| `wg_private_key` | `[u8;32]` + `Zeroize`, `ZeroizeOnDrop` | Exactly 32 bytes; generated from `OsRng`; never copied by value into per-probe call graphs (pass by reference). |
| `client_id` | `[u8;3]` | A malformed decoded value is a **hard error**, not `[0,0,0]` (a zero tag is indistinguishable from every other broken client). |
| `masque_key_pem` | `SecretVec<u8>` | PKCS#8; envelope-only. |
| `ipv4`/`ipv6` | `Ipv4Addr`/`Ipv6Addr` (parsed, not `String`) | A malformed tunnel address is a fatal config error, never `unwrap_or(172.16.0.2)` — the current silent substitution produces a wrong source address that is then misreported as "QUIC is blocked". |

### ConfigEnvelope (on-disk)

```
offset 0   magic            b"AETHERCFG2\n"      (11 B)
offset 11  schema_version   u8                   (must == 2)
offset 12  nonce            [u8; 12]             (OsRng, unique per record under this key)
offset 24  ciphertext ‖ tag  ChaCha20-Poly1305
```

**AAD** = `canonical_absolute_file_path ‖ b"AETHERCFG2" ‖ schema_version`.

| Rule | Behaviour |
|---|---|
| Key source absent (`KeySource::None`) | `save()` writes **only** `UserConfig`; secrets are refused with an explicit error naming the consequence ("identity not persisted; run under the GUI shell or provision a key"). |
| Truncated / tampered body | `Err(Envelope::Truncated)` → quarantine; never falls back to plaintext. |
| Same ciphertext at a different path | **Authentication failure** (this is the replay fix; today an encrypted `aether-masque.toml` blob copies onto `aether.toml`). |
| Plaintext file found on load | Re-encrypt → verify read-back → only then overwrite; abort startup if the re-save fails. |
| `<path>.bak` present | **Ignored.** No auto-restore. `ReplaceFileW` is called with `lpBackupFileName = NULL` so no `.bak` is created. |
| Temp file naming | `{path}.{pid}.{seq}.{rand}.tmp`, created exclusive; mirrors the already-correct pattern in `cache.rs`. |
| Durability | Windows: `FlushFileBuffers` before replace. Unix: fsync file **and** parent directory. |
| Unknown TOML keys | `#[serde(deny_unknown_fields)]` — a mistyped `wg_priv_key` must not silently default. |

**File ACL** (Windows): descriptor `D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;<sid>)` applied with `SetNamedSecurityInfoW`, principal derived from the **process token / active console session**, never `%USERNAME%`. Preferred design (R21): the elevated child does not open this file at all — the GUI decrypts and hands configuration over the child's stdin.
> **As shipped (2026-09-22):** the principal rule is what the code does — `config.rs::restrict_windows_acl` grants `*<token SID>:F` and strips inheritance, through `icacls` rather than `SetNamedSecurityInfoW`, and **no** grant is made to SYSTEM or the Administrators group. The descriptor above was the original plan and was only ever built by a function nothing called; it is kept here as history. Do not "fix" the code back to it: the envelope is sealed with DPAPI against the user's master key, so those two trustees could read ciphertext and nothing else, which is a wider readable set for no extra recoverability.

---

## 3. EndpointRegistry (replaces the `cache.rs` free functions)

An **actor**: one task owns the data; every read and write is an `mpsc` request/response. The file is a write-behind snapshot only. This removes the "sorted getter reads without the lock" and "read path renames the file" defects by construction (R22).

### CachedEndpoint

| Field | Type | Rules |
|---|---|---|
| `addr` | `SocketAddr` | Must be inside a compiled `MASQUE_CIDRS_*`/`WG_PREFIXES_*` allowlist. Out-of-allowlist → `drop+count`. |
| `kind` | `CacheKind` **plus** `transport: TransportKind` | The cache slot is keyed by transport. Today H2 and H3 share one slot, so an H2 gateway verified over QUIC is always failed and evicted. |
| `successes`/`failures` | `u32` | Clamped to `MAX_SUCCESSES = 1000`; `total = successes.saturating_add(failures)`; `trust_score` inputs clamped. |
| `epoch_secs` | `u64` | Rejected if `> now + 300`. |
| `monotonic_ticks` | `u64` | **All decay uses this**, never the wall clock. Today a future `timestamp` makes `saturating_sub` yield 0 and the entry never decays while permanently earning the freshness bonus. |
| `consecutive_failures` | `u8` | Eviction threshold preserved. |

### EndpointsFile

```
{ version: 2, written_at, entries: [ … ] }
```
`#[serde(default)]` on both arrays so a partially-written file is recoverable rather than fatal. Corrupt file → `.corrupt.<seq>` with a **monotonic sequence**, never clobbering a prior `.corrupt` (today's `rename` overwrites it, destroying evidence). Reads are non-destructive.

### Locking

Windows `CreateMutexW` (kernel-owned; `WAIT_ABANDONED_0` reveals a dead holder). Unix `flock` on a permanent fd held for process life. Rules: never `remove_file` a lock the caller did not create; never fail open after a timeout; delete the dead `PROVISION_LOCK_STALE` constant. The existing `ProvisionGuard` (documented "never fails open") is the model to copy.

**Trust rule (global)**: a cached endpoint may be **re-verified**, never preferred over a freshly verified one. This is what makes cache poisoning non-authoritative even if the file is tampered with.

---

## 4. TrustAnchorSet, PinSet & VerifyPolicy

```
packaging/trust/engine-trust.json        (committed, human-reviewable, release-time generated)
  { files: [ { name, file_sha256, cert_sha256, spki_sha256, issued_cn, not_before, not_after } ],
    anchors: [ { name, der_sha256 } ] }

packaging/trust/masque-pins.json         (per-host SPKI pins with expiry)
  { hosts: [ { host, require_hostname, require_chain,
               pins: [ { spki_sha256, expires_unix, cert_sha256, note } ] } ] }
    # require_chain has no serde default: an omitted key is a load error, because a
    #   missing field used to decode to "discard BoringSSL's chain verdict".
    # note is provenance, not a comment: "MEASURED <date> …" (with the leaf digest it
    #   was read from) or "UNMEASURED FALLBACK …" naming the sweep that may delete it.
    #   active_pins() warns on a pin that is neither; trust.rs's committed-file test
    #   makes that a build failure for what ships.
```

**Provenance rule**: these files are written by the **release job after signing** and reviewed as a diff. `build.rs` embeds the *bytes and hash of the anchor file*; it never hashes `resources/aether.exe`. This is the fix for the self-referential pin — today `build.rs:38-53` hashes the shipped file, so the runtime check can never fail, and `resources/*.exe` is gitignored so on a clean checkout it hashes **nothing** and emits no entry, meaning the "missing digest is an error" guard is unreachable.

### VerifyPolicy (compile-time honest)

```rust
enum VerifyPolicy<'a> {
    Pinned(&'a [PinSet]),      // only variant constructible in release
    ReadOnlyProbe,             // chain verification, no pins; never used for tunnel traffic
    #[cfg(debug_assertions)]
    Insecure { reason: &'static str },   // variant does not exist in a release binary
}
```
Empty pin set or all-pins-expired → `Err`. Failure surface: `error!` + `SessionEvent::Error` naming host, observed leaf SPKI in hex, `X509VerifyResult`, and the expiry date — replacing today's `log::debug!`.

### Binary trust verification order (before spawn, every mode)

```
1. resolve absolute canonical path            (parent-supplied; no env, no CWD)
2. file SHA-256 in anchor set                 (fail → refuse)
3. leaf certificate hash + SPKI hash == pin   (fail → refuse)
4. CertGetCertificateChain anchored at pinned leaf
5. CertVerifyCertificateChainPolicy(AUTHENTICODE)
6. WinVerifyTrust used only as a PE-digest check, WTD_REVOCATION_CHECK_NONE (0x40000),
   always WTD_STATEACTION_CLOSE               ← today: 0x80 mislabelled as NONE, IGNORE state action
```

`allow_unsigned_in_debug` is removed. Dev bypass = a compile-time-absent variant plus `option_env!("AETHER_DEV_TRUST")`.

**Validation rules**: verification is never conditional on `routing_mode`; every branch that resolves a binary (resource dir, portable loop, repo-build fallback, custom `enginePath`) passes through it; the trusted root is the exe directory **only**, not its parent (today `exe.parent().parent()` includes `C:\Program Files` on perMachine installs and a user-writable directory on portable, while the child is handed the DPAPI master key).

---

## 5. HostState: RouteJournal, ProxySnapshot, RepairRecord

### RouteJournal (written **before** any mutation)

```
{ version, created_at, creator_pid, creator_process_start_time,
  tun_luid, tun_alias, tun_if_index, phys_luid, gateway, peer_host,
  entries: [ { prefix, next_hop, family, proto: NetMgmt, valid_lifetime } ],
  before:  { adapter_dns, interface_metric, peer_route_present } }
```

| Rule | Behaviour |
|---|---|
| Identifiers missing/zero | Deletion restricted to routes whose **next-hop equals the recorded tunnel address**. Global prefix deletion is impossible. (Today `tun_if == 0 && phys_if == 0` removes `0.0.0.0/1` etc. from *every* interface — the exact shape of a coexisting corporate VPN's split tunnel.) |
| Two instances | The second refuses to mutate; a per-instance named mutex, not substring PID matching. (Today `s.contains(&pid.to_string())` matches "4" inside unrelated columns, so a dead holder looks alive and a second instance's cleanup deletes the first one's routes.) |
| Mutation failure mid-sequence | Journal records partial state; repair is idempotent and can complete or roll back. |
| Teardown failure | `log::error!` + event. Today every cleanup error is discarded with `let _ = ps(&script)`. |
| Route lifetime | 90 s lease, refreshed every 30 s, as a backstop — never the primary mechanism. |

### ProxySnapshot

Snapshots **all five** values with hard-fail reads (no `.unwrap_or(0)`): `ProxyEnable`, `ProxyServer`, `ProxyOverride`, `AutoConfigURL`, and per-connection `INTERNET_PER_CONN_PROXY_PAC`. Written before enabling, mirrored to `HKCU\Software\AetherNext\ProxyJournal`, 3-tuple read-back verified, deleted on success.

**Orphan sweep**: `ProxyEnable == 1 && ProxyServer == 127.0.0.1:<our port>` with **no** journal ⇒ clear and log. This closes the "recovery file deleted by AV" hole that the current file-only replay leaves open. `INTERNET_OPTION_SETTINGS_CHANGED` + `INTERNET_OPTION_REFRESH` fire after both directions.

### RepairRecord

Produced by `route_repair::run_unconditionally()`, called as the first action of shell startup in **every** routing mode, plus `aether.exe --repair-routes` for the uninstall path. Today the repair is reachable only from `tun_win::spawn`, so proxy-only users and uninstalls never repair a broken machine.

---

## 6. Settings (single Rust definition, generated TypeScript)

Becomes `#[derive(specta::Type, Serialize, Deserialize)]` with `#[serde(rename_all = "camelCase")]` (already in use), and `#[serde(default)]` on fields so hydration merges in Rust, not at render time (fixes the desktop white-screen on a dropped field). Stringly allowlists become enums:

| Old (stringly) | New |
|---|---|
| `ip_version ∈ ["auto","4","6","v4","v6","ipv4","ipv6","dual"]` with the UI sending `"both"` | `enum IpVersion { Auto, V4, V6, Dual }` — `"both"` becomes **non-representable**, and Scanner's working `"both"`/Settings' broken `"both"` collapse to one meaning. |
| `scan_mode ∈ [… "thorogh" …]` | `enum ScanMode { Turbo, Balanced, Thorough, Stealth, Fast, Deep, Auto, Ironclad }` — typo removed. |
| `protocol`, `transport`, `routing_mode`, `noize` | Real enums; engine `FromStr` accepts only the canonical spellings plus documented aliases, and unknown input is an error rather than "MASQUE by default". |
| `concurrency` UI `max=2000` vs `clamp(1,500)` | `Builder::constant("SCAN_MAX", 500)` exported into `bindings.ts`; one number, two consumers. |

**Rules**: every field is range-validated at the boundary (ports `1..=65535` and `≥1024` for listeners unless loopback-explicit; `u16` fields via `try_from`, so `AETHER_WG_KEEPALIVE=70000` errors instead of wrapping); a rejected save returns `Err(CommandError)` **and** the offending field name so the UI can render an inline error instead of an eternal "Auto-Saving".

**Removed**: `endpointPreset` (declared in TS, absent from Rust, read by nothing).

---

## 7. ScanRun & SessionEvent (typed across all three layers)

### ScanRun

```
{ run_id: u64, protocol, pool, ip_version, scan_mode, concurrency,
  started_at, phase: ScanPhase, endpoints: [...], cancelled: bool }
```

`run_id` is injected into the engine child as a control token and **echoed on every event**. Shell and UI drop non-matching events. Today there is no run identifier at all, so after Halt→Start the previous run's `scan_progress` overwrites the new totals (progress bar jumps backwards) and a late synthetic `scan_done` flips a live scan back to idle.

### SessionEvent / ScanEvent (NDJSON on engine stderr)

Rules (see `contracts/engine-event-protocol.md`):
- Engine emits `AETHER_EVENT {json}` lines, line-flushed; shell parses them into a **typed** `SessionEvent` (`serde_json::from_str`) instead of matching on `serde_json::Value`, so a new engine variant fails the shell's compile. Today `pump_scan_stream` forwards 4 of the variants and `_ => {}` silently discards the rest.
- `ScanDone` gains the missing `working` field, or the field is deleted from `types.ts` — the current TS declares `scan_failed` and `scan_done.working` that **no layer emits**, making `useScanner.ts:88-91` dead code and a failed scan read "Completed (0 found)".
- All JSON payloads are serialised with `serde_json`, never interpolated: today a peer-controlled HTTP header value lands inside `AETHER_EVENT {…,"detail":"{detail}"}` (`quic.rs:85-88`), letting the peer break or forge sibling fields.
- Every `rtt` field is `Option<u32>`, not an empty string — the engine emits `ScanDone { rtt: String::new() }` today, producing UI text like `best: 1.1.1.1:443 ()`.

### Readiness state machine (transport, per R2/R4)

```
Idle → Handshaking → ConnectSent → Established(localOnly: false)
                                        ↓  exactly one 2xx on req_stream
                                    Ready → TunnelReady (data-plane proof)
Interim(1xx)      → stay in ConnectSent (log, count)
OffStream(:status)→ ignored + counted (never latches)
SecondFinal / 3xx+ → Failed → teardown with reason=PeerRejected
LocalClosing      → Closing → Ended(Ok)      ← the ONLY path returning Ok(())
Any recv error ≠ Done → Ended(TransportError)
```
`quic.rs:627-680` currently maps every close — including a swallowed `recv` error — to `Ok(())`, and `session.rs:222-226` then records a **success** for the peer that killed the tunnel.

**Data-plane proof**: must validate that a reply to the session's own probe was received. `dns.rs:222 is_dns_reply` is `#[cfg(test)]`-only today; the live path accepts "any datagram (even ICMP errors)".

---

## 8. TunnelLiveness (Android, per R37)

```
{ baseline: [tx_packets, tx_bytes, rx_packets, rx_bytes],
  windows: VecDeque<WindowDelta>, attempts: u8, last_event: NetworkEvent }

decideLiveness(prev, now, elapsedMs, attempt) -> Alive | DeadRxOnly | DeadSilent | Exhausted
```

A pure function (unit-testable without a device). Rules: `rx advancing && tx frozen` for 3 windows (15 s) ⇒ Dead; all-zero for 6 windows (30 s) ⇒ Dead **only if** a concurrent foreground probe also failed; otherwise Alive. `attempts ≥ 3` ⇒ Exhausted ⇒ terminal `error` state, no auto-retry until the user taps connect. Backoff 2/8/30 s. `TProxyGetStats` counters are per-session and zero on each `hev_socks5_tunnel_main()` entry, so the baseline must be captured after start, not before.

`markConnected()` is replaced by a re-evaluable `connected: AtomicBoolean` with `resetConnected()`; today it is a one-shot compare-and-set that can never be revoked, so a dead path keeps a green badge.

---

## 9. NetStackReservation & frame accounting (per R8/R12)

| Entity | Field | Rule |
|---|---|---|
| `NetStack` | `mem_budget: u64` | 128 MB total. Grants 1 MB rx / 256 KB tx while ≥16 MB headroom remains, else 128 KB / 64 KB. Replaces 512 eager × 2 MB = 1 GB. |
| | `device.tx` | Bounded ring, `TX_RING = 256`; `transmit()` returns `None` at capacity. |
| | `counters` | `tx_deferred`, `dgram_dropped`, `inbound_dropped`, `frames_lost`, `cache_entries_rejected` — every silent-drop path has a number and is exportable in diagnostics. |
| `Quota` | `MAX_UDP_PROXY = 96`, `MAX_UDP_RESOLVER = 32`, `MAX_TCP_PROXY = 480`, `MAX_TCP_RESOLVER = 32` | Enforced per **class**, not per process. Today proxy UDP associations and internal DNS compete for one 128-slot pool, so a full scanner breaks DNS for every domain CONNECT. |
| `PortAllocator` | `next_port`, `stride` (odd), `live: HashSet<u16>` | Random start + odd stride across the 2^14-wide ephemeral band. Sequential ports make DNS spoofing cheap. |
| `TcpFlow` | `last_activity`, `state` | On `Established`: `set_timeout(75s) + set_keep_alive(15s)`. |
| | `pending: BytesMut` | Overflow is a **hard error to the writer**, not `half_closed = true` — today a >512 KB burst is acknowledged as sent and then discarded mid-stream. |

---

## 10. UiContracts: bindings.ts, tokens, log model (per R25/R32/R36)

### Generated types
`bindings.ts` is machine-generated and never hand-edited; CI regenerates and diffs. `RuntimeState` gains `handshake_rtt_ms: number | null` and `active_endpoint_rtt_ms: number | null`. `null` renders `—` with `aria-label="unavailable"`. Any metric without a measured source is **deleted**, not zero-filled (`"< 45 ms"`, `"0.0%"`, the hardcoded 16-value sparkline, `SOCKS5 READY` beside `DORMANT`, `TLS 1.3` on the WireGuard path).

### Log model
`LogEntry { id: u64, ts, level, message, source: "engine" | "scan_event" }`. The Hits filter is built from structured `scan_hit` events, not substring matching on prose — today each hit is counted twice (the human line **and** the raw JSON line each match a clause) and two clauses can never match (`EndpointSelected` vs serde's `endpoint_selected`; `"Selected edge"` exists nowhere). Buffer capped at `MAX_LOGS` at the single append site; rendering windowed.

### Design tokens
`--edge` (decorative separation, ≥1.6:1), `--edge-interactive` (control boundary, ≥3:1), one radius scale, one disabled-opacity value, one border-alpha set, `--muted` raised to ≥4.5:1 (today `#47535e` measures 2.4-2.6:1 and is the colour of every log timestamp and every numeric constraint hint). Rules: no `100vh`, no `transition: all`, no bare `:hover`, no `border: 1px solid rgba(255,255,255,<0.10)`, no undefined `var(--x)`, every `className` token resolves to a selector, no inline hex outside the token file.

---

## 11. Relationships

```
RuntimeConfig ──(sole reader)──► every engine module
EndpointRegistry ──owns──► CachedEndpoint[] ──snapshot──► EndpointsFile
        ▲                                                    ▲
        │ re-verify only, never prefer              CreateMutexW / flock
        │
Session ──uses──► TrustAnchorSet ──feeds──► VerifyPolicy ──guards──► TlsConfig
   │                └──(release job writes anchors AFTER signing; build.rs embeds anchor file only)
   ├──spawns──► EngineChild ──owned by──► EngineSupervisor(thread) ──owns──► Job(RAII)
   │                    └── emits ──► SessionEvent NDJSON ──► ScanRun(run_id) ──► bindings.ts types ──► UI
   ├──mutates──► HostState { RouteJournal, ProxySnapshot, RepairRecord }  (GUI-owned)
   └──persists──► ConfigEnvelope ──wraps──► Identity + UserConfig

Android:  AetherBridge(requestId) ─► SessionController(coroutine scope)
             ├─► TunnelLiveness ─► decideLiveness() ─► supervised restart
             └─► AetherVpnService ─► VpnBuilder (fail-closed exclusion)

Shared:   packages/ui ─► {tokens.css, components} ─► apps/desktop/src + apps/android/src
```

---

## 12. Migration & backfill

| Artifact | Detection | Action |
|---|---|---|
| Plaintext config | No `AETHERCFG2\n` magic | Re-encrypt → verify read-back → overwrite. Abort startup if the save fails (behaviour that already exists and is correct — preserved). |
| v1 envelope (no AAD) | Magic `AETHERCFG\n` / missing version | Read with the legacy rule, rewrite as v2; if the file is a copy, it will fail AAD — report it as "config copied from another location", not "corrupt". |
| Old endpoint cache (no `version`, no `transport`) | Deserialise with `#[serde(default)]` then upgrade | Entries default `transport` from their slot; entries outside the allowlist or with future timestamps are dropped **and counted**; on total rejection, log once and start empty rather than failing. |
| Legacy `tun-routes.json` without LUIDs/zero indexes | `version` absent or identifiers 0 | Repair in **next-hop-scoped** mode only; never global delete. Rewrite with `version` + LUIDs. |
| Orphaned system proxy | Enabled pointing at our listener, no journal | Clear + log, on every startup. |
| Stale `.bak` secret files | `<path>.bak` exists | Quarantine to a `.quarantined` name; never read as a source of truth. |
| `AETHER_CONFIG_KEY` in the child's environment | Present at spawn | Stop supplying it; key is handed over stdin once, then removed. |
| Committed `libhev-socks5-tunnel.so` | Present without `hev-lock.json` | Generate `hev-lock.json` from the current blobs (recording "provenance unknown, digest pinned as-is"), then replace with CI-built artefacts from the upstream tag; the digest change is the review event. |
| TypeScript hand-written types | `bindings.ts` absent | Generate; diff the generated file against the hand-written one **once** and record every mismatch as a defect confirmation rather than a silent reconciliation. |
| `.gitignore` holes | `*.key`/`*.pem` not ignored | Add ignores with explicit `!` exceptions for the vendored example keys already in `quiche/`. |
| Desktop vs Android UI forks | Both define the same component | Move to `packages/ui`; behavioural differences become props. The deliberate-difference list must end up empty or justified in writing. |

**Compatibility rule**: a reader must never fatal on a missing optional field, and a writer must never produce an artifact a previous version cannot parse without a `version` field. Every format above carries one.

---

## 13. Validation matrix (invariant → entity → test)

| Invariant | Primary entity | Falsifying test (fails against today's code) |
|---|---|---|
| BC-01 no plaintext secrets | ConfigEnvelope | Assert a saved file has the magic; assert `KeySource::None` refuses secret persistence. |
| BC-02 verify before spawn, all modes | TrustAnchorSet | Portable-fallback resolve → verification invoked; delete the call and the test fails. |
| BC-03 no release bypass path | VerifyPolicy | Compile-fail test naming `Insecure` in release; string-grep the built binary. |
| BC-04 one config reader | RuntimeConfig | `grep 'std::env::var("AETHER_'` returns only `runtime_env.rs`. |
| BC-05 no lock unwrap in lifecycle paths | EngineSupervisor | clippy `disallowed-methods`; inject a panic and assert the child is still reclaimed. |
| BC-06 no panic on hostile input | SessionEvent, DnsReply, NoizeHeader | Fuzz-shaped fixtures for each parser; no `unwrap`/`as`-truncation on wire data. |
| BC-07 fatal ≠ success | Readiness FSM | Peer-initiated close ⇒ `Err`; local close ⇒ `Ok(())`. |
| BC-08 generated types match | bindings.ts | CI regenerate + `git diff --exit-code`. |
| BC-09 IPC parity both ways | Settings, commands | Today 5 commands are registered and never invoked ⇒ must fail on unused-unlisted as well as missing. |
| BC-10 every class resolves | Design tokens | `className` extraction; `.metric-icon` (4 uses, 0 definitions) fails today. |
| BC-11 no banned CSS patterns | Design tokens | stylelint; `100vh`×8, `transition: all`×17, undefined-class failures today. |
| BC-12 contrast | Design tokens | Measured contrast: `#47535e` at 2.4:1 and `.05`/`.07` borders at 1.05-1.18:1 fail today. |
| BC-13 gates can fire | verify-invariants | `--selftest-fail` exits non-zero. |
| BC-14 no fabricated metrics | RuntimeMetrics | Regex for the literal strings; `<StatValue>` renders `—` on `null`. |
| BC-15 nothing blocks the bridge | AetherBridge | `invoke` returns < 50 ms behind a 12 s stub. |
| BC-16 run-id discipline | ScanRun | A `run_id: 1` event after scan #2 leaves the row count unchanged. |
| BC-17 versioned + validated files | RouteJournal, EndpointsFile | Future-timestamp / out-of-allowlist / zeroed-LUID fixtures all rejected. |
| BC-18 pinned provenance | hev-lock.json | Corrupt the lock file ⇒ build fails. |
| BC-19 budget honesty | ScanRun | `total` equals candidates actually examined under a real deadline. |
| BC-20 typed IPC errors | CommandError | `grep 'Result<.*String>'` in the shell returns nothing. |
| BC-21 APK compliance | build.gradle.kts, .so digests | `targetSdk < 36` or `p_align < 0x4000` ⇒ CI fails. |
| BC-22 one UI source | packages/ui | Same component name with two bodies ⇒ CI fails. |
