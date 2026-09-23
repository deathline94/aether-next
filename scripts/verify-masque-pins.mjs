#!/usr/bin/env node
// Gate: packaging/trust/masque-pins.json must be per-host, parseable by the same
// rules the engine applies, and every active pin must carry measured provenance.
//
// Why this exists next to `trust::load_pins`: the engine's loader cannot run here
// (the crate needs libclang + MSVC via boring-sys), so nothing on this machine
// executed the shipped trust file's rules until now. This mirrors
// aether/src/trust.rs (`PinFile`/`PinSet`/`Pin`, `load_pins`, `active_pins`) field
// for field, and adds the data contract the audit's ITEM 12 established:
//
//   * a pin is `MEASURED <date>` with the leaf's `cert_sha256` recorded so the
//     next rotation can be diffed; an unmeasured fallback is not a trust key;
//   * `require_chain` / `require_hostname` may only be true where the measured
//     certificate supports them: chain => a pin whose note records a verifiable
//     chain (`Verify return code: 0`); hostname => a note recording a SAN that
//     covers the host. Those two flags are the whole defect ITEM 12 was about, and
//     a true written without that evidence is a claim, not a policy.
//
//   node scripts/verify-masque-pins.mjs               # gate: exit 1 on a violation
//   node scripts/verify-masque-pins.mjs --selftest-fail  # prove the gate can fail
//   node scripts/verify-masque-pins.mjs --file <path>    # check another copy, e.g.
//       # the pre-measurement file, which it rejects: git show HEAD:packaging/trust/masque-pins.json

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const FILE = join('packaging', 'trust', 'masque-pins.json');

// trust::MAX_PIN_VALIDITY_SECS, restated here on purpose: a second reader that
// disagrees about the number is a finding, not a bug in this file.
const MAX_PIN_VALIDITY_SECS = 180 * 24 * 60 * 60;
const HEX64 = /^[0-9a-fA-F]{64}$/;

/** The subset of serde's behaviour `#[serde(default)]` + missing fields give. */
function parse(raw) {
  const doc = JSON.parse(raw);
  if (doc.version !== 1) throw new Error(`unsupported pin file schema ${doc.version} (expected 1)`);
  if (!Array.isArray(doc.hosts) || doc.hosts.length === 0) throw new Error('no hosts');
  return doc.hosts.map((h) => {
    if (typeof h.host !== 'string' || !h.host) throw new Error('host without a name');
    // `require_chain` has no serde default in the Rust struct; an absent key is a
    // load error there, and `missing(...)` is what proves that here.
    if (typeof h.require_chain !== 'boolean') {
      throw new Error(`host ${h.host}: missing require_chain`);
    }
    return {
      host: h.host,
      require_hostname: h.require_hostname === true,
      require_chain: h.require_chain,
      pins: (h.pins ?? []).map((p) => ({
        spki_sha256: p.spki_sha256,
        expires_unix: Number(p.expires_unix),
        cert_sha256: p.cert_sha256 ?? null,
        note: p.note ?? '',
      })),
    };
  });
}

/** trust::active_pins(), plus the evidence contract this file added. */
function validate(hosts, nowSecs) {
  const v = [];
  if (hosts.length === 0) return ['no pinned hosts: refusing to connect unverified'];
  for (const h of hosts) {
    if (h.pins.length === 0) v.push(`${h.host}: zero SPKI pins`);
    for (const p of h.pins) {
      if (!HEX64.test(p.spki_sha256 ?? '')) v.push(`${h.host}: malformed SPKI pin`);
      if (!Number.isFinite(p.expires_unix)) v.push(`${h.host}: pin without expires_unix`);
      if (p.cert_sha256 !== null && !HEX64.test(p.cert_sha256)) {
        v.push(`${h.host}: cert_sha256 is not a SHA-256 digest`);
      }
      const status = p.note.trim().split(/[.,;]/)[0];
      if (!p.note.startsWith('MEASURED ')) {
        v.push(`${h.host}: pin ${String(p.spki_sha256).slice(0, 8)}… has no measured provenance (got ${JSON.stringify(status)})`);
      }
      if (p.note.startsWith('MEASURED') && p.cert_sha256 === null) {
        v.push(`${h.host}: a MEASURED pin must record the leaf digest it was measured from`);
      }
      if (!/^MEASURED \d{4}-\d{2}-\d{2}/.test(p.note) && p.note.startsWith('MEASURED')) {
        v.push(`${h.host}: a MEASURED pin needs the date it was measured`);
      }
    }
    const live = h.pins.filter((p) => p.expires_unix > nowSecs).length;
    if (live === 0) v.push(`${h.host}: every pin has expired`);
    if (h.require_chain && !h.pins.some((p) => /Verify return code: 0/.test(p.note))) {
      v.push(`${h.host}: require_chain=true with no pin recording a verifiable chain`);
    }
    if (h.require_hostname && !h.pins.some((p) => /SAN covers|SAN contains/i.test(p.note))) {
      v.push(`${h.host}: require_hostname=true with no pin recording a SAN that covers the host`);
    }
  }
  const latest = Math.max(...hosts.flatMap((h) => h.pins.map((p) => p.expires_unix || 0)));
  if (latest > nowSecs + MAX_PIN_VALIDITY_SECS) {
    // `active_pins` only logs this; it is a violation here because a file that
    // drifts past policy silently is how the 30-year pin was going to happen.
    v.push(`a pin is valid longer than the 180-day policy allows (expiry ${latest})`);
  }
  return v;
}

const SELFTEST = process.argv.includes('--selftest-fail');
// `--file <path>` exists so the gate can be shown against the file it replaced:
// a check that has never rejected a real defect is not evidence of anything.
//   node scripts/verify-masque-pins.mjs --file <(git show HEAD:packaging/trust/masque-pins.json)
const flag = process.argv.indexOf('--file');
const TARGET = flag > -1 ? process.argv[flag + 1] : join(ROOT, FILE);
const raw = readFileSync(TARGET, 'utf8');

if (SELFTEST) {
  // Each case is the defect this gate exists to catch; all must be caught.
  const tamper = [
    ['an unlabelled pin', (o) => (o.hosts[0].pins[0].note = 'some cloudflare key')],
    ['an unmeasured fallback', (o) => (o.hosts[0].pins[0].note = 'UNMEASURED FALLBACK old guess')],
    ['a measured pin without its leaf digest', (o) => delete o.hosts[0].pins[0].cert_sha256],
    ['require_chain=true with no chain evidence', (o) => (o.hosts[0].require_chain = true)],
    ['require_hostname=true with no SAN evidence', (o) => (o.hosts[0].require_hostname = true)],
    ['a silently absent require_chain', (o) => delete o.hosts[1].require_chain],
    ['a host with no pins', (o) => (o.hosts[1].pins = [])],
    ['a pin outliving the 180-day policy', (o) => (o.hosts[0].pins[0].expires_unix = 4e9)],
  ];
  let missed = 0;
  for (const [label, mutate] of tamper) {
    const doc = JSON.parse(raw);
    mutate(doc);
    let caught;
    try {
      caught = validate(parse(JSON.stringify(doc)), Math.floor(Date.now() / 1000)).length > 0;
    } catch (e) {
      caught = true;
      void e;
    }
    console.log(`${caught ? 'ok  ' : 'FAIL'} selftest: ${label}`);
    if (!caught) missed += 1;
  }
  if (missed) {
    console.error(`verify-masque-pins: ${missed} selftest case(s) not caught`);
    process.exit(1);
  }
  console.log('verify-masque-pins: every selftest case is caught');
  process.exit(0);
}

let violations = [];
try {
  violations = validate(parse(raw), Math.floor(Date.now() / 1000));
} catch (e) {
  violations = [String(e.message ?? e)];
}
if (violations.length) {
  console.error(`FAIL: ${TARGET}`);
  for (const v of violations) console.error(`  - ${v}`);
  process.exit(1);
}
const hosts = parse(raw);
console.log(
  `${TARGET} OK: ${hosts.length} host(s), ` +
    hosts.map((h) => `${h.host}[${h.pins.length} pin(s), chain=${h.require_chain}, hostname=${h.require_hostname}]`).join(' '),
);
