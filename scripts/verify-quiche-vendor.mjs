#!/usr/bin/env node
// Vendor integrity gate for the vendored `quiche/` tree (specs/015 T236).
//
// `quiche/` is a *copy*, not a submodule: no .gitmodules, imported wholesale in
// commit 3c4fb69. Nothing in the tree records which upstream bytes it came from,
// so "upgraded quiche" and "someone edited quiche" are indistinguishable.
//
// This script pins the answer twice:
//   1. per-file: the recorded upstream blob id (git hash-object) of every file
//      that deviates from the base commit, so a deviation is named, not guessed;
//   2. whole-tree: a single digest over every tracked quiche file, so *any* drift
//      - content, added file, deleted file - turns this red.
//
// Line endings: the vendored tree is checked out with CRLF while upstream is LF,
// which is why a plain `diff -r` against upstream reports 329 changed files and
// nobody could read the real patch surface. Every digest here is computed over
// CR-stripped bytes so it is stable across platforms and checkouts.
//
// Usage:
//   node scripts/verify-quiche-vendor.mjs            # check against the pin
//   node scripts/verify-quiche-vendor.mjs --write     # re-record the pin
//   node scripts/verify-quiche-vendor.mjs --selftest-fail  # prove it can go red

import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { join, posix, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
// The pin lives OUTSIDE the hashed tree, and the only Aether-authored file inside
// `quiche/` is excluded from the digest, so recording a patch never invalidates
// its own checksum.
const PIN = join(ROOT, 'packaging', 'trust', 'quiche-vendor.json');
const PREFIX = 'quiche/';
const EXCLUDED = new Set(['quiche/PATCHES.md']);

const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');
const normalized = (buf) => {
  const s = buf.toString('binary');
  const out = Buffer.alloc(s.length);
  let j = 0;
  for (let i = 0; i < s.length; i += 1) {
    if (s[i] === '\r' && s[i + 1] === '\n') continue;
    out[j++] = s.charCodeAt(i);
  }
  return out.subarray(0, j);
};

function trackedFiles() {
  return execFileSync('git', ['ls-files', '-z', PREFIX], { cwd: ROOT })
    .toString('utf8')
    .split('\0')
    .filter(Boolean)
    .map((p) => posix.normalize(p))
    .filter((p) => !EXCLUDED.has(p))
    .sort();
}

function build() {
  const perFile = {};
  const lines = [];
  for (const p of trackedFiles()) {
    let buf;
    try {
      buf = readFileSync(join(ROOT, p));
    } catch {
      throw new Error(`tracked file vanished from the working tree: ${p}`);
    }
    const d = sha256(normalized(buf));
    perFile[p] = d;
    lines.push(`${d}  ${p}`);
  }
  return {
    tree: sha256(Buffer.from(lines.join('\n') + '\n', 'utf8')),
    count: Object.keys(perFile).length,
    files: perFile,
  };
}

const args = process.argv.slice(2);
if (args.includes('--selftest-fail')) {
  // Prove the gate bites: a substituted vendored file must change the digest.
  const probe = join(ROOT, 'quiche', 'COPYING');
  if (!existsSync(probe)) throw new Error(`selftest fixture missing: ${probe}`);
  const before = build().tree;
  const original = readFileSync(probe);
  try {
    writeFileSync(probe, Buffer.concat([original, Buffer.from('\n// tampered\n')]));
    const after = build().tree;
    if (before === after) {
      throw new Error('selftest FAILED: tampering with a vendored file did not change the tree digest');
    }
  } finally {
    writeFileSync(probe, original);
  }
  if (build().tree !== before) throw new Error('selftest FAILED: the tree did not restore cleanly');
  console.log(`verify-quiche-vendor selftest: tampering moved the digest ${before.slice(0, 12)} -> changed, and restored.`);
  process.exit(0);
}

const now = build();

if (args.includes('--write')) {
  const pin = existsSync(PIN) ? JSON.parse(readFileSync(PIN, 'utf8')) : {};
  writeFileSync(
    PIN,
    JSON.stringify({ ...pin, tree: now.tree, file_count: now.count, files: now.files }, null, 2) + '\n',
  );
  console.log(`recorded vendor tree ${now.tree} over ${now.count} files -> ${PIN}`);
  process.exit(0);
}

if (!existsSync(PIN)) {
  console.error(`FAIL: ${PIN} is missing, so the vendored tree is unpinned.`);
  process.exit(1);
}
const pin = JSON.parse(readFileSync(PIN, 'utf8'));
const errors = [];
if (pin.tree !== now.tree) {
  const drifted = Object.keys(now.files).filter((p) => pin.files?.[p] !== now.files[p]);
  const added = Object.keys(now.files).filter((p) => !(p in (pin.files ?? {})));
  const removed = Object.keys(pin.files ?? {}).filter((p) => !(p in now.files));
  errors.push(
    `vendored quiche tree digest ${pin.tree} -> ${now.tree}` +
      ` (changed: ${drifted.length - added.length}, added: ${added.length}, removed: ${removed.length})`,
  );
  for (const p of added) errors.push(`  added   ${p}`);
  for (const p of removed) errors.push(`  removed ${p}`);
  for (const p of drifted) if (!added.includes(p)) errors.push(`  changed ${p}`);
}
if (errors.length) {
  console.error('FAIL: the vendored quiche tree no longer matches its pin.');
  console.error(errors.join('\n'));
  console.error('\nIf this was a deliberate re-vendor or a recorded patch, re-run');
  console.error('  node scripts/verify-quiche-vendor.mjs --write');
  console.error('and update quiche/PATCHES.md in the same commit.');
  process.exit(1);
}
console.log(`quiche vendor pin OK: ${now.count} files, tree ${now.tree}`);
