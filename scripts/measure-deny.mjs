#!/usr/bin/env node
// Regenerates the `[bans] skip` block of deny.toml from the committed lockfiles.
//
// `bans.multiple-versions` is a hard error in deny.toml, and the only thing that
// makes that survivable is that the exemption list is *generated* rather than
// hand-curated: a new duplicated crate then fails `cargo deny check bans` instead
// of joining a warning list nobody reads. Run this after a dependency change and
// review the diff - entries may only be removed, never added by hand.
//
//   node scripts/measure-deny.mjs           # report counts, exit 1 if deny.toml is stale
//   node scripts/measure-deny.mjs --write   # rewrite the skip block

import { readFileSync, writeFileSync } from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const LOCKS = ['aether/Cargo.lock', 'apps/desktop/src-tauri/Cargo.lock'];
const CFG = join(ROOT, 'deny.toml');

function lockPackages(rel) {
  const text = readFileSync(join(ROOT, rel), 'utf8');
  const out = new Map();
  // `\r?\n`, not `\n`: these lockfiles are committed with CRLF and a bare-\n regex
  // silently matches zero packages, which reads as "no duplicates" and green-lights
  // a deny rule that was never actually measured.
  for (const m of text.matchAll(/\[\[package\]\]\r?\nname = "([^"]+)"\r?\nversion = "([^"]+)"/g)) {
    if (!out.has(m[1])) out.set(m[1], new Set());
    out.get(m[1]).add(m[2]);
  }
  return out;
}

const merged = new Map();
for (const l of LOCKS) {
  for (const [name, versions] of lockPackages(l)) {
    if (!merged.has(name)) merged.set(name, new Set());
    for (const v of versions) merged.get(name).add(v);
  }
}

const dup = [...merged.entries()]
  .filter(([, v]) => v.size > 1)
  // Code-unit order, not localeCompare: `--write` has to be byte-reproducible
  // across platforms, or the staleness check below becomes locale-dependent.
  .sort((x, y) => (x[0] < y[0] ? -1 : x[0] > y[0] ? 1 : 0));
const pairs = dup.flatMap(([name, versions]) =>
  [...versions].sort().map((version) => `  { name = "${name}", version = "${version}" },`),
);

const header =
  `  # Generated from the two committed lockfiles: ${dup.length} crate names carry more\n` +
  `  # than one version (${pairs.length} name+version pairs). Each\n` +
  `  # one is a transitive disagreement this repository does not own - boring/quiche,\n` +
  `  # tauri, smoltcp/boringtun pin different major lines of the same low-level crate.\n` +
  `  # Regenerate with \`node scripts/measure-deny.mjs\`; a *new* duplicate then shows up\n` +
  `  # as a red \`cargo deny check bans\` rather than a warning nobody reads.\n`;

const current = readFileSync(CFG, 'utf8').replace(/\r\n/g, '\n');
const start = current.indexOf('  # Generated from the two committed lockfiles:');
const end = current.indexOf('\n]', start);
if (start < 0 || end < 0) {
  console.error('FAIL: deny.toml no longer carries the generated skip block.');
  process.exit(1);
}
// No trailing newline: `existing` below is the slice up to and including the last
// entry line, and a stray '\n' here made a byte-identical file look stale forever.
const rebuilt = `${header}${pairs.join('\n')}`;
const existing = current.slice(start, end + 2).replace('\n]', '');

if (process.argv.includes('--write')) {
  writeFileSync(CFG, current.slice(0, start) + rebuilt + current.slice(end), 'utf8');
  console.log(`deny.toml: wrote ${pairs.length} skip entries across ${dup.length} duplicated crates`);
  process.exit(0);
}

if (existing !== rebuilt) {
  console.error('FAIL: deny.toml [bans] skip does not match the committed lockfiles.');
  console.error(`expected ${pairs.length} entries for ${dup.length} crates; run \`node scripts/measure-deny.mjs --write\``);
  process.exit(1);
}
console.log(`deny.toml [bans] skip OK: ${pairs.length} entries / ${dup.length} duplicated crates over ${merged.size} locked names`);
