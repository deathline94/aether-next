#!/usr/bin/env node
// Reports the standing rustfmt debt in this repository (non-blocking).
//
// `cargo fmt --check` was never wired up, so the tree accumulated drift. The
// blocking half of that gate lives in ci.yml's `fmt` job, which formats only the
// files a change actually touches - a whole-tree gate would have been red on
// arrival. This script exists so the size of the remaining debt is a number in the
// CI log on every run rather than a guess, and so it can only go down.
//
//   node scripts/fmt-report.mjs            # count + list, exit 0
//   node scripts/fmt-report.mjs --json     # machine-readable
//
// Vendored `quiche/` is excluded: it is a byte-pinned upstream copy (see
// quiche/PATCHES.md) and reformatting it would destroy the recorded patch surface.

import { execFileSync } from 'node:child_process';
import { resolve, dirname, join } from 'node:path';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

const files = execFileSync('git', ['ls-files', '-z', '*.rs'], { cwd: ROOT })
  .toString('utf8')
  .split('\0')
  .filter(Boolean)
  .filter((p) => !p.startsWith('quiche/'));

function rustfmtEditionOf(rel) {
  // Each crate declares its own edition; guessing 2015 silently "passes" files
  // that rustfmt would otherwise rewrite.
  const manifest = rel.startsWith('apps/desktop/src-tauri/')
    ? 'apps/desktop/src-tauri/Cargo.toml'
    : 'aether/Cargo.toml';
  try {
    const m = readFileSync(join(ROOT, manifest), 'utf8').match(/^edition *= *"(\d+)"/m);
    return m ? m[1] : '2021';
  } catch {
    return '2021';
  }
}

const dirty = [];
for (const f of files) {
  try {
    execFileSync('rustfmt', ['--edition', rustfmtEditionOf(f), '--check', f], {
      cwd: ROOT,
      stdio: 'pipe',
    });
  } catch (err) {
    const out = `${err.stdout ?? ''}${err.stderr ?? ''}`;
    dirty.push({ file: f, hunks: (out.match(/^Diff in /gm) ?? []).length });
  }
}

const totalHunks = dirty.reduce((a, d) => a + d.hunks, 0);
if (process.argv.includes('--json')) {
  console.log(JSON.stringify({ checked: files.length, dirty: dirty.length, hunks: totalHunks, files: dirty }));
} else {
  console.log(
    `rustfmt debt: ${dirty.length}/${files.length} non-vendored .rs files are not rustfmt-clean ` +
      `(${totalHunks} hunks). Vendored quiche/ is excluded by design.`,
  );
  for (const d of dirty) console.log(`  ${String(d.hunks).padStart(4)}  ${d.file}`);
  if (dirty.length) {
    console.log(
      '\nFixing one file is a self-contained, reviewable commit; the ci.yml `fmt` job already\n' +
        'refuses to let any file in this list be touched without leaving the list.',
    );
  }
}
process.exit(0);
