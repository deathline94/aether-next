#!/usr/bin/env node
/*
 * Build-time design-token include (P1-3 remediation).
 *
 * packages/ui/tokens.css is the single authored source of the shared design
 * tokens. This script inlines the span between /*==SHARED-BEGIN==* / and
 * /*==SHARED-END==* / into the /*==AETHER-TOKENS-START==* / ... /*==AETHER-
 * TOKENS-END==* / fence at the top of each app stylesheet.
 *
 * Why inline instead of a runtime `@import`: the BC-11 invariant gate
 * (scripts/verify-invariants.mjs) resolves every `var(--x)` against definitions
 * found in the SAME file and cannot see across an @import, so the literals must
 * be physically present in each sheet. Inlining also guarantees `npm run build`
 * and the Vite dev server ship identical tokens with zero network/CSS @import
 * resolution surprises.
 *
 * It is idempotent: running it on already-synced sheets is a no-op.
 *   node scripts/sync-tokens.mjs            # write
 *   node scripts/sync-tokens.mjs --check    # exit 1 if a sheet drifts
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const TOKENS = join(ROOT, 'packages/ui/tokens.css');
// `packages/ui/src/shared.css` is the sheet both frontends load before their own
// (reviewer item 24). It needs the fence for the same reason the app sheets do:
// every CSS gate resolves `var(--x)` inside one file, so the literals have to be
// physically present there too, not only at runtime.
const SHEETS = [
  'packages/ui/src/shared.css',
  'apps/desktop/src/App.css',
  'apps/android/src/App.css',
];
const CHECK = process.argv.includes('--check');

const src = readFileSync(TOKENS, 'utf8');
const shared = src.match(/\/\*==SHARED-BEGIN==\*\/([\s\S]*?)\/\*==SHARED-END==\*\//);
if (!shared) {
  console.error('sync-tokens: tokens.css has no SHARED-BEGIN/END span');
  process.exit(1);
}
const body = shared[1].replace(/^\s*\n/, '').replace(/\s+$/, '');
const fence = (content, eol) => {
  const text = `/*==AETHER-TOKENS-START==*/\n/* GENERATED from packages/ui/tokens.css by scripts/sync-tokens.mjs — do not edit this block. */\n${content}\n/*==AETHER-TOKENS-END==*/`;
  // Match the host sheet's line endings so the check is idempotent even after a
  // Windows editor (git autocrlf / the Edit tool) rewrites the file as CRLF.
  return eol === '\r\n' ? text.replace(/\n/g, '\r\n') : text;
};

let drifted = 0;
for (const rel of SHEETS) {
  const abs = join(ROOT, rel);
  const css = readFileSync(abs, 'utf8');
  // The fence is always exactly one block. A stale second pair anywhere in the
  // sheet used to be invisible: the non-global replace only ever touched the
  // first, and in CSS last-definition-wins the stale one won.
  const fenceRe = /\/\*==AETHER-TOKENS-START==\*\/[\s\S]*?\/\*==AETHER-TOKENS-END==\*\//g;
  const fences = css.match(fenceRe) ?? [];
  if (fences.length !== 1) {
    console.error(`sync-tokens: ${rel} has ${fences.length} AETHER-TOKENS fences (expected exactly 1) — delete the stale block by hand`);
    process.exit(1);
  }
  // EOL-agnostic on purpose. The generated fence is written LF and drift is
  // compared with line endings normalized: the file-wide CRLF detection used to
  // flip the whole fence to CRLF when one stray CRLF appeared, and the check
  // then flip-flopped between runs instead of settling.
  const want = fence(body, '\n');
  const normalized = (s) => s.replace(/\r\n/g, '\n');
  const next = css.replace(fenceRe, () => want);
  if (normalized(next) !== normalized(css)) {
    drifted += 1;
    if (CHECK) {
      console.error(`sync-tokens: ${rel} drifts from tokens.css (run: npm run sync-tokens)`);
    } else {
      writeFileSync(abs, next);
      console.log(`sync-tokens: updated ${rel}`);
    }
  } else {
    console.log(`sync-tokens: ${rel} already in sync`);
  }
}
if (CHECK && drifted) process.exit(1);
