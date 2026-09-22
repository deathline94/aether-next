#!/usr/bin/env node
/*
 * Mechanical invariant gates for Aether.
 *
 * WHY THIS FILE EXISTS
 * The project's recurring defect is not a missing check but a check that can
 * never fail: a CI step verifying the wrong artifact, a build script pinning a
 * hash of the file it ships, a test asserting on an AtomicLong instead of the
 * class under test. So this harness has a structural rule: every gate registers
 * an `inject` case that recreates the defect it detects, and `--selftest-fail`
 * runs those injections through the *same* checker. A gate that fails to
 * notice its own injected defect is reported as blind and the run exits
 * non-zero.
 *
 * Usage:
 *   node scripts/verify-invariants.mjs                  # run every gate
 *   node scripts/verify-invariants.mjs --gate <name>    # run one gate
 *   node scripts/verify-invariants.mjs --selftest-fail  # prove every gate can fail
 */

import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, sep, basename } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(fileURLToPath(new URL('.', import.meta.url)), '..');
// A gate that cannot show you the whole failure list cannot fix it either.
const MAX_FINDINGS = Number(process.env.VERIFY_MAX_FINDINGS ?? 25);

const SKIP_DIRS = new Set([
  'node_modules', '.git', 'target', 'dist', 'build', 'out', '.gradle', 'coverage', '.next',
]);

// `android/app/src/main/assets/www/` is the *bundled* copy of `apps/android/src`
// that `pnpm android:sync` regenerates and .gitignore excludes. Scanning it
// doubles every frontend finding with a minified, stale duplicate and reports
// violations against files nobody can edit — the source tree is the contract.
const GENERATED_PATHS = ['/assets/www/'];

function existsRel(p) {
  try {
    return statSync(join(ROOT, p)).isFile();
  } catch {
    return false;
  }
}

function walk(dir, re, out) {
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return out;
  }
  for (const e of entries) {
    const p = join(dir, e.name);
    if (e.isDirectory()) {
      if (SKIP_DIRS.has(e.name)) continue;
      if (GENERATED_PATHS.some((g) => `${relative(ROOT, p).split(sep).join('/')}/`.includes(g)))
        continue;
      walk(p, re, out);
    } else if (re.test(e.name)) {
      out.push(p);
    }
  }
  return out;
}

const rel = (abs) => relative(ROOT, abs).split(sep).join('/');
function locate(abs, text, idx) {
  const line = text.slice(0, idx).split('\n').length;
  return `${rel(abs)}:${line}`;
}

/* ------------------------------------------------------------------- gates */
/* Each gate: name, invariant, summary, scan(api), inject() -> {file, content} */

/* ------------------------------------------------- WCAG colour arithmetic */
/*
 * Shared by the contrast gates. A ratio somebody eyeballed in a mockup is not a
 * contract; these are the numbers WCAG 1.4.3/1.4.11 actually specify, including
 * the step that design tools fake and browsers really do: a translucent layer
 * must be composited over its backdrop *before* it can be measured. Measuring
 * `--coral-border` as "#ff5c5c, 6.26:1" is what let the repo's token comments
 * quote AA-passing numbers for colours that composite to 1.59:1 on screen.
 */
function parseColour(token) {
  const t = String(token).trim();
  let m = t.match(/^#([0-9a-f]{3,8})$/i);
  if (m) {
    let h = m[1].toLowerCase();
    if (h.length === 3 || h.length === 4) h = h.split('').slice(0, 3).map((c) => c + c).join('');
    if (h.length === 8) h = h.slice(0, 6);
    return [parseInt(h.slice(0, 2), 16), parseInt(h.slice(2, 4), 16), parseInt(h.slice(4, 6), 16), 1];
  }
  m = t.match(/^rgba?\(([^)]*)\)$/i);
  if (m) {
    const p = m[1].split(/[,\s/]+/).filter(Boolean).map(Number);
    if (p.length < 3) return null;
    return [p[0], p[1], p[2], p.length > 3 ? p[3] : 1];
  }
  return null;
}

function channel(c) {
  const v = c / 255;
  return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4);
}

function colourRatio(a, b) {
  const la = 0.2126 * channel(a[0]) + 0.7152 * channel(a[1]) + 0.0722 * channel(a[2]);
  const lb = 0.2126 * channel(b[0]) + 0.7152 * channel(b[1]) + 0.0722 * channel(b[2]);
  return (Math.max(la, lb) + 0.05) / (Math.min(la, lb) + 0.05);
}

/** `layer` painted with its own alpha on top of an opaque `base`. */
function compositeOver(layer, base) {
  const a = layer[3];
  return [
    layer[0] * a + base[0] * (1 - a),
    layer[1] * a + base[1] * (1 - a),
    layer[2] * a + base[2] * (1 - a),
    1,
  ];
}

/** Top-level commas only: `rgba(1, 2, 3, .4), url(x)` splits into two layers. */
function splitTopLevel(s) {
  const out = [];
  let depth = 0;
  let cur = '';
  for (const ch of s) {
    if (ch === '(') depth += 1;
    if (ch === ')') depth -= 1;
    if (ch === ',' && depth === 0) {
      out.push(cur);
      cur = '';
      continue;
    }
    cur += ch;
  }
  if (cur.trim()) out.push(cur);
  return out;
}

/** `:root` custom properties of one sheet, with `var(--x)` chains resolved. */
function sheetColourTokens(src) {
  const raw = {};
  for (const m of src.matchAll(/(--[\w-]+)\s*:\s*([^;{}]+);/g)) {
    if (!(m[1] in raw)) raw[m[1]] = m[2].trim();
  }
  const resolved = {};
  const solve = (name, seen) => {
    if (name in resolved) return resolved[name];
    if (seen.has(name)) return null;
    seen.add(name);
    let v = raw[name];
    if (v === undefined) return null;
    for (let i = 0; i < 8; i += 1) {
      const m = v.match(/^var\(\s*(--[\w-]+)\s*\)$/);
      if (!m) break;
      const inner = solve(m[1], seen);
      if (inner === null) return null;
      v = inner;
    }
    resolved[name] = v;
    return v;
  };
  Object.keys(raw).forEach((n) => solve(n, new Set()));
  return { raw, resolved };
}

function expandVars(value, tokens) {
  let v = value;
  for (let i = 0; /var\(/.test(v) && i < 12; i += 1) {
    v = v.replace(/var\(\s*(--[\w-]+)\s*(?:,\s*([^()]*))?\)/g, (_all, n, fb) => tokens.resolved[n] ?? fb ?? '');
  }
  return v;
}

/**
 * Colours a declaration actually paints with. A `linear-gradient` background
 * yields its stops as `stops` and the rule is measured against each of them,
 * because the text sits on whichever stop is worst for it, not on an average.
 */
function declarationColours(value, tokens) {
  const v = expandVars(value, tokens);
  const out = { scalars: [], stops: null, resolved: false };
  let work = v;
  const g = v.match(/(?:linear|radial|conic)-gradient\(([^)]*(?:\([^)]*\)[^)]*)*)\)/i);
  if (g) {
    work = `${v.slice(0, g.index)} ${v.slice(g.index + g[0].length)}`;
    out.stops = [];
    for (const part of splitTopLevel(g[1])) {
      const c = part.match(/(#[0-9a-f]{3,8}|rgba?\([^)]*\))/i);
      const p = c && parseColour(c[0]);
      if (p) out.stops.push(p);
    }
    if (!out.stops.length) out.stops = null;
  }
  for (const part of splitTopLevel(work)) {
    const c = part.match(/(#[0-9a-f]{3,8}|rgba?\([^)]*\))/i);
    const p = c && parseColour(c[0]);
    if (p) {
      out.scalars.push(p);
      out.resolved = true;
    }
  }
  if (out.stops) out.resolved = true;
  return out;
}

/** Every opaque background a piece of text can end up sitting on. */
function sheetSurfaces(tokens) {
  const out = [];
  for (const [name, value] of Object.entries(tokens.resolved)) {
    if (!/^(--bg-|--panel)/.test(name)) continue;
    const p = parseColour(value);
    if (p && p[3] === 1) out.push([name, p]);
  }
  return out;
}

/** Innermost rule blocks as [selector, body, offset], comments blanked out. */
function ruleBlocks(maskedSrc) {
  const out = [];
  const re = /([^{}]+)\{([^{}]*)\}/g;
  let m;
  while ((m = re.exec(maskedSrc))) {
    const sel = m[1].trim().split('\n').pop().trim();
    if (!sel || sel.startsWith('@')) continue;
    out.push([sel, m[2], m.index]);
  }
  return out;
}

const blankComments = (s) => s.replace(/\/\*[\s\S]*?\*\//g, (c) => c.replace(/[^\n]/g, ' '));

const GATES = [
  {
    name: 'config-single-reader',
    invariant: 'BC-04',
    summary: 'AETHER_* is read through runtime_env, never std::env',
    scan(api) {
      const v = [];
      // The shell is scanned too: it *writes* the engine environment (those are
      // `Command::env` calls and do not match), but an ambient *read* there is
      // just as much a second source of truth as one in the engine.
      //
      // Allowlist is per-key and has to say why it is safe: a value that can
      // only ever *add* verification cannot be used to turn a check off.
      const SHELL_ADDITIVE_ONLY = new Set(['AETHER_WINTUN_SHA256']);
      for (const dir of ['aether/src', 'apps/desktop/src-tauri/src']) {
        for (const f of api.files(dir, /\.rs$/)) {
          if (rel(f).endsWith('runtime_env.rs')) continue;
          const t = api.read(f);
          const re = /std::env::var(?:_os)?\(\s*"(AETHER_[A-Z0-9_]*)"/g;
          let m;
          while ((m = re.exec(t))) {
            if (rel(f).startsWith('apps/desktop') && SHELL_ADDITIVE_ONLY.has(m[1])) continue;
            v.push(`${locate(f, t, m.index)} reads ${m[1]} from the process env`);
          }
        }
      }
      return v;
    },
    inject() {
      return {
        file: 'aether/src/__selftest__.rs',
        content: 'fn f() { let _ = std::env::var("AETHER_DANGEROUS_DISABLE_TLS_VERIFY"); }',
      };
    },
  },
  {
    name: 'secrets-not-in-child-env',
    invariant: 'BC-04',
    summary: 'the config key is handed to the engine over stdin, never in its environment',
    scan(api) {
      const v = [];
      // A child's environment is readable for its whole lifetime (crash
      // collectors, profilers, `adb` on a debuggable build) and is not cleared
      // when the parent wipes its own copy. The key now travels on the control
      // pipe, so any code that puts it back into the spawn environment is
      // re-opening the leak this replaced.
      const re = /\.env\(\s*"AETHER_CONFIG_KEY"|\["AETHER_CONFIG_KEY"\]\s*=|"AETHER_CONFIG_KEY"\s+to/g;
      for (const dir of ['apps/desktop/src-tauri/src', 'apps/android/android/app/src/main']) {
        for (const f of api.files(dir, /\.(rs|kt)$/)) {
          const t = api.read(f);
          let m;
          while ((m = re.exec(t))) {
            v.push(`${locate(f, t, m.index)} puts AETHER_CONFIG_KEY back into the child environment`);
          }
        }
      }
      return v;
    },
    inject() {
      return {
        file: 'apps/desktop/src-tauri/src/__selftest_secrets__.rs',
        content: 'fn f(c: &mut std::process::Command) { c.env("AETHER_CONFIG_KEY", "x"); }\n',
      };
    },
  },
  {
    name: 'ipc-typed-errors',
    invariant: 'BC-20',
    summary: 'Tauri commands return CommandError, never String',
    scan(api) {
      const v = [];
      for (const f of api.files('apps/desktop/src-tauri/src', /\.rs$/)) {
        const t = api.read(f);
        const re = /Result<[^<>]*,\s*String\s*>/g;
        let m;
        while ((m = re.exec(t))) v.push(`${locate(f, t, m.index)} stringly IPC error type`);
      }
      return v;
    },
    inject() {
      return {
        file: 'apps/desktop/src-tauri/src/__selftest__.rs',
        content: '#[tauri::command]\nfn demo() -> Result<u8, String> { Ok(1) }\n',
      };
    },
  },
  {
    name: 'shell-lock-unwraps',
    invariant: 'BC-05',
    summary: 'no Mutex::lock().unwrap() on the shell lifecycle path',
    scan(api) {
      const v = [];
      for (const f of api.files('apps/desktop/src-tauri/src', /\.rs$/)) {
        const t = api.read(f);
        const re = /\.lock\(\)\s*\.unwrap\(\)/g;
        let m;
        while ((m = re.exec(t))) v.push(`${locate(f, t, m.index)} lock().unwrap() can panic a supervisor thread`);
      }
      return v;
    },
    inject() {
      return {
        file: 'apps/desktop/src-tauri/src/__selftest__.rs',
        content: 'fn f(m: &std::sync::Mutex<u8>) { let _g = m.lock().unwrap(); }',
      };
    },
  },
  {
    name: 'css-class-resolution',
    invariant: 'BC-10',
    summary: 'every className token resolves to a rule',
    scan(api) {
      const sheet = (p) => (existsRel(p) ? readFileSync(join(ROOT, p), 'utf8') : '');
      const tokens = sheet('packages/ui/tokens.css');
      const defined = (src) =>
        new Set([...src.matchAll(/\.([A-Za-z][\w-]*)/g)].map((m) => m[1]));
      const FOR_APP = {
        'apps/desktop': defined(sheet('apps/desktop/src/App.css') + '\n' + tokens),
        'apps/android': defined(sheet('apps/android/src/App.css') + '\n' + tokens),
      };
      /*
       * Per app, not a union. Unioning the two sheets is how a class that only
       * the *other* surface styles slipped through: `apps/desktop` markup could
       * point at a selector living in Android's copy and the gate read it as
       * resolved, while the desktop element rendered with no rule at all.
       */
      /*
       * Tailwind generates utilities at build time, so they never appear as a
       * literal `.class` in the source sheets. The list is deliberately
       * per-token: a wildcard/prefix rule would blind this gate to every
       * genuinely unstyled element, which is the bug it exists to catch.
       */
      const BUILD_GENERATED = new Set(['font-mono', 'tabular-nums', 'text-red-400']);
      const v = [];
      for (const f of api.files('apps', /\.(tsx|jsx)$/)) {
        const app = Object.keys(FOR_APP).find((a) => rel(f).startsWith(`${a}/`));
        if (!app) continue;
        const definedFor = FOR_APP[app];
        const t = api.read(f);
        for (const m of t.matchAll(/className=(?:"([^"]*)"|\{`([^`]*)`\})/g)) {
          const raw = (m[1] ?? m[2] ?? '').replace(/\$\{[^}]*\}/g, ' ');
          for (const tok of raw.split(/\s+/).filter(Boolean)) {
            if (BUILD_GENERATED.has(tok)) continue;
            // `badge-${tone}` strips to `badge-`: accept it as a family only if
            // at least one `badge-*` rule actually exists.
            if (tok.endsWith('-')) {
              let hit = false;
              for (const c of definedFor) if (c.startsWith(tok)) { hit = true; break; }
              if (hit) continue;
            }
            if (!definedFor.has(tok)) v.push(`${locate(f, t, m.index)} className "${tok}" has no rule in ${app}/src`);
          }
        }
      }
      return v;
    },
    inject() {
      return {
        file: 'apps/desktop/src/__selftest__.tsx',
        content: 'export const X = () => <div className="totally-undefined-widget-qx" />;',
      };
    },
  },
  {
    name: 'css-banned-patterns',
    invariant: 'BC-11',
    summary: 'no 100vh, transition:all, unguarded :hover, alpha hairlines, nested keyframes, undefined vars',
    scan(api) {
      const v = [];
      const all = api.files('apps', /\.css$/).concat(api.files('packages', /\.css$/));
      for (const f of all) {
        const raw = api.read(f);
        /*
         * Comments legitimately quote the defects being removed ("was
         * rgba(255,255,255,.05)", ".profile-card:hover"), so pattern scans run
         * against a masked copy. Masking replaces comment bytes with spaces to
         * keep every offset — and therefore every reported line number — intact.
         */
        const t = raw.replace(/\/\*[\s\S]*?\*\//g, (c) => c.replace(/[^\s]/g, ' '));
        const tests = [
          [/\b100vh\b/g, '100vh (use svh/dvh)'],
          [/transition\s*:\s*all\b/g, 'transition: all'],
          [/:hover\b/g, 'hover rule (must sit inside @media (hover: hover) and (pointer: fine))'],
          // U-E1: any translucent-white border at all, not just the .0x tier —
          // the previous pattern read `.0\d|1[01]` and waved through 0.12–0.28,
          // which is how the hairlines survived the first pass at this gate.
          [/border[^;{}]*rgba\(255,\s*255,\s*255,\s*0?\.\d+\)/g, 'alpha hairline border (use an opaque --edge token)'],
        ];
        for (const [re, label] of tests) {
          let m;
          while ((m = re.exec(t))) {
            // Hover is allowed only inside a pointer-guarded media block; a
            // hover without (pointer: fine) latches on touch (T191 / U-F3).
            if (label.startsWith('hover')) {
              const before = t.slice(0, m.index);
              const openMedia = before.lastIndexOf('@media');
              const closeRule = Math.max(before.lastIndexOf('\n}', openMedia), -1);
              const cond = before.slice(openMedia, m.index);
              if (openMedia > closeRule && /hover\s*:\s*hover/.test(cond) && /pointer\s*:\s*fine/.test(cond)) continue;
            }
            v.push(`${locate(f, t, m.index)} ${label}`);
          }
        }
        /*
         * U-E4/U-E5: an @keyframes nested inside an @media block only exists
         * when that query matches, so a spinner defined that way is frozen for
         * everyone else. Keyframes are top-level; the reduced-motion block is
         * only ever allowed to *remove* motion.
         */
        let depth = 0;
        for (const m of t.matchAll(/@keyframes\s+[\w-]+|[{}]/g)) {
          if (m[0] === '{') depth++;
          else if (m[0] === '}') depth--;
          else if (depth > 0) v.push(`${locate(f, t, m.index)} @keyframes sits inside an @media block — it stops animating outside it`);
        }
        const names = [...t.matchAll(/@keyframes\s+([\w-]+)/g)].map((x) => x[1]);
        if (names.length) {
          const rm = [...t.matchAll(/@media[^{]*prefers-reduced-motion[^{]*\{/g)];
          // Blanket neutraliser: a `*` rule turning animation off, which covers
          // every name above and any keyframe added later.
          const blanket = rm.some((m) => {
            const body = t.slice(m.index);
            return /\*\s*(?:,\s*[^{}]*)?\{[^}]*animation(?:-name)?\s*:\s*none\s*!important/.test(body)
              || /\*,\s*\*::before,/.test(body);
          });
          if (!rm.length) v.push(`${rel(f)}:0 defines ${names.length} animations but has no prefers-reduced-motion block`);
          else if (!blanket) v.push(`${rel(f)}:0 reduced-motion block names selectors instead of neutralising all ${names.length} @keyframes (${names.join(', ')})`);
        }
        const defined = new Set([...t.matchAll(/(--[\w-]+)\s*:/g)].map((x) => x[1]));
        for (const m of t.matchAll(/var\((--[\w-]+)/g)) {
          if (!defined.has(m[1])) v.push(`${locate(f, t, m.index)} var ${m[1]} is never defined`);
        }
      }
      return v;
    },
    inject() {
      return {
        file: 'packages/ui/__selftest__.css',
        content:
          '.a{height:100vh;transition:all .2s;border:1px solid rgba(255, 255, 255, 0.14)}\n'
          + '.a:hover{color:red}\n'
          + '@media (hover: hover){\n.b:hover{color:red}\n}\n'
          + '@keyframes live{to{opacity:1}}\n'
          + '@media (prefers-reduced-motion: reduce){@keyframes nested{to{opacity:0}}\n.c{transition:none}}\n'
          + '.d{color:var(--nope-zz)}\n',
      };
    },
  },
  {
    name: 'ipc-command-parity',
    invariant: 'BC-09',
    summary: 'desktop commands registered in the shell == invoked by the desktop UI, both directions',
    scan(api) {
      // The registry is collected from every file under src-tauri/src rather than
      // lib.rs alone: the shell is being split into modules, and a gate that reads
      // one named file goes silently blind the moment the handler list moves.
      const shellDir = join(ROOT, 'apps/desktop/src-tauri/src');
      const registered = new Set();
      let sawList = false;
      for (const f of readdirSync(shellDir)) {
        if (!f.endsWith('.rs')) continue;
        const src = readFileSync(join(shellDir, f), 'utf8');
        for (const m of src.matchAll(/generate_handler!\s*\[([^\]]*)\]/g)) {
          sawList = true;
          for (const part of m[1].split(',')) {
            const cmd = part.trim();
            if (cmd) registered.add(cmd);
          }
        }
      }
      if (!sawList) return ['no generate_handler! list under src-tauri/src — parity is unverifiable'];
      const invoked = new Set();
      // Desktop only. Android talks to a different plane — the Capacitor-style
      // `window.AetherAndroid.invoke(...)` bridge in AetherBridge.kt — and comparing
      // its command names against the Tauri registry reported a perfectly good
      // bridge command (`get_result`) as a missing shell command, which is how a
      // check with the wrong scope teaches you to rename working code.
      for (const f of api.files('apps/desktop/src', /\.(ts|tsx)$/)) {
        const src = api.read(f);
        for (const x of src.matchAll(/invoke[^()"']*\(\s*["'`]([a-z_]+)["'`]/g)) invoked.add(x[1]);
      }
      const v = [];
      for (const cmd of invoked) if (!registered.has(cmd)) v.push(`invoke("${cmd}") has no registered command`);
      for (const cmd of registered) if (!invoked.has(cmd)) v.push(`command "${cmd}" is registered but never invoked`);
      return v;
    },
    inject() {
      // Parity reads the real shell, so inject an invocation of a command that
      // cannot exist.
      return {
        file: 'apps/desktop/src/__selftest__.ts',
        content: 'export const go = () => window.__TAURI__.core.invoke("no_such_command_zz");',
      };
    },
  },
  {
    name: 'android-bridge-parity',
    invariant: 'BC-09',
    summary: 'the Android UI invokes only bridge commands the Kotlin handler implements, and all are reachable',
    scan(api) {
      const BRIDGE = 'apps/android/android/app/src/main/java/app/aethernext/AetherBridge.kt';
      if (!existsRel(BRIDGE)) return ['AetherBridge.kt missing'];
      const src = readFileSync(join(ROOT, BRIDGE), 'utf8');
      const handled = new Set();
      for (const m of src.matchAll(/"([a-z_]+)"\s*->/g)) handled.add(m[1]);
      if (!handled.size) return ['no `"command" ->` dispatch table in AetherBridge.kt — parity is unverifiable'];
      const invoked = new Set();
      for (const f of api.files('apps/android/src', /\.(ts|tsx)$/)) {
        for (const x of api.read(f).matchAll(/invoke[^()"']*\(\s*["'`]([a-z_]+)["'`]/g)) invoked.add(x[1]);
      }
      const v = [];
      for (const cmd of invoked) if (!handled.has(cmd)) v.push(`invoke("${cmd}") is not implemented by the Kotlin bridge`);
      for (const cmd of handled) if (!invoked.has(cmd) && cmd !== 'default') v.push(`bridge command "${cmd}" is implemented but never called`);
      return v;
    },
    inject() {
      return {
        file: 'apps/android/src/__selftest__.ts',
        content: 'export const go = () => window.AetherAndroid.invoke("no_such_bridge_command_zz", "{}");',
      };
    },
  },
  {
    name: 'android-settings-parity',
    invariant: 'BC-09',
    summary: 'every Android Settings field is persisted by Kotlin *and* settable from the UI',
    scan(api) {
      const KT = 'apps/android/android/app/src/main/java/app/aethernext/SettingsStore.kt';
      if (!existsRel(KT)) return ['SettingsStore.kt missing'];
      const kt = readFileSync(join(ROOT, KT), 'utf8');
      const open = kt.indexOf('data class Settings(');
      const close = kt.indexOf('\n) {', open);
      if (open < 0 || close < 0) return ['no `data class Settings(…)` in SettingsStore.kt — parity is unverifiable'];
      const native = new Set(
        [...kt.slice(open, close).matchAll(/^ +var ([A-Za-z]\w*)/gm)].map((m) => m[1]),
      );
      if (!native.size) return ['SettingsStore.kt `Settings` has no fields — parity is unverifiable'];

      // The file declaring the type also declares `defaults`, so it mentions every
      // key by construction. A field is only reachable if some *other* module reads
      // or patches it — that is what `startMinimized`, `enginePath` and
      // `endpointPreset` lacked while they survived in the persisted payload.
      const declared = new Map();
      const rest = [];
      for (const f of api.files('apps/android/src', /\.(ts|tsx)$/)) {
        const src = api.read(f);
        if (/\.test\.tsx?$/.test(f)) continue;
        const block = src.match(/export type Settings\s*=\s*\{([\s\S]*?)\n\};/);
        if (block) {
          for (const k of block[1].matchAll(/^ {2}([A-Za-z]\w*)\??:/gm)) declared.set(k[1], [f, src, k.index]);
          continue;
        }
        rest.push([f, src]);
      }
      if (!declared.size) return ['no `export type Settings = { … }` under apps/android/src — parity is unverifiable'];

      const v = [];
      for (const [key, [f, src, idx]] of declared) {
        if (!native.has(key)) {
          v.push(`${locate(f, src, idx)} "${key}" is sent to the shell but SettingsStore.kt persists no such field`);
        }
        const word = new RegExp(`(^|[^A-Za-z0-9_$])${key}([^A-Za-z0-9_$]|$)`);
        const user = rest.find(([, s]) => word.test(s));
        if (!user) {
          v.push(`${locate(f, src, idx)} "${key}" is persisted by both layers but no component ever reads or patches it`);
        }
      }
      for (const key of native) {
        if (!declared.has(key)) {
          v.push(`${rel(join(ROOT, KT))}: SettingsStore.kt persists "${key}", which apps/android/src never sends`);
        }
      }
      return v;
    },
    inject() {
      return {
        file: 'apps/android/src/__selftest__.ts',
        content: 'export type Settings = {\n  phantomSettingZz: boolean;\n};\n',
      };
    },
  },
  {
    name: 'tls-no-ambient-bypass',
    invariant: 'BC-03',
    summary: 'no env-var TLS kill-switch; insecure policy is debug-only',
    scan(api) {
      const banned = [
        /AETHER_DANGEROUS_DISABLE_TLS_VERIFY/g,
        /AETHER_MASQUE_DISABLE_SPKI_PINS/g,
      ];
      const v = [];
      const dirs = ['aether/src', 'apps/desktop/src-tauri/src', 'apps/android/android/app/src/main'];
      const re = /\.(rs|kt)$/;
      for (const dir of dirs) {
        for (const f of api.files(dir, re)) {
          const t = api.read(f);
          for (const rx of banned) {
            let m;
            while ((m = rx.exec(t))) v.push(`${locate(f, t, m.index)} ambient TLS kill-switch`);
          }
          // `Insecure` must sit under a debug-only cfg attribute.
          const lines = t.split('\n');
          lines.forEach((line, i) => {
            if (!/VerifyPolicy::Insecure|Insecure\s*\{/.test(line) || line.includes('//!')) return;
            const window = lines.slice(Math.max(0, i - 4), i).join('\n');
            if (!/cfg\(\s*debug_assertions\s*\)/.test(window)) {
              v.push(`${rel(f)}:${i + 1} Insecure variant without a debug_assertions gate`);
            }
          });
        }
      }
      return v;
    },
    inject() {
      return {
        file: 'aether/src/__selftest__.rs',
        content: 'fn f() {\n  let _ = std::env::var("AETHER_DANGEROUS_DISABLE_TLS_VERIFY");\n  let p = VerifyPolicy::Insecure { reason: "x" };\n  let _ = p;\n}\n',
      };
    },
  },
  {
    name: 'no-fabricated-metrics',
    invariant: 'BC-14',
    summary: 'no invented telemetry in shipped UI',
    scan(api) {
      const banned = /(< 45 ms|0\.0%|HTTP LISTENING|SOCKS5 READY|END-TO-END TLS 1\.3|V4 DUAL-READY|0-RTT|TRAFFIC SECURE)/g;
      // A literal list of numbers rendered as bars is a measurement nobody took.
      const series = /\[\s*\d+\s*(?:,\s*\d+\s*){4,}\]/g;
      const v = [];
      const all = api.files('apps/desktop/src', /\.(tsx|ts)$/).concat(api.files('apps/android/src', /\.(tsx|ts)$/));
      for (const f of all) {
        const t = api.read(f);
        let m;
        while ((m = banned.exec(t))) v.push(`${locate(f, t, m.index)} fabricated metric "${m[1]}"`);
        while ((m = series.exec(t))) v.push(`${locate(f, t, m.index)} hard-coded sample series "${m[0]}" is presented as telemetry`);
      }
      return v;
    },
    inject() {
      return {
        file: 'apps/desktop/src/__selftest__.tsx',
        content:
          'export const X = () => <b>{"< 45 ms"}{[42, 68, 55, 84, 62, 75].map((v) => <i key={v} />)}</b>;',
      };
    },
  },
  {
    name: 'trust-anchor-not-self-generated',
    invariant: 'BC-02',
    summary: 'the shell digests come from the committed anchor, never from the artifact being shipped',
    scan(api) {
      const v = [];
      for (const f of api.files('apps/desktop/src-tauri', /^build\.rs$/)) {
        const t = api.read(f);
        if (!/engine-trust\.json/.test(t)) {
          v.push(`${rel(f)} derives no digest from packaging/trust/engine-trust.json — the runtime comparison has nothing independent to compare against`);
        }
        for (const m of t.matchAll(/(?:compute_sha256|file_sha256_hex|\bsha256_hex)\s*\(([^)]*)\)/g)) {
          if (/resources|target[\\/]release|aether\.exe|wintun\.dll/.test(m[1])) {
            v.push(`${locate(f, t, m.index)} hashes the shipped artifact (${m[1].trim()}) — the check can then only ever succeed`);
          }
        }
        for (const m of t.matchAll(/unwrap_or_default\s*\(\)|\.unwrap_or\s*\(\s*""/g)) {
          v.push(`${locate(f, t, m.index)} a missing digest defaults to nothing — that is how an empty allow-list ships green`);
        }
      }
      return v;
    },
    inject() {
      return {
        file: 'apps/desktop/src-tauri/build.rs',
        content: 'fn main() {\n    let h = compute_sha256(Path::new("resources/aether.exe")).unwrap_or_default();\n    println!("{h}");\n}\n',
      };
    },
  },
  {
    name: 'engine-spawns-scrub-ambient-env',
    invariant: 'BC-04',
    summary: 'every engine spawn site clears the inherited AETHER_* environment first',
    scan(api) {
      const v = [];
      for (const f of api.files('apps/desktop/src-tauri/src', /\.rs$/)) {
        const t = api.read(f);
        const spawns = [...t.matchAll(/Command::new\(&executable\)/g)].length;
        const scrubs = [...t.matchAll(/scrub_ambient_engine_env\(&mut command\)/g)].length;
        if (spawns > scrubs) {
          v.push(`${rel(f)}: ${spawns - scrubs} of ${spawns} spawn sites inherit AETHER_* untouched — a session variable then outranks the handoff the shell promised`);
        }
      }
      return v;
    },
    inject() {
      return {
        file: 'apps/desktop/src-tauri/src/lib.rs',
        content: 'fn a() {\n  let mut command = Command::new(&executable);\n  command.env("AETHER_TUN", "1");\n}\n',
      };
    },
  },
  {
    name: 'engine-verified-before-every-spawn',
    invariant: 'BC-02',
    summary: 'every engine spawn site verifies the binary first, in every routing mode',
    scan(api) {
      const v = [];
      for (const f of api.files('apps/desktop/src-tauri/src', /\.rs$/)) {
        const t = api.read(f);
        const spawns = [...t.matchAll(/Command::new\(&executable\)/g)].length;
        const verified = [...t.matchAll(/verify_engine_or_refuse\(&executable\)/g)].length;
        if (verified < spawns) {
          v.push(`${rel(f)}: ${spawns - verified} spawn site(s) reach Command::new without the signature/digest check — verification used to be gated on routing_mode == "tun", so proxy mode spawned an unchecked binary`);
        }
        const modeGatedTrust = /routing_mode\s*==\s*"tun"[\s\S]{0,400}?verify_elevated_binary\(&executable/.test(t);
        if (modeGatedTrust) {
          v.push(`${rel(f)}: an engine trust check sits inside a routing-mode branch again`);
        }
      }
      return v;
    },
    inject() {
      return {
        file: 'apps/desktop/src-tauri/src/lib.rs',
        content: 'fn a() {\n  if settings.routing_mode == "tun" {\n    verify_elevated_binary(&executable, "aether.exe", &policy).unwrap();\n  }\n  let mut command = Command::new(&executable);\n  command.spawn();\n}\n',
      };
    },
  },
  {
    name: 'no-cross-token-elevation-spawn',
    invariant: 'BC-05',
    summary: 'no child is spawned across a token boundary, which the kill-on-close job cannot control',
    scan(api) {
      const banned = [
        [/-Verb\s+RunAs/g, 'Start-Process -Verb RunAs'],
        [/"runas"|'runas'/g, 'ShellExecute "runas"'],
        [/CreateProcessWithTokenW|CreateProcessAsUserW/g, 'token-duplicating process creation'],
        [/\bLogonUser\w*\(/g, 'LogonUser'],
      ];
      const v = [];
      for (const dir of ['apps/desktop/src-tauri/src', 'aether/src']) {
        for (const f of api.files(dir, /\.(rs|toml|json)$/)) {
          const t = api.read(f);
          for (const [re, label] of banned) {
            let m;
            while ((m = re.exec(t))) {
              // The rules that forbid this are documentation, not code.
              const line = t.slice(0, m.index).split('\n').pop() ?? '';
              if (/^\s*(\/\/|\/\*|\*)/.test(line)) continue;
              v.push(`${locate(f, t, m.index)} ${label}: a process created across a token boundary cannot be assigned to the caller's job object, so kill-on-close stops working (see aether/src/trust.rs)`);
            }
          }
        }
      }
      return v;
    },
    inject() {
      return {
        file: 'apps/desktop/src-tauri/src/__selftest__.rs',
        content: 'fn escalate() {\n    let args = ["-Verb", "RunAs"];\n    ShellExecuteW(0, "runas", p, 0, 0, 0);\n    CreateProcessWithTokenW(t, 0, 0, 0, 0, 0, 0, 0, 0, 0);\n}\n',
      };
    },
  },
  {
    name: 'actions-pinned-to-full-commit',
    invariant: 'BC-18',
    summary: 'workflow actions are pinned to a full commit SHA, one SHA per action',
    scan(api) {
      const v = [];
      const seen = new Map();
      for (const f of api.files('.github/workflows', /\.ya?ml$/)) {
        const t = api.read(f);
        for (const m of t.matchAll(/uses:\s*([^\s@]+)@([^\s#]+)/g)) {
          const action = m[1];
          const ref = m[2];
          if (action.startsWith('./')) continue; // local composite action
          if (!/^[0-9a-f]{40}$/.test(ref)) {
            const why = /^[0-9a-f]+$/.test(ref)
              ? `a ${ref.length}-character hex ref is not a commit — GitHub reports "unable to resolve action", which reads as runner flakiness, and it took three red runs to notice`
              : `floating ref "${ref}" can move under the workflow without a commit here`;
            v.push(`${locate(f, t, m.index)} ${action}@${ref}: ${why}`);
            continue;
          }
          const prior = seen.get(action);
          if (prior && prior !== ref) {
            v.push(`${locate(f, t, m.index)} ${action} is pinned to two different commits (${prior.slice(0, 8)}… and ${ref.slice(0, 8)}…)`);
          }
          seen.set(action, ref);
        }
      }
      return v;
    },
    inject() {
      return {
        file: '.github/workflows/__selftest__.yml',
        content: 'jobs:\n  a:\n    steps:\n      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af68\n      - uses: actions/setup-node@v4\n',
      };
    },
  },
  {
    name: 'css-no-dead-duplicates',
    invariant: 'BC-11',
    summary: 'no declaration repeated with the same value inside one rule',
    scan(api) {
      // A second identical declaration is not a fallback (that would be a
      // different value) and not a cascade (same block): it is one of the two
      // lines doing nothing, and it survives every review because it is
      // invisible. Both sheets carried `overflow-wrap: anywhere` twice, in the
      // same rule, in parallel copies of each other.
      const v = [];
      for (const f of api.files('apps', /\.css$/).concat(api.files('packages', /\.css$/))) {
        const text = api.read(f);
        // Strip comments' bodies but keep their newlines: replacing a block comment
        // with nothing shifts every later line number, and a violation that names
        // the wrong line is worse than no check at all.
        const code = text.replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, ' '));
        let depth = 0;
        let props = new Map();
        let buffer = '';
        const line = (idx) => code.slice(0, idx).split('\n').length;
        const flushDeclaration = (decl, at) => {
          const m = decl.match(/^([a-z-]+)\s*:\s*(.+)$/i);
          if (!m) return;
          const key = `${m[1].toLowerCase()}:${m[2].trim().replace(/\s+/g, ' ').toLowerCase()}`;
          const seen = props.get(key);
          if (seen !== undefined) {
            v.push(
              `${rel(f)}:${line(at)} \`${m[1]}: ${m[2].trim()}\` is declared twice in the same rule (first at line ${seen}); the second one does nothing`,
            );
          } else {
            props.set(key, line(at));
          }
        };
        for (let i = 0; i < code.length; i += 1) {
          const ch = code[i];
          if (ch === '{') {
            depth += 1;
            props = new Map();
            buffer = '';
          } else if (ch === '}') {
            if (buffer.trim()) flushDeclaration(buffer.trim(), i);
            depth -= 1;
            buffer = '';
          } else if (ch === ';' && depth > 0) {
            if (buffer.trim()) flushDeclaration(buffer.trim(), i);
            buffer = '';
          } else if (ch !== '\n' || buffer.trim()) {
            buffer += ch;
          }
        }
      }
      return v;
    },
    inject() {
      return {
        file: 'apps/desktop/src/__selftest__.css',
        content: '.a {\n  color: red;\n  color: red;\n}\n',
      };
    },
  },
  {
    name: 'css-breakpoint-reachable',
    invariant: 'BC-11',
    summary: 'no desktop media query narrower or shorter than the window minimum',
    scan(api) {
      // A window that cannot be resized below 900x620 can never show a 680 px
      // layout, so every rule under such a breakpoint is dead CSS that reads as
      // responsive work. Two desktop blocks were like that in this repo's history
      // (measured across all 29 commits that touched the sheet, which is the same
      // shape of check this gate runs on every push); they are gone now, and the
      // rule keeps them from coming back. Desktop only: on the phone the viewport
      // *is* the device, so a 680 px query there is the layout, not a fiction.
      const CONF = 'apps/desktop/src-tauri/tauri.conf.json';
      if (!existsRel(CONF)) return ['tauri.conf.json missing'];
      let conf;
      try {
        conf = JSON.parse(readFileSync(join(ROOT, CONF), 'utf8'));
      } catch (e) {
        return [`tauri.conf.json does not parse: ${e.message}`];
      }
      const win = conf?.app?.windows?.[0] ?? {};
      if (typeof win.width !== 'number' || typeof win.height !== 'number') {
        return ['no primary window size in tauri.conf.json — reachability is unverifiable'];
      }
      const minWidth = typeof win.minWidth === 'number' ? win.minWidth : 0;
      const minHeight = typeof win.minHeight === 'number' ? win.minHeight : 0;
      const v = [];
      for (const f of api.files('apps/desktop/src', /\.css$/)) {
        const src = api.read(f);
        for (const m of src.matchAll(/@media[^{]*?\((max-width|max-height):\s*(\d+)px\)/g)) {
          const limit = m[1] === 'max-width' ? minWidth : minHeight;
          const px = Number(m[2]);
          // Contract U-F2 forbids *coincidence*, not just an unreachable query:
          // at exactly the minimum the block still applies, which is what let it
          // switch off the app's only status widget while looking reachable.
          if (px <= limit) {
            v.push(
              `${locate(f, src, m.index)} (${m[1]}: ${px}px) sits at or below the window minimum of ${limit}px: ${px === limit ? 'it is the boundary layout the user is forced into, so anything it hides has no other way to appear' : 'it can never match, so every rule in this block is dead'}`,
            );
          }
        }
      }
      return v;
    },
    inject() {
      return {
        file: 'apps/desktop/src/__selftest__.css',
        content: '@media (max-width: 400px) {\n  .impossible { color: red; }\n}\n',
      };
    },
  },
  {
    name: 'npm-lock-is-the-one-npm-reads',
    invariant: 'BC-18',
    summary: 'a workspaces root owns the lockfile; no committed lock sits where npm cannot see it',
    scan(api) {
      // `workspaces` in an ancestor manifest makes every descendant
      // `package-lock.json` invisible: npm resolves the workspace root and reads
      // only *its* lock — and if the root has none, `npm ci` in `apps/desktop`
      // fails with EUSAGE on a clean checkout while the committed 100 KB lock
      // beside it looks perfectly pinned. This repo shipped both halves of that:
      // a root declaring three workspaces, no root lock, and two member locks
      // that pinned nothing (their Tailwind entries survived the removal of
      // Tailwind itself).
      const FIRST_PARTY = /^(|apps\/[^/]+|packages\/[^/]+)$/;
      const dirOf = (abs) => {
        const parts = rel(abs).split('/');
        return parts.slice(0, -1).join('/');
      };
      // The workspace root of the repository itself is the empty relative dir, and
      // everything below it is inside that root.
      const isUnder = (dir, root) => (root === '' ? true : dir === root || dir.startsWith(`${root}/`));

      const manifests = [];
      for (const f of api.files('.', /^package\.json$/)) {
        const dir = dirOf(f);
        if (!FIRST_PARTY.test(dir)) continue;
        let json;
        try {
          json = JSON.parse(api.read(f));
        } catch {
          continue;
        }
        manifests.push([dir, f, json]);
      }
      if (!manifests.length) return ['no first-party package.json found — the check is unverifiable'];

      const locked = new Set(api.files('.', /^package-lock\.json$/).map(dirOf));
      const roots = manifests.filter(([, , j]) => Array.isArray(j.workspaces) || typeof j.workspaces === 'object');
      const v = [];
      for (const [dir, f] of roots) {
        if (!locked.has(dir)) {
          v.push(`${rel(f)} declares workspaces but has no package-lock.json beside it: every lockfile below it is unreadable and \`npm ci\` fails there`);
        }
      }
      for (const lock of api.files('.', /^package-lock\.json$/)) {
        const dir = dirOf(lock);
        if (!dir) continue;
        const owner = roots.map(([rdir]) => rdir).find((rdir) => isUnder(dir, rdir) && dir !== rdir);
        if (owner !== undefined) {
          v.push(`${rel(lock)} is inside the workspace root "${owner || '.'}/package.json" — npm resolves the root manifest and never reads this lock`);
        }
      }
      return v;
    },
    inject() {
      return {
        file: 'packages/__selftest__/package.json',
        content: '{ "name": "phantom-workspace", "workspaces": ["apps/*"] }\n',
      };
    },
  },
  {
    name: 'wcag-pair-contrast',
    invariant: 'BC-12',
    summary: 'every colour-on-background pair a rule declares clears WCAG 1.4.3 after compositing',
    scan(api) {
      /*
       * FR-033/BC-12 asked for "informational text >= 4.5:1" and the repo had no
       * way to observe it: both axe suites pass `color-contrast: disabled` (axe
       * cannot compute it in jsdom, which has no layout), so the only contrast
       * evidence in the project was a number quoted in a CSS comment. Those
       * comments were measured against bare surfaces; the moment a translucent
       * chip sits over one the number changes, and two rules in this repo were
       * below AA because of it (.nav-shortcut at 4.33:1, .empty-term-icon at
       * 1.59:1). So the check composites the declaration the way the browser
       * does, and it is conservative about the backdrop: a rule that does not
       * set its own background is measured against *every* surface it can
       * inherit, and a gradient is measured against each of its stops.
       *
       * Known limit, stated rather than hidden: text that inherits its colour
       * from an ancestor is only measured at the rule that declares it. That is
       * still every colour in the sheets, because each one is declared somewhere.
       */
      const v = [];
      for (const f of api.files('apps', /\.css$/).concat(api.files('packages', /\.css$/))) {
        const src = api.read(f);
        const masked = blankComments(src);
        const tokens = sheetColourTokens(masked);
        const surfaces = sheetSurfaces(tokens);
        if (!surfaces.length) continue;
        for (const [sel, body, at] of ruleBlocks(masked)) {
          const cd = body.match(/(?:^|[;{\s])color:\s*([^;]+)/);
          if (!cd) continue;
          const fg = declarationColours(cd[1].trim(), tokens);
          if (!fg.resolved || !fg.scalars.length) continue;
          const bd = body.match(/(?:^|[;{\s])background(?:-color)?:\s*([^;]+)/);
          let bases = surfaces.map(([n, s]) => [n, s]);
          if (bd) {
            const bg = declarationColours(bd[1].trim(), tokens);
            if (!bg.resolved) continue;
            const layers = (bg.stops ?? []).concat(bg.scalars);
            if (!layers.length) continue;
            bases = [];
            for (const l of layers) {
              if (l[3] === 1) bases.push([bd[1].trim().slice(0, 26), l]);
              else for (const [n, s] of surfaces) bases.push([`${bd[1].trim().slice(0, 20)} on ${n}`, compositeOver(l, s)]);
            }
          }
          // WCAG large text: >= 24px, or >= 18.66px at a bold weight.
          const px = Number((body.match(/font-size:\s*([\d.]+)px/) ?? [])[1]);
          const weight = /font-weight:\s*(bold|[6-9]00)/.test(body);
          const need = px >= 24 || (px >= 18.66 && weight) ? 3 : 4.5;
          const colour = fg.scalars[0];
          let worst = null;
          for (const [bn, bgColour] of bases) {
            const r = colourRatio(compositeOver(colour, bgColour), bgColour);
            if (!worst || r < worst.r) worst = { r, bn };
          }
          if (worst && worst.r < need) {
            v.push(
              `${locate(f, masked, at)} ${sel.slice(0, 44)}: color ${cd[1].trim()} on ${worst.bn} is ${worst.r.toFixed(2)}:1, needs ${need}:1`,
            );
          }
        }
      }
      return v;
    },
    inject() {
      return {
        file: 'apps/desktop/src/__selftest__.css',
        content: ':root{--panel:#0d1116;}\n.dim{color:#334155;background:var(--panel);font-size:13px;}\n',
      };
    },
  },
  {
    name: 'wcag-state-edges',
    invariant: 'BC-12',
    summary: 'state edge tokens and control boundaries clear WCAG 1.4.11 (3:1) on every surface',
    scan(api) {
      /*
       * FR-032: "edges that carry meaning must meet >=3:1". Meaning-carrying is
       * decided by role, not by alpha, so this gate looks at the two places the
       * role is written down: a `--*-border` / `--edge-*` token exists *to*
       * signal state, and a control's boundary is the only thing showing its
       * extent. Everything else (beacon rings, the signal meter's unlit bars,
       * card hairlines) is decoration next to text that already says the same
       * thing, and 1.4.11 does not ask anything of it.
       *
       * A `--*-dim` wash is a background, not an edge, so it is measured by the
       * pair gate as whatever sits on it; `--*-glow` is a shadow, which conveys
       * no information by itself.
       */
      const CONTROL = /(input|select|textarea|combobox|search|stepper|chassis|toggle|knob|checkbox|radio|-btn|button)/i;
      const v = [];
      for (const f of api.files('apps', /\.css$/).concat(api.files('packages', /\.css$/))) {
        const src = api.read(f);
        const masked = blankComments(src);
        const tokens = sheetColourTokens(masked);
        const surfaces = sheetSurfaces(tokens);
        if (!surfaces.length) continue;
        const worstAgainst = (colour) => {
          let worst = null;
          for (const [n, s] of surfaces) {
            const r = colourRatio(compositeOver(colour, s), s);
            if (!worst || r < worst.r) worst = { r, n };
          }
          return worst;
        };
        for (const [name, value] of Object.entries(tokens.resolved)) {
          if (!(/-border$/.test(name) || name.startsWith('--edge-'))) continue;
          const colour = parseColour(value);
          if (!colour) continue;
          const w = worstAgainst(colour);
          if (w && w.r < 3) {
            v.push(`${rel(f)}:0 ${name} = ${value} is ${w.r.toFixed(2)}:1 on ${w.n}, needs 3:1 (WCAG 1.4.11)`);
          }
        }
        for (const [sel, body, at] of ruleBlocks(masked)) {
          if (!CONTROL.test(sel)) continue;
          for (const bd of body.matchAll(/(?:^|[;{\s])border(?:-color)?:\s*([^;]+)/g)) {
            const colours = declarationColours(bd[1].trim(), tokens);
            for (const colour of colours.scalars) {
              const w = worstAgainst(colour);
              if (w && w.r < 3) {
                v.push(
                  `${locate(f, masked, at)} ${sel.slice(0, 44)}: control boundary ${bd[1].trim().slice(0, 28)} is ${w.r.toFixed(2)}:1 on ${w.n}, needs 3:1 (WCAG 1.4.11)`,
                );
              }
            }
          }
        }
      }
      return v;
    },
    inject() {
      return {
        file: 'apps/desktop/src/__selftest__.css',
        content: ':root{--panel:#0d1116;--weak-border:rgba(255,92,92,0.32);}\n.weak-input{border:1px solid var(--weak-border);}\n',
      };
    },
  },
  {
    name: 'type-scale-floor',
    invariant: 'BC-12',
    summary: 'no font-size below 11px, in a token or in a literal',
    scan(api) {
      // FR-033 pairs the 4.5:1 floor with an 11px one, and both sheets used to
      // sit under it in 44 declarations -- of the *status* layer (timestamps,
      // stat labels, field hints). The floor is `--text-micro`; this gate keeps
      // either spelling from drifting back down.
      const FLOOR = 11;
      const v = [];
      for (const f of api.files('apps', /\.css$/).concat(api.files('packages', /\.css$/))) {
        const src = api.read(f);
        const masked = blankComments(src);
        for (const m of masked.matchAll(/(--text-[\w-]+)\s*:\s*([\d.]+)px/g)) {
          if (Number(m[2]) < FLOOR) v.push(`${locate(f, masked, m.index)} ${m[1]} is ${m[2]}px, below the ${FLOOR}px floor`);
        }
        for (const m of masked.matchAll(/font-size:\s*([\d.]+)px/g)) {
          if (Number(m[1]) < FLOOR) v.push(`${locate(f, masked, m.index)} font-size: ${m[1]}px is below the ${FLOOR}px floor`);
        }
      }
      return v;
    },
    inject() {
      return {
        file: 'apps/desktop/src/__selftest__.css',
        content: '.tiny{font-size:9.5px}\n',
      };
    },
  },
  {
    name: 'declarations-live-in-a-block',
    invariant: 'BC-11',
    summary: 'every CSS declaration sits inside a rule block',
    scan(api) {
      /*
       * A custom property written between two rules is not a token: it is
       * invalid CSS that every text scanner in this file still reads as
       * defined, so `var(--fg)` resolves to nothing on screen while all
       * nineteen of the colour gates go green. This gate exists because a
       * script added ~100 tokens that way, and nothing else noticed.
       */
      const v = [];
      for (const f of api.files('apps', /\.css$/).concat(api.files('packages', /\.css$/))) {
        const code = blankComments(api.read(f));
        let depth = 0;
        const at = (idx) => code.slice(0, idx).split('\n').length;
        // Only custom properties are checked, and only at depth 0: `--x:` can be
        // nothing but a declaration, whereas a bare `color:` at depth 0 could be
        // part of a selector or an @media condition and would read as a false
        // positive. That is enough to catch the defect this gate exists for.
        for (const m of code.matchAll(/[{}]|(--[\w-]+)\s*:/g)) {
          if (m[0] === '{') { depth += 1; continue; }
          if (m[0] === '}') { depth -= 1; continue; }
          if (depth === 0) {
            v.push(`${rel(f)}:${at(m.index)} ${m[1]}: is declared outside any rule block, so it does nothing`);
          }
        }
      }
      return v;
    },
    inject() {
      return { file: 'packages/ui/__selftest__.css', content: '.a{color:red}\n--loose: #123456;\n' };
    },
  },
  {
    name: 'touch-target-minimum',
    invariant: 'BC-14',
    summary: 'controls declare a target box at least 24px (44px for the primary ones)',
    scan(api) {
      /*
       * U-F4 / WCAG 2.5.8. Two things make this more than a regex over CSS.
       * First, the target is the element a pointer lands on, so the classes
       * that matter come from the JSX (button/input/select/a/[role]), not from
       * every selector that happens to contain "btn" -- the knob inside a
       * switch and the icon inside a button are 18px on purpose. Second, a
       * control's box is declared across its base rule, its state rules and its
       * media overrides, so the sizes merge per class and the *largest* declared
       * box is what a finger meets.
       *
       * It is measured on the sheet rather than on a rendered page because the
       * test environment has no layout engine (jsdom) and the browser surface
       * here reports a 0x0 viewport: a "just measure it" check would silently
       * measure nothing, which is the failure mode this harness exists for.
       */
      const MIN = 24;
      const PRIMARY = new Set(['master-switch-chassis', 'master-toggle-btn', 'primary-cta']);
      const px = (body, prop) => {
        const m = body.match(new RegExp(`(?:^|[;\\s])${prop}:\\s*(?:calc\\()?(\\d+(?:\\.\\d+)?)px`));
        return m ? Number(m[1]) : null;
      };
      const v = [];
      // Only the leading class counts as what an element *is*: the tokens after
      // it are state modifiers (`.profile-card.active`) and utilities
      // (`font-mono`), and `[a-z][a-z0-9-]*` keeps the camelCase expressions out
      // of the vocabulary entirely.
      const classToken = (s) => (s ?? '').split(/[\s${}]+/).find((t) => /^[a-z][a-z0-9-]*$/.test(t)) ?? null;
      for (const app of ['apps/desktop', 'apps/android']) {
        const classes = new Map();
        const note = (token, where) => {
          if (token && !classes.has(token)) classes.set(token, where);
        };
        for (const f of api.files(`${app}/src`, /\.tsx$/)) {
          if (/[.\-/]tests?[.\-]/.test(rel(f)) || f.endsWith('.test.tsx')) continue;
          const src = api.read(f);
          for (const m of src.matchAll(/<(?:button|input|select|a)\b[\s\S]{0,600}?className\s*=\s*(?:"([^"]*)"|\{`([^`]*)`\})/g)) {
            note(classToken(m[1] ?? m[2]), locate(f, src, m.index));
          }
          // A div is a pointer target when it says so with an interactive role
          // or a handler. `aria-label` alone is not enough: the 6px progress bar
          // carries one and nobody taps it.
          for (const m of src.matchAll(/className\s*=\s*(?:"([^"]*)"|\{`([^`]*)`\})[^>]{0,400}?(?:onClick|onKeyDown|onPointerDown|role\s*=\s*"(?:button|tab|checkbox|switch|link|menuitem|option)")[^>]*>/g)) {
            note(classToken(m[1] ?? m[2]), locate(f, src, m.index));
          }
        }
        const size = new Map();
        // A gate that inspected nothing must not report success.
        if (!classes.size) v.push(`${app}: no pointer targets found in the JSX, so this gate is checking nothing`);
        for (const f of api.files(app, /\.css$/)) {
          const code = blankComments(api.read(f));
          for (const [sel, body] of ruleBlocks(code)) {
            const h = Math.max(px(body, 'height') ?? -Infinity, px(body, 'min-height') ?? -Infinity);
            const w = Math.max(px(body, 'width') ?? -Infinity, px(body, 'min-width') ?? -Infinity);
            const pad = /(?:^|[;\s])padding/.test(body);
            for (const cls of sel.match(/\.([\w-]+)/g) ?? []) {
              const name = cls.slice(1);
              if (!classes.has(name)) continue;
              const cur = size.get(name) ?? { h: -Infinity, w: -Infinity, pad: false };
              size.set(name, { h: Math.max(cur.h, h), w: Math.max(cur.w, w), pad: cur.pad || pad });
            }
          }
        }
        for (const [name, where] of classes) {
          const floor = PRIMARY.has(name) ? 44 : MIN;
          const box = size.get(name);
          if (!box || (box.h === -Infinity && box.w === -Infinity)) {
            if (!box?.pad) v.push(`${where}: .${name} is a pointer target with no declared size or padding, so its box is whatever its content is`);
            continue;
          }
          if (box.h !== -Infinity && box.h < floor) v.push(`${where}: .${name} is ${box.h}px tall, below the ${floor}px target floor`);
          if (box.w !== -Infinity && box.w < floor) v.push(`${where}: .${name} is ${box.w}px wide, below the ${floor}px target floor`);
        }
      }
      return v;
    },
    inject() {
      return [
        {
          file: 'apps/desktop/src/__selftest__.tsx',
          content: 'export const V = () => <button className="tiny-btn">x</button>;\n',
        },
        { file: 'apps/desktop/src/__selftest__.css', content: '.tiny-btn{height:18px;width:18px}\n' },
      ];
    },
  },
  {
    name: 'colour-single-source',
    invariant: 'BC-11',
    summary: 'no colour literal in an app sheet outside the fenced token block',
    scan(api) {
      /*
       * Contract U-B5 says the tokens file is the sole colour source, and the
       * tree disagreed: 408 chromatic literals sat in the two app sheets, of
       * which the interesting part is what they had already become -- `#38bdf8`
       * and `rgba(56,189,248,.x)` painted a blue the palette had retired to
       * `#5cc8ff` in 20 places, and one sheet's primary text was `#edf2f5`
       * while the emphasis step was `#ffffff` in 62. A hue spelled 23 different
       * ways never gets changed, so the palette comment claiming it had been
       * "reconciled" was describing an intention rather than the CSS.
       *
       * Achromatic alphas (r == g == b) stay allowed: a black shadow or a white
       * overlay carries no hue, so there is nothing for it to drift from.
       */
      const v = [];
      for (const f of api.files('apps', /\.css$/)) {
        const raw = api.read(f);
        const outside = raw
          .split('/*==AETHER-TOKENS-START==*/')
          .map((part) => part.split('/*==AETHER-TOKENS-END==*/').pop())
          .join('');
        const code = blankComments(outside);
        for (const m of code.matchAll(/#[0-9a-fA-F]{3,8}\b|\brgba?\([^)]*\)|\bhsla?\([^)]*\)/g)) {
          const p = parseColour(m[0]);
          if (!p) {
            v.push(`${locate(f, code, m.index)} ${m[0]} is a colour notation this gate cannot read; write it as a token`);
            continue;
          }
          if (p[0] === p[1] && p[1] === p[2]) continue;
          v.push(`${locate(f, code, m.index)} ${m[0]} spells a hue in the sheet instead of the palette`);
        }
      }
      return v;
    },
    inject() {
      return { file: 'apps/desktop/src/__selftest__.css', content: '.drift{color:#38bdf8}\n' };
    },
  },
  {
    name: 'token-alpha-triples',
    invariant: 'BC-11',
    summary: 'every --<family>-aNN token is still its family hue at that alpha',
    scan(api) {
      // The alpha ladder is spelled out as `rgba(0, 240, 138, 0.25)` rather than
      // derived, because the alternative is a CSS function newer than anything
      // else in these sheets and an Android WebView nobody can force to update.
      // That trade only holds while a gate keeps every rung tied to its hue:
      // change --emerald without the ladder and this fails, instead of quietly
      // shipping emerald text under sky-blue glows.
      const v = [];
      for (const f of api.files('apps', /\.css$/).concat(api.files('packages', /\.css$/))) {
        const tokens = sheetColourTokens(blankComments(api.read(f)));
        for (const [name, value] of Object.entries(tokens.resolved)) {
          const m = name.match(/^--(.+)-a(\d{2,3})$/);
          if (!m) continue;
          const family = tokens.resolved[`--${m[1]}`];
          if (!family) continue;
          const hue = parseColour(expandVars(family, tokens));
          const rung = parseColour(value);
          if (!hue || !rung) continue;
          if (rung[0] !== hue[0] || rung[1] !== hue[1] || rung[2] !== hue[2]) {
            v.push(`${rel(f)}:0 ${name} = ${value} is no longer --${m[1]} (${family})`);
          }
        }
      }
      return v;
    },
    inject() {
      return {
        file: 'packages/ui/__selftest__.tokens.css',
        content: ':root{--emerald:#00f08a;--emerald-a25:rgba(56, 189, 248, 0.25);}\n',
      };
    },
  },
];

/* ------------------------------------------------------------------ runner */

function realApi() {
  return {
    files: (dir, re) => walk(join(ROOT, dir), re, []),
    read: (abs) => readFileSync(abs, 'utf8'),
  };
}

/** API where exactly one synthetic file is visible to the gate. */
function injectedApi(spec) {
  // A gate whose defect spans two artefacts (a class in the JSX *and* the rule
  // that sizes it) injects a list; every other gate injects one file.
  const specs = Array.isArray(spec) ? spec : [spec];
  const byBasename = specs.map((s) => [join(ROOT, s.file), s.content]);
  return {
    files: (_dir, re) => byBasename.filter(([abs]) => re.test(basename(abs))).map(([abs]) => abs),
    read: (p) => byBasename.find(([abs]) => abs === p)?.[1] ?? readFileSync(p, 'utf8'),
  };
}

function scanOf(gate, api) {
  const out = gate.scan(api);
  return Array.isArray(out) ? out : [];
}

function main() {
  const args = process.argv.slice(2);
  const selftest = args.includes('--selftest-fail');
  const wantGate = args.includes('--gate') ? args[args.indexOf('--gate') + 1] : null;
  const selected = wantGate ? GATES.filter((g) => g.name === wantGate) : GATES;

  if (wantGate && !selected.length) {
    console.error(`unknown gate: ${wantGate}`);
    console.error(`known: ${GATES.map((g) => g.name).join(', ')}`);
    process.exit(2);
  }

  if (selftest) {
    console.log(`# verify-invariants --selftest-fail (${selected.length} gate(s))`);
    let blind = 0;
    for (const g of selected) {
      let caught = false;
      let detail = '';
      try {
        const out = scanOf(g, injectedApi(g.inject()));
        caught = out.length > 0;
        detail = out[0] ?? '';
      } catch (e) {
        detail = `threw: ${e.message}`;
      }
      if (caught) {
        console.log(`  ok   ${g.name} [${g.invariant}] detects its injected defect`);
      } else {
        console.log(`  FAIL ${g.name} [${g.invariant}] BLIND — injected defect not detected (${detail})`);
        blind += 1;
      }
    }
    console.log(blind ? `\n# SELFTEST FAILED: ${blind} blind gate(s)` : '\n# selftest passed');
    process.exit(blind ? 1 : 0);
  }

  console.log(`# verify-invariants (${selected.length} gate(s))`);
  let failing = 0;
  for (const g of selected) {
    let out;
    try {
      out = scanOf(g, realApi());
    } catch (e) {
      out = [`checker threw: ${e.message}`];
    }
    const ok = out.length === 0;
    console.log(`${ok ? 'ok  ' : 'FAIL'} ${g.name} [${g.invariant}] — ${g.summary}`);
    for (const line of out.slice(0, MAX_FINDINGS)) console.log(`   ${line}`);
    if (out.length > MAX_FINDINGS) console.log(`   … ${out.length - MAX_FINDINGS} more`);
    if (!ok) failing += 1;
  }
  console.log(failing ? `\n# ${failing}/${selected.length} gate(s) failing` : `\n# all ${selected.length} gate(s) passing`);
  process.exit(failing ? 1 : 0);
}

main();
