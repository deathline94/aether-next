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
      const sheets = ['apps/desktop/src/App.css', 'apps/android/src/App.css', 'packages/ui/tokens.css']
        .filter(existsRel)
        .map((p) => readFileSync(join(ROOT, p), 'utf8'))
        .join('\n');
      const defined = new Set([...sheets.matchAll(/\.([A-Za-z][\w-]*)/g)].map((m) => m[1]));
      /*
       * Tailwind generates utilities at build time, so they never appear as a
       * literal `.class` in the source sheets. The list is deliberately
       * per-token: a wildcard/prefix rule would blind this gate to every
       * genuinely unstyled element, which is the bug it exists to catch.
       */
      const BUILD_GENERATED = new Set(['font-mono', 'tabular-nums', 'text-red-400']);
      const v = [];
      for (const f of api.files('apps', /\.(tsx|jsx)$/)) {
        const t = api.read(f);
        for (const m of t.matchAll(/className=(?:"([^"]*)"|\{`([^`]*)`\})/g)) {
          const raw = (m[1] ?? m[2] ?? '').replace(/\$\{[^}]*\}/g, ' ');
          for (const tok of raw.split(/\s+/).filter(Boolean)) {
            if (BUILD_GENERATED.has(tok)) continue;
            // `badge-${tone}` strips to `badge-`: accept it as a family only if
            // at least one `badge-*` rule actually exists.
            if (tok.endsWith('-')) {
              let hit = false;
              for (const c of defined) if (c.startsWith(tok)) { hit = true; break; }
              if (hit) continue;
            }
            if (!defined.has(tok)) v.push(`${locate(f, t, m.index)} className "${tok}" has no rule`);
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
    summary: 'no 100vh, transition:all, bare :hover, alpha hairlines, undefined vars',
    scan(api) {
      const v = [];
      const all = api.files('apps', /\.css$/).concat(api.files('packages', /\.css$/));
      for (const f of all) {
        const t = api.read(f);
        const tests = [
          [/\b100vh\b/g, '100vh (use svh/dvh)'],
          [/transition\s*:\s*all\b/g, 'transition: all'],
          [/:hover\b/g, 'hover rule (must sit inside @media (hover: hover))'],
          [/border\s*:\s*1px solid rgba\(255,\s*255,\s*255,\s*\.?0?\.(?:0\d|1[01])\)/g, 'alpha hairline border'],
        ];
        for (const [re, label] of tests) {
          let m;
          while ((m = re.exec(t))) {
            // Hover is allowed only inside a pointer-guarded media block.
            if (label.startsWith('hover')) {
              const before = t.slice(0, m.index);
              const openMedia = before.lastIndexOf('@media');
              const closeRule = Math.max(before.lastIndexOf('\n}', openMedia), -1);
              if (openMedia > closeRule && /hover\s*:\s*hover/.test(before.slice(openMedia, m.index))) continue;
            }
            v.push(`${locate(f, t, m.index)} ${label}`);
          }
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
        content: '.a{height:100vh;transition:all .2s}\n.a:hover{color:red}\n.b{color:var(--nope-zz)}\n',
      };
    },
  },
  {
    name: 'ipc-command-parity',
    invariant: 'BC-09',
    summary: 'registered commands == invoked commands, both directions',
    scan(api) {
      if (!existsRel('apps/desktop/src-tauri/src/lib.rs')) return ['shell lib.rs missing'];
      const t = readFileSync(join(ROOT, 'apps/desktop/src-tauri/src/lib.rs'), 'utf8');
      const m = t.match(/generate_handler!\s*\[([^\]]*)\]/);
      if (!m) return ['generate_handler! not found — parity is unverifiable'];
      const registered = new Set(m[1].split(',').map((s) => s.trim()).filter(Boolean));
      const invoked = new Set();
      for (const f of api.files('apps', /\.(ts|tsx)$/)) {
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
  const abs = join(ROOT, spec.file);
  return {
    files: (_dir, re) => (re.test(basename(spec.file)) ? [abs] : []),
    read: (p) => (p === abs ? spec.content : readFileSync(p, 'utf8')),
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
