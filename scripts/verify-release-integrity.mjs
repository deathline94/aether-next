#!/usr/bin/env node
/*
 * Static gates over the release pipeline: the two workflows, the signing helper,
 * the trust anchor and the shell's verification code.
 *
 * WHY: the four defects this harness watches for were all invisible to review
 * because they lived in YAML or in a contract between two files. A checksum step
 * that could never pass, a witness cut from one binary and released from another,
 * a package whose engine has no anchor, a signature no clean machine can verify -
 * each of those is a property of *which steps run, in what order, against what*,
 * and none of them are testable by running the thing (that takes a release).
 *
 * So each gate reads the pipeline as data and every gate registers an `inject`
 * case that recreates the defect it detects; `--selftest-fail` runs the injected
 * defects through the same checker, the way scripts/verify-invariants.mjs does. A
 * gate that cannot see its own defect is reported blind and the run fails.
 *
 * Usage:
 *   node scripts/verify-release-integrity.mjs                 # every gate
 *   node scripts/verify-release-integrity.mjs --gate <name>   # one gate
 *   node scripts/verify-release-integrity.mjs --selftest-fail # prove they can fail
 */

import { readFileSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
// Overridable with --root so the same gates can be pointed at a scratch checkout
// (used to show what the pre-fix pipeline looked like to these checks).
let BASE = ROOT;
const BUILD = ".github/workflows/build.yml";
const PREPARE = ".github/workflows/prepare-anchor.yml";
const HELPER = ".github/scripts/sign-windows.ps1";
const PACK = ".github/scripts/pack-checksums.sh";
const PACK_TEST = ".github/scripts/test-pack-checksums.sh";
const ANCHOR = "packaging/trust/engine-trust.json";
const TRUST_RS = "apps/desktop/src-tauri/src/trust.rs";
const POLICY = "scripts/package-policy.mjs";
const WITNESS_ARTIFACT = "engine-witness";

const realApi = () => ({
  read: (rel) => readFileSync(join(BASE, rel), "utf8"),
  exists: (rel) => {
    try {
      return statSync(join(BASE, rel)).isFile();
    } catch {
      return false;
    }
  },
});

/** API in which exactly one file has been replaced by a synthetic version. */
function injectedApi(spec) {
  const base = realApi();
  return {
    read: (rel) => (rel === spec.file ? spec.content : base.read(rel)),
    exists: (rel) => (rel === spec.file ? true : base.exists(rel)),
  };
}

/* ------------------------------------------------------------- step reader */
/*
 * A deliberately small reader for GitHub's step lists: enough to answer "which
 * steps exist, in what order, under what `if`, running what text" without a YAML
 * dependency (this repository's root has no node_modules by design). It is not a
 * parser: it is line-oriented, and the shapes it looks for are the ones the
 * workflows actually use.
 */
function stepsOf(text, job) {
  const lines = text.split(/\r?\n/);
  const start = lines.findIndex((l) => l === `  ${job}:`);
  if (start === -1) return null;
  const steps = [];
  let current = null;
  let inRun = false;
  let inBlock = null;
  for (let i = start + 1; i < lines.length; i += 1) {
    const line = lines[i];
    if (/^  [A-Za-z0-9_-]+:\s*$/.test(line)) break; // next job
    if (/^      - /.test(line)) {
      current = {
        line: i + 1,
        name: "",
        uses: "",
        if: "",
        run: "",
        withText: "",
        all: line,
      };
      const m = line.match(/^      - (name|uses):\s*(.*)$/);
      if (m) {
        if (m[1] === "name") current.name = m[2].trim();
        else current.uses = m[2].trim();
      }
      steps.push(current);
      inRun = false;
      inBlock = null;
      continue;
    }
    if (!current) continue;
    current.all += `\n${line}`;
    // A step may declare `name:` on its list item and `uses:`/`if:` underneath, or
    // the other way round; both orders are used in these workflows.
    if (!inRun && !inBlock) {
      const uses = line.match(/^        uses:\s*(.*)$/);
      if (uses) {
        current.uses = uses[1].trim();
        continue;
      }
      const nm = line.match(/^        name:\s*(.*)$/);
      if (nm) {
        current.name = nm[1].trim();
        continue;
      }
    }
    const cond = line.match(/^        if:\s*(.*)$/);
    if (cond) {
      current.if = cond[1].trim();
      continue;
    }
    if (/^        (with|env):\s*$/.test(line)) {
      inBlock = "with";
      inRun = false;
      continue;
    }
    if (/^        run:\s*\|/.test(line)) {
      inRun = true;
      inBlock = null;
      continue;
    }
    if (/^ {10,}\S/.test(line)) {
      if (inRun) current.run += `\n${line}`;
      else if (inBlock) current.withText += `\n${line}`;
      continue;
    }
    inRun = false;
    inBlock = null;
  }
  return steps;
}

const devGuarded = (s) =>
  /AETHER_PACKAGE_KIND\s*!=\s*'release'/.test(s.if) ||
  /AETHER_PACKAGE_KIND\s*==\s*'development'/.test(s.if);
const releaseOnly = (s) => /AETHER_PACKAGE_KIND\s*==\s*'release'/.test(s.if);

/** One job's own text, so a per-job declaration cannot be satisfied elsewhere. */
function jobText(text, job) {
  const lines = text.split(/\r?\n/);
  const start = lines.findIndex((l) => l === `  ${job}:`);
  if (start === -1) return "";
  let end = lines.length;
  for (let i = start + 1; i < lines.length; i += 1) {
    if (/^  [A-Za-z0-9_-]+:\s*$/.test(lines[i])) {
      end = i;
      break;
    }
  }
  return lines.slice(start, end).join("\n");
}

/** Engine bytes may not be produced or signed by a release run: name the shapes. */
const ENGINE_REBUILD = [
  { re: /cargo\s+build\b/, why: "rebuilds the engine" },
  { re: /Set-AuthenticodeSignature/, why: "signs a binary" },
  { re: /sign-windows\.ps1(?!\s+-VerifyOnly)[^\n]*aether\.exe/, why: "signs the engine" },
  {
    re: /Copy-Item[^\n]*aether\/target\/release\/aether\.exe[^\n]*resources/,
    why: "stages a locally built engine into the bundle",
  },
];

/* --------------------------------------------------------------- the gates */
const GATES = [
  {
    name: "cross-run-witness-and-signing-provenance",
    invariant: "BC-02",
    summary: "the witness download has actions:read and the publish job receives the Windows signing verdict",
    scan(api) {
      const v = [];
      const build = api.read(BUILD);
      const windows = jobText(build, "windows-app");
      const publish = jobText(build, "publish");
      const permissions = windows.match(/^    permissions:\s*\n((?:^      [^\n]*\n)*)/m)?.[1] ?? "";
      if (!/^      actions:\s*read\b/m.test(permissions)) {
        v.push(`${BUILD}:windows-app needs actions: read to download a witness from another run`);
      }
      if (!/signing_mode:\s*\$\{\{\s*steps\.cert\.outputs\.signing_mode\s*\}\}/.test(windows)) {
        v.push(`${BUILD}:windows-app does not export the certificate selection verdict`);
      }
      if (!/AETHER_SIGNING_MODE:\s*\$\{\{\s*needs\.windows-app\.outputs\.signing_mode\s*\}\}/.test(publish)) {
        v.push(`${BUILD}:publish cannot check which signing identity the Windows job actually used`);
      }
      if (!/if:[^\n]*startsWith\(github\.ref,\s*'refs\/tags\/'\)/.test(publish)) {
        v.push(`${BUILD}:publish must be restricted to tag runs`);
      }
      return v;
    },
    inject() {
      const build = readFileSync(join(BASE, BUILD), "utf8");
      return { file: BUILD, content: build.replace(/^      actions:\s*read[^\n]*\n/m, "") };
    },
  },
  {
    name: "witnessed-engine-is-the-packaged-engine",
    invariant: "BC-02",
    summary: "a release packages the witnessed artifact; nothing between witnessing and packaging re-signs or rebuilds the engine",
    scan(api) {
      const v = [];
      const build = api.read(BUILD);
      const steps = stepsOf(build, "windows-app");
      if (!steps) return [`${BUILD}: no windows-app job to audit`];

      const download = steps.findIndex(
        (s) => /download-artifact/.test(s.uses) && /witnessed-engine/.test(s.withText + s.run),
      );
      const pack = steps.findIndex((s) => s.name === "Package");
      if (download === -1) {
        v.push(`${BUILD}: a release downloads no witnessed engine artifact, so it packages whatever it just built`);
      }
      if (pack === -1) return v.concat(`${BUILD}: no Package step to audit`);

      if (download !== -1) {
        const withText = steps[download].withText;
        if (!/run-id:/.test(withText)) {
          v.push(
            `${BUILD}:${steps[download].line} the witnessed download names no run-id: without one the artifact ` +
              "comes from this run, which is the self-referential check this replaced",
          );
        }
        if (!releaseOnly(steps[download])) {
          v.push(`${BUILD}:${steps[download].line} the witnessed download is not release-guarded; a release must not fall back to a locally built engine`);
        }
        for (const s of steps.slice(download + 1, pack)) {
          if (devGuarded(s) || !/cargo build|Set-AuthenticodeSignature|sign-windows\.ps1|Copy-Item/.test(s.run + s.all)) continue;
          for (const { re, why } of ENGINE_REBUILD) {
            if (re.test(s.run) && !s.name.includes("GUI")) {
              v.push(
                `${BUILD}:${s.line} "${s.name || s.uses}" ${why} between witnessing and packaging - ` +
                  "two separately compiled/signed PE files cannot share the digest the anchor holds",
              );
            }
          }
        }
      }

      // A release must not merely download: it has to put those bytes where the
      // bundle picks them up.
      const stage = steps.find((s) => s.name === "Stage the witnessed engine");
      if (!stage) {
        v.push(`${BUILD}: no step stages the witnessed engine, so the download goes nowhere`);
      } else {
        if (!releaseOnly(stage)) {
          v.push(`${BUILD}:${stage.line} "Stage the witnessed engine" is not release-guarded`);
        }
        if (!/witnessed-engine\/aether\.exe/.test(stage.run) || !/resources/.test(stage.run)) {
          v.push(`${BUILD}:${stage.line}: the staging step does not copy witnessed-engine/aether.exe into resources/`);
        }
        if (/sign-windows\.ps1/.test(stage.run)) {
          v.push(`${BUILD}:${stage.line}: the staging step signs the engine it just witnessed`);
        }
      }

      // A development run still builds and signs its own engine; that has to be
      // said in the step's `if`, not assumed from a comment.
      for (const name of ["Build engine", "Sign and verify engine", "Stage engine"]) {
        const s = steps.find((x) => x.name === name);
        if (!s) {
          v.push(`${BUILD}: the development path has no "${name}" step any more - where do unwitnessed builds come from?`);
          continue;
        }
        if (!devGuarded(s)) {
          v.push(`${BUILD}:${s.line} "${name}" runs on a release too, so the downloaded witness is not what ships`);
        }
      }

      // Both sides of the packaging boundary measure the same digest.
      const checks = steps.map((s) => s.run);
      const pre = checks.some((r) => /publish-engine-trust\.mjs --check --name aether\.exe --file apps\/desktop\/src-tauri\/resources\/aether\.exe/.test(r));
      const post = checks.some((r) => /publish-engine-trust\.mjs --check --name aether\.exe --file dist-windows\/portable\/engine\/aether\.exe/.test(r));
      if (!pre) v.push(`${BUILD}: nothing verifies the staged engine against the witness before the app is built`);
      if (!post) v.push(`${BUILD}: nothing verifies the packaged engine against the witness after packaging`);

      // The witness has to be handed over, not described.
      const prepare = api.read(PREPARE);
      const psteps = stepsOf(prepare, "cut");
      if (!psteps) return v.concat(`${PREPARE}: no cut job to audit`);
      const upload = psteps.find((s) => /upload-artifact/.test(s.uses));
      if (!upload) {
        v.push(`${PREPARE}: the witnessed engine is never uploaded, so no release can package these exact bytes`);
      } else if (!new RegExp(`name:\\s*${WITNESS_ARTIFACT}`).test(upload.withText)) {
        v.push(`${PREPARE}:${upload.line} uploads the witness as something other than "${WITNESS_ARTIFACT}"`);
      }
      const witness = psteps.findIndex((s) => s.name === "Witness the staged engine");
      const after = psteps.slice(witness + 1);
      for (const { re, why } of ENGINE_REBUILD) {
        if (witness !== -1 && after.some((s) => re.test(s.run))) {
          v.push(`${PREPARE}: a step after the witness ${why} - the anchor would describe bytes no release ships`);
        }
      }
      if (!/anchor-witness\.mjs/.test(psteps.map((s) => s.run).join("\n"))) {
        v.push(`${PREPARE}: the anchor records no witness pointer, so the release job has to guess which artifact to take`);
      }
      return v;
    },
    inject() {
      const text = readFileSync(join(BASE, BUILD), "utf8");
      // Recreate the defect: a release run that signs the engine it built itself.
      // Line endings are CRLF in a Windows checkout and LF on the runner, so the
      // pattern has to accept both or the injection silently does nothing.
      const unguard = (name) => (t) =>
        t.replace(new RegExp(`(\\n[ ]{6}- name: ${name}\\r?\\n)[ ]{8}if: env\\.AETHER_PACKAGE_KIND != 'release'\\r?\\n`), "$1");
      let mutated = text;
      for (const name of ["Build engine", "Sign and verify engine"]) mutated = unguard(name)(mutated);
      return { file: BUILD, content: mutated === text ? `${text}\n# injection found no target\n` : mutated };
    },
  },
  {
    name: "no-ephemeral-signature-on-a-distributable-artifact",
    invariant: "BC-03",
    summary: "release signing needs a real certificate and the pinned leaf; the self-signed path is opt-in per call",
    scan(api) {
      const v = [];
      const build = api.read(BUILD);
      const helper = api.read(HELPER);
      const steps = stepsOf(build, "windows-app");
      if (!steps) return [`${BUILD}: no windows-app job to audit`];

      if (!/-DevEphemeral/.test(helper)) {
        v.push(`${HELPER}: no -DevEphemeral switch, so the run-local exception is available to every caller`);
      }
      if (!/\$selfIssuedRunCert\s*=\s*\(\s*\r?\n\s*\$AllowEphemeral -and/.test(helper)) {
        v.push(
          `${HELPER}: the run-local exception is no longer gated on -DevEphemeral - any caller that passes a ` +
            "thumbprint can have a self-signed signature called 'verified', which is the defect in one line",
        );
      }
      if (!/self-signed/.test(helper)) {
        v.push(`${HELPER}: nothing refuses to sign a distributable artifact with a self-signed certificate`);
      }
      if (!/-not\s+\$DevEphemeral/.test(helper)) {
        v.push(`${HELPER}: the self-signed refusal is not guarded by -DevEphemeral, so it applies to nobody or to everybody`);
      }
      if (!/ExpectedCertSha256/.test(helper)) {
        v.push(`${HELPER}: the pinned leaf digest is not compared, so any certificate that chains is accepted`);
      }

      const releaseSteps = steps.filter((s) => !devGuarded(s) && !/AETHER_SIGNING_MODE -eq 'ephemeral'/.test(s.run));
      for (const s of releaseSteps) {
        if (/-DevEphemeral/.test(s.run) && !/AETHER_SIGNING_MODE/.test(s.run)) {
          v.push(`${BUILD}:${s.line} "${s.name}" passes -DevEphemeral on a path a release run takes`);
        }
      }
      if (!/AETHER_CODESIGN_PFX_BASE64/.test(build)) {
        v.push(`${BUILD}: no release path installs a real code-signing certificate from secrets`);
      }
      const cert = steps.find((s) => s.name === "Install the code-signing identity");
      if (!cert) {
        v.push(`${BUILD}: no step decides which signing identity this run may use`);
      } else {
        if (!/AETHER_SIGNING_MODE=trusted/.test(cert.run)) {
          v.push(`${BUILD}:${cert.line}: the release branch never records a trusted signing mode`);
        }
        if (!/is self-signed/.test(cert.run) && !/Subject -eq .*Issuer/.test(cert.run)) {
          v.push(`${BUILD}:${cert.line}: the release certificate's chain is never examined`);
        }
        if (!/cert_sha256/.test(cert.run)) {
          v.push(`${BUILD}:${cert.line}: the release certificate is never compared against the anchor's pinned identity`);
        }
      }
      // The runtime half: the shell must keep refusing an unpinned or mismatched signer.
      const trust = api.read(TRUST_RS);
      if (!/expected_cert_sha256/.test(trust)) {
        v.push(`${TRUST_RS}: the pinned leaf digest is no longer read by the runtime`);
      }
      if (!/AnchorNotPublished/.test(trust)) {
        v.push(`${TRUST_RS}: an unpublished anchor is no longer a refusal`);
      }
      if (!/subject_names_common_name/.test(trust)) {
        v.push(`${TRUST_RS}: the publisher subject is compared by substring again`);
      }
      return v;
    },
    inject() {
      const text = readFileSync(join(BASE, HELPER), "utf8");
      // The defect, exactly: the run-local exception available to any caller that
      // happens to pass a thumbprint, with nothing saying "this is a development
      // build". A release verify would then accept a self-signed package.
      const mutated = text.replace(/\r?\n\s*\$AllowEphemeral -and/, "");
      return { file: HELPER, content: mutated === text ? `${text}\n# injection found no target\n` : mutated };
    },
  },
  {
    name: "an-unwitnessed-package-is-never-a-download",
    invariant: "BC-18",
    summary: "packaging and publishing both refuse a zero-anchor build; development builds are named, not the default",
    scan(api) {
      const v = [];
      const build = api.read(BUILD);
      for (const job of ["windows-app", "publish"]) {
        const text = jobText(build, job);
        if (!text) {
          v.push(`${BUILD}: no ${job} job to audit`);
          continue;
        }
        if (!/AETHER_PACKAGE_KIND:\s*\$\{\{[^}]*startsWith\(github\.ref,\s*'refs\/tags\/'\)/.test(text)) {
          v.push(
            `${BUILD}:${job}: AETHER_PACKAGE_KIND is not derived from the ref here, so "is this a release?" ` +
              "is being decided somewhere else - or not at all",
          );
        }
        if (job === "windows-app" && /AETHER_ALLOW_UNWITNESSED:/.test(text) &&
            !/AETHER_ALLOW_UNWITNESSED:\s*\$\{\{[^}]*startsWith\(github\.ref/.test(text)) {
          v.push(`${BUILD}:windows-app: AETHER_ALLOW_UNWITNESSED is set unconditionally: the development opt-out reaches a tag`);
        }
      }
      const pack = (stepsOf(build, "windows-app") || []).find((s) => s.name === "Package");
      if (!pack) {
        v.push(`${BUILD}: no Package step to audit`);
      } else if (!new RegExp(`${POLICY.replace(/[./]/g, "\\$&")} --check`).test(pack.run)) {
        v.push(`${BUILD}:${pack.line}: packaging does not ask the policy whether this package may exist - a zero-anchor package is only caught after it is installed`);
      }
      const pub = stepsOf(build, "publish") || [];
      const eligible = pub.find((s) => /package-policy\.mjs/.test(s.run));
      if (!eligible) {
        v.push(`${BUILD}: the publish job never consults scripts/package-policy.mjs, so anything that builds becomes a download`);
      } else if (!/--anchor dist\/engine-trust\.json/.test(eligible.run)) {
        v.push(`${BUILD}:${eligible.line}: eligibility is judged on the repository's anchor rather than the one shipped inside the artifacts`);
      }
      const upload = pub.find((s) => s.name === "Upload to GitHub Release");
      if (!upload) {
        v.push(`${BUILD}: the release upload step has gone missing`);
      } else if (!/publishable == 'true'/.test(upload.if)) {
        v.push(`${BUILD}:${upload.line}: the GitHub Release upload is not gated on publishable=true`);
      }
      // And the anchor has to be able to say any of this: flat entries, all fields.
      const doc = JSON.parse(api.read(ANCHOR));
      if (!Array.isArray(doc.files) || !doc.files.length) return v.concat(`${ANCHOR}: no files[]`);
      for (const f of doc.files) {
        for (const key of ["file_sha256", "cert_sha256", "issued_cn", "signing_profile"]) {
          if (!(key in f)) v.push(`${ANCHOR}: ${f.name} has no ${key} - the policy has nothing to read`);
        }
        for (const [k, val] of Object.entries(f)) {
          if (val && typeof val === "object") {
            v.push(`${ANCHOR}: ${f.name}.${k} is a nested ${Array.isArray(val) ? "array" : "object"}; publish-engine-trust.mjs's locator only rewrites flat entries`);
          }
        }
      }
      const engine = doc.files.find((f) => f.name === "aether.exe");
      if (!engine) v.push(`${ANCHOR}: no aether.exe entry`);
      else if (!("witnessed_run" in engine) || !("witnessed_artifact" in engine)) {
        v.push(`${ANCHOR}: aether.exe records no witness pointer`);
      }
      if (!api.exists(POLICY)) v.push(`${POLICY}: missing, so the rule above has no implementation`);
      return v;
    },
    inject() {
      const text = readFileSync(join(BASE, BUILD), "utf8");
      const mutated = text.replace(
        "          node scripts/package-policy.mjs --check --anchor dist/engine-trust.json",
        "          echo \"shipping whatever the build jobs produced\"",
      );
      return { file: BUILD, content: mutated === text ? `${text}\n# injection found no target\n` : mutated };
    },
  },
  {
    name: "release-manifest-logic-runs-from-a-tested-script",
    invariant: "BC-18",
    summary: "the checksum step is a script, the workflow calls it, and a test exercises it with several payloads",
    scan(api) {
      const v = [];
      if (!api.exists(PACK)) v.push(`${PACK}: missing - the checksum logic has nowhere to live but YAML`);
      if (!api.exists(PACK_TEST)) v.push(`${PACK_TEST}: missing - the step would again be code nobody can run`);
      const build = api.read(BUILD);
      const steps = stepsOf(build, "publish");
      if (!steps) return [`${BUILD}: no publish job to audit`];
      const pack = steps.find((s) => s.name === "Pack + checksums");
      if (!pack) return v.concat(`${BUILD}: the publish job has no pack step`);
      const code = pack.run
        .split(/\r?\n/)
        .filter((l) => !/^\s*#/.test(l))
        .join("\n");
      if (/sha256sum|SHA256SUMS/.test(code)) {
        v.push(
          `${BUILD}:${pack.line}: the pack step computes checksums inline again - that is the shape that let a manifest` +
            " hash its own sidecars for a full release cycle without anyone being able to run it",
        );
      }
      if (!/pack-checksums\.sh/.test(code)) {
        v.push(`${BUILD}:${pack.line}: the pack step does not call ${PACK}`);
      }
      if (!/test-pack-checksums\.sh/.test(build)) {
        v.push(`${BUILD}: no job runs ${PACK_TEST}, so the step is untested in CI`);
      }
      return v;
    },
    inject() {
      const text = readFileSync(join(BASE, BUILD), "utf8");
      const mutated = text.replace(
        "          bash .github/scripts/pack-checksums.sh --src dist --out out",
        '          sha256sum ./* > SHA256SUMS.txt\n          sha256sum -c --quiet SHA256SUMS.txt',
      );
      return { file: BUILD, content: mutated === text ? `${text}\n# injection found no target\n` : mutated };
    },
  },
];

/* ------------------------------------------------------------------ runner */
const MAX_FINDINGS = Number(process.env.VERIFY_MAX_FINDINGS ?? 25);

function runGate(gate, api) {
  const out = gate.scan(api);
  return Array.isArray(out) ? out : [];
}

function main() {
  const args = process.argv.slice(2);
  if (args.includes("--root")) BASE = resolve(args[args.indexOf("--root") + 1]);
  const selftest = args.includes("--selftest-fail");
  const wantGate = args.includes("--gate") ? args[args.indexOf("--gate") + 1] : null;
  const selected = wantGate ? GATES.filter((g) => g.name === wantGate) : GATES;
  if (wantGate && !selected.length) {
    console.error(`unknown gate: ${wantGate}`);
    console.error(`known: ${GATES.map((g) => g.name).join(", ")}`);
    process.exit(2);
  }

  if (selftest) {
    console.log(`# verify-release-integrity --selftest-fail (${selected.length} gate(s))`);
    let blind = 0;
    for (const g of selected) {
      let caught = false;
      let detail = "";
      try {
        const before = runGate(g, realApi());
        if (before.length) {
          detail = `the tree already fails this gate: ${before[0]}`;
        } else {
          const out = runGate(g, injectedApi(g.inject()));
          caught = out.length > 0;
          detail = out[0] ?? "";
        }
      } catch (e) {
        detail = `threw: ${e.message}`;
      }
      if (caught) console.log(`  ok   ${g.name} [${g.invariant}] detects its injected defect`);
      else {
        console.log(`  FAIL ${g.name} [${g.invariant}] BLIND - injected defect not detected (${detail})`);
        blind += 1;
      }
    }
    console.log(blind ? `\n# SELFTEST FAILED: ${blind} blind gate(s)` : "\n# selftest passed");
    process.exit(blind ? 1 : 0);
  }

  console.log(`# verify-release-integrity (${selected.length} gate(s))`);
  let failing = 0;
  for (const g of selected) {
    let out;
    try {
      out = runGate(g, realApi());
    } catch (e) {
      out = [`checker threw: ${e.message}`];
    }
    const ok = out.length === 0;
    console.log(`${ok ? "ok  " : "FAIL"} ${g.name} [${g.invariant}] — ${g.summary}`);
    for (const line of out.slice(0, MAX_FINDINGS)) console.log(`   ${line}`);
    if (!ok) failing += 1;
  }
  console.log(failing ? `\n# ${failing}/${selected.length} gate(s) failing` : `\n# all ${selected.length} gate(s) passing`);
  process.exit(failing ? 1 : 0);
}

main();
