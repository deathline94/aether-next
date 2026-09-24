#!/usr/bin/env node
// Record *provenance* in packaging/trust/engine-trust.json: which run's artifact
// holds the witnessed bytes, what that artifact is called, and whether it is
// unsigned or vendor-signed.
//
// Why a second script touches the anchor when scripts/publish-engine-trust.mjs
// already owns it: the two write different things, and one of them cannot be
// measured from a file. `file_sha256` is measured by publish-engine-trust.mjs.
// `witnessed_run`,
// `witnessed_artifact` and `signing_profile` are facts about the run that produced
// those bytes - the engine job cannot know them, and a release that has to guess
// which artifact to download is a release that will quietly download whatever it
// just built. Hand-editing them is what the anchor's own $comment forbids, so they
// get a script too, with the same surgical rewrite and the same --check.
//
//   node scripts/anchor-witness.mjs --name aether.exe --run 1984213301 \
//         --artifact engine-witness --profile unsigned-witnessed
//   node scripts/anchor-witness.mjs --check --name aether.exe --run 1984213301 \
//         --artifact engine-witness --profile unsigned-witnessed
//   node scripts/anchor-witness.mjs --selftest-fail     # proves the rewrite, on a copy
//
// Entries stay FLAT: publish-engine-trust.mjs finds one with a no-braces regex, so
// nesting anything inside an entry would blind the digest writer to the entry it
// has to update - a failure that only shows up as a release job dying on "add it
// in a reviewed commit". Every write here re-checks that constraint.

import { copyFileSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const ANCHOR = join(ROOT, "packaging", "trust", "engine-trust.json");
const PROFILES = new Set(["trusted-ca", "unsigned-witnessed", "ephemeral-dev", "unwitnessed"]);
const ARTIFACT_NAME = /^[A-Za-z0-9._-]{1,100}$/;
const FIELDS = ["witnessed_run", "witnessed_artifact", "signing_profile"];

function fail(msg) {
  console.error(`anchor-witness: ${msg}`);
  process.exit(1);
}

function parseArgs(argv) {
  const out = { check: false, selftest: false };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (a === "--check") out.check = true;
    else if (a === "--selftest-fail") out.selftest = true;
    else if (a === "--anchor") out.anchor = argv[++i];
    else if (a === "--name") out.name = argv[++i];
    else if (a === "--run") out.run = argv[++i];
    else if (a === "--artifact") out.artifact = argv[++i];
    else if (a === "--profile") out.profile = argv[++i];
    else fail(`unknown argument ${a} (want --check --name --run --artifact --profile --anchor)`);
  }
  if (out.selftest) return out;
  if (!out.name) fail("--name is required");
  if (out.run === undefined) fail("--run is required");
  if (out.artifact === undefined) fail("--artifact is required");
  if (out.profile === undefined) fail("--profile is required");
  if (!/^\d{1,20}$/.test(out.run)) {
    fail(`--run must be the numeric run id whose artifact holds these bytes, got "${out.run}"`);
  }
  if (!ARTIFACT_NAME.test(out.artifact)) {
    fail(`--artifact "${out.artifact}" is not a usable actions/upload-artifact name`);
  }
  if (!PROFILES.has(out.profile)) {
    fail(`--profile must be one of ${[...PROFILES].join(", ")}, got "${out.profile}"`);
  }
  return out;
}

/** The locator scripts/publish-engine-trust.mjs uses, kept identical on purpose. */
const entryPattern = (name) => new RegExp(`\\{[^{}]*"name":\\s*"${name}"[^{}]*\\}`);

function entrySlice(text, name) {
  const m = text.match(entryPattern(name));
  if (!m) {
    throw new Error(
      `${name}: no flat files[] entry found - it is either missing (add it in a reviewed commit) ` +
        "or it holds a nested object/array, which publish-engine-trust.mjs cannot rewrite",
    );
  }
  return m[0];
}

const hasField = (entry, key) => new RegExp(`"${key}":\\s*"`).test(entry);

function field(entry, key) {
  const m = entry.match(new RegExp(`"${key}":\\s*"([^"]*)"`));
  return m ? m[1] : null;
}

function setField(entry, key, value, name) {
  const re = new RegExp(`("${key}":\\s*")[^"]*(")`);
  if (!re.test(entry)) {
    throw new Error(
      `the ${name} entry has no "${key}" field - add it in a reviewed commit rather than ` +
        "letting the writer invent a shape no reviewer has seen",
    );
  }
  return entry.replace(re, `$1${value}$2`);
}

/**
 * Write (or check) the three provenance fields of one entry inside `text`.
 * Anything that can go wrong is an exception: the CLI turns those into exits, the
 * selftest turns them into expectations.
 */
function applyProvenance({ text, name, wanted, check }) {
  const entry = entrySlice(text, name);
  for (const key of Object.keys(wanted)) {
    if (!hasField(entry, key)) {
      throw new Error(
        `the ${name} entry has no ${key} field; the anchor's $comment explains what it means, ` +
          "so add it in a reviewed commit rather than letting this script invent one",
      );
    }
  }
  if (check) {
    for (const [key, want] of Object.entries(wanted)) {
      const have = field(entry, key);
      if (have !== want) {
        throw new Error(
          `${name}: ${key} is "${have}" but this run recorded "${want}" - the anchor does not ` +
            "describe the artifact this workflow is releasing",
        );
      }
    }
    return { text, changed: false };
  }

  let next = entry;
  for (const [key, value] of Object.entries(wanted)) next = setField(next, key, value, name);
  if (next === entry) return { text, changed: false };

  const updated = text.replace(entry, next).replace(
    /"generated_by":\s*"[^"]*"/,
    `"generated_by": "scripts/anchor-witness.mjs @ ${process.env.GITHUB_SHA || "not-a-ci-run"}"`,
  );
  // The rewrite has to leave the file readable by everything else that consumes it:
  // JSON, build.rs (serde_json), and the digest writer's locator.
  let doc;
  try {
    doc = JSON.parse(updated);
  } catch (e) {
    throw new Error(`the rewrite would not parse as JSON: ${e.message}`);
  }
  if (!Array.isArray(doc.files) || !doc.files.length) throw new Error("the rewrite lost files[]");
  if (!entryPattern(name).test(updated)) {
    throw new Error(
      `the rewrite left ${name} in a shape publish-engine-trust.mjs can no longer locate ` +
        "(entries must stay flat)",
    );
  }
  return { text: updated, changed: true };
}

function selftest() {
  const dir = mkdtempSync(join(tmpdir(), "aether-anchor-witness-"));
  const copy = join(dir, "engine-trust.json");
  let failed = 0;
  const expect = (what, fn, want) => {
    let got;
    try {
      got = fn();
    } catch (e) {
      got = `threw: ${e.message}`;
    }
    if (got === want) console.log(`  ok   ${what}`);
    else {
      console.log(`  FAIL ${what}: got ${JSON.stringify(got)} want ${JSON.stringify(want)}`);
      failed += 1;
    }
  };
  const wanted = {
    witnessed_run: "1984213301",
    witnessed_artifact: "engine-witness",
    signing_profile: "trusted-ca",
  };
  try {
    copyFileSync(ANCHOR, copy);
    const read = () => readFileSync(copy, "utf8");
    const write = (r) => writeFileSync(copy, r.text);

    expect("the committed anchor already carries the three fields", () => {
      const e = entrySlice(readFileSync(ANCHOR, "utf8"), "aether.exe");
      return FIELDS.every((k) => hasField(e, k));
    }, true);

    expect("a nested object in the entry is refused, not written past", () => {
      const nested = read().replace(
        /("name":\s*"aether.exe")/,
        '$1,\n      "signer": { "cn": "CN=deathline94" }',
      );
      try {
        applyProvenance({ text: nested, name: "aether.exe", wanted, check: false });
        return "accepted";
      } catch (e) {
        return /flat files\[\] entry/.test(e.message) ? "refused" : `refused for the wrong reason: ${e.message}`;
      }
    }, "refused");

    expect("writing the pointer records all three fields", () => {
      write(applyProvenance({ text: read(), name: "aether.exe", wanted, check: false }));
      const e = entrySlice(read(), "aether.exe");
      return FIELDS.every((k) => field(e, k) === wanted[k]) ? "written" : field(e, "witnessed_run");
    }, "written");

    expect("…and --check then agrees with it", () => {
      applyProvenance({ text: read(), name: "aether.exe", wanted, check: true });
      return "ok";
    }, "ok");

    expect("…and --check refuses a pointer to a different run", () => {
      try {
        applyProvenance({
          text: read(),
          name: "aether.exe",
          wanted: { ...wanted, witnessed_run: "999" },
          check: true,
        });
        return "accepted";
      } catch (e) {
        return /witnessed_run/.test(e.message) ? "refused" : e.message;
      }
    }, "refused");

    expect("the digests a provenance write must not disturb survive it", () => {
      const before = JSON.parse(readFileSync(ANCHOR, "utf8"));
      const after = JSON.parse(read());
      const dig = (doc, n) => {
        const f = doc.files.find((x) => x.name === n);
        return `${f.file_sha256}/${f.cert_sha256}/${f.issued_cn}`;
      };
      const same =
        before.files.map((f) => dig(before, f.name)).join() ===
        after.files.map((f) => dig(after, f.name)).join();
      return same ? "intact" : "changed";
    }, "intact");

    expect("an unknown signing profile is rejected by the argument parser", () => {
      // parseArgs exits the process, so exercise the rule rather than the CLI.
      return PROFILES.has("who-knows") ? "accepted" : "refused";
    }, "refused");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
  console.log(
    failed
      ? `\n# anchor-witness SELFTEST FAILED: ${failed} expectation(s) unmet`
      : "\n# anchor-witness selftest passed",
  );
  process.exit(failed ? 1 : 0);
}

const args = parseArgs(process.argv.slice(2));
if (args.selftest) selftest();

const path = args.anchor ? resolve(ROOT, args.anchor) : ANCHOR;
const wanted = {
  witnessed_run: args.run,
  witnessed_artifact: args.artifact,
  signing_profile: args.profile,
};
let text;
try {
  text = readFileSync(path, "utf8");
} catch (e) {
  fail(`cannot read ${path}: ${e.message}`);
}
let result;
try {
  result = applyProvenance({ text, name: args.name, wanted, check: args.check });
} catch (e) {
  fail(e.message);
}
if (args.check) {
  console.log(`OK ${args.name}: run ${args.run}, artifact ${args.artifact}, profile ${args.profile}`);
  process.exit(0);
}
if (!result.changed) {
  console.log(`unchanged ${args.name}: ${args.run} ${args.artifact} ${args.profile}`);
  process.exit(0);
}
writeFileSync(path, result.text);
console.log(`wrote ${args.name}: run ${args.run}, artifact ${args.artifact}, profile ${args.profile}`);
