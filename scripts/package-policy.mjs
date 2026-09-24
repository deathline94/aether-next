#!/usr/bin/env node
// Decide whether the package this run is producing may be called distributable.
//
// Why this exists: the same workflow that builds a release-tag app also builds one
// for every push to main, and it used to do so with `AETHER_ALLOW_UNWITNESSED`
// switched on by the shape of the ref (`!startsWith(github.ref, 'refs/tags/')`).
// With the committed anchor still carrying an all-zero digest for aether.exe,
// such a package would refuse to start its own engine at launch. The package
// policy prevents a release without a separately witnessed engine digest.
//
// The rule now, in one place:
//   publishable  = a release run with a complete anchor: a reviewed unsigned
//                  engine digest and artifact pointer, plus the vendor-signed
//                  WinTUN driver and its certificate pin.
//   release runs must be publishable or the job fails; a development run may exist,
//                  gets `-dev` in every artifact name, and is never uploaded to a
//                  GitHub Release download.
// The default is the strict one: an unset kind is `release`.
//
//   node scripts/package-policy.mjs --check            # gate: exit 1 if unusable
//   node scripts/package-policy.mjs --check --anchor dist/engine-trust.json
//   node scripts/package-policy.mjs --selftest-fail    # prove the gate can fail
//
// Outputs for the calling workflow (written when GITHUB_OUTPUT / GITHUB_ENV exist):
//   publishable=true|false  artifact_label=  anchor_complete=true|false  reason=

import { createHash } from "node:crypto";
import { readFileSync, appendFileSync, existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const ANCHOR = join(ROOT, "packaging", "trust", "engine-trust.json");
const PLACEHOLDER = "0".repeat(64);
const HEX64 = /^[0-9a-f]{64}$/;

const ROLES = [
  { name: "aether.exe", needsWitnessPointer: true, profile: "unsigned-witnessed" },
  { name: "wintun.dll", needsWitnessPointer: false, profile: "trusted-ca" },
];

/**
 * @param {{ kind?: string, anchor: object, allowUnwitnessed?: string }} p
 * @returns {{ problems: string[], warnings: string[], publishable: boolean, anchorComplete: boolean, label: string }}
 */
export function evaluatePolicy({ kind, anchor, allowUnwitnessed }) {
  const problems = [];
  const warnings = [];
  const runKind = (kind ?? "").trim() === "development" ? "development" : "release";

  if (!anchor || !Array.isArray(anchor.files) || anchor.files.length === 0) {
    return {
      problems: ["the trust anchor has no files[] entries to check"],
      warnings,
      publishable: false,
      anchorComplete: false,
      label: runKind === "development" ? "-dev" : "",
    };
  }

  for (const role of ROLES) {
    const entry = anchor.files.find(
      (f) => typeof f.name === "string" && f.name.toLowerCase() === role.name,
    );
    if (!entry) {
      problems.push(`${role.name}: the anchor carries no entry for it`);
      continue;
    }
    if (entry.file_sha256 === PLACEHOLDER) {
      problems.push(
        `${role.name}: file_sha256 is the all-zero placeholder - no witness has been published, ` +
          "so nothing can vouch for the bytes and a release shell will refuse to run them",
      );
    } else if (!HEX64.test(String(entry.file_sha256).toLowerCase())) {
      problems.push(`${role.name}: file_sha256 is not 64 hex characters`);
    }
    if (role.profile === "trusted-ca") {
      if (entry.cert_sha256 === PLACEHOLDER || !HEX64.test(String(entry.cert_sha256).toLowerCase())) {
        problems.push(`${role.name}: a trusted certificate digest is required`);
      }
      if (!String(entry.issued_cn ?? "").trim()) {
        problems.push(`${role.name}: issued_cn is empty`);
      }
    } else if (entry.cert_sha256 || entry.issued_cn) {
      problems.push(`${role.name}: an unsigned engine must not claim a signing identity`);
    }

    const profile = String(entry.signing_profile ?? "").trim();
    if (profile !== role.profile) {
      problems.push(`${role.name}: signing_profile must be ${role.profile}, got "${profile || "unset"}"`);
    }

    if (role.needsWitnessPointer) {
      if (!/^\d+$/.test(String(entry.witnessed_run ?? ""))) {
        problems.push(
          `${role.name}: witnessed_run is "${entry.witnessed_run ?? ""}" - the anchor must name the ` +
            "prepare-anchor run whose artifact holds these bytes, otherwise the release job has no " +
            "way to package the witnessed binary instead of rebuilding it",
        );
      }
      if (!String(entry.witnessed_artifact ?? "").trim()) {
        problems.push(`${role.name}: witnessed_artifact is empty - name the artifact, not just the run`);
      }
    }
  }

  const anchorComplete = problems.length === 0;
  if (String(allowUnwitnessed ?? "").trim() && runKind === "release") {
    problems.push(
      "AETHER_ALLOW_UNWITNESSED is set on a release run - the development opt-out may not " +
        "reach a tag, by any route",
    );
  }

  const publishable = runKind === "release" && problems.length === 0;
  if (runKind === "development") {
    warnings.push("this package is a development artifact: it is named -dev and is not published");
  }
  return {
    problems,
    warnings,
    publishable,
    anchorComplete,
    label: publishable ? "" : "-dev",
  };
}

function anchorDigest(path) {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

function selftest() {
  const witnessed = {
    files: [
      {
        name: "aether.exe",
        file_sha256: "a".repeat(64),
        signing_profile: "unsigned-witnessed",
        witnessed_run: "1984213301",
        witnessed_artifact: "engine-witness",
      },
      {
        name: "wintun.dll",
        file_sha256: "c".repeat(64),
        cert_sha256: "d".repeat(64),
        issued_cn: "CN=WireGuard LLC",
        signing_profile: "trusted-ca",
      },
    ],
  };
  const asCommitted = JSON.parse(readFileSync(ANCHOR, "utf8"));
  let failed = 0;
  const expect = (what, got, want) => {
    if (got === want) {
      console.log(`  ok   ${what}`);
    } else {
      console.log(`  FAIL ${what}: got ${JSON.stringify(got)} want ${JSON.stringify(want)}`);
      failed += 1;
    }
  };

  const good = evaluatePolicy({ kind: "release", anchor: witnessed });
  expect("a witnessed unsigned engine and signed driver are publishable", good.publishable, true);
  expect("  ... and carries no problems", good.problems.length, 0);
  expect("  ... and no -dev label", good.label, "");

  const committed = evaluatePolicy({ kind: "release", anchor: asCommitted });
  expect(
    "the committed anchor (placeholder engine witness) is refused for a release",
    committed.publishable,
    false,
  );
  expect(
    "  ... and says which artifact has no witness",
    committed.problems.some((p) => p.startsWith("aether.exe:") && /placeholder/.test(p)),
    true,
  );

  const devKind = evaluatePolicy({ kind: "development", anchor: asCommitted });
  expect("a development run is not publishable either", devKind.publishable, false);
  expect("  ... and it is labelled -dev", devKind.label, "-dev");

  const completeDev = evaluatePolicy({ kind: "development", anchor: witnessed });
  expect("a complete anchor does not make a development run publishable", completeDev.publishable, false);
  expect("  ... but its engine witness can still be used", completeDev.anchorComplete, true);
  expect("  ... and its package remains labelled -dev", completeDev.label, "-dev");

  const unwitnessedFlag = evaluatePolicy({
    kind: "release",
    anchor: witnessed,
    allowUnwitnessed: "1",
  });
  expect("AETHER_ALLOW_UNWITNESSED cannot reach a release run", unwitnessedFlag.publishable, false);

  for (const [field, why] of [
    ["witnessed_run", "no pointer to the witnessed artifact"],
    ["witnessed_artifact", "a run id with no artifact name"],
    ["signing_profile", "an unknown signing profile"],
  ]) {
    const broken = structuredClone(witnessed);
    broken.files[0][field] = field === "signing_profile" ? "who-knows" : "";
    const r = evaluatePolicy({ kind: "release", anchor: broken });
    expect(`${why} is refused`, r.publishable, false);
  }

  const swapped = structuredClone(witnessed);
  swapped.files[0].file_sha256 = PLACEHOLDER;
  expect("a placeholder engine digest survives no policy", evaluatePolicy({ kind: "release", anchor: swapped }).publishable, false);

  for (const field of ["cert_sha256", "issued_cn"]) {
    const broken = structuredClone(witnessed);
    broken.files[0][field] = "forged";
    expect(`unsigned engine cannot claim ${field}`, evaluatePolicy({ kind: "release", anchor: broken }).publishable, false);
  }

  const badDriver = structuredClone(witnessed);
  badDriver.files[1].cert_sha256 = PLACEHOLDER;
  expect("driver certificate stays pinned", evaluatePolicy({ kind: "release", anchor: badDriver }).publishable, false);

  const empty = evaluatePolicy({ kind: "release", anchor: { files: [] } });
  expect("an anchor with no entries is a problem, not a pass", empty.publishable, false);

  console.log(
    failed
      ? `\n# package-policy SELFTEST FAILED: ${failed} expectation(s) unmet`
      : "\n# package-policy selftest passed",
  );
  process.exit(failed ? 1 : 0);
}

const args = process.argv.slice(2);
if (args.includes("--selftest-fail")) {
  selftest();
} else {
  const anchorPath = args.includes("--anchor")
    ? resolve(ROOT, args[args.indexOf("--anchor") + 1])
    : ANCHOR;
  if (!existsSync(anchorPath)) {
    console.error(`package-policy: ${anchorPath} is missing - refusing to call that distributable`);
    process.exit(1);
  }
  let doc;
  try {
    doc = JSON.parse(readFileSync(anchorPath, "utf8"));
  } catch (e) {
    console.error(`package-policy: ${anchorPath} is not parseable JSON: ${e.message}`);
    process.exit(1);
  }
  const kind = process.env.AETHER_PACKAGE_KIND ?? "";
  const verdict = evaluatePolicy({
    kind,
    anchor: doc,
    allowUnwitnessed: process.env.AETHER_ALLOW_UNWITNESSED ?? "",
  });
  const runKind = kind.trim() === "development" ? "development" : "release";
  console.log(
    `package-policy: kind=${runKind} anchor=${anchorDigest(anchorPath).slice(0, 12)}… ` +
      `publishable=${verdict.publishable} label=${verdict.label || "(none)"}`,
  );
  for (const w of verdict.warnings) console.log(`::notice::${w}`);
  if (!verdict.publishable) {
    for (const p of verdict.problems) console.error(`::error::${p}`);
    console.error(
      `package-policy: this package is NOT distributable. It may only be built as a ` +
        `development artifact (AETHER_PACKAGE_KIND=development, set by the workflow for ` +
        `non-tag runs), in which case it is named -dev and never published as a download.`,
    );
  }
  if (process.env.GITHUB_OUTPUT) {
    appendFileSync(
      process.env.GITHUB_OUTPUT,
      `publishable=${verdict.publishable}\nartifact_label=${verdict.label}\nanchor_complete=${verdict.anchorComplete}\n` +
        `anchor_digest=${anchorDigest(anchorPath)}\n`,
    );
  }
  if (process.env.GITHUB_ENV && runKind === "development") {
    appendFileSync(process.env.GITHUB_ENV, `AETHER_ARTIFACT_LABEL=${verdict.label}\n`);
  }
  process.exit(!verdict.publishable && runKind === "release" ? 1 : 0);
}
