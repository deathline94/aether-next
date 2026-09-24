#!/usr/bin/env node
// Static checks for the Windows release path. Every check has an injected
// regression so --selftest-fail proves the checker still catches its own target.
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const rootArg = process.argv.indexOf("--root");
const base = rootArg < 0 ? ROOT : resolve(process.argv[rootArg + 1]);
const read = (path) => readFileSync(join(base, path), "utf8");
const files = {
  build: ".github/workflows/build.yml",
  prepare: ".github/workflows/prepare-anchor.yml",
  anchor: "packaging/trust/engine-trust.json",
  policy: "scripts/package-policy.mjs",
  trust: "apps/desktop/src-tauri/src/trust.rs",
  verifier: "scripts/verify-installers.ps1",
};
const source = Object.fromEntries(Object.entries(files).map(([key, path]) => [key, read(path)]));
const windowsJob = (build) => build.split(/^  windows-app:\s*$/m)[1]?.split(/^  android-apk:\s*$/m)[0] ?? "";
const publishJob = (build) => build.split(/^  publish:\s*$/m)[1] ?? "";

const gates = [
  {
    name: "reviewed-engine-witness",
    check(s) {
      const out = [];
      if (!/--profile unsigned-witnessed/.test(s.prepare)) out.push("prepare-anchor must record the unsigned-witnessed profile");
      if (!/publish-engine-trust\.mjs --name aether\.exe --file/.test(s.prepare)) out.push("prepare-anchor must measure engine bytes");
      if (!/upload-artifact@/.test(s.prepare) || !/name: engine-witness/.test(s.prepare)) out.push("prepare-anchor must upload the measured engine");
      if (!/gh pr create/.test(s.prepare)) out.push("the witness must enter main through a pull request");
      if (/sign-windows\.ps1|AETHER_CODESIGN_PFX/.test(s.prepare)) out.push("the unsigned witness must not be signed");
      return out;
    },
    inject(s) { return { ...s, prepare: s.prepare.replaceAll("--profile unsigned-witnessed", "--profile unwitnessed") }; },
  },
  {
    name: "release-uses-witnessed-bytes",
    check(s) {
      const out = [];
      const job = windowsJob(s.build);
      if (!/AETHER_PACKAGE_KIND:.*startsWith\(github\.ref/.test(job)) out.push("release kind must come from the tag ref");
      if (!/actions\/download-artifact@/.test(job) || !/run-id: \$\{\{ steps\.witness\.outputs\.run \}\}/.test(job)) out.push("release must download the witnessed engine");
      if (!/publish-engine-trust\.mjs --check --name aether\.exe --file/.test(job)) out.push("downloaded engine must match the committed digest");
      if (!/if: env\.AETHER_PACKAGE_KIND != 'release' && steps\.policy\.outputs\.anchor_complete != 'true'/.test(job)) out.push("engine rebuild must be limited to development without a witness");
      if (/AETHER_CODESIGN_PFX|sign-windows\.ps1/.test(job)) out.push("Aether's Windows binaries must not require code signing");
      return out;
    },
    inject(s) { return { ...s, build: s.build.replace("run-id: ${{ steps.witness.outputs.run }}", "run-id: ${{ github.run_id }}") }; },
  },
  {
    name: "unsigned-engine-still-has-a-digest",
    check(s) {
      const out = [];
      const anchor = JSON.parse(s.anchor);
      const engine = anchor.files.find((f) => f.name === "aether.exe");
      const driver = anchor.files.find((f) => f.name === "wintun.dll");
      if (!engine || !("file_sha256" in engine) || !("witnessed_run" in engine) || !("witnessed_artifact" in engine)) out.push("engine anchor lacks a digest or artifact pointer");
      if (engine?.cert_sha256 || engine?.issued_cn) out.push("unsigned engine falsely claims a certificate");
      if (!driver?.cert_sha256 || !driver?.issued_cn) out.push("WinTUN vendor signature pin is missing");
      if (!/unsigned-witnessed/.test(s.policy) || !/trusted-ca/.test(s.policy)) out.push("policy must require the engine and driver profiles");
      if (!/actual_hash\.eq_ignore_ascii_case\(expected_hash\)/.test(s.trust) || !/unsigned-witnessed/.test(s.trust)) out.push("runtime must compare engine bytes before accepting the unsigned profile");
      if (!/Get-FileHash \$engine\.FullName -Algorithm SHA256/.test(s.verifier)) out.push("installer verifier must hash the extracted engine");
      return out;
    },
    inject(s) { return { ...s, verifier: s.verifier.replace("Get-FileHash $engine.FullName -Algorithm SHA256", "Get-Item $engine.FullName") }; },
  },
  {
    name: "release-publishing-is-gated",
    check(s) {
      const out = [];
      const job = publishJob(s.build);
      if (!/package-policy\.mjs --check --anchor dist\/engine-trust\.json/.test(job)) out.push("publish must check the anchor shipped with the artifacts");
      if (!/if: steps\.eligible\.outputs\.publishable == 'true'/.test(job)) out.push("upload must require publishable=true");
      if (!/bash \.github\/scripts\/pack-checksums\.sh --src dist --out out/.test(job)) out.push("publish must use the tested checksum script");
      if (!/test-pack-checksums\.sh/.test(s.build)) out.push("CI must test the checksum script");
      return out;
    },
    inject(s) { return { ...s, build: s.build.replace("node scripts/package-policy.mjs --check --anchor dist/engine-trust.json", "echo unchecked") }; },
  },
];

const gateArg = process.argv.indexOf("--gate");
const selected = gateArg < 0 ? gates : gates.filter((gate) => gate.name === process.argv[gateArg + 1]);
if (!selected.length) {
  console.error("unknown release-integrity gate");
  process.exit(2);
}
const selftest = process.argv.includes("--selftest-fail");
let failures = 0;
for (const gate of selected) {
  const baseline = gate.check(source);
  const detected = selftest && baseline.length === 0 ? gate.check(gate.inject(source)) : [];
  const okay = selftest ? baseline.length === 0 && detected.length > 0 : baseline.length === 0;
  console.log(`${okay ? "ok" : "FAIL"} ${gate.name}${baseline.length ? ": " + baseline.join("; ") : ""}`);
  if (!okay) failures += 1;
}
process.exit(failures ? 1 : 0);
