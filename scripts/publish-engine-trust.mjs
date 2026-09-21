#!/usr/bin/env node
// Publish or check the digests in packaging/trust/engine-trust.json.
//
// Why this exists as a separate step: the shell compares the engine it is about
// to launch against a witness that must not be produced by that same comparison.
// Hashing resources/aether.exe inside build.rs made the check structurally
// incapable of failing; the anchor file is now the single source, and this
// script is the only sanctioned way to change what it says.
//
//   node scripts/publish-engine-trust.mjs --name aether.exe --file apps/desktop/src-tauri/resources/aether.exe \
//         --cert-sha <sha256 of leaf DER> --cn "CN=deathline94"
//   node scripts/publish-engine-trust.mjs --check --name wintun.dll --file packaging/wintun.dll
//
// Rewrites are surgical (the surrounding comment block and formatting survive),
// so a rotation shows up as the one-line diff a reviewer is supposed to see.

import { createHash } from "node:crypto";
import { readFileSync, writeFileSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const ANCHOR = join(ROOT, "packaging", "trust", "engine-trust.json");
const PLACEHOLDER = "0".repeat(64);
const HEX64 = /^[0-9a-fA-F]{64}$/;

function fail(msg) {
  console.error(`publish-engine-trust: ${msg}`);
  process.exit(1);
}

function parseArgs(argv) {
  const out = { check: false };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (a === "--check") out.check = true;
    else if (a === "--name") out.name = argv[++i];
    else if (a === "--file") out.file = argv[++i];
    else if (a === "--cert-sha") out.certSha = argv[++i];
    else if (a === "--cn") out.cn = argv[++i];
    else fail(`unknown argument ${a} (want --check --name --file --cert-sha --cn)`);
  }
  if (!out.name) fail("--name is required");
  if (!out.file) fail("--file is required");
  if (!["aether.exe", "wintun.dll"].includes(out.name)) {
    fail(`--name must be aether.exe or wintun.dll, got ${out.name}`);
  }
  if (out.certSha && !HEX64.test(out.certSha)) {
    fail(`--cert-sha must be 64 hex characters (sha256 over the leaf certificate DER), got ${out.certSha}`);
  }
  return out;
}

function sha256File(path) {
  const st = statSync(path);
  if (!st.isFile()) fail(`${path} is not a regular file`);
  if (st.size === 0) fail(`${path} is empty`);
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

/** Returns the raw text of the one `files[]` object whose name is `name`. */
function entrySlice(text, name) {
  const re = new RegExp(`\\{[^{}]*"name":\\s*"${name}"[^{}]*\\}`);
  const m = text.match(re);
  if (!m) {
    fail(
      `${ANCHOR} has no files[] entry named "${name}" — add it in a reviewed commit, ` +
        "do not let an absent entry mean \"nothing to check\"",
    );
  }
  return m[0];
}

function field(entry, key) {
  const m = entry.match(new RegExp(`"${key}":\\s*"([^"]*)"`));
  if (!m) fail(`anchor entry for ${entry.match(/"name":\s*"([^"]*)"/)[1]} has no "${key}" field`);
  return m[1];
}

function setField(entry, key, value) {
  const re = new RegExp(`("${key}":\\s*")[^"]*(")`);
  if (!re.test(entry)) fail(`anchor entry has no "${key}" field to update`);
  return entry.replace(re, `$1${value}$2`);
}

const args = parseArgs(process.argv.slice(2));
const file = resolve(ROOT, args.file);
let text;
try {
  text = readFileSync(ANCHOR, "utf8");
} catch (e) {
  fail(`cannot read ${ANCHOR}: ${e.message}`);
}

const entry = entrySlice(text, args.name);
const want = sha256File(file);
const current = field(entry, "file_sha256");

if (args.check) {
  if (current === PLACEHOLDER) {
    fail(
      `check mode refuses a placeholder witness for ${args.name}: publish it first ` +
        "(release builds would refuse to run this artifact)",
    );
  }
  if (current !== want) {
    fail(
      `${args.name}: staged bytes are ${want} but ${ANCHOR} says ${current}. ` +
        "The artifact the shell ships is not the artifact the shell vouches for.",
    );
  }
  console.log(`OK ${args.name} ${want}`);
  process.exit(0);
}

let next = setField(entry, "file_sha256", want);
if (args.certSha) next = setField(next, "cert_sha256", args.certSha.toLowerCase());
if (args.cn) next = setField(next, "issued_cn", args.cn);

if (next === entry && current === want) {
  console.log(`unchanged ${args.name} ${want}`);
  process.exit(0);
}

const updated = text.replace(entry, next)
  .replace(/"generated_unix":\s*\d+/, `"generated_unix": ${Math.floor(Date.now() / 1000)}`)
  .replace(
    /"generated_by":\s*"[^"]*"/,
    `"generated_by": "scripts/publish-engine-trust.mjs @ ${process.env.GITHUB_SHA || "not-a-ci-run"}"`,
  );
writeFileSync(ANCHOR, updated);
console.log(`published ${args.name}: ${current} -> ${want}`);
console.log(`wrote ${ANCHOR}`);
