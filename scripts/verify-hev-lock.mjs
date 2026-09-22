#!/usr/bin/env node
// Verify the vendored Android native payloads against apps/android/hev-lock.json.
//
// Replaces `test -s <file>` in the CI gates. A byte count proves a file is not
// empty; it does not prove the library inside the shipped APK is the one that
// was reviewed. This checks the digest, and reads the ELF program headers to
// check the 16 KB page alignment the Play requirement is actually about.
//
//   node scripts/verify-hev-lock.mjs                # verify the tree
//   node scripts/verify-hev-lock.mjs --selftest-fail # prove the check can fail

import { createHash } from "node:crypto";
import { readFileSync, existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const LOCK = join(ROOT, "apps/android/hev-lock.json");
const JNI = join(ROOT, "apps/android/android/app/src/main/jniLibs");
const MIN_PAGE_ALIGN = 16384;

function fail(msg) {
  console.error(`verify-hev-lock: ${msg}`);
  process.exitCode = 1;
}

/**
 * Smallest p_align among the ELF PT_LOAD program headers, or null if this is
 * not an ELF we can parse. p_align is what the loader honours for page size;
 * a binary built without `-z max-page-size` lands back at 0x1000.
 */
export function minProgramAlignment(buf) {
  if (buf.length < 64 || buf.readUInt32BE(0) !== 0x7f454c46) return null;
  const is64 = buf[4] === 2;
  const le = buf[5] === 1;
  const u16 = (o) => (le ? buf.readUInt16LE(o) : buf.readUInt16BE(o));
  const u32 = (o) => (le ? buf.readUInt32LE(o) : buf.readUInt32BE(o));

  const phoff = is64 ? Number(buf.readBigUInt64LE(0x20)) : u32(0x1c);
  const phentsize = is64 ? u16(0x36) : u16(0x2a);
  const phnum = is64 ? u16(0x38) : u16(0x2c);
  let min = null;
  for (let i = 0; i < phnum; i += 1) {
    const off = phoff + i * phentsize;
    if (off + phentsize > buf.length) return null;
    const ptype = u32(off);
    if (ptype !== 1) continue; // PT_LOAD
    const align = is64 ? Number(buf.readBigUInt64LE(off + 48)) : u32(off + 28);
    if (align === 0) return null;
    min = min === null ? align : Math.min(min, align);
  }
  return min;
}

export function checkOne(name, abi, expected, path) {
  const problems = [];
  if (!existsSync(path)) {
    problems.push(`${name}/${abi}: missing ${path}`);
    return problems;
  }
  const buf = readFileSync(path);
  const sum = createHash("sha256").update(buf).digest("hex");
  if (sum !== expected.sha256) {
    problems.push(`${name}/${abi}: digest mismatch\n    locked ${expected.sha256}\n    actual ${sum}`);
  }
  if (buf.length !== expected.bytes) {
    problems.push(`${name}/${abi}: size is ${buf.length}, lock says ${expected.bytes}`);
  }
  const align = minProgramAlignment(buf);
  if (align === null) {
    problems.push(`${name}/${abi}: not a parseable ELF`);
  } else if (align < MIN_PAGE_ALIGN) {
    problems.push(`${name}/${abi}: PT_LOAD p_align 0x${align.toString(16)} is under the 0x4000 page-size requirement`);
  } else if (align !== expected.min_p_align) {
    problems.push(`${name}/${abi}: p_align 0x${align.toString(16)} but the lock records 0x${expected.min_p_align.toString(16)}`);
  }
  return problems;
}

export function checkLock(lock, jniRoot) {
  const problems = [];
  for (const [name, abis] of Object.entries(lock.libraries)) {
    for (const [abi, expected] of Object.entries(abis)) {
      problems.push(...checkOne(name, abi, expected, join(jniRoot, abi, name)));
    }
  }
  return problems;
}

async function selftest() {
  // The gate is only worth having if a substituted blob trips it. Corrupt a
  // digest in memory and require a failure.
  const lock = JSON.parse(readFileSync(LOCK, "utf8"));
  const real = Object.keys(lock.libraries["libhev-socks5-tunnel.so"])[0];
  const before = checkLock(lock, JNI);
  if (before.length) {
    console.error("selftest cannot run while the tree is already failing:");
    for (const p of before) console.error(`  ${p}`);
    process.exit(1);
  }
  const tampered = structuredClone(lock);
  const good = tampered.libraries["libhev-socks5-tunnel.so"][real].sha256;
  tampered.libraries["libhev-socks5-tunnel.so"][real].sha256 =
    (good[0] === "0" ? "1" : "0") + good.slice(1);
  const after = checkLock(tampered, JNI);
  if (after.length === 0) {
    console.error("selftest FAILED: a changed digest passed the lock check");
    process.exit(1);
  }
  console.log(`verify-hev-lock: selftest ok (${after.length} expected failure(s) observed)`);
}

const args = process.argv.slice(2);

/**
 * `--align <files...>`: assert 16 KB PT_LOAD alignment on artifacts this run
 * just built. The lock covers vendored blobs; a freshly compiled libaether.so
 * has no lock entry and its alignment depends on the linker flags used, so it
 * is measured rather than assumed.
 */
function checkAlignment(paths) {
  let bad = 0;
  for (const p of paths) {
    if (!existsSync(p)) {
      fail(`${p}: not found`);
      bad += 1;
      continue;
    }
    const align = minProgramAlignment(readFileSync(p));
    if (align === null) {
      fail(`${p}: not a parseable ELF`);
      bad += 1;
    } else if (align < MIN_PAGE_ALIGN) {
      fail(`${p}: PT_LOAD p_align 0x${align.toString(16)} < 0x4000 (needs -Wl,-z,max-page-size=16384)`);
      bad += 1;
    } else {
      console.log(`align ok ${p} (0x${align.toString(16)})`);
    }
  }
  return bad;
}

if (args.includes("--align")) {
  const paths = args.slice(args.indexOf("--align") + 1).filter((a) => !a.startsWith("--"));
  if (paths.length === 0) {
    console.error("verify-hev-lock: --align needs at least one file");
    process.exit(2);
  }
  process.exit(checkAlignment(paths) === 0 ? 0 : 1);
}

if (args.includes("--selftest-fail")) {
  await selftest();
} else {
  if (!existsSync(LOCK)) {
    console.error(`verify-hev-lock: ${LOCK} is missing — refusing to skip verification`);
    process.exit(1);
  }
  const lock = JSON.parse(readFileSync(LOCK, "utf8"));
  if (lock.source?.upstream === null || lock.source?.tag === null) {
    console.warn(
      "verify-hev-lock: upstream provenance is NOT established (hev-lock.json records\n" +
      "    upstream/tag as null). The digests below detect substitution of the blobs in\n" +
      "    this repository; they do not prove who built them.",
    );
  }
  const problems = checkLock(lock, JNI);
  if (problems.length) {
    for (const p of problems) console.error(`  ${p}`);
    process.exit(1);
  }
  const n = Object.values(lock.libraries).reduce((a, b) => a + Object.keys(b).length, 0);
  console.log(`verify-hev-lock: ${n} payload(s) match the lock and are 16 KB aligned`);
}
