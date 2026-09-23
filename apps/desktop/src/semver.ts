/**
 * Semantic-version precedence, per SEMVER 2.0.0 §11 — no dependency.
 *
 * Its own module rather than a helper inside `hooks/useRuntime.ts` because that
 * file is one of the pairs the `frontend-fork-parity` gate measures: it scores how
 * much of the Android hook's code is the same code as the desktop hook's, and the
 * desktop app is the only one that checks GitHub for a release, so a rule that lives
 * on one side has exactly one home. Putting it here keeps the comparator with the
 * shell that owns the question ("is this tag newer than the version I am running?").
 *
 * Why it is not a numeric compare of the dotted parts: `semverGt` used to drop
 * everything after the first `-`, so `1.3.0-beta` scored equal to the stable
 * `1.3.0` it precedes. `compareSemver(a, b) === 0` meant the banner never showed for
 * the prerelease that *is* newer than `1.3.0-alpha`, and a build published as
 * `1.3.0-beta` read as up to date against the stable release that came after it.
 */
export type SemverParts = {
  core: number[];
  pre: string[];
  /** Invalid input: comparable to nothing, so a caller must not claim an update. */
  valid: boolean;
};

/**
 * Parse `MAJOR.MINOR.PATCH[-prerelease][+build]`.
 *
 * Tolerant of the shapes a release host actually sends — a leading `v`, a missing
 * patch (`1.3`), a prerelease that itself contains a hyphen (`1.3.0-rc.1-fix`) — and
 * rejects the shapes that are not a version at all (`latest`, `""`, `1.x.0`), which
 * compare equal to nothing rather than to everything. Build metadata is dropped
 * before parsing: SEMVER §10 says it is not part of precedence, so `1.0.0` and
 * `1.0.0+build.7` are the same version.
 */
export function parseSemver(version: string): SemverParts {
  const invalid: SemverParts = { core: [0, 0, 0], pre: [], valid: false };
  const text = String(version ?? "").trim().replace(/^v/i, "");
  if (!text) return invalid;
  const withoutBuild = text.split("+")[0] ?? "";
  const dash = withoutBuild.indexOf("-");
  const coreText = dash < 0 ? withoutBuild : withoutBuild.slice(0, dash);
  const preText = dash < 0 ? "" : withoutBuild.slice(dash + 1);
  const coreParts = coreText.split(".");
  if (!coreParts.length || coreParts.length > 3) return invalid;
  const core = [0, 1, 2].map((i) => {
    const part = coreParts[i];
    if (part === undefined) return 0;
    if (!/^\d+$/.test(part)) return Number.NaN;
    return Number.parseInt(part, 10);
  });
  if (core.some((n) => !Number.isFinite(n))) return invalid;
  if (preText && !/^[0-9A-Za-z.-]+$/.test(preText)) return invalid;
  return { core, pre: preText ? preText.split(".") : [], valid: true };
}

/** Is a numeric identifier, which sorts below an alphanumeric one (SEMVER §11.4.1). */
function isNumeric(identifier: string): boolean {
  return /^\d+$/.test(identifier);
}

function compareIdentifiers(a: string, b: string): number {
  const aNum = isNumeric(a);
  const bNum = isNumeric(b);
  if (aNum && bNum) return Number.parseInt(a, 10) - Number.parseInt(b, 10);
  if (aNum) return -1;
  if (bNum) return 1;
  // Neither is numeric: ASCII order, which is what "lexically" means here —
  // `alpha` < `beta` < `rc`, and lowercase sorts after uppercase by the same rule.
  return a < b ? -1 : a > b ? 1 : 0;
}

/**
 * `<0` when `a` precedes `b`, `0` when they are the same version, `>0` after it.
 *
 * An invalid operand compares equal to everything: the caller then reports no
 * update, which is the only honest answer about a string that is not a version.
 */
export function compareSemver(a: string, b: string): number {
  const pa = parseSemver(a);
  const pb = parseSemver(b);
  if (!pa.valid || !pb.valid) return 0;
  for (let i = 0; i < 3; i += 1) {
    const diff = (pa.core[i] ?? 0) - (pb.core[i] ?? 0);
    if (diff !== 0) return diff;
  }
  // §11.3: a release outranks any of its own prereleases — `1.0.0` > `1.0.0-rc.1`.
  if (pa.pre.length === 0 || pb.pre.length === 0) {
    if (pa.pre.length === pb.pre.length) return 0;
    return pa.pre.length === 0 ? 1 : -1;
  }
  const shared = Math.min(pa.pre.length, pb.pre.length);
  for (let i = 0; i < shared; i += 1) {
    const diff = compareIdentifiers(pa.pre[i] ?? "", pb.pre[i] ?? "");
    if (diff !== 0) return diff;
  }
  // §11.4.4: when every identifier they share is equal, the longer set is greater.
  return pa.pre.length - pb.pre.length;
}

/** Does `latest` outrank `current` — i.e. is there a release worth offering? */
export function semverGt(latest: string, current: string): boolean {
  return compareSemver(latest, current) > 0;
}
