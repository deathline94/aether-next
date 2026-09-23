import { describe, expect, it } from "vitest";

import { compareSemver, parseSemver, semverGt } from "./semver";

/**
 * The defect these exist for: `semverGt` used to cut every operand at its first
 * `-`, so a prerelease was indistinguishable from the release it precedes. Each
 * case below fails on that rule and passes on SEMVER §11 — including the two
 * directions the update banner got wrong (`1.3.0-beta` read as up to date, and
 * `1.3.0` read as newer than the stable release that superseded it).
 */
describe("semver precedence (SEMVER 2.0.0 §11)", () => {
  it("offers an update for a plain newer release", () => {
    expect(semverGt("1.3.1", "1.3.0")).toBe(true);
    expect(semverGt("2.0.0", "1.9.9")).toBe(true);
    expect(semverGt("1.3.0", "1.3.1")).toBe(false);
  });

  it("ranks a release above its own prereleases", () => {
    expect(semverGt("1.3.0", "1.3.0-beta")).toBe(true);
    expect(semverGt("1.3.0-beta", "1.3.0")).toBe(false);
    expect(compareSemver("1.3.0-beta", "1.3.0")).toBeLessThan(0);
  });

  it("offers the prerelease that is newer than the installed prerelease", () => {
    expect(semverGt("1.3.0-beta", "1.3.0-alpha")).toBe(true);
    expect(semverGt("1.3.0-alpha.2", "1.3.0-alpha.1")).toBe(true);
    expect(semverGt("1.2.9", "1.3.0-alpha")).toBe(false);
  });

  it("holds the whole §11.4 example chain in order", () => {
    const chain = [
      "1.0.0-alpha",
      "1.0.0-alpha.1",
      "1.0.0-alpha.beta",
      "1.0.0-beta",
      "1.0.0-beta.2",
      "1.0.0-beta.11",
      "1.0.0-rc.1",
      "1.0.0",
    ];
    for (let i = 1; i < chain.length; i += 1) {
      const lower = chain[i - 1] ?? "";
      const higher = chain[i] ?? "";
      expect(compareSemver(higher, lower), `${higher} vs ${lower}`).toBeGreaterThan(0);
      expect(compareSemver(lower, higher), `${lower} vs ${higher}`).toBeLessThan(0);
    }
  });

  it("compares numeric identifiers as numbers, not as text", () => {
    expect(semverGt("1.0.0-beta.11", "1.0.0-beta.2")).toBe(true);
    expect(semverGt("1.10.0", "1.9.0")).toBe(true);
  });

  it("treats equal versions as no update", () => {
    expect(compareSemver("1.3.0", "1.3.0")).toBe(0);
    expect(compareSemver("1.3.0", "v1.3.0")).toBe(0);
    expect(semverGt("1.3.0", "1.3.0")).toBe(false);
  });

  it("drops build metadata, which is not part of precedence", () => {
    expect(compareSemver("1.0.0+build.7", "1.0.0")).toBe(0);
    expect(compareSemver("1.0.0", "1.0.0+build.7")).toBe(0);
    expect(semverGt("1.0.0+build.7", "1.0.0")).toBe(false);
    // …and still compares the versions behind it.
    expect(semverGt("1.0.1+build.1", "1.0.0+build.9")).toBe(true);
  });

  it("claims nothing about a string that is not a version", () => {
    for (const notAVersion of ["latest", "", "1.x.0", "next", "1.2.3.4"]) {
      expect(parseSemver(notAVersion).valid, notAVersion).toBe(false);
      expect(semverGt(notAVersion, "1.3.0"), notAVersion).toBe(false);
      expect(semverGt("1.3.0", notAVersion), notAVersion).toBe(false);
    }
  });

  it("accepts the shortened forms a release host actually sends", () => {
    expect(parseSemver("1.3").core).toEqual([1, 3, 0]);
    expect(semverGt("1.4", "1.3.9")).toBe(true);
    expect(compareSemver("1.3.0-rc.1-fix", "1.3.0-rc.1")).toBeGreaterThan(0);
  });
});
