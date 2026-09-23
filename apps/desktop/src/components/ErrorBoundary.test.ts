// @vitest-environment jsdom
import { describe, expect, it } from "vitest";
import { resetKeysChanged } from "@aether/ui";

/*
 * The half of T186 that jsdom can actually observe. A boundary's fallback cannot
 * be rendered in a unit test here (React 19 rethrows a child that throws during
 * render out of `act()` and unmounts the tree), so the recovery decision - the
 * one line of the design that is logic rather than plumbing - is tested where it
 * lives: as a pure function shared by both apps.
 */
describe("resetKeysChanged", () => {
  const a = { status: "connected" };
  const b = { status: "connecting" };

  it("does not clear a boundary when the keys are the same array", () => {
    const keys = [a, 1];
    expect(resetKeysChanged(keys, keys)).toBe(false);
    expect(resetKeysChanged([a, 1], [a, 1])).toBe(false);
  });

  it("clears when any key changes identity", () => {
    expect(resetKeysChanged([a, 1], [b, 1])).toBe(true);
    expect(resetKeysChanged([a, 1], [a, 2])).toBe(true);
  });

  it("clears when the number of keys changes", () => {
    expect(resetKeysChanged([a], [a, b])).toBe(true);
    expect(resetKeysChanged([a, b], [a])).toBe(true);
  });

  it("treats a boundary gaining or losing resetKeys as a change", () => {
    expect(resetKeysChanged(undefined, [a])).toBe(true);
    expect(resetKeysChanged([a], undefined)).toBe(true);
    expect(resetKeysChanged(undefined, undefined)).toBe(false);
  });

  it("compares with Object.is, so NaN is stable and +0/-0 are not", () => {
    expect(resetKeysChanged([NaN], [NaN])).toBe(false);
    expect(resetKeysChanged([0], [-0])).toBe(true);
  });

  it("re-heals on a new object with identical contents", () => {
    // The tabs key on the settings *object*, which a reload replaces wholesale.
    // Value-equality here would keep a crashed tab showing its fallback after a
    // settings reload that genuinely produced fresh data.
    expect(resetKeysChanged([{ x: 1 }], [{ x: 1 }])).toBe(true);
  });
});
