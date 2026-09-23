/*
 * ITEM 15: the settings save lifecycle, as the one vocabulary that owns it.
 *
 * The dock used to render `saved ? "synchronized" : "synchronizing changes…"`, which
 * lied twice over: from first paint — before a single edit — it claimed a write was in
 * flight, and after a refusal it kept claiming it forever. `saveState.ts` is the
 * module that decides what may be said, so its two rules are checked here as data
 * rather than as markup: this app cannot render-assert a status line that throws
 * (T186: under React 19 + jsdom a failed render is rethrown out of `act()` and the
 * tree unmounts), and the wording rule is the part that was actually broken.
 *
 * The two claims the reviewer named, in this file and in
 * `hooks/useRuntime.saveLifecycle.test.ts`:
 *   - with no edit, the indicator reads `idle`;
 *   - nothing but an in-flight write may read `saving`.
 */
import { describe, expect, it } from "vitest";
import { saveDockCopy, saveStateOf } from "./saveState";
import type { SaveState } from "./saveState";

const ALL_STATES: SaveState[] = ["idle", "dirty", "saving", "saved"];

describe("saveStateOf reads a claim, not a flag", () => {
  it("passes a lifecycle value through untouched, all four of them", () => {
    for (const state of ALL_STATES) expect(saveStateOf(state)).toBe(state);
  });

  it("never reads 'saving' out of a boolean, whatever the call site meant", () => {
    // The whole point of accepting a boolean: a call site that predates the lifecycle
    // can only say "a write just landed" or "nothing pending". It cannot say "saving",
    // and the dock must not invent a pulse for a write nobody started.
    expect(saveStateOf(false)).toBe("idle");
    expect(saveStateOf(true)).toBe("saved");
    expect(saveStateOf(false)).not.toBe("saving");
    expect(saveStateOf(true)).not.toBe("saving");
  });

  it("treats the boolean and the lifecycle it stands for as the same two answers", () => {
    expect(saveStateOf(false)).toBe(saveStateOf("idle"));
    expect(saveStateOf(true)).toBe(saveStateOf("saved"));
  });
});

describe("saveDockCopy says one thing per state", () => {
  it("has copy for every state the runtime can reach", () => {
    const copy = ALL_STATES.map(saveDockCopy);
    // Four states, four sentences, four icons: a table that collapses two of them is
    // the bug class this file exists for, and `toBeUndefined` would catch only a gap.
    expect(new Set(copy.map((c) => c.text)).size).toBe(ALL_STATES.length);
    expect(new Set(copy.map((c) => c.icon)).size).toBe(ALL_STATES.length);
    for (const entry of copy) {
      expect(entry.text.length).toBeGreaterThan(0);
      expect(entry.icon).toBeTruthy();
    }
  });

  it("reserves the synchronising sentence for the state that is synchronising", () => {
    const pulsing = ALL_STATES.filter((s) => saveDockCopy(s).icon === "pulse");
    expect(pulsing).toEqual(["saving"]);
    for (const state of ALL_STATES) {
      // The progressive form only: "…synchronized" is the *past* tense, which is the
      // `saved` copy and is honest. "Synchronizing changes…" is a claim about a write
      // in flight, and only the state that has one may say it.
      const inFlight = /synchronizing/i.test(saveDockCopy(state).text);
      expect(inFlight, `${state}: ${saveDockCopy(state).text}`).toBe(state === "saving");
    }
  });

  it("calls a first load 'nothing pending', never a write in progress", () => {
    const idle = saveDockCopy("idle");
    expect(idle.icon).toBe("idle");
    // The sentence has to say the form matches the disk, which is what the boolean
    // version could not say at all.
    expect(idle.text.toLowerCase()).toContain("no changes pending");
    expect(idle.text.toLowerCase()).not.toContain("synchronizing");
  });

  it("keeps a refused or unsent edit away from the success wording", () => {
    // `dirty` is the state a refusal leaves the form in: on screen, not on disk.
    for (const state of ["dirty", "idle"] as const) {
      const text = saveDockCopy(state).text.toLowerCase();
      expect(text).not.toContain("synchronized");
    }
    expect(saveDockCopy("dirty").text.toLowerCase()).toContain("not on disk");
    expect(saveDockCopy("dirty").icon).toBe("pending");
    expect(saveDockCopy("saved").icon).toBe("check");
  });
});
