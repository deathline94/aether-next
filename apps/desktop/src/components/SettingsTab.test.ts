import { describe, expect, it } from "vitest";
import { commitPath, noiseFieldState } from "./SettingsTab";
import { defaults } from "../types";
import type { Settings } from "../types";

const at = (over: Partial<Settings>): Settings => ({ ...defaults, ...over });

describe("noiseFieldState", () => {
  it("blocks the profile only where the transport cannot carry it", () => {
    // UDP junk frames do not exist on an HTTP/2 TCP stream.
    expect(noiseFieldState(at({ protocol: "masque", transport: "h2" }))).toEqual({
      blocked: true,
      showMatrix: false,
    });
    expect(noiseFieldState(at({ protocol: "masque", transport: "h3" }))).toEqual({
      blocked: false,
      showMatrix: false,
    });
  });

  it("shows the parameters of a custom profile it lets you pick", () => {
    // The select was enabled for wireguard/gool on h2 and accepted "custom" while
    // the matrix only rendered for `transport !== "h2"`: a profile was committed
    // with no way to see or edit the numbers inside it.
    const state = noiseFieldState(at({ protocol: "wireguard", transport: "h2", noize: "custom" }));
    expect(state).toEqual({ blocked: false, showMatrix: true });
    expect(noiseFieldState(at({ protocol: "gool", noize: "custom" })).showMatrix).toBe(true);
    expect(
      noiseFieldState(at({ protocol: "masque", transport: "h3", noize: "custom" })),
    ).toEqual({ blocked: false, showMatrix: true });
  });

  it("never offers a matrix for a profile that is not custom", () => {
    expect(noiseFieldState(at({ noize: "medium" })).showMatrix).toBe(false);
    expect(noiseFieldState(at({ protocol: "masque", transport: "h2", noize: "custom" })).showMatrix).toBe(
      false,
    );
  });
});

describe("commitPath", () => {
  it("writes nothing until the field is left or entered", () => {
    // Per-keystroke patching plus a 400 ms debounce persisted a half-typed path
    // on the way to a real one, and an abandoned edit stayed saved.
    expect(commitPath("C:\Users", "C:\Users\aether.exe")).toBe("C:\Users");
    expect(commitPath("C:\Users\aether.exe", "C:\Users\aether.exe")).toBeNull();
    expect(commitPath("  ", "")).toBeNull();
    expect(commitPath("  C:\a.exe  ", "C:\a.exe")).toBeNull();
  });

  it("lets a blank draft mean the default location", () => {
    expect(commitPath("", "C:\old\aether.exe")).toBe("");
  });
});
