import { describe, expect, it } from "vitest";
import { commitPath } from "./SettingsTab";

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
