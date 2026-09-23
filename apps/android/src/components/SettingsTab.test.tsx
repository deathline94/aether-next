// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { SettingsTab } from "./SettingsTab";
import { defaults } from "../types";
import type { Settings } from "../types";

// vitest runs without `globals: true`, so testing-library never auto-cleans: every
// render in this file would otherwise share one document and the role query would
// find two switches.
afterEach(() => cleanup());

const switch_ = () => screen.getByRole("switch", { name: /resume after reboot/i });

const renderTab = (settings: Settings) => {
  const patchSettings = vi.fn();
  render(
    <SettingsTab
      settings={settings}
      settingsLocked={false}
      settingsLoaded
      saved
      admin
      saveError={null}
      patchSettings={patchSettings}
    />,
  );
  return patchSettings;
};

describe("android boot-start setting", () => {
  it("labels point at a control instead of wrapping one", () => {
    // The desktop's a11y suite asserts the same two facts; this file is the only
    // place the Android markup gets checked at all, because there is no Android
    // axe suite (T171 covers the desktop tabs only). A `<label>` that contains the
    // −/+ buttons labels a compound control by nesting, and a label with no `for`
    // associates only until someone reorders the children.
    renderTab({ ...defaults });
    const labels = Array.from(document.querySelectorAll("label"));
    expect(labels.length).toBeGreaterThan(0);
    expect(labels.filter((l) => l.querySelector("button, input, select")).length).toBe(0);
    const withFor = labels.filter((l) => l.hasAttribute("for"));
    expect(withFor.length).toBeGreaterThan(0);
    for (const l of withFor) {
      expect(document.getElementById(l.getAttribute("for") ?? "")).not.toBeNull();
    }
  });

  it("offers a switch that reports and writes launchAtLogin", () => {
    const patch = renderTab({ ...defaults, launchAtLogin: false });
    expect(switch_().getAttribute("aria-checked")).toBe("false");

    fireEvent.click(switch_());
    expect(patch).toHaveBeenCalledWith({ launchAtLogin: true });

    // The row mirrors the stored value, not its own last click: a save the shell
    // refused must not leave the switch claiming a state nothing persists.
    cleanup();
    renderTab({ ...defaults, launchAtLogin: true });
    expect(switch_().getAttribute("aria-checked")).toBe("true");
  });

  it("promises a notification, not an auto-connect, because a boot receiver cannot open a VPN", () => {
    renderTab(defaults);
    const copy = switch_().closest(".setting-row")?.textContent ?? "";
    expect(copy.toLowerCase()).toContain("notification");
    expect(copy).not.toMatch(/auto(?:matically)? (?:start|connect)/i);
  });
});
