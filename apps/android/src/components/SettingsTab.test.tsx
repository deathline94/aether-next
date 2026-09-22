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
