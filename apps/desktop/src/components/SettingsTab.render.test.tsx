// @vitest-environment jsdom
import { afterEach, describe, expect, it } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { SettingsTab } from "./SettingsTab";
import { defaults } from "../types";

afterEach(() => cleanup());

const rejected = {
  code: "validation",
  message: "HTTP port must be 1024–65535 (got 80)",
  field: "httpPort",
};

function renderTab(withError: boolean) {
  render(
    <SettingsTab
      settings={{ ...defaults, httpPort: 80 }}
      settingsLocked={false}
      settingsLoaded
      saved={false}
      saveError={withError ? rejected : null}
      patchSettings={() => {}}
    />,
  );
}

describe("SettingsTab save feedback", () => {
  it("shows the shell's rejection where the user can see it", () => {
    renderTab(true);
    expect(screen.getByRole("alert").textContent).toContain("HTTP port must be 1024");
    expect(screen.getByText("Save Rejected")).toBeTruthy();
    expect(screen.getByText(/Last save was rejected/)).toBeTruthy();
  });

  it("marks the refused input, not the whole form", () => {
    renderTab(true);
    const refused = screen.getByRole("spinbutton", { name: /HTTP proxy port/i });
    const untouched = screen.getByRole("spinbutton", { name: /SOCKS5 proxy port/i });
    expect(refused.getAttribute("aria-invalid")).toBe("true");
    expect(untouched.hasAttribute("aria-invalid")).toBe(false);
  });

  it("says nothing when the save was accepted", () => {
    renderTab(false);
    expect(screen.queryByText("Save Rejected")).toBeNull();
    expect(screen.queryByText(/AUTO-SAVE REJECTED/)).toBeNull();
    expect(screen.getByText("Synchronizing changes…")).toBeTruthy();
  });
});
