// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { SettingsTab } from "./SettingsTab";
import { defaults } from "../types";

afterEach(() => cleanup());

const rejected = {
  code: "validation",
  message: "HTTP port must be 1024–65535 (got 80)",
  field: "httpPort",
};

function renderTab(props: { saveError?: unknown; dirty?: boolean; saved?: boolean } = {}) {
  const { saveError = null, dirty = false, saved = false } = props;
  render(
    <SettingsTab
      settings={{ ...defaults, httpPort: 80 }}
      settingsLocked={false}
      settingsLoaded
      saved={saved}
      dirty={dirty}
      saveError={saveError as never}
      patchSettings={vi.fn()}
    />,
  );
}

describe("SettingsTab save feedback", () => {
  it("shows the shell's rejection where the user can see it", () => {
    renderTab({ saveError: rejected });
    expect(screen.getByRole("alert").textContent).toContain("HTTP port must be 1024");
    expect(screen.getByText("Save Rejected")).toBeTruthy();
    expect(screen.getByText(/Last save was rejected/)).toBeTruthy();
  });

  it("marks the refused input, not the whole form", () => {
    renderTab({ saveError: rejected });
    const refused = screen.getByRole("spinbutton", { name: /HTTP proxy port/i });
    const untouched = screen.getByRole("spinbutton", { name: /SOCKS5 proxy port/i });
    expect(refused.getAttribute("aria-invalid")).toBe("true");
    expect(untouched.hasAttribute("aria-invalid")).toBe(false);
  });

  it("says nothing when the save was accepted", () => {
    renderTab();
    expect(screen.queryByText("Save Rejected")).toBeNull();
    expect(screen.queryByText(/AUTO-SAVE REJECTED/)).toBeNull();
  });

  it("does not claim it is saving when nothing is pending", () => {
    // The dock pulsed "Auto-Saving / Synchronizing changes…" for as long as the
    // 1.2 s "Synchronized" flash was not showing — including on first load, with
    // no edit made and nothing on its way to disk.
    renderTab();
    expect(screen.queryByText("Synchronizing changes…")).toBeNull();
    expect(screen.queryByText("Auto-Saving")).toBeNull();
    expect(screen.getByText(/no changes pending/i)).toBeTruthy();
    expect(screen.getByText("Idle")).toBeTruthy();
  });

  it("names the three real states distinctly", () => {
    renderTab({ dirty: true });
    expect(screen.getByText("Synchronizing changes…")).toBeTruthy();
    expect(screen.getByText("Auto-Saving")).toBeTruthy();

    cleanup();
    renderTab({ saved: true });
    expect(screen.getByText(/All parameters synchronized/)).toBeTruthy();
    expect(screen.getByText("Synchronized")).toBeTruthy();

    cleanup();
    render(
      <SettingsTab
        settings={defaults}
        settingsLocked={false}
        settingsLoaded={false}
        saved={false}
        dirty={false}
        saveError={null}
        patchSettings={vi.fn()}
      />,
    );
    expect(screen.getByText(/Reading configuration profile from disk/)).toBeTruthy();
  });

  it("renders the custom noise matrix only where the profile can be applied", () => {
    // The select accepted "custom" for WireGuard/Gool on h2 while the matrix hid
    // itself, so the numbers went to disk unseen.
    render(
      <SettingsTab
        settings={{ ...defaults, protocol: "wireguard", transport: "h2", noize: "custom" }}
        settingsLocked={false}
        settingsLoaded
        saved={false}
        dirty={false}
        saveError={null}
        patchSettings={vi.fn()}
      />,
    );
    expect(screen.getByText(/CUSTOM NOISE PARAMETERS/i)).toBeTruthy();
    expect(screen.getByRole("spinbutton", { name: /junk count/i })).toBeTruthy();
  });
});
