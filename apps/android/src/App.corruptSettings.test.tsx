// @vitest-environment jsdom
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import axe from "axe-core";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

/*
 * ITEM 10's other half, on the surface the user actually opens: the corruption has
 * to be said out loud where it blocks them — not only in the log buffer, which is a
 * tab away and scrolls.
 *
 * The banner lives in `App.tsx` rather than inside `SettingsTab` because the failure
 * is not a settings-form detail: the same refused write stops `connect`, so a user on
 * the Connection tab who presses the primary control and gets an error sentence has
 * to be able to see why, and reach the one action that clears it, from there.
 */
const mocks = vi.hoisted(() => {
  const handlers = new Map<string, (e: { payload: unknown }) => void>();
  const calls: string[] = [];
  const state = { corrupt: true, resetRefused: false };
  const listen = vi.fn(async (event: string, handler: (e: { payload: unknown }) => void) => {
    handlers.set(event, handler);
    return () => {
      handlers.delete(event);
    };
  });
  const invoke = vi.fn(async (cmd: string) => {
    calls.push(cmd);
    if (cmd === "get_state") {
      return {
        status: "disconnected",
        detail: "Ready",
        pid: null,
        endpoint: null,
        settingsError: state.corrupt
          ? {
              state: "corrupt",
              reason: "noize is \"firewall-4\", which the engine has no name for",
              field: "noize",
              detectedAt: 1761234567890,
              action: "reset",
            }
          : null,
      };
    }
    if (cmd === "get_settings") return { protocol: "masque", transport: "h2", noize: "off" };
    if (cmd === "reset_settings" && state.resetRefused) throw new Error("unknown command reset_settings");
    if (cmd === "reset_settings") state.corrupt = false;
    return cmd === "app_info" ? { version: "1.3.0" } : null;
  });
  return { handlers, calls, listen, invoke, state };
});

vi.mock("./bridge", async (importOriginal) => ({
  ...(await importOriginal<typeof import("./bridge")>()),
  listen: mocks.listen,
  invoke: mocks.invoke,
}));

import App from "./App";

// jsdom lays nothing out, and the Activity tab's end marker calls this on mount.
beforeAll(() => {
  Element.prototype.scrollIntoView = () => {};
});

beforeEach(() => {
  vi.clearAllMocks();
  mocks.handlers.clear();
  mocks.calls.length = 0;
  mocks.state.corrupt = true;
  mocks.state.resetRefused = false;
});

afterEach(() => cleanup());

describe("the corrupt-settings surface", () => {
  it("states the diagnosis and offers the reset, from the tab the user is on", async () => {
    render(<App />);
    await screen.findByRole("heading", { name: "Connection" });

    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toContain("noize");
    expect(alert.textContent?.toLowerCase()).toContain("not overwritten");
    expect(mocks.calls.filter((c) => c === "reset_settings")).toHaveLength(0);
  });

  it("gives the diagnosis a semantics axe accepts on the corrupt screen", async () => {
    const { container } = render(<App />);
    await screen.findByRole("alert");
    // The same rule the a11y suite runs: `color-contrast` cannot be answered in
    // jsdom, and this asserts the new banner's role/naming, not its palette.
    const results = await axe.run(container, { rules: { "color-contrast": { enabled: false } } });
    const detail = results.violations.map(
      (v) => `${v.id} (${v.impact}): ${v.help} -> ${v.nodes.map((n) => n.target.join(" ")).join(" | ")}`,
    );
    expect(detail, `axe violations in the corrupt-settings banner`).toEqual([]);
  });

  it("dispatches reset_settings and clears itself when the shell accepts it", async () => {
    render(<App />);
    const button = await screen.findByRole("button", { name: /reset settings/i });

    await act(async () => {
      fireEvent.click(button);
    });

    expect(mocks.calls).toContain("reset_settings");
    // The report is gone and the profile on screen is the one on disk again.
    await waitFor(() => expect(screen.queryByRole("alert")).toBeNull());
    expect(screen.queryByText(/SAVED SETTINGS CORRUPT/i)).toBeNull();
    expect(mocks.calls.filter((c) => c === "get_settings").length).toBeGreaterThan(1);
  });

  it("keeps the diagnosis on screen and names the refusal when the shell rejects the reset", async () => {
    mocks.state.resetRefused = true;
    render(<App />);
    const button = await screen.findByRole("button", { name: /reset settings/i });

    await act(async () => {
      fireEvent.click(button);
    });

    expect(mocks.calls).toContain("reset_settings");
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toContain("reset_settings");
    // Still on screen, still pressable: a refused reset has not resolved anything, and
    // telling the user to reload the app is not a remedy the shell did not grant.
    expect((screen.getByRole("button", { name: /reset settings/i }) as HTMLButtonElement).disabled).toBe(false);
  });

  it("says nothing about corruption when the shell reports none", async () => {
    mocks.state.corrupt = false;
    render(<App />);
    await screen.findByRole("heading", { name: "Connection" });
    expect(screen.queryByText(/SAVED SETTINGS CORRUPT/i)).toBeNull();
    expect(screen.queryByRole("button", { name: /reset settings/i })).toBeNull();
  });
});
