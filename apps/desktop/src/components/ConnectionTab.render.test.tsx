// @vitest-environment jsdom
/*
 * The desktop half of the claim that the two frontends say the same thing.
 *
 * `frontend-fork-parity` compares lines; it cannot tell that a sentence about the
 * session was rewritten on one surface and not the other, which is how a
 * `proxy-only` session came to be described as routing the device on Windows while
 * the phone said it did not. So this mounts the real component for every connected
 * mode and reads the surfaces that make the claim back out of the DOM, against the
 * table in `packages/ui` - not against strings restated here. A local paraphrase
 * reintroduced into `ConnectionTab.tsx` fails it, and so does editing a claim on
 * one surface only.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render } from "@testing-library/react";
import { ConnectionTab, PLATFORM, START_HINT } from "./ConnectionTab";
import { defaults, initialRuntime } from "../types";
import type { RuntimeState, Settings } from "../types";
import {
  connectedCopy,
  heroCopy,
  portStateCopy,
  powerControlLabel,
  powerHint,
} from "@aether/ui/statusCopy";

afterEach(() => cleanup());

type Mode = Settings["routingMode"];
const MODES: Mode[] = ["tun", "system-proxy", "proxy-only"];

function renderTab(mode: Mode, runtime: Partial<RuntimeState> = {}, connected = true, running = true) {
  const props = {
    settings: { ...defaults, routingMode: mode },
    runtime: {
      ...initialRuntime,
      status: connected ? ("connected" as const) : ("connecting" as const),
      detail: connected ? "Session is up." : "Starting…",
      pid: 4242,
      endpoint: "104.16.23.19:443",
      ...runtime,
    },
    busy: false,
    testBusy: false,
    connected,
    running,
    settingsLocked: false,
    settingsLoaded: true,
    admin: true,
    testResult: null,
    appVersion: "1.3.0",
    updateAvailable: null,
    dismissUpdate: vi.fn(),
    toggleConnection: vi.fn(),
    patchSettings: vi.fn(),
    runTest: vi.fn(),
    dismissError: vi.fn(),
    appendLog: vi.fn(),
  };
  return render(<ConnectionTab {...props} />);
}

const text = (el: Element | null | undefined) => (el?.textContent ?? "").trim();

describe("the desktop renders the shared claim table", () => {
  for (const mode of MODES) {
    it(`says the table's piece about a connected ${mode} session`, () => {
      const { container } = renderTab(mode);
      const copy = connectedCopy(mode, PLATFORM);
      const listeners = portStateCopy(true, mode, PLATFORM);

      expect(text(container.querySelector(".switch-status-pill"))).toBe(copy.badge);
      // The live region carries the body verbatim: what a screen reader is told is
      // the sentence a sighted user reads, not a paraphrase of it.
      expect(text(container.querySelector('.connection-copy p[aria-live="polite"]'))).toContain(copy.body);
      const tags = Array.from(container.querySelectorAll(".daemon-tag strong")).map(text);
      expect(tags).toContain(listeners.http);
      expect(tags).toContain(listeners.socks);
      cleanup();
    });
  }

  it("names the state the same way whatever the mode, and only the badge carries the mode", () => {
    for (const status of ["disconnected", "connecting", "error"] as const) {
      for (const mode of MODES) {
        cleanup();
        const { container } = renderTab(mode, { status }, false, status === "connecting");
        const hero = heroCopy(status);
        expect(text(container.querySelector(".eyebrow span"))).toBe(hero.eyebrow);
        expect(text(container.querySelector(".connection-copy h2"))).toBe(hero.title);
        expect(text(container.querySelector(".switch-status-pill"))).toBe(hero.badge);
      }
    }
  });

  it("calls the control what it does, in this surface's verb", () => {
    const stopped = renderTab("system-proxy", { status: "disconnected" }, false, false);
    expect(text(stopped.container.querySelector(".switch-action-hint"))).toBe(powerHint(false, PLATFORM));
    expect(
      stopped.container.querySelector(".master-toggle-btn")?.getAttribute("aria-label"),
    ).toBe(powerControlLabel(false));
    cleanup();

    const up = renderTab("tun");
    expect(text(up.container.querySelector(".switch-action-hint"))).toBe(powerHint(true, PLATFORM));
    expect(up.container.querySelector(".master-toggle-btn")?.getAttribute("aria-label")).toBe(
      powerControlLabel(true),
    );
    // The accessible name and the visible hint agree about which verb this surface
    // uses, which is the part no line-comparison gate can see.
    expect(powerHint(true, PLATFORM)).toContain(PLATFORM.actionVerb.toUpperCase());
    expect(START_HINT.startsWith(PLATFORM.actionVerb)).toBe(true);
  });

  it("does not reach past a local proxy in the mode that is one", () => {
    for (const mode of ["proxy-only", "system-proxy"] as const) {
      cleanup();
      const { container } = renderTab(mode);
      const said = container.textContent ?? "";
      if (mode === "proxy-only") {
        expect(said).not.toMatch(/system proxy is set|whole device|every app on this device/i);
      }
      expect(said).not.toMatch(/unbreakable|anonymous|100\s*%|traffic secure|route open/i);
    }
  });
});
