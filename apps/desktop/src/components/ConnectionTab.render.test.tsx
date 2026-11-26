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
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { ConnectionTab, PLATFORM, START_HINT } from "./ConnectionTab";
import { defaults, initialRuntime } from "../types";
import type { RuntimeState, Settings } from "../types";
import {
  nordicHeroHeadline,
  nordicRoutingSummary,
  powerControlLabel,
} from "@aether/ui/statusCopy";
import { RELEASES_PAGE } from "../hooks/useRuntime";

vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));

import { invoke } from "@tauri-apps/api/core";

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
      expect(text(container.querySelector(".hero-title"))).toBe(
        nordicHeroHeadline("connected", mode, PLATFORM.canSetSystemProxy),
      );
      const liveBody = text(container.querySelector('.hero-subtitle[aria-live="polite"]'));
      if (mode === "proxy-only") {
        expect(liveBody).toContain("127.0.0.1");
        expect(nordicHeroHeadline("connected", mode, PLATFORM.canSetSystemProxy)).toBe("Connected");
      } else {
        expect(liveBody).toContain("Cloudflare Edge");
        expect(nordicHeroHeadline("connected", mode, PLATFORM.canSetSystemProxy)).toBe("Protected");
      }
      expect(container.textContent ?? "").toContain(nordicRoutingSummary(mode, "desktop"));
      const proxyCodes = Array.from(
        container.querySelectorAll('section[aria-label="Local Proxies"] code'),
      ).map(text);
      expect(proxyCodes).toContain(`127.0.0.1:${defaults.socksPort}`);
      expect(proxyCodes).toContain(`127.0.0.1:${defaults.httpPort}`);
      cleanup();
    });
  }

  it("names the state the same way whatever the mode", () => {
    for (const status of ["disconnected", "connecting", "error"] as const) {
      for (const mode of MODES) {
        cleanup();
        const { container } = renderTab(mode, { status }, false, status === "connecting");
        expect(text(container.querySelector(".hero-title"))).toBe(
          nordicHeroHeadline(status, mode, PLATFORM.canSetSystemProxy),
        );
      }
    }
  });

  it("calls the control what it does, in this surface's verb", () => {
    const stopped = renderTab("system-proxy", { status: "disconnected" }, false, false);
    const stoppedBtn = stopped.container.querySelector(".primary-cta");
    expect(stoppedBtn?.getAttribute("aria-label")).toBe(powerControlLabel(false));
    expect(text(stoppedBtn)).toBe("Connect");
    cleanup();

    const up = renderTab("tun");
    const upBtn = up.container.querySelector(".primary-cta");
    expect(upBtn?.getAttribute("aria-label")).toBe(powerControlLabel(true));
    expect(text(upBtn)).toBe("Disconnect");
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

describe("the update banner's opener", () => {
  function renderBanner(url: string) {
    return render(
      <ConnectionTab
        settings={defaults}
        runtime={{ ...initialRuntime, status: "connected", detail: "Session is up." }}
        busy={false}
        testBusy={false}
        connected
        running
        settingsLocked
        settingsLoaded
        admin
        testResult={null}
        appVersion="1.3.0"
        updateAvailable={{ version: "v9.9.9", url }}
        dismissUpdate={vi.fn()}
        toggleConnection={vi.fn()}
        patchSettings={vi.fn()}
        runTest={vi.fn()}
        dismissError={vi.fn()}
        appendLog={vi.fn()}
      />,
    );
  }

  it("opens this repository's release page", () => {
    vi.mocked(invoke).mockResolvedValue(undefined);
    const url = "https://github.com/deathline94/aether-next/releases/tag/v9.9.9";
    renderBanner(url);
    fireEvent.click(screen.getByRole("button", { name: "View release" }));
    expect(invoke).toHaveBeenCalledWith("plugin:opener|open_url", { url });
  });

  it("refuses a URL taken from network data", () => {
    vi.mocked(invoke).mockResolvedValue(undefined);
    renderBanner("javascript:alert(1)");
    fireEvent.click(screen.getByRole("button", { name: "View release" }));
    expect(invoke).toHaveBeenCalledWith("plugin:opener|open_url", { url: RELEASES_PAGE });
  });

  it("triggers inline download and install when assetUrl and handler are provided", () => {
    const installUpdate = vi.fn();
    render(
      <ConnectionTab
        settings={defaults}
        runtime={{ ...initialRuntime, status: "connected", detail: "Session is up." }}
        busy={false}
        testBusy={false}
        connected
        running
        settingsLocked
        settingsLoaded
        admin
        testResult={null}
        appVersion="1.3.16"
        updateInfo={{
          available: true,
          currentVersion: "1.3.16",
          latestVersion: "1.3.17",
          releaseUrl: RELEASES_PAGE,
          assetName: "AetherNext-windows-x64-setup.exe",
          assetUrl: "https://github.com/deathline94/aether-next/releases/download/v1.3.17/AetherNext-windows-x64-setup.exe",
          assetSize: 6_700_000,
          sha256: "a".repeat(64),
          notes: "",
        }}
        installUpdate={installUpdate}
        dismissUpdate={vi.fn()}
        toggleConnection={vi.fn()}
        patchSettings={vi.fn()}
        runTest={vi.fn()}
        dismissError={vi.fn()}
        appendLog={vi.fn()}
      />,
    );
    fireEvent.click(screen.getByRole("button", { name: "Download & install" }));
    expect(installUpdate).toHaveBeenCalledTimes(1);
  });
});
