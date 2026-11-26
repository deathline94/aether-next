// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach } from "vitest";
import { renderHook, act, waitFor } from "@testing-library/react";
import { useRuntime } from "./useRuntime";
import { IpcRejection } from "../ipcError";

vi.mock("../bridge", () => ({
  invoke: vi.fn(),
  listen: vi.fn().mockResolvedValue(() => {}),
}));

import { invoke } from "../bridge";

describe("android useRuntime hook", () => {
  const appendLog = vi.fn();

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("completes hydration in finally block even when get_settings rejects", async () => {
    vi.mocked(invoke).mockImplementation(async (cmd: string) => {
      if (cmd === "get_settings") throw new Error("Bridge failure");
      if (cmd === "get_state") return null;
      if (cmd === "is_admin") return false;
      if (cmd === "app_info") return { version: "1.2.9" };
      return null;
    });

    const { result } = renderHook(() => useRuntime(appendLog));

    await waitFor(() => {
      expect(result.current.settingsLoaded).toBe(true);
    });

    expect(result.current.settingsLoadError).toBe(true);
    expect(result.current.settings.protocol).toBe("masque");
  });

  it("applies loaded settings when get_settings succeeds", async () => {
    vi.mocked(invoke).mockImplementation(async (cmd: string) => {
      if (cmd === "get_settings") {
        return { protocol: "wireguard", socksPort: 9050 };
      }
      if (cmd === "get_state") return null;
      if (cmd === "is_admin") return false;
      if (cmd === "app_info") return { version: "1.2.9" };
      return null;
    });

    const { result } = renderHook(() => useRuntime(appendLog));

    await waitFor(() => {
      expect(result.current.settingsLoaded).toBe(true);
    });

    expect(result.current.settingsLoadError).toBe(false);
    expect(result.current.settings.protocol).toBe("wireguard");
    expect(result.current.settings.socksPort).toBe(9050);
  });

  it("recovers from hydration failure when retrySettings succeeds", async () => {
    let failFirst = true;
    vi.mocked(invoke).mockImplementation(async (cmd: string) => {
      if (cmd === "get_settings") {
        if (failFirst) {
          throw new Error("Bridge error");
        }
        return { protocol: "gool", socksPort: 1080 };
      }
      return null;
    });

    const { result } = renderHook(() => useRuntime(appendLog));

    await waitFor(() => {
      expect(result.current.settingsLoaded).toBe(true);
    });
    expect(result.current.settingsLoadError).toBe(true);

    failFirst = false;
    await act(async () => {
      await result.current.retrySettings();
    });

    expect(result.current.settingsLoadError).toBe(false);
    expect(result.current.settings.protocol).toBe("gool");
    expect(result.current.settings.socksPort).toBe(1080);
  });

  it("maintains settingsLoadError when retrySettings fails again", async () => {
    vi.mocked(invoke).mockImplementation(async (cmd: string) => {
      if (cmd === "get_settings") throw new Error("Persistent bridge error");
      return null;
    });

    const { result } = renderHook(() => useRuntime(appendLog));

    await waitFor(() => {
      expect(result.current.settingsLoaded).toBe(true);
    });
    expect(result.current.settingsLoadError).toBe(true);

    await act(async () => {
      await result.current.retrySettings();
    });

    expect(result.current.settingsLoadError).toBe(true);
  });

  it("keeps the carrier unchanged until the connect it chose actually lands", async () => {
    let rejectConnect: (e: unknown) => void = () => {};
    vi.mocked(invoke).mockImplementation(async (cmd: string) => {
      if (cmd === "get_settings") return { protocol: "masque", transport: "h2", peer: "" };
      if (cmd === "connect") {
        return new Promise((_, reject) => {
          rejectConnect = reject;
        });
      }
      if (cmd === "app_info") return { version: "1.2.9" };
      return null;
    });

    const { result } = renderHook(() => useRuntime(appendLog));
    await waitFor(() => expect(result.current.settingsLoaded).toBe(true));

    let attempt: Promise<void> = Promise.resolve();
    await act(async () => {
      attempt = result.current.connectToPeer("9.9.9.9:443", "wireguard", "h3");
    });

    // Nothing has been reached yet, so no address may be presented as carrying
    // traffic — the endpoint used to be published the moment the dial started.
    expect(result.current.runtime.status).toBe("connecting");
    expect(result.current.runtime.endpoint).toBeNull();

    await act(async () => {
      rejectConnect(new Error("engine refused the endpoint"));
      await attempt;
    });

    // The optimistic commit is rolled back: a direct connect that never came up
    // must not leave the user's carrier protocol rewritten and saved.
    expect(result.current.settings.protocol).toBe("masque");
    expect(result.current.settings.transport).toBe("h2");
    expect(result.current.settings.peer).toBe("");
    expect(result.current.runtime.status).toBe("error");
  });

  it("keeps the reason a save was rejected instead of only logging it", async () => {
    vi.mocked(invoke).mockImplementation(async (cmd: string) => {
      if (cmd === "get_settings") {
        return { protocol: "masque", routingMode: "proxy-only", socksPort: 1080, httpPort: 8080 };
      }
      if (cmd === "save_settings") {
        throw new IpcRejection({
          code: "validation",
          message: "custom obfuscation: max size must be <= 2048 (got 4000)",
          field: "noizeJmax",
        });
      }
      return null;
    });

    const { result } = renderHook(() => useRuntime(appendLog));
    await waitFor(() => expect(result.current.settingsLoaded).toBe(true));

    act(() => {
      result.current.patchSettings({ noize: "custom", noizeJmax: 4000 });
    });

    await waitFor(() => expect(result.current.saveError).not.toBeNull());
    expect(result.current.saveError?.code).toBe("validation");
    expect(result.current.saveError?.field).toBe("noizeJmax");

    act(() => {
      result.current.patchSettings({ noizeJmax: 128 });
    });
    expect(result.current.saveError).toBeNull();
  });
});
