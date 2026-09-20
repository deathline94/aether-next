// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach } from "vitest";
import { renderHook, act, waitFor } from "@testing-library/react";
import { useRuntime } from "./useRuntime";

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
});
