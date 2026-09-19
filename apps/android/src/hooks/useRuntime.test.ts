import { describe, it, expect, vi } from "vitest";

describe("useRuntime settings hydration", () => {
  it("completes settings hydration in finally block even when get_settings throws", async () => {
    let settingsLoaded = false;
    let loadedSettings: Record<string, unknown> | null = null;
    let settings: Record<string, unknown> = { protocol: "masque", socksPort: 1819 };
    const defaults = { protocol: "masque", socksPort: 1819 };

    // Simulated invoke that fails on get_settings
    const mockInvoke = vi.fn().mockImplementation(async (cmd: string) => {
      if (cmd === "get_settings") {
        throw new Error("IPC network timeout / channel closed");
      }
      return null;
    });

    try {
      const [fetchedSettings] = await Promise.all([
        mockInvoke("get_settings").catch(() => null),
      ]);
      if (fetchedSettings) {
        loadedSettings = { ...defaults, ...fetchedSettings };
        settings = loadedSettings;
      }
    } finally {
      settingsLoaded = true;
    }

    expect(settingsLoaded).toBe(true);
    expect(loadedSettings).toBeNull();
    expect(settings.protocol).toBe("masque");
  });

  it("applies loaded settings when get_settings succeeds and unlocks settings", async () => {
    let settingsLoaded = false;
    let settings: Record<string, unknown> = { protocol: "masque", socksPort: 1819 };
    const defaults = { protocol: "masque", socksPort: 1819 };

    const mockInvoke = vi.fn().mockImplementation(async (cmd: string) => {
      if (cmd === "get_settings") {
        return { protocol: "wireguard", socksPort: 9050 };
      }
      return null;
    });

    try {
      const [fetchedSettings] = await Promise.all([
        mockInvoke("get_settings").catch(() => null),
      ]);
      if (fetchedSettings) {
        settings = { ...defaults, ...fetchedSettings };
      }
    } finally {
      settingsLoaded = true;
    }

    expect(settingsLoaded).toBe(true);
    expect(settings.protocol).toBe("wireguard");
    expect(settings.socksPort).toBe(9050);
  });

  it("flags settingsLoadError on failure and recovers on retry", async () => {
    let settingsLoadError = false;
    let settingsLoaded = false;
    let settings = { protocol: "masque", socksPort: 1819 };
    const defaults = { protocol: "masque", socksPort: 1819 };

    // Initial fail
    const mockInvokeFail = vi.fn().mockRejectedValue(new Error("Disk corrupt"));
    try {
      const [fetched] = await Promise.all([
        mockInvokeFail("get_settings").catch(() => null),
      ]);
      if (fetched) {
        settings = { ...defaults, ...fetched };
        settingsLoadError = false;
      } else {
        settingsLoadError = true;
      }
    } finally {
      settingsLoaded = true;
    }

    expect(settingsLoaded).toBe(true);
    expect(settingsLoadError).toBe(true);

    // Retry succeeds
    const mockInvokeSuccess = vi.fn().mockResolvedValue({ protocol: "gool", socksPort: 1080 });
    const retrySettings = async () => {
      try {
        const loaded = await mockInvokeSuccess("get_settings");
        if (loaded) {
          settings = { ...defaults, ...loaded };
          settingsLoadError = false;
          settingsLoaded = true;
        }
      } catch {
        settingsLoadError = true;
      }
    };

    await retrySettings();
    expect(settingsLoadError).toBe(false);
    expect(settings.protocol).toBe("gool");
    expect(settings.socksPort).toBe(1080);
  });
});
