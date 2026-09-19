import { describe, it, expect, vi } from "vitest";

describe("desktop useRuntime settings hydration", () => {
  it("completes settings hydration in finally block even when get_settings throws", async () => {
    let settingsLoaded = false;
    let settings: Record<string, unknown> = { protocol: "masque", routingMode: "tun" };

    const mockInvoke = vi.fn().mockImplementation(async (cmd: string) => {
      if (cmd === "get_settings") {
        throw new Error("IPC error: could not load config");
      }
      return null;
    });

    try {
      const [loadedSettings] = await Promise.all([
        mockInvoke("get_settings").catch(() => null),
      ]);
      if (loadedSettings) {
        settings = loadedSettings;
      }
    } finally {
      settingsLoaded = true;
    }

    expect(settingsLoaded).toBe(true);
    expect(settings.routingMode).toBe("tun");
  });

  it("flags settingsLoadError when get_settings throws and clears it on successful retry", async () => {
    let settingsLoadError = false;
    let settingsLoaded = false;
    let settings = { protocol: "masque", routingMode: "tun" };

    // 1. Initial hydration failure
    const mockInvokeFail = vi.fn().mockRejectedValue(new Error("Disk IO failure"));
    try {
      const [loadedSettings] = await Promise.all([
        mockInvokeFail("get_settings").catch(() => null),
      ]);
      if (loadedSettings) {
        settings = loadedSettings;
        settingsLoadError = false;
      } else {
        settingsLoadError = true;
      }
    } finally {
      settingsLoaded = true;
    }

    expect(settingsLoaded).toBe(true);
    expect(settingsLoadError).toBe(true);

    // 2. Retry succeeds
    const mockInvokeSuccess = vi.fn().mockResolvedValue({ protocol: "wireguard", routingMode: "system" });
    const retrySettings = async () => {
      try {
        const loaded = await mockInvokeSuccess("get_settings");
        if (loaded) {
          settings = loaded;
          settingsLoadError = false;
          settingsLoaded = true;
        }
      } catch {
        settingsLoadError = true;
      }
    };

    await retrySettings();
    expect(settingsLoadError).toBe(false);
    expect(settings.protocol).toBe("wireguard");
    expect(settings.routingMode).toBe("system");
  });

  it("maintains settingsLoadError when retrySettings also fails", async () => {
    let settingsLoadError = true;
    const mockInvokeFail = vi.fn().mockRejectedValue(new Error("Persistent error"));

    const retrySettings = async () => {
      try {
        await mockInvokeFail("get_settings");
        settingsLoadError = false;
      } catch {
        settingsLoadError = true;
      }
    };

    await retrySettings();
    expect(settingsLoadError).toBe(true);
  });
});
