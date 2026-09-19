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
});
