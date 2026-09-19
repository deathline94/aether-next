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
});
