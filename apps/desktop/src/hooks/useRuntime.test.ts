// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { renderHook, act, waitFor, cleanup } from "@testing-library/react";
import { useRuntime } from "./useRuntime";

vi.mock("@tauri-apps/api/core", () => ({
  invoke: vi.fn(),
}));

vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn(),
}));

import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";

type Handler = (event: { payload: unknown }) => void;

/** Every `session://state` handler the hook subscribes, so a test can emit. */
function captureState(): (payload: unknown) => void {
  const handlers: Handler[] = [];
  vi.mocked(listen).mockImplementation(((event: string, handler: Handler) => {
    if (event === "session://state") handlers.push(handler);
    return Promise.resolve(() => {});
  }) as typeof listen);
  return (payload: unknown) => {
    if (handlers.length === 0) throw new Error("the hook never subscribed to session://state");
    act(() => {
      for (const h of handlers) h({ payload });
    });
  };
}

const appendLog = vi.fn();

/**
 * A realistic `get_settings` payload: all eighteen fields the Rust `Settings`
 * serialises. The previous mock returned three of them and asserted only
 * `protocol`, so the suite passed green on the very render that dereferences
 * `settings.ipVersion` / `scanMode` / `noize`.
 */
function shellSettings(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    protocol: "masque",
    transport: "h2",
    scanMode: "balanced",
    ipVersion: "v4",
    noize: "off",
    noizeJc: 5,
    noizeJmin: 50,
    noizeJmax: 128,
    noizeIntervalMs: 0,
    routingMode: "system-proxy",
    socksPort: 1080,
    httpPort: 8080,
    startMinimized: false,
    launchAtLogin: false,
    enginePath: "",
    peer: "",
    quicInitialFrag: false,
    quicInitialFragSize: 96,
    ...over,
  };
}

function stubInvoke(loaded: Record<string, unknown> | null) {
  vi.mocked(invoke).mockImplementation(async (command: string) => {
    if (command === "get_settings") {
      if (loaded === null) throw new Error("IPC error");
      return loaded;
    }
    if (command === "get_state") return null;
    if (command === "is_admin") return false;
    if (command === "app_info") return { version: "1.2.9" };
    return null;
  });
}

beforeEach(() => {
  vi.clearAllMocks();
  appendLog.mockClear();
  // The default `listen` subscription: a no-op unlisten, like the real one.
  vi.mocked(listen).mockImplementation(async () => async () => {});
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("desktop useRuntime hydration", () => {
  it("completes hydration in finally block even when get_settings rejects", async () => {
    stubInvoke(null);

    const { result } = renderHook(() => useRuntime(appendLog));

    await waitFor(() => {
      expect(result.current.settingsLoaded).toBe(true);
    });

    expect(result.current.settingsLoadError).toBe(true);
    expect(result.current.settings.protocol).toBe("masque");
    // The fallback has to be usable by every reader, not merely shaped enough to
    // satisfy a `protocol` assertion.
    expect(result.current.settings.ipVersion).toBe("v4");
    expect(result.current.settings.noize).toBe("off");
    expect(result.current.settings.scanMode).toBe("balanced");
  });

  it("applies loaded settings when get_settings succeeds", async () => {
    stubInvoke(shellSettings({ protocol: "wireguard" }));

    const { result } = renderHook(() => useRuntime(appendLog));

    await waitFor(() => {
      expect(result.current.settingsLoaded).toBe(true);
    });

    expect(result.current.settingsLoadError).toBe(false);
    expect(result.current.settings.protocol).toBe("wireguard");
    // Every field the panels dereference survived the round trip.
    expect(Object.keys(result.current.settings).sort()).toEqual(
      Object.keys(shellSettings()).sort(),
    );
    expect(result.current.settings.ipVersion).toBe("v4");
    expect(result.current.settings.scanMode).toBe("balanced");
    expect(result.current.settings.noize).toBe("off");
  });

  it("merges a payload that is missing fields over the defaults", async () => {
    // A shell build that drops a field used to hand the UI `undefined` there,
    // and `settings.ipVersion.toUpperCase()` threw on the next render.
    const partial = shellSettings();
    delete (partial as Record<string, unknown>).ipVersion;
    delete (partial as Record<string, unknown>).scanMode;
    stubInvoke(partial);

    const { result } = renderHook(() => useRuntime(appendLog));
    await waitFor(() => expect(result.current.settingsLoaded).toBe(true));

    expect(result.current.settings.ipVersion).toBe("v4");
    expect(result.current.settings.scanMode).toBe("balanced");
    expect(appendLog.mock.calls.map((c) => c[0].message).join("\n")).toMatch(/ipVersion/);
    // The merge is not itself an edit: nothing may be written back to disk.
    expect(vi.mocked(invoke).mock.calls.some(([c]) => c === "save_settings")).toBe(false);
  });

  it("refuses an out-of-enum value instead of rendering it", async () => {
    stubInvoke(shellSettings({ routingMode: "system", noize: "turbo-udp" }) as Record<string, unknown>);

    const { result } = renderHook(() => useRuntime(appendLog));
    await waitFor(() => expect(result.current.settingsLoaded).toBe(true));

    expect(result.current.settings.routingMode).toBe("system-proxy");
    expect(result.current.settings.noize).toBe("off");
  });

  it("does not write the hydrated settings straight back to disk", async () => {
    stubInvoke(shellSettings());
    const { result } = renderHook(() => useRuntime(appendLog));
    await waitFor(() => expect(result.current.settingsLoaded).toBe(true));
    // Past the 400 ms save debounce: hydration is not an edit.
    await act(async () => {
      await new Promise((r) => setTimeout(r, 600));
    });
    expect(vi.mocked(invoke).mock.calls.some(([c]) => c === "save_settings")).toBe(false);
    expect(result.current.dirty).toBe(false);
  });

  it("recovers from hydration failure when retrySettings succeeds", async () => {
    let failFirst = true;
    vi.mocked(invoke).mockImplementation(async (cmd: string) => {
      if (cmd === "get_settings") {
        if (failFirst) throw new Error("Disk error");
        return shellSettings({ protocol: "gool", routingMode: "tun" });
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
    expect(result.current.settings.ipVersion).toBe("v4");
  });

  it("maintains settingsLoadError when retrySettings fails again", async () => {
    vi.mocked(invoke).mockImplementation(async (cmd: string) => {
      if (cmd === "get_settings") throw new Error("Persistent error");
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

describe("desktop connect watchdog", () => {
  // Android refused to let the UI sit on "connecting" forever; the desktop hook
  // had no such bound, so a handshake that neither fails nor completes left the
  // beacon spinning and the settings panel locked with nothing to read back.
  it("fails a connect that never reaches readiness, and stops the engine", async () => {
    const emit = captureState();
    stubInvoke(shellSettings());
    const log = vi.fn();
    const { result } = renderHook(() => useRuntime(log));
    await waitFor(() => expect(result.current.settingsLoaded).toBe(true));

    vi.useFakeTimers();
    try {
      emit({ status: "connecting", detail: "Starting engine", pid: 7, endpoint: null, handshakeRttMs: null });
      vi.mocked(invoke).mockClear();

      act(() => {
        vi.advanceTimersByTime(90_000);
      });

      expect(result.current.runtime.status).toBe("error");
      expect(result.current.runtime.detail).toMatch(/timed out/i);
      expect(vi.mocked(invoke).mock.calls.map((c) => c[0])).toContain("disconnect");
      expect(log.mock.calls.map((c) => c[0].message).join("\n")).toMatch(/timed out after 90s/i);
    } finally {
      vi.useRealTimers();
    }
  });

  it("does not fire once the session is up", async () => {
    const emit = captureState();
    stubInvoke(shellSettings());
    const log = vi.fn();
    const { result } = renderHook(() => useRuntime(log));
    await waitFor(() => expect(result.current.settingsLoaded).toBe(true));

    vi.useFakeTimers();
    try {
      emit({ status: "connecting", detail: "Starting engine", pid: 7, endpoint: null, handshakeRttMs: null });
      act(() => {
        vi.advanceTimersByTime(89_000);
      });
      emit({ status: "connected", detail: "Session active", pid: 7, endpoint: "104.16.0.1:443", handshakeRttMs: 21 });
      act(() => {
        vi.advanceTimersByTime(60_000);
      });

      expect(result.current.runtime.status).toBe("connected");
      expect(log.mock.calls.map((c) => c[0].message).join("\n")).not.toMatch(/timed out/i);
    } finally {
      vi.useRealTimers();
    }
  });
});

describe("desktop useRuntime session state", () => {
  it("applies a well-formed session state including the measured round-trip", async () => {
    const emit = captureState();
    stubInvoke(shellSettings());
    const { result } = renderHook(() => useRuntime(appendLog));
    await waitFor(() => expect(result.current.settingsLoaded).toBe(true));

    emit({
      status: "connected",
      detail: "Session active",
      pid: 4242,
      endpoint: "104.16.0.1:443",
      handshakeRttMs: 17,
    });

    expect(result.current.runtime.status).toBe("connected");
    expect(result.current.runtime.handshakeRttMs).toBe(17);
    expect(result.current.connected).toBe(true);
  });

  it("rejects a payload whose status the UI cannot render, and says so", async () => {
    const emit = captureState();
    stubInvoke(shellSettings());
    const { result } = renderHook(() => useRuntime(appendLog));
    await waitFor(() => expect(result.current.settingsLoaded).toBe(true));

    // `heroCopy["reconnecting"]` is undefined and the next property access throws,
    // taking the whole window down. The listener used to write the raw payload.
    emit({ status: "reconnecting", detail: "x", pid: null, endpoint: null });

    expect(result.current.runtime.status).toBe("disconnected");
    const messages = appendLog.mock.calls.map((c) => c[0].message).join("\n");
    expect(messages).toMatch(/reconnecting/);
    expect(appendLog.mock.calls.map((c) => c[0].level)).toContain("error");

    // A second copy of the same malformed frame does not shout again.
    const before = appendLog.mock.calls.length;
    emit({ status: "reconnecting", detail: "x", pid: null, endpoint: null });
    expect(appendLog.mock.calls.length).toBe(before);

    // ...and a valid frame still lands.
    emit({ status: "connected", detail: "ok", pid: 1, endpoint: null, handshakeRttMs: null });
    expect(result.current.runtime.status).toBe("connected");
  });

  it("keeps the last understood state when the frame is not an object at all", async () => {
    const emit = captureState();
    stubInvoke(shellSettings());
    const { result } = renderHook(() => useRuntime(appendLog));
    await waitFor(() => expect(result.current.settingsLoaded).toBe(true));

    emit({ status: "connecting", detail: "Handshaking", pid: 3, endpoint: null });
    expect(result.current.runtime.detail).toBe("Handshaking");

    emit("nope");
    emit(null);
    expect(result.current.runtime.detail).toBe("Handshaking");
  });

  it("releases the Settings lock as soon as the session reaches a terminal state", async () => {
    stubInvoke(shellSettings({ routingMode: "proxy-only" }));

    const { result } = renderHook(() => useRuntime(appendLog));
    await waitFor(() => expect(result.current.settingsLoaded).toBe(true));
    expect(result.current.settingsLocked).toBe(false);

    act(() => {
      result.current.setRuntime({
        status: "connecting",
        detail: "x",
        pid: 1,
        endpoint: null,
        handshakeRttMs: null,
      });
    });
    expect(result.current.settingsLocked).toBe(true);

    act(() => {
      result.current.setRuntime({
        status: "error",
        detail: "Connection timed out",
        pid: null,
        endpoint: null,
        handshakeRttMs: null,
      });
    });
    expect(result.current.settingsLocked).toBe(false);
  });
});

describe("desktop useRuntime save state", () => {
  it("keeps the reason a save was rejected, not only a log line", async () => {
    vi.mocked(invoke).mockImplementation(async (cmd: string) => {
      if (cmd === "get_settings") return shellSettings({ routingMode: "proxy-only" });
      if (cmd === "save_settings") {
        throw {
          code: "validation",
          message: "custom obfuscation: max size must be <= 2048 (got 4000)",
          field: "noizeJmax",
        };
      }
      return null;
    });

    const { result } = renderHook(() => useRuntime(appendLog));
    await waitFor(() => expect(result.current.settingsLoaded).toBe(true));

    // Out-of-range ports never reach the shell — the form skips those saves — so
    // this is a value the client accepts and only the shell can refuse.
    act(() => {
      result.current.patchSettings({ noize: "custom", noizeJmax: 4000 });
    });
    expect(result.current.dirty).toBe(true);

    await waitFor(() => expect(result.current.saveError).not.toBeNull());
    expect(result.current.saveError?.code).toBe("validation");
    expect(result.current.saveError?.field).toBe("noizeJmax");
    expect(result.current.saved).toBe(false);
    // The rejected value is still pending on disk, so the form must not go idle.
    expect(result.current.dirty).toBe(true);

    // Editing again is not a new complaint about the old value.
    act(() => {
      result.current.patchSettings({ noizeJmax: 128 });
    });
    expect(result.current.saveError).toBeNull();
  });

  it("is idle before the first edit and settled once the shell accepts one", async () => {
    // The defect: `!saved` was the whole idle test, so the Settings dock pulsed
    // "Auto-Saving / Synchronizing changes…" from first paint with nothing pending.
    vi.mocked(invoke).mockImplementation(async (cmd: string) => {
      if (cmd === "get_settings") return shellSettings();
      return null;
    });

    const { result } = renderHook(() => useRuntime(appendLog));
    await waitFor(() => expect(result.current.settingsLoaded).toBe(true));
    expect(result.current.dirty).toBe(false);
    expect(result.current.saved).toBe(false);

    act(() => {
      result.current.patchSettings({ noize: "light" });
    });
    expect(result.current.dirty).toBe(true);

    await waitFor(() => expect(result.current.saved).toBe(true));
    expect(result.current.dirty).toBe(false);
  });
});

describe("desktop useRuntime update check", () => {
  it("does not contact the release host before a tunnel exists", async () => {
    const fetchMock = vi.fn().mockReturnValue(new Promise(() => {}));
    vi.stubGlobal("fetch", fetchMock);
    stubInvoke(shellSettings());

    const { result } = renderHook(() => useRuntime(appendLog));
    await waitFor(() => expect(result.current.settingsLoaded).toBe(true));
    expect(result.current.connected).toBe(false);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("checks once the session is up, and aborts a check that outlives the view", async () => {
    const fetchMock = vi.fn().mockReturnValue(new Promise(() => {}));
    vi.stubGlobal("fetch", fetchMock);
    const emit = captureState();
    stubInvoke(shellSettings());

    const { result } = renderHook(() => useRuntime(appendLog));
    await waitFor(() => expect(result.current.settingsLoaded).toBe(true));

    emit({ status: "connected", detail: "ok", pid: 1, endpoint: null, handshakeRttMs: null });
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1));

    const call = fetchMock.mock.calls[0];
    if (!call) throw new Error("the release host was never contacted");
    const url = String(call[0]);
    expect(url).toContain("api.github.com");
    const init = call[1] as RequestInit | undefined;
    expect(init?.signal).toBeInstanceOf(AbortSignal);
    expect(init?.signal?.aborted).toBe(false);

    cleanup();
    expect(init?.signal?.aborted).toBe(true);
  });
});
