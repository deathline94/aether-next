// @vitest-environment jsdom
import { act, renderHook, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

/*
 * Reviewer ITEM 10, the frontend half.
 *
 * `SettingsStore.load()` distinguishes three reads now — MISSING, Healthy, CORRUPT —
 * and for CORRUPT it hands the shell `Settings()`, i.e. a perfectly valid payload of
 * defaults, while publishing the diagnosis on the *state* frame as `settingsError`.
 * So the two facts "the profile on screen is not the user's" and "their bytes are
 * still on the device, unwritten" arrive on two different payloads, and the frontend
 * half of the fix is to put them back together: report it, refuse to call it
 * "settings loaded", and offer the one action that clears it.
 *
 * The shapes below are copied from the Kotlin, not invented:
 * `SettingsStore.kt:103-109` (the frame) and `SettingsStore.kt:372-379` (the report).
 */

const NATIVE_CORRUPTION = {
  state: "corrupt",
  reason: "the stored settings are not readable: Expected a value at protocol: but got String",
  field: "protocol",
  detectedAt: 1761234567890,
  action: "reset",
};

function nativeFrame(overrides: Record<string, unknown> = {}) {
  return {
    status: "disconnected",
    detail: "Ready",
    pid: null,
    endpoint: null,
    settingsError: NATIVE_CORRUPTION,
    ...overrides,
  };
}

const mocks = vi.hoisted(() => {
  const handlers = new Map<string, (e: { payload: unknown }) => void>();
  const listen = vi.fn(async (event: string, handler: (e: { payload: unknown }) => void) => {
    handlers.set(event, handler);
    return () => {
      handlers.delete(event);
    };
  });
  const state = { frame: null as unknown, settings: null as unknown, resetError: null as unknown };
  const calls: string[] = [];
  const invoke = vi.fn(async (cmd: string) => {
    calls.push(cmd);
    if (cmd === "get_settings") return state.settings;
    if (cmd === "get_state") return state.frame;
    if (cmd === "is_admin") return true;
    if (cmd === "app_info") return { version: "1.3.0" };
    if (cmd === "reset_settings") {
      if (state.resetError) throw state.resetError;
      return null;
    }
    return null;
  });
  return { handlers, listen, invoke, calls, state };
});

vi.mock("../bridge", () => ({ listen: mocks.listen, invoke: mocks.invoke }));

import { useRuntime } from "./useRuntime";
import { defaults } from "../types";
import { IpcRejection } from "../ipcError";

const appendLog = vi.fn();

function emit(payload: unknown) {
  const handler = mocks.handlers.get("session://state");
  if (!handler) throw new Error("the hook never registered a state listener");
  act(() => handler({ payload }));
}

/** Hydration has finished when the version read out of `app_info` is on screen. */
async function hydrated(result: { current: { appVersion: string } }) {
  await waitFor(() => expect(result.current.appVersion).toBe("1.3.0"), { timeout: 5000 });
}

beforeEach(() => {
  vi.clearAllMocks();
  mocks.handlers.clear();
  mocks.calls.length = 0;
  // The exact pair the corrupt device produces: valid defaults from `get_settings`,
  // and the diagnosis on the state frame.
  mocks.state.settings = { ...defaults };
  mocks.state.frame = nativeFrame();
  mocks.state.resetError = null;
});

describe("corrupt Android settings are reported, not presented as loaded", () => {
  it("does not call a corrupt profile 'settings loaded' when get_settings hands back valid defaults", async () => {
    const { result } = renderHook(() => useRuntime(appendLog));
    await hydrated(result);

    // The trap: `SettingsStore.load()` returns `Settings()` for a corrupt blob, so
    // `get_settings` parses cleanly. Before this fix that was the whole story, and
    // the panel said "All parameters synchronized" over a profile the user never wrote.
    expect(result.current.settingsLoaded).toBe(false);
    expect(result.current.settingsLoadError).toBe(true);
    expect(result.current.settingsCorrupt).toBe(true);
  });

  it("carries the shell's own diagnosis through to the surface, verbatim", async () => {
    const { result } = renderHook(() => useRuntime(appendLog));
    await hydrated(result);

    expect(result.current.settingsCorruption).toEqual(NATIVE_CORRUPTION);
    // Preserved-and-not-overwritten is the part the user can act on, and the reset
    // affordance has to be named because every other path is refused on the device.
    expect(result.current.settingsCorruptionNotice).toContain(NATIVE_CORRUPTION.reason);
    expect(result.current.settingsCorruptionNotice).toContain("protocol");
    // The shell's own stamp on the refused read, printed rather than dropped.
    expect(result.current.settingsCorruptionNotice).toContain(
      new Date(NATIVE_CORRUPTION.detectedAt).toLocaleString(),
    );
    expect(result.current.settingsCorruptionNotice?.toLowerCase()).toContain("not overwritten");
    expect(result.current.settingsCorruptionNotice?.toLowerCase()).toContain("reset");
  });

  it("revokes 'settings loaded' when the report arrives on an event frame after hydration", async () => {
    mocks.state.frame = nativeFrame({ settingsError: null });
    const { result } = renderHook(() => useRuntime(appendLog));
    await hydrated(result);
    expect(result.current.settingsLoaded).toBe(true);
    expect(result.current.settingsCorrupt).toBe(false);

    // A later load — the shell re-reads the store on `getSettings()` — can be the
    // first frame that says the blob is unreadable. It must not be a no-op.
    emit(nativeFrame());

    expect(result.current.settingsLoaded).toBe(false);
    expect(result.current.settingsLoadError).toBe(true);
    expect(result.current.settingsCorrupt).toBe(true);
  });

  it("keeps the last state it understood and says the report was unreadable, rather than dropping it", async () => {
    // ITEM 9's clause: invalid native data is a recoverable load error, never silent.
    // `{state:"corrupt"}` with no `reason`/`action` is a settings report this build
    // cannot honour; treating it as "no error" is the drop that caused ITEM 10.
    mocks.state.frame = nativeFrame({ settingsError: { state: "corrupt" } });
    const { result } = renderHook(() => useRuntime(appendLog));
    await hydrated(result);

    expect(result.current.settingsLoaded).toBe(false);
    expect(result.current.settingsLoadError).toBe(true);
    expect(result.current.settingsCorrupt).toBe(true);
    expect(result.current.settingsCorruption).toBeNull();
    expect(result.current.settingsCorruptionNotice).toContain("cannot read");
    // The tunnel frame beside it is still valid, and is still shown.
    expect(result.current.runtime.status).toBe("disconnected");
  });

  it("reads an absent or null settingsError as no error at all", async () => {
    // An older shell sends neither key nor `settingsError: null`
    // (`RuntimeState.toJson` puts `JSONObject.NULL`); the settings screen must not
    // start crying wolf.
    mocks.state.frame = nativeFrame({ settingsError: null });
    const { result } = renderHook(() => useRuntime(appendLog));
    await hydrated(result);

    expect(result.current.settingsCorrupt).toBe(false);
    expect(result.current.settingsCorruption).toBeNull();
    expect(result.current.settingsCorruptionNotice).toBeNull();
    expect(result.current.settingsLoaded).toBe(true);
    expect(result.current.settingsLoadError).toBe(false);
  });

  it("keeps refusing to save while the report stands, so a retry cannot unlock the form", async () => {
    const { result } = renderHook(() => useRuntime(appendLog));
    await hydrated(result);

    await act(async () => {
      await result.current.retrySettings();
    });

    // `get_settings` still answers with defaults, so a bare "Retry" that only
    // re-reads settings would clear the banner and unlock an editable form whose
    // every write the shell refuses.
    expect(result.current.settingsLoaded).toBe(false);
    expect(result.current.settingsLocked).toBe(true);
    expect(result.current.settingsCorrupt).toBe(true);
  });
});

describe("the reset action", () => {
  it("dispatches reset_settings and, on success, re-reads and unlocks", async () => {
    const { result } = renderHook(() => useRuntime(appendLog));
    await hydrated(result);
    mocks.calls.length = 0;

    await act(async () => {
      await result.current.resetSettings();
    });

    expect(mocks.calls.filter((c) => c === "reset_settings")).toHaveLength(1);
    // The defaults the shell just wrote are the profile now, and it is honest to
    // say so: the report is gone, the form is readable and unlocked again.
    expect(mocks.calls.filter((c) => c === "get_settings").length).toBeGreaterThan(0);
    expect(result.current.settingsCorrupt).toBe(false);
    expect(result.current.settingsCorruption).toBeNull();
    expect(result.current.settingsLoaded).toBe(true);
    expect(result.current.settingsLoadError).toBe(false);
    expect(result.current.resetSettingsError).toBeNull();
    // Said out loud, not only in the banner: the bytes the user did not lose are the
    // fact they will want to check from the Activity tab afterwards.
    expect(appendLog).toHaveBeenCalledWith(
      expect.objectContaining({
        level: "info",
        message: expect.stringContaining("Settings reset"),
      }),
    );
  });

  it("leaves the report standing and surfaces the refusal when the shell rejects the reset", async () => {
    mocks.state.resetError = new IpcRejection({
      code: "unknown_command",
      message: "unknown command reset_settings",
    });
    const { result } = renderHook(() => useRuntime(appendLog));
    await hydrated(result);

    await act(async () => {
      await result.current.resetSettings();
    });

    expect(result.current.settingsCorrupt).toBe(true);
    expect(result.current.settingsLoaded).toBe(false);
    expect(result.current.resetSettingsError?.message).toContain("reset_settings");
    expect(mocks.calls.filter((c) => c === "get_settings")).toHaveLength(1);
  });
});
