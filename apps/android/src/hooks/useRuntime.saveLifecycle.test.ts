// @vitest-environment jsdom
/*
 * ITEM 15, at the seam that produced the lie.
 *
 * The dock's whole story was one boolean, and it was wrong at both ends: `false` meant
 * "synchronizing…" from first paint — before any edit, before any write — and it stayed
 * `false` after the shell refused a save, so a value that would never reach disk was
 * reported as being written. `hooks/useRuntime.ts` now owns a four-state lifecycle and
 * `components/SettingsTab.tsx` says nothing the table below it does not permit, so the
 * five moments the reviewer named are checked here in the order a user meets them:
 * first load, edit, successful save, rejected save, locked settings.
 *
 * The writes are deferred by hand rather than by timer so that "a write is in flight"
 * is a fact the test creates and observes, not a window it races.
 */
import { act, renderHook, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => {
  const handlers = new Map<string, (e: { payload: unknown }) => void>();
  const listen = vi.fn(async (event: string, handler: (e: { payload: unknown }) => void) => {
    handlers.set(event, handler);
    return () => {
      handlers.delete(event);
    };
  });
  const calls: string[] = [];
  // The behaviour under `save_settings`, swappable per test. The default is a write
  // that never settles, which is the only way to observe "in flight" without racing it.
  const state = {
    save: null as null | (() => Promise<unknown>),
    settings: null as null | (() => Promise<unknown>),
  };
  const invoke = vi.fn(async (cmd: string) => {
    calls.push(cmd);
    if (cmd === "save_settings") return state.save ? state.save() : new Promise(() => {});
    if (cmd === "get_settings") return state.settings ? state.settings() : null;
    if (cmd === "get_state") return null;
    if (cmd === "is_admin") return false;
    if (cmd === "app_info") return { version: "1.3.0" };
    return null;
  });
  return { handlers, listen, invoke, calls, state };
});

vi.mock("../bridge", () => ({ listen: mocks.listen, invoke: mocks.invoke }));

import { useRuntime } from "./useRuntime";
import { defaults } from "../types";
import { saveDockCopy, saveStateOf } from "../saveState";
import { IpcRejection } from "../ipcError";

const appendLog = vi.fn();

function emit(payload: unknown) {
  const handler = mocks.handlers.get("session://state");
  if (!handler) throw new Error("the hook never registered a state listener");
  act(() => handler({ payload }));
}

const saveCalls = () => mocks.calls.filter((c) => c === "save_settings").length;

/** What the dock would actually print for the lifecycle the hook reports. */
function dockText(saved: Parameters<typeof saveStateOf>[0]): string {
  return saveDockCopy(saveStateOf(saved)).text;
}

beforeEach(() => {
  vi.clearAllMocks();
  mocks.handlers.clear();
  mocks.calls.length = 0;
  let resolveHydration: (v: unknown) => void = () => {};
  const hydration = new Promise((resolve) => {
    resolveHydration = resolve;
  });
  mocks.state.settings = () => hydration.then(() => ({ ...defaults }));
  mocks.state.save = null;
  // Release the stored profile only once the test has asked for it, so hydration is
  // awaited through `hydrated` below and nothing races the first assertion.
  queueMicrotask(() => resolveHydration(undefined));
});

async function hydrated(result: { current: { appVersion: string } }) {
  await waitFor(() => expect(result.current.appVersion).toBe("1.3.0"), { timeout: 5000 });
  await waitFor(() => expect(result.current.settingsLoaded).toBe(true), { timeout: 5000 });
}

describe("first load", () => {
  it("reads idle, not 'synchronizing', the moment the profile is on screen", async () => {
    const { result } = renderHook(() => useRuntime(appendLog));
    await hydrated(result);

    // The defect in one line: `saved === false` used to render "Synchronizing changes…"
    // here, on a form nobody had touched and with no write dispatched.
    expect(result.current.saved).toBe("idle");
    expect(dockText(result.current.saved)).toContain("No changes pending");
    expect(dockText(result.current.saved)).not.toMatch(/synchroniz/i);
    expect(saveCalls()).toBe(0);
    expect(result.current.saveError).toBeNull();
  });

  it("does not call a load a change", async () => {
    const { result } = renderHook(() => useRuntime(appendLog));
    await hydrated(result);
    const loaded = result.current.settings;

    // A second read of the same profile (`retrySettings`) is not an edit.
    await act(async () => {
      await result.current.retrySettings();
    });

    expect(result.current.settings).toEqual(loaded);
    expect(result.current.saved).toBe("idle");
    expect(saveCalls()).toBe(0);
  });
});

describe("an edit, and the write that follows it", () => {
  it("goes dirty on the edit and only then to saving", async () => {
    let settle: (v: unknown) => void = () => {};
    mocks.state.save = () => new Promise((resolve) => {
      settle = resolve;
    });
    const { result } = renderHook(() => useRuntime(appendLog));
    await hydrated(result);

    act(() => {
      result.current.patchSettings({ noize: "light" });
    });

    // Synchronously, before the debounce can fire: the edit is on screen and not on
    // disk, and the dock may not claim a write that has not started.
    expect(result.current.saved).toBe("dirty");
    expect(dockText(result.current.saved)).toContain("not on disk");
    expect(saveCalls()).toBe(0);

    await waitFor(() => expect(result.current.saved).toBe("saving"));
    // Only now is there a write outstanding, and it carries the edited value.
    expect(saveCalls()).toBe(1);

    await act(async () => {
      settle(undefined);
    });
    await waitFor(() => expect(result.current.saved).toBe("saved"));
    expect(dockText(result.current.saved)).toContain("synchronized");

    // The confirmation is a flash, not a permanent claim: the form is back to matching
    // the disk, which is the same thing `idle` said before the edit.
    await waitFor(() => expect(result.current.saved).toBe("idle"), { timeout: 4000 });
    expect(result.current.saveError).toBeNull();
  });

  it("sends one write for a burst of edits, and the newest value", async () => {
    let settle: (v: unknown) => void = () => {};
    mocks.state.save = () => new Promise((resolve) => {
      settle = resolve;
    });
    const { result } = renderHook(() => useRuntime(appendLog));
    await hydrated(result);

    act(() => {
      result.current.patchSettings({ noizeJc: 7 });
      result.current.patchSettings({ noizeJc: 8 });
      result.current.patchSettings({ noizeJc: 9 });
    });
    expect(result.current.saved).toBe("dirty");

    await waitFor(() => expect(result.current.saved).toBe("saving"));
    await act(async () => {
      settle(undefined);
    });
    await waitFor(() => expect(result.current.saved).toBe("saved"));
    expect(saveCalls()).toBe(1);
    const call = mocks.invoke.mock.calls.find(([cmd]) => cmd === "save_settings");
    expect((call?.[1] as { settings: { noizeJc: number } }).settings.noizeJc).toBe(9);
  });
});

describe("a save the shell refuses", () => {
  it("leaves the edit pending and says which value it refused", async () => {
    mocks.state.save = () =>
      Promise.reject(
        new IpcRejection({ code: "validation", field: "httpPort", message: "port is reserved" }),
      );
    const { result } = renderHook(() => useRuntime(appendLog));
    await hydrated(result);

    act(() => {
      result.current.patchSettings({ httpPort: 443 });
    });
    expect(result.current.saved).toBe("dirty");

    await waitFor(() => expect(result.current.saveError).not.toBeNull());
    expect(result.current.saveError?.field).toBe("httpPort");
    // Refused is not saved, and not "still saving" either: the value is on screen and
    // not on disk, which is the state the dock has to name.
    expect(result.current.saved).toBe("dirty");
    expect(dockText(result.current.saved)).toContain("not on disk");
    expect(dockText(result.current.saved)).not.toMatch(/synchronized/);
  });

  it("does not keep complaining once the edit that drew the refusal is replaced", async () => {
    let reject = true;
    mocks.state.save = () =>
      reject
        ? Promise.reject(new IpcRejection({ code: "validation", field: "socksPort", message: "bound" }))
        : Promise.resolve(undefined);
    const { result } = renderHook(() => useRuntime(appendLog));
    await hydrated(result);

    act(() => {
      result.current.patchSettings({ socksPort: 2080 });
    });
    await waitFor(() => expect(result.current.saveError).not.toBeNull());

    reject = false;
    act(() => {
      result.current.patchSettings({ socksPort: 2081 });
    });
    expect(result.current.saveError).toBeNull();
    expect(result.current.saved).toBe("dirty");

    await waitFor(() => expect(result.current.saved).toBe("saved"), { timeout: 3000 });
    expect(result.current.saveError).toBeNull();
  });
});

describe("locked settings", () => {
  it("accepts no edit while the profile is still being read", async () => {
    let release: (v: unknown) => void = () => {};
    mocks.state.settings = () => new Promise((resolve) => {
      release = resolve;
    });
    const { result } = renderHook(() => useRuntime(appendLog));

    await waitFor(() => expect(mocks.calls).toContain("get_settings"));
    expect(result.current.settingsLoaded).toBe(false);
    expect(result.current.settingsLocked).toBe(true);

    // The write that used to happen here persisted `defaults` over the user's real
    // profile; the hook must refuse the edit, not queue it.
    act(() => {
      result.current.patchSettings({ protocol: "wireguard" });
    });
    expect(result.current.settings).toEqual(defaults);
    expect(result.current.saved).toBe("idle");
    expect(saveCalls()).toBe(0);

    release({ ...defaults });
    await hydrated(result);
    expect(saveCalls()).toBe(0);
  });

  it("accepts no edit while a tunnel is up, and keeps saying what the disk holds", async () => {
    let settle: (v: unknown) => void = () => {};
    mocks.state.save = () => new Promise((resolve) => {
      settle = resolve;
    });
    const { result } = renderHook(() => useRuntime(appendLog));
    await hydrated(result);

    act(() => {
      result.current.patchSettings({ transport: "h3" });
    });
    await waitFor(() => expect(result.current.saved).toBe("saving"));
    await act(async () => {
      settle(undefined);
    });
    await waitFor(() => expect(result.current.saved).toBe("saved"));
    const onDisk = result.current.settings;
    expect(onDisk.transport).toBe("h3");

    emit({ status: "connected", detail: "VPN active (full device)", pid: 42, endpoint: "1.1.1.1:443" });
    expect(result.current.running).toBe(true);
    expect(result.current.settingsLocked).toBe(true);

    act(() => {
      result.current.patchSettings({ transport: "h2" });
    });
    // Locked means the form does not move: no half-edit on screen, no queued write,
    // and no lifecycle change pretending otherwise.
    expect(result.current.settings.transport).toBe("h3");
    expect(saveCalls()).toBe(1);
    expect(result.current.saved).toBe("saved");
    expect(dockText(result.current.saved)).toContain("synchronized");
  });
});
