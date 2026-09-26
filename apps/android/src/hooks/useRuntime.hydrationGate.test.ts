// @vitest-environment jsdom
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
  const state = {
    settings: undefined as unknown,
    // Holds `get_settings` open until a test releases it, so hydration can be
    // observed mid-flight rather than only before/after.
    settingsGate: null as null | ((payload: unknown) => void),
  };
  const invoke = vi.fn(async (cmd: string) => {
    if (cmd === "get_settings") {
      if (state.settingsGate) {
        const payload = await new Promise((resolve) => state.settingsGate(resolve));
        state.settingsGate = null;
        return payload;
      }
      return state.settings;
    }
    if (cmd === "get_state") return { status: "disconnected", detail: "", pid: null, endpoint: null };
    if (cmd === "is_admin") return false;
    if (cmd === "app_info") return { version: "1.3.0" };
    return null;
  });
  return { handlers, listen, invoke, state };
});

vi.mock("../bridge", () => ({ listen: mocks.listen, invoke: mocks.invoke }));

import { useRuntime } from "./useRuntime";
import { defaults } from "../types";

const appendLog = vi.fn();

beforeEach(() => {
  vi.clearAllMocks();
  mocks.handlers.clear();
  mocks.state.settings = { ...defaults };
  mocks.state.settingsGate = null;
});

describe("the connect arm waits for settings hydration", () => {
  it("refuses to connect while hydration is still in flight, then connects once loaded", async () => {
    // SessionController.connect persists the settings it receives (`store.save`),
    // so a tap during the hydration window used to store factory defaults over
    // the user's saved profile — the same reason the settings rows are locked.
    let release!: (payload: unknown) => void;
    mocks.state.settingsGate = (resolve) => {
      release = resolve;
    };

    const { result } = renderHook(() => useRuntime(appendLog));
    await waitFor(() => expect(mocks.invoke).toHaveBeenCalledWith("get_settings"));
    expect(result.current.settingsLoaded).toBe(false);

    await act(async () => {
      await result.current.toggleConnection();
    });
    expect(mocks.invoke).not.toHaveBeenCalledWith("connect", expect.anything());

    release({ ...defaults });
    await waitFor(() => expect(result.current.settingsLoaded).toBe(true));

    await act(async () => {
      await result.current.toggleConnection();
    });
    expect(mocks.invoke).toHaveBeenCalledWith("connect", expect.anything());
  });

  it("still allows a disconnect when hydration never lands", async () => {
    // A blocked or failed load must not trap a live tunnel: only the connect arm
    // is gated on the load, because only the connect arm would persist defaults.
    mocks.state.settingsGate = () => {}; // never resolves
    mocks.handlers.get("session://state");

    const { result } = renderHook(() => useRuntime(appendLog));
    await waitFor(() => expect(mocks.invoke).toHaveBeenCalledWith("get_state"));

    act(() => {
      const handler = mocks.handlers.get("session://state");
      handler?.({ payload: { status: "connected", detail: "Up", pid: 7, endpoint: "1.1.1.1:443" } });
    });
    await waitFor(() => expect(result.current.running).toBe(true));

    await act(async () => {
      await result.current.toggleConnection();
    });
    expect(mocks.invoke).toHaveBeenCalledWith("disconnect");
  });
});
