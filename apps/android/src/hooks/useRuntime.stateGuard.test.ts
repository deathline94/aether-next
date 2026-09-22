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
  const invoke = vi.fn(async (cmd: string) => {
    if (cmd === "get_state") return { status: "connected", detail: "Up", pid: 7, endpoint: "1.1.1.1:443" };
    return null;
  });
  return { handlers, listen, invoke };
});

vi.mock("../bridge", () => ({ listen: mocks.listen, invoke: mocks.invoke }));

import { useRuntime } from "./useRuntime";

function emit(payload: unknown) {
  const handler = mocks.handlers.get("session://state");
  if (!handler) throw new Error("the hook never registered a state listener");
  act(() => handler({ payload }));
}

const appendLog = vi.fn();

beforeEach(() => {
  vi.clearAllMocks();
  mocks.handlers.clear();
});

describe("android session state guard", () => {
  it("keeps the last state it understood when a frame arrives the UI cannot render", async () => {
    // The listener used to be `setRuntime(event.payload)`, so any frame whose
    // `status` is not one of the four the interface knows reached
    // `heroCopy[status]` as `undefined` and threw during a background event —
    // a blank WebView with no way back but a restart.
    const { result } = renderHook(() => useRuntime(appendLog));
    await waitFor(() => expect(result.current.runtime.status).toBe("connected"));

    emit({ status: "degraded", detail: "?", pid: null, endpoint: null });

    expect(result.current.runtime.status).toBe("connected");
    await waitFor(() => {
      expect(appendLog).toHaveBeenCalledWith(
        expect.objectContaining({ level: "error", message: expect.stringContaining("cannot render") }),
      );
    });
  });

  it("reports one refusal per distinct shape, not one per frame", async () => {
    const { result } = renderHook(() => useRuntime(appendLog));
    await waitFor(() => expect(result.current.runtime.status).toBe("connected"));
    appendLog.mockClear();

    for (let i = 0; i < 5; i += 1) emit({ status: 42 });
    const refusals = appendLog.mock.calls.filter(
      ([entry]) => typeof entry.message === "string" && entry.message.includes("cannot render"),
    );
    expect(refusals).toHaveLength(1);
    expect(result.current.runtime.status).toBe("connected");
  });

  it("accepts a well-formed frame and drops the fields it cannot verify", async () => {
    const { result } = renderHook(() => useRuntime(appendLog));
    await waitFor(() => expect(result.current.runtime.status).toBe("connected"));

    emit({ status: "error", detail: 12, pid: "8", endpoint: undefined });

    expect(result.current.runtime).toEqual({
      status: "error",
      detail: "",
      pid: null,
      endpoint: null,
    });
  });
});
