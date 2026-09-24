// @vitest-environment jsdom
import { act, renderHook, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

/*
 * ITEM 9's remaining clause, on the one payload this app still wrote into state
 * unchecked: `test_connection`. The bridge unwraps the native `{ok,data,error}`
 * envelope and hands back `data as T`, and `as T` is not a check — so a shell that
 * answered `{detail: null, latencyMs: "42"}` put a `null` sentence and a string
 * measurement on screen, and the tile rendered them. The recoverable answer to an
 * unreadable check is the one the rejection path already gives: a failed check, with
 * nothing measured.
 */
const mocks = vi.hoisted(() => {
  const state = { outcome: null as unknown };
  const invoke = vi.fn(async (cmd: string) => {
    if (cmd === "test_connection") return state.outcome;
    if (cmd === "get_state") return { status: "disconnected", detail: "Ready", pid: null, endpoint: null };
    if (cmd === "app_info") return { version: "1.3.0" };
    return null;
  });
  return { invoke, state };
});

vi.mock("../bridge", () => ({
  invoke: mocks.invoke,
  listen: vi.fn(async () => () => {}),
}));

import { useRuntime } from "./useRuntime";

const appendLog = vi.fn();

async function ready(result: { current: { appVersion: string; settingsLoaded: boolean } }) {
  await waitFor(() => expect(result.current.appVersion).toBe("1.3.0"), { timeout: 5000 });
}

beforeEach(() => {
  vi.clearAllMocks();
  mocks.state.outcome = null;
});

describe("the connectivity check's answer", () => {
  it("keeps a measured number as the measurement it is", async () => {
    mocks.state.outcome = { detail: "OK via http://127.0.0.1:1820 - ip=1.2.3.4 loc=XX", latencyMs: 37.6 };
    const { result } = renderHook(() => useRuntime(appendLog));
    await ready(result);

    await act(async () => {
      await result.current.runTest();
    });
    expect(result.current.testResult).toEqual({
      detail: "OK via http://127.0.0.1:1820 - ip=1.2.3.4 loc=XX",
      latencyMs: 38,
    });
  });

  it("refuses an answer whose sentence is not a sentence, and says so as a failed check", async () => {
    mocks.state.outcome = { detail: null, latencyMs: 42 };
    const { result } = renderHook(() => useRuntime(appendLog));
    await ready(result);

    await act(async () => {
      await result.current.runTest();
    });

    // What entered state before this guard was the payload itself: a `null` sentence
    // the tile printed, beside a number it was allowed to keep.
    expect(typeof result.current.testResult?.detail).toBe("string");
    expect(result.current.testResult?.detail).toContain("cannot read");
    expect(result.current.testResult?.latencyMs).toBeNull();
    expect(appendLog).toHaveBeenCalledWith(expect.objectContaining({ level: "error" }));
  });

  it("refuses an answer whose measurement is prose", async () => {
    // A latency that arrived as `"12ms"` is exactly the shape the old code scraped
    // numbers out of sentences to invent; it is not a number this tile may print.
    mocks.state.outcome = { detail: "OK", latencyMs: "12" };
    const { result } = renderHook(() => useRuntime(appendLog));
    await ready(result);

    await act(async () => {
      await result.current.runTest();
    });
    expect(result.current.testResult?.latencyMs).toBeNull();
    expect(result.current.testResult?.detail).toContain("cannot read");
  });
});
