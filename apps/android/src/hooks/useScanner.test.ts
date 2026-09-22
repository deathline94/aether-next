// @vitest-environment jsdom
import { act, renderHook } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => {
  const handlers = new Map<string, (e: { payload: unknown }) => void>();
  const listen = vi.fn(async (event: string, handler: (e: { payload: unknown }) => void) => {
    handlers.set(event, handler);
    return () => {
      handlers.delete(event);
    };
  });
  const invoke = vi.fn(async () => null);
  return { handlers, listen, invoke };
});

vi.mock("../bridge", () => ({ listen: mocks.listen, invoke: mocks.invoke }));

import { useScanner } from "./useScanner";
import type { ScanEvent } from "../types";

/** Fire one `scan://event` the way the native bridge forwards it. */
function emit(payload: ScanEvent) {
  const handler = mocks.handlers.get("scan://event");
  if (!handler) throw new Error("the hook never registered a scan listener");
  act(() => handler({ payload }));
}

const appendLog = vi.fn();

beforeEach(() => {
  vi.clearAllMocks();
  mocks.handlers.clear();
});

describe("android scanner verdict", () => {
  it("calls a scan that found nothing what it was", () => {
    // The fork set `phase: "Verified"` on every `scan_done`, so an empty result
    // read as a verified route — the phone's headline lie about discovery.
    const { result } = renderHook(() => useScanner(appendLog, false, undefined));
    emit({ type: "scan_start", mode: "balanced", total: 400, concurrency: 128 });
    emit({ type: "scan_done", addr: "", rtt: "", protocol: "" });
    expect(result.current.scanState.phase).toBe("Completed (0 found)");
    expect(result.current.scanState.active).toBe(false);
  });

  it("keeps a run that found hits verified even when the lagging counter says zero", () => {
    // `working` only republishes every fifty probes, so the last batch of hits can
    // be missing from it; the list the user can see is the authority.
    const { result } = renderHook(() => useScanner(appendLog, false, undefined));
    emit({ type: "scan_start", mode: "balanced", total: 400, concurrency: 128 });
    emit({ type: "scan_hit", addr: "162.159.193.1:443", rtt: "18 ms", rttMs: 18, protocol: "masque-h3" });
    emit({ type: "scan_done", addr: "162.159.193.1:443", rtt: "18 ms", protocol: "masque-h3" });
    expect(result.current.scanState.phase).toBe("Verified");
    expect(result.current.endpoints).toHaveLength(1);
  });

  it("says so when the event listener never installed", async () => {
    // `listen` used to have no `.catch()`: the rejection was unhandled and the
    // panel kept offering a scan whose events could not arrive.
    mocks.listen.mockRejectedValueOnce(new Error("bridge unavailable"));
    renderHook(() => useScanner(appendLog, false, undefined));
    await vi.waitFor(() => {
      expect(appendLog).toHaveBeenCalledWith(
        expect.objectContaining({ level: "error", message: expect.stringContaining("failed to start") }),
      );
    });
    expect(mocks.listen).toHaveBeenCalledTimes(1);
  });

  it("clears the log with the callback it was last given", async () => {
    // `clearLogs` was missing from the `startScan` dependency array, so the
    // callback kept the log-clearing function from the render that first created
    // it — a stale closure over a list the UI had already replaced.
    const stale = vi.fn();
    const current = vi.fn();
    const { rerender, result } = renderHook(
      ({ clear }: { clear: () => void }) => useScanner(appendLog, false, clear),
      { initialProps: { clear: stale } },
    );
    rerender({ clear: current });
    await act(async () => {
      await result.current.startScan();
    });
    expect(current).toHaveBeenCalled();
    expect(stale).not.toHaveBeenCalled();
  });
});
