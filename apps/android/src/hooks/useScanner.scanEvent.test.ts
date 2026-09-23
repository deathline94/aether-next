// @vitest-environment jsdom
/*
 * ITEM 9's unfinished clause, at the seam it was unfinished at.
 *
 * The subscription was `listen<ScanEvent>(...)` and wrote `event.payload` into state
 * unchecked, so a malformed frame did not fail — it *became* state: a `working` that
 * never arrived left the "N healthy" chip reading `undefined`, and a `rttMs` that
 * arrived as text made the hit list's sort comparator return `NaN`, which is an
 * unsorted list that looks exactly like a sorted one.
 *
 * Every case below drives the real hook and reads the state it exposes. The positive
 * control is first, because a test of a guard that never let anything through would
 * pass on a parser that refuses everything.
 *
 * The frames carry no `runId` except where one is being tested: `useScanner` drops an
 * event from a run it did not start, and a test that invented an id would be dropped
 * by that rule rather than reaching the guard under test.
 */
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
import { SCAN_MAX_CONCURRENCY } from "../types";
import type { LogInput, ScanState } from "../types";

/** Hand a frame to the hook exactly as the WebView does — raw, unvalidated. */
function emit(payload: unknown) {
  const handler = mocks.handlers.get("scan://event");
  if (!handler) throw new Error("the hook never registered a scan listener");
  act(() => handler({ payload }));
}

let logs: LogInput[] = [];
const appendLog = (entry: LogInput) => {
  logs.push(entry);
};

const errors = () => logs.filter((l) => l.level === "error").map((l) => l.message);

beforeEach(() => {
  vi.clearAllMocks();
  mocks.handlers.clear();
  logs = [];
});

describe("a scan event the interface can read still drives the panel", () => {
  it("applies start, progress and hit frames", () => {
    const { result } = renderHook(() => useScanner(appendLog, false, undefined));

    emit({ type: "scan_start", mode: "balanced", total: 400, concurrency: 128 });
    expect(result.current.scanState).toMatchObject({
      active: true,
      mode: "balanced",
      total: 400,
      concurrency: 128,
      scanned: 0,
      working: 0,
    });

    emit({ type: "scan_progress", scanned: 48, total: 400, working: 3 });
    expect(result.current.scanState).toMatchObject({ scanned: 48, working: 3 });

    emit({
      type: "scan_hit",
      addr: "162.159.193.1:443",
      rtt: "18ms",
      rttMs: 18,
      protocol: "MASQUE H3",
    });
    expect(result.current.endpoints).toEqual([
      { addr: "162.159.193.1:443", rtt: "18ms", rttMs: 18, protocol: "MASQUE H3" },
    ]);
    expect(result.current.scanState.bestRtt).toBe("18ms");
    expect(errors()).toEqual([]);
  });
});

describe("a scan event the interface cannot read is reported, not applied", () => {
  /** A run part-way through, with one hit on the board. */
  function runningScan() {
    const view = renderHook(() => useScanner(appendLog, false, undefined));
    emit({ type: "scan_start", mode: "balanced", total: 400, concurrency: 128 });
    emit({ type: "scan_progress", scanned: 48, total: 400, working: 3 });
    emit({
      type: "scan_hit",
      addr: "162.159.193.1:443",
      rtt: "18ms",
      rttMs: 18,
      protocol: "MASQUE H3",
    });
    return view;
  }

  const stillWhereItWas = (state: ScanState) => {
    expect(state).toMatchObject({ active: true, scanned: 48, total: 400, working: 3 });
  };

  it("says so when a field is missing, and leaves the run exactly as it was", () => {
    const { result } = runningScan();
    const before = result.current.scanState;

    // The tally has to arrive with the frame: a `scan_progress` that never names
    // `working` is not "0 working", it is a frame this build cannot read, and writing
    // `undefined` over the count is what made the chip go blank mid-run.
    emit({ type: "scan_progress", scanned: 96, total: 400 });

    expect(result.current.scanState).toBe(before);
    stillWhereItWas(result.current.scanState);
    expect(result.current.endpoints).toHaveLength(1);
    expect(errors()).toEqual([expect.stringContaining("cannot read")]);
    expect(errors()[0]).toContain("working");
  });

  it("keeps the hit list sorted when a measurement arrives as text", () => {
    const { result } = runningScan();

    // The cast accepted this and the comparator went `NaN`: the row was appended, the
    // "best" chip kept the first hit's text, and nothing said a word.
    emit({
      type: "scan_hit",
      addr: "162.159.193.9:443",
      rtt: "4ms",
      rttMs: "4",
      protocol: "MASQUE H3",
    });

    expect(result.current.endpoints).toHaveLength(1);
    expect(result.current.endpoints[0]?.addr).toBe("162.159.193.1:443");
    expect(result.current.scanState.bestRtt).toBe("18ms");
    expect(errors()).toEqual([expect.stringContaining("rttMs")]);
  });

  it("refuses a lane count the scanner cannot be running rather than showing it", () => {
    const { result } = renderHook(() => useScanner(appendLog, false, undefined));

    emit({
      type: "scan_start",
      mode: "balanced",
      total: 400,
      concurrency: SCAN_MAX_CONCURRENCY + 1,
    });

    // No state at all: the progress card must not print a width no shell will put on
    // the wire, which is the same rule the lane control already holds on screen.
    expect(result.current.scanState.active).toBe(false);
    expect(result.current.scanState.concurrency).toBe(0);
    expect(errors()).toEqual([expect.stringContaining("concurrency")]);
  });

  it("keeps a live run live when a terminal frame cannot be read", () => {
    const { result } = runningScan();

    emit({ type: "scan_done", addr: "162.159.193.1:443", rtt: 18, protocol: "MASQUE H3" });

    // "Unreadable" is not "finished": deactivating on a frame the guard refused would
    // let garbage stop a scan the engine is still running.
    expect(result.current.scanState.active).toBe(true);
    expect(result.current.scanState.phase).toBe("Probing Pool");
    stillWhereItWas(result.current.scanState);
  });

  it("complaints once per distinct shape, not once per frame", () => {
    const { result } = runningScan();

    emit({ type: "scan_progress", scanned: 96, total: 400 });
    emit({ type: "scan_progress", scanned: 144, total: 400 });

    expect(errors()).toHaveLength(1);
    expect(result.current.scanState.scanned).toBe(48);
  });

  it("recovers: the next frame it can read is applied as if the last had never arrived", () => {
    const { result } = runningScan();

    emit({ type: "engine_heartbeat", seq: 4 });
    expect(errors()).toEqual([expect.stringContaining("type")]);

    emit({ type: "scan_progress", scanned: 400, total: 400, working: 4 });
    expect(result.current.scanState).toMatchObject({ active: true, scanned: 400, working: 4 });
    expect(errors()).toHaveLength(1);
  });

  /*
   * The guard reads fields and rebuilds the frame, so it owns the run scope as well:
   * dropping `runId` on the way through would let a cancelled run's terminal event end
   * the live one, which is the defect `runIdRef` exists for.
   */
  it("keeps the run id it read, so another run's event is still dropped", async () => {
    vi.stubGlobal("crypto", { randomUUID: () => "run-under-test" });
    const { result } = renderHook(() => useScanner(appendLog, false, undefined));
    await act(async () => {
      await result.current.startScan();
    });
    expect(result.current.scanState).toMatchObject({ active: true, phase: "Starting" });

    // A frame from the run this window did not start: silence, and no change.
    emit({ runId: "some-other-run", type: "scan_progress", scanned: 400, total: 400, working: 9 });
    expect(result.current.scanState.scanned).toBe(0);
    expect(errors()).toEqual([]);

    // The same frame for this run, applied — and its id is still on the parsed event.
    emit({ runId: "run-under-test", type: "scan_progress", scanned: 400, total: 400, working: 9 });
    expect(result.current.scanState).toMatchObject({ scanned: 400, working: 9 });

    vi.unstubAllGlobals();
  });
});
