// @vitest-environment jsdom
import { beforeEach, describe, expect, it, vi } from "vitest";
import { act, renderHook, waitFor } from "@testing-library/react";
import { useScanner } from "./useScanner";

vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));
vi.mock("@tauri-apps/api/event", () => ({ listen: vi.fn() }));

import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { initialScanState } from "../types";
import { SCAN_MAX_CONCURRENCY, SCAN_MAX_CONCURRENCY_H3 } from "@aether/ui";
import { scanNoizeFor } from "./useScanner";

type Listener = (event: { payload: unknown }) => void;

/** Capture the `scan://event` subscriber so a test can push engine events. */
function captureListener(): (payload: unknown) => void {
  let cb: Listener | null = null;
  vi.mocked(listen).mockImplementation(((_event: string, handler: Listener) => {
    cb = handler;
    return Promise.resolve(() => {});
  }) as typeof listen);
  return (payload: unknown) => {
    if (!cb) throw new Error("the scanner never subscribed to scan://event");
    cb({ payload });
  };
}

const appendLog = vi.fn();

/** The run id the hook passed to the engine for its most recent `scan` invoke. */
function lastScanArgs(): Record<string, unknown> {
  const call = vi
    .mocked(invoke)
    .mock.calls.filter(([command]) => command === "scan")
    .at(-1);
  if (!call) throw new Error("startScan never invoked `scan`");
  return call[1] as Record<string, unknown>;
}

function lastScanRunId(): string {
  return lastScanArgs().runId as string;
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(invoke).mockResolvedValue(null);
});

describe("desktop useScanner", () => {
  it("keeps one address found on two protocols", async () => {
    const emit = captureListener();
    const { result } = renderHook(() => useScanner(appendLog, false));
    await waitFor(() => expect(result.current.scanState !== undefined).toBe(true));

    act(() => {
      emit({ type: "scan_hit", addr: "104.16.0.1:443", rtt: "12ms", rttMs: 12, protocol: "masque-h2" });
      emit({ type: "scan_hit", addr: "104.16.0.1:443", rtt: "19ms", rttMs: 19, protocol: "masque-h3" });
    });

    expect(result.current.endpoints).toHaveLength(2);

    // A true duplicate — same address, same protocol — is still folded.
    act(() => {
      emit({ type: "scan_hit", addr: "104.16.0.1:443", rtt: "12ms", rttMs: 12, protocol: "masque-h2" });
    });
    expect(result.current.endpoints).toHaveLength(2);
  });

  it("takes the working tally from scan_progress, never from hits", async () => {
    // A hit records that one address answered one protocol; the engine counts how
    // many addresses work. Incrementing the counter per hit made the "N Healthy
    // Gateways" chip oscillate, because the next engine frame overwrote it with a
    // number that was true fifty probes earlier.
    const emit = captureListener();
    const { result } = renderHook(() => useScanner(appendLog, false));
    await waitFor(() => expect(result.current.scanState.working).toBe(0));

    act(() => {
      emit({ type: "scan_hit", addr: "104.16.0.1:443", rtt: "12ms", rttMs: 12, protocol: "masque-h2" });
      emit({ type: "scan_hit", addr: "104.16.0.1:443", rtt: "19ms", rttMs: 19, protocol: "masque-h3" });
    });
    expect(result.current.endpoints).toHaveLength(2);
    expect(result.current.scanState.working).toBe(0);

    act(() => {
      emit({ type: "scan_progress", scanned: 40, total: 100, working: 2 });
    });
    expect(result.current.scanState.working).toBe(2);

    // Neither a later hit nor a later frame may walk the tally backwards.
    act(() => {
      emit({ type: "scan_hit", addr: "188.114.96.1:443", rtt: "7ms", rttMs: 7, protocol: "masque-h3" });
    });
    expect(result.current.scanState.working).toBe(2);
  });

  it("drops events stamped with another run's id", async () => {
    const emit = captureListener();
    const { result } = renderHook(() => useScanner(appendLog, false));
    await waitFor(() => expect(result.current.scanState.active).toBe(false));

    await act(async () => {
      await result.current.startScan();
    });
    const runId = lastScanRunId();
    expect(runId).toBeTruthy();

    act(() => {
      emit({ type: "scan_hit", runId: "a-different-run", addr: "9.9.9.9:443", rtt: "1ms", rttMs: 1, protocol: "masque-h3" });
      emit({ type: "scan_done", runId: "a-different-run", addr: "9.9.9.9:443" });
    });
    expect(result.current.endpoints).toHaveLength(0);
    expect(result.current.scanState.active).toBe(true);

    act(() => {
      emit({ type: "scan_hit", runId, addr: "104.16.0.1:443", rtt: "12ms", rttMs: 12, protocol: "masque-h3" });
    });
    expect(result.current.endpoints).toHaveLength(1);
  });

  it("retires the run id before the next scan can inherit a cancelled run's stragglers", async () => {
    const emit = captureListener();
    const { result } = renderHook(() => useScanner(appendLog, false));
    await waitFor(() => expect(result.current.scanState.active).toBe(false));

    await act(async () => {
      await result.current.startScan();
    });
    const firstRun = lastScanRunId();

    await act(async () => {
      await result.current.stopScan();
    });
    expect(result.current.scanState.active).toBe(false);

    // The engine's last word on a stopped run arrives whenever it likes. It must
    // not be merged into whatever scan starts next.
    act(() => {
      emit({ type: "scan_hit", runId: firstRun, addr: "1.1.1.1:443", rtt: "5ms", rttMs: 5, protocol: "masque-h3" });
    });
    expect(result.current.endpoints).toHaveLength(0);
  });

  it("stamps the new run id before awaiting the teardown of the old one", async () => {
    const emit = captureListener();
    // running=true makes startScan await `disconnect` before it invokes `scan`.
    // That await is the window: the counters have already restarted for run two
    // while the ref still named run one, so run one's late hit used to be merged
    // into a scan that had not started yet.
    const { result } = renderHook(() => useScanner(appendLog, true));
    await waitFor(() => expect(result.current.scanState.active).toBe(false));

    await act(async () => {
      await result.current.startScan();
    });
    const firstRun = lastScanRunId();

    // Run one ends normally, so `startScan` is callable again.
    act(() => {
      emit({ type: "scan_done", runId: firstRun, addr: "104.16.0.1:443" });
    });
    await waitFor(() => expect(result.current.scanState.active).toBe(false));

    let releaseDisconnect: () => void = () => {};
    let disconnectIsPending = false;
    const previous = vi.mocked(invoke).getMockImplementation();
    vi.mocked(invoke).mockImplementation((async (command: string, args?: Record<string, unknown>) => {
      if (command === "disconnect") {
        disconnectIsPending = true;
        await new Promise<void>((resolve) => (releaseDisconnect = resolve));
        disconnectIsPending = false;
        return null;
      }
      return previous ? previous(command, args) : null;
    }) as never);

    let scanReturned = false;
    void result.current.startScan().then(() => (scanReturned = true));
    // Wait for the teardown await itself rather than for a tick count: the window
    // under test is "disconnect is in flight and `scan` has not been invoked yet".
    await waitFor(() => expect(disconnectIsPending).toBe(true));
    expect(scanReturned).toBe(false);

    act(() => {
      emit({ type: "scan_hit", runId: firstRun, addr: "1.1.1.1:443", rtt: "5ms", rttMs: 5, protocol: "masque-h3" });
    });
    expect(result.current.endpoints).toHaveLength(0);

    releaseDisconnect();
    await waitFor(() => expect(scanReturned).toBe(true));
    if (previous) vi.mocked(invoke).mockImplementation(previous);
    expect(lastScanRunId()).not.toBe(firstRun);
  });

  it("starts a scan with an empty result list", async () => {
    const emit = captureListener();
    const { result } = renderHook(() => useScanner(appendLog, false));
    await waitFor(() => expect(result.current.scanState !== undefined).toBe(true));

    act(() => {
      emit({ type: "scan_hit", addr: "1.1.1.1:443", rtt: "5ms", rttMs: 5, protocol: "wireguard" });
    });
    expect(result.current.endpoints).toHaveLength(1);

    await act(async () => {
      await result.current.startScan();
    });

    // Rows from a previous run outlive the counters that describe them, so the
    // table and "N working" disagree until the engine's own scan_start lands.
    expect(result.current.endpoints).toHaveLength(0);
  });

  it("sends the noise profile the panel displays", async () => {
    captureListener();
    const { result } = renderHook(() => useScanner(appendLog, false));

    act(() => result.current.setNoize("custom"));
    expect(result.current.noize).toBe("custom");

    // H2 probes are TCP: UDP junk frames cannot be sent at all. The select read
    // "off" while the scan still forwarded `noize: "custom"`.
    act(() => result.current.setProtocol("masque-h2"));
    expect(result.current.noize).toBe("off");
    await act(async () => {
      await result.current.startScan();
    });
    expect(lastScanArgs().noize).toBe("off");

    // The user's own choice is not erased by the transport that cannot carry it.
    act(() => result.current.setProtocol("masque-h3"));
    expect(result.current.noize).toBe("custom");
  });

  it("never asks the engine for more workers than it will run", async () => {
    captureListener();
    const { result } = renderHook(() => useScanner(appendLog, false));
    await waitFor(() => expect(result.current.scanState.active).toBe(false));

    await act(async () => {
      await result.current.startScan();
    });
    expect(Number(lastScanArgs().concurrency)).toBeLessThanOrEqual(SCAN_MAX_CONCURRENCY);

    act(() => result.current.setConcurrency(SCAN_MAX_CONCURRENCY * 4));
    await act(async () => {
      await result.current.stopScan();
    });
    await act(async () => {
      await result.current.startScan();
    });
    // The ceiling is the protocol's: this hook defaults to an H3 scan, which the
    // engine narrows to 16 lanes because more concurrent BoringSSL handshakes
    // abort the process. Asserting the generic 500 here would have been the test
    // protecting the number the engine never runs.
    expect(Number(lastScanArgs().concurrency)).toBe(SCAN_MAX_CONCURRENCY_H3);
  });

  it("derives the Best chip from the rows, which are its only owner", () => {
    // `ScanState.bestRtt` used to be both stored (and rewritten per hit) and
    // derived, so the chip could sit directly above a faster first row.
    expect("bestRtt" in initialScanState).toBe(false);

    const emit = captureListener();
    const { result } = renderHook(() => useScanner(appendLog, false));

    act(() => {
      emit({ type: "scan_hit", addr: "104.16.0.1:443", rtt: "12ms", rttMs: 12, protocol: "masque-h3" });
      emit({ type: "scan_hit", addr: "188.114.96.1:443", rtt: "240ms", rttMs: 240, protocol: "masque-h3" });
    });

    expect(result.current.scanState.bestRtt).toBe("12ms");
  });
});

describe("scanNoizeFor", () => {
  it("resolves the profile a scan will actually run", () => {
    expect(scanNoizeFor("masque-h2", "custom")).toBe("off");
    expect(scanNoizeFor("masque-h2", "off")).toBe("off");
    expect(scanNoizeFor("masque-h3", "high")).toBe("high");
    expect(scanNoizeFor("wireguard", "medium")).toBe("medium");
  });

  it("falls back to sending nothing rather than to a name the shell rejects", () => {
    expect(scanNoizeFor("masque-h3", "turbo-udp" as never)).toBe("off");
    expect(scanNoizeFor("masque-h3", "" as never)).toBe("off");
  });
});
