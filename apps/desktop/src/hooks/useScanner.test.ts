// @vitest-environment jsdom
import { beforeEach, describe, expect, it, vi } from "vitest";
import { act, renderHook, waitFor } from "@testing-library/react";
import { useScanner } from "./useScanner";

vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));
vi.mock("@tauri-apps/api/event", () => ({ listen: vi.fn() }));

import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";

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

describe("desktop useScanner", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(invoke).mockResolvedValue(null);
  });

  it("keeps one address found on two protocols", async () => {
    const emit = captureListener();
    const { result } = renderHook(() => useScanner(appendLog, false));
    await waitFor(() => expect(result.current.scanState !== undefined).toBe(true));

    act(() => {
      emit({ type: "scan_hit", addr: "104.16.0.1:443", rtt: "12ms", rttMs: 12, protocol: "masque-h2" });
      emit({ type: "scan_hit", addr: "104.16.0.1:443", rtt: "19ms", rttMs: 19, protocol: "masque-h3" });
    });

    expect(result.current.endpoints).toHaveLength(2);
    expect(result.current.scanState.working).toBe(2);

    // A true duplicate — same address, same protocol — is still folded.
    act(() => {
      emit({ type: "scan_hit", addr: "104.16.0.1:443", rtt: "12ms", rttMs: 12, protocol: "masque-h2" });
    });
    expect(result.current.endpoints).toHaveLength(2);
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
});
