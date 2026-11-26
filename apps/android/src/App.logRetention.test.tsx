// @vitest-environment jsdom
import { act, cleanup, render } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

/*
 * The activity log is the only record of why a session failed. The shell reuses
 * "connecting" for supervised recovery, so clearing on every entry into that
 * state destroyed the evidence of the failure being recovered from — the desktop
 * sheet had exactly that bug, and this file pins the rule on the phone: only a
 * start from a clean disconnect, or a clean disconnect, resets the buffer.
 */
const mocks = vi.hoisted(() => {
  const handlers = new Map<string, (e: { payload: unknown }) => void>();
  const invoke = vi.fn(async (cmd: string) => {
    if (cmd === "get_state") return { status: "disconnected", detail: "Idle", pid: null, endpoint: null };
    if (cmd === "get_settings") return { routingMode: "proxy-only" };
    return null;
  });
  const listen = vi.fn(async (event: string, handler: (e: { payload: unknown }) => void) => {
    handlers.set(event, handler);
    return () => {
      handlers.delete(event);
    };
  });
  return { handlers, invoke, listen };
});

vi.mock("./bridge", async (importOriginal) => ({
  ...(await importOriginal<typeof import("./bridge")>()),
  listen: mocks.listen,
  invoke: mocks.invoke,
}));

import App from "./App";

afterEach(() => cleanup());
beforeEach(() => mocks.handlers.clear());

function emitState(status: string): void {
  const emit = mocks.handlers.get("session://state");
  if (!emit) throw new Error("useRuntime never registered a session://state listener");
  act(() => emit({ payload: { status, detail: `${status} detail`, pid: null, endpoint: null } }));
}

function emitLog(message: string): void {
  const emit = mocks.handlers.get("session://log");
  if (!emit) throw new Error("useRuntime never registered a session://log listener");
  act(() => emit({ payload: { level: "error", message } }));
}

/** The badge only exists while the buffer has at least one line. */
function logCount(): number {
  const badge = document.querySelector(".nav-dot-badge");
  return badge ? Number(badge.getAttribute("aria-label")?.split(" ")[0] ?? 0) : 0;
}

describe("activity log retention", () => {
  it("keeps the failure evidence when the shell recovers from it", async () => {
    render(<App />);
    await act(async () => {});

    emitState("error");
    emitLog("probe timeout on 162.159.193.1");
    expect(logCount()).toBeGreaterThan(0);

    // Supervised recovery: error -> connecting is the same session continuing.
    emitState("connecting");
    expect(logCount()).toBeGreaterThan(0);

    // A fresh user-start from idle is the only thing that clears it.
    emitState("disconnected");
    emitState("connecting");
    expect(logCount()).toBe(0);
  });
});
