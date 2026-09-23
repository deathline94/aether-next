// @vitest-environment jsdom
import { act, cleanup, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

/*
 * The header beacon is the one status string visible from every tab, and it used to
 * read "Protected" for any connected session — including the local-proxy modes, where
 * only apps the user pointed at Aether's own ports are carried at all. That is the
 * same class of claim repair item 8 and item 21 exist to remove, so the beacon now
 * resolves its word from the stored routing mode, exactly as the Connection hero does.
 *
 * These drive the real `App` over the real `useRuntime` with only the bridge mocked:
 * the assertion is about what a user is told while a session is up, which no
 * component-level test of `ConnectionTab` can see.
 */
const mocks = vi.hoisted(() => {
  const handlers = new Map<string, (e: { payload: unknown }) => void>();
  const settings = { routingMode: "proxy-only" };
  const listen = vi.fn(async (event: string, handler: (e: { payload: unknown }) => void) => {
    handlers.set(event, handler);
    return () => {
      handlers.delete(event);
    };
  });
  const invoke = vi.fn(async (cmd: string) => {
    if (cmd === "get_state") return { status: "disconnected", detail: "Idle", pid: null, endpoint: null };
    if (cmd === "get_settings") return { routingMode: settings.routingMode };
    return null;
  });
  return { handlers, settings, listen, invoke };
});

vi.mock("./bridge", async (importOriginal) => ({
  ...(await importOriginal<typeof import("./bridge")>()),
  listen: mocks.listen,
  invoke: mocks.invoke,
}));

import App from "./App";

afterEach(() => cleanup());

beforeEach(() => {
  mocks.handlers.clear();
  mocks.settings.routingMode = "proxy-only";
});

function beacon(): Element {
  const node = document.querySelector(".beacon-status-text");
  if (!node) throw new Error("the header renders no .beacon-status-text");
  return node;
}

/** The frame emitter `useRuntime` registered; a missing listener is a test failure. */
function emitFrame(payload: unknown): void {
  const emit = mocks.handlers.get("session://state");
  if (!emit) throw new Error("useRuntime never registered a session://state listener");
  act(() => emit({ payload }));
}

async function connect(routingMode: string): Promise<void> {
  mocks.settings.routingMode = routingMode;
  const { container } = render(<App />);
  await screen.findByRole("heading", { name: "Connection" });
  emitFrame({ status: "connected", detail: "up", pid: 4242, endpoint: "10.0.0.1:8080" });
  expect(container).toBeTruthy();
}

describe("App status line follows the routing mode (items 8, 21)", () => {
  it("does not claim a blanket protection for a local-proxy session", async () => {
    await connect("proxy-only");
    const text = beacon().textContent?.trim() ?? "";
    expect(text).toBe("Local proxy");
    expect(text).not.toMatch(/protected/i);
  });

  it("says the device is routed only when the VPN mode is what is running", async () => {
    await connect("tun");
    const text = beacon().textContent?.trim() ?? "";
    expect(text).toBe("Routed");
    expect(text).not.toMatch(/local proxy/i);
  });

  it("reads the stored mode, not an assumption about the default", async () => {
    // `system-proxy` is the shipped default, and on Android it behaves as a local
    // listener set: an app cannot write the system proxy, so the beacon must not
    // imply device-wide routing for it either.
    await connect("system-proxy");
    expect(beacon().textContent?.trim()).toBe("Local proxy");
  });

  it("still names the non-connected states in text", async () => {
    await connect("tun");
    emitFrame({ status: "disconnected", detail: "Idle", pid: null, endpoint: null });
    expect(beacon().textContent?.trim()).toBe("Standby");
    emitFrame({ status: "connecting", detail: "…", pid: null, endpoint: null });
    expect(beacon().textContent?.trim()).toBe("Connecting");
    emitFrame({ status: "error", detail: "engine died", pid: null, endpoint: null });
    expect(beacon().textContent?.trim()).toBe("Error");
  });
});
