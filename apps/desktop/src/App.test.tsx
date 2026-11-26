// @vitest-environment jsdom
import { beforeEach, describe, expect, it, vi } from "vitest";
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import App, { carrierProtocol } from "./App";
import { RUNTIME_STATUS_TAGS } from "@aether/ui";
import { nordicHeroHeadline } from "@aether/ui/statusCopy";
import type { Settings } from "./types";

vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));
vi.mock("@tauri-apps/api/event", () => ({ listen: vi.fn() }));

interface Recorded {
  label: string | undefined;
  resetKeys: readonly unknown[] | undefined;
  hasRetry: boolean;
}
const mounted: Recorded[] = [];

// React 19 + jsdom cannot observe a boundary's fallback: a child that throws
// during render is rethrown out of `act()` and the tree unmounts. What *is*
// observable — and was the defect — is that App never mounted a per-tab
// boundary at all, so `resetKeys`/`onRetry` could not fire. Stub the component
// and assert the props each tab gets.
vi.mock("./components/ErrorBoundary", () => ({
  ErrorBoundary: (props: {
    label?: string;
    resetKeys?: readonly unknown[];
    onRetry?: () => void;
    children?: React.ReactNode;
  }) => {
    mounted.push({
      label: props.label,
      resetKeys: props.resetKeys,
      hasRetry: typeof props.onRetry === "function",
    });
    return props.children ?? null;
  },
}));

import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";

const fullSettings: Settings = {
  protocol: "masque",
  transport: "h2",
  scanMode: "balanced",
  ipVersion: "v4",
  noize: "off",
  noizeJc: 5,
  noizeJmin: 50,
  noizeJmax: 128,
  noizeIntervalMs: 0,
  routingMode: "system-proxy",
  socksPort: 1819,
  httpPort: 1820,
  startMinimized: false,
  launchAtLogin: false,
  enginePath: "",
  peer: "",
  quicInitialFrag: false,
  quicInitialFragSize: 96,
};

beforeEach(() => {
  cleanup();
  mounted.length = 0;
  vi.mocked(invoke).mockImplementation(async (command: string) => {
    if (command === "get_settings") return fullSettings;
    if (command === "app_info") return { version: "1.3.0" };
    if (command === "is_admin") return false;
    return null;
  });
  vi.mocked(listen).mockImplementation(((_event: string, handler: (e: { payload: unknown }) => void) => {
    void handler;
    return Promise.resolve(() => {});
  }) as typeof listen);
});

/** Every listener the app subscribes, keyed by event name, so a test can emit. */
function capture(): Map<string, (e: { payload: unknown }) => void> {
  const handlers = new Map<string, (e: { payload: unknown }) => void>();
  vi.mocked(listen).mockImplementation(((event: string, handler: (e: { payload: unknown }) => void) => {
    handlers.set(event, handler);
    return Promise.resolve(() => {});
  }) as typeof listen);
  return handlers;
}

describe("App tab boundaries", () => {
  it("wraps each tab in its own named boundary with reset keys", async () => {
    render(<App />);
    await screen.findByRole("heading", { name: "Connection" });
    const labels = mounted.map((m) => m.label);
    expect(labels).toContain("Connection tab");
    expect(labels.some((l) => l === "Activity tab" || l === "Settings tab")).toBe(false);

    fireEvent.click(screen.getByRole("button", { name: /Scanner/ }));
    await screen.findByText(/Cloudflare Edge Scanner/);
    expect(mounted.at(-1)?.label).toBe("Scanner tab");
    expect(Array.isArray(mounted.at(-1)?.resetKeys)).toBe(true);
  });

  it("gives the Settings boundary a retry that reloads from disk", async () => {
    render(<App />);
    fireEvent.click(screen.getByRole("button", { name: /Settings/ }));
    await screen.findByText(/Probe Velocity Profile/);
    const settings = mounted.at(-1);
    expect(settings?.label).toBe("Settings tab");
    expect(settings?.hasRetry).toBe(true);
  });
});

describe("App navigation shortcuts", () => {
  it("switches tabs on a bare number key", async () => {
    render(<App />);
    await screen.findByRole("heading", { name: "Connection" });
    fireEvent.keyDown(window, { key: "2" });
    await screen.findByText(/Cloudflare Edge Scanner/);
  });

  it("leaves modified number keys to the browser", async () => {
    // Ctrl/Alt/Cmd+1..4 are browser/OS tab shortcuts; the handler only checked
    // whether focus sat in an input, so they switched views underneath.
    render(<App />);
    await screen.findByRole("heading", { name: "Connection" });
    for (const mods of [
      { ctrlKey: true },
      { altKey: true },
      { metaKey: true },
      { ctrlKey: true, shiftKey: true },
    ]) {
      fireEvent.keyDown(window, { key: "2", ...mods });
    }
    expect(mounted.map((m) => m.label).filter((l) => l === "Scanner tab")).toHaveLength(0);
    await screen.findByRole("heading", { name: "Connection" });
  });

  it("ignores number keys typed into a field", async () => {
    render(<App />);
    fireEvent.click(screen.getByRole("button", { name: /Settings/ }));
    await screen.findByText(/Probe Velocity Profile/);
    const input = screen.getByRole("spinbutton", { name: /HTTP proxy port/i });
    input.focus();
    fireEvent.keyDown(input, { key: "2" });
    expect(document.activeElement).toBe(input);
    expect(screen.queryByText(/Cloudflare Edge Scanner/)).toBeNull();
    await screen.findByText(/Probe Velocity Profile/);

    // The same key with focus on the page body does switch.
    input.blur();
    fireEvent.keyDown(window, { key: "2" });
    await screen.findByText(/Cloudflare Edge Scanner/);
  });

  it("moves focus to the new view's heading when a shortcut changes the view", async () => {
    render(<App />);
    await screen.findByRole("heading", { name: "Connection" });

    // Focus something inside the tab, which unmounts with the view change.
    const control = document.querySelector(".hero-card .primary-cta") as HTMLElement | null;
    if (!control) throw new Error("the Connection tab did not render its control");
    control.focus();
    expect(document.activeElement).toBe(control);

    fireEvent.keyDown(window, { key: "2" });

    const heading = await screen.findByRole("heading", { name: "Scanner" });
    expect(document.activeElement).toBe(heading);
  });
});

describe("App activity log retention", () => {
  const state = (status: string) => ({ status, detail: `${status} state`, pid: null, endpoint: null });
  const line = (message: string) => ({ level: "info", message });

  async function mountWithLogs() {
    const handlers = capture();
    render(<App />);
    await screen.findByRole("heading", { name: "Connection" });
    await waitFor(() => {
      expect(handlers.has("session://state")).toBe(true);
      expect(handlers.has("session://log")).toBe(true);
    });
    return {
      state: (status: string) => act(() => handlers.get("session://state")!({ payload: state(status) })),
      log: (message: string) => act(() => handlers.get("session://log")!({ payload: line(message) })),
    };
  }

  it("keeps the evidence of a failure while the shell recovers from it", async () => {
    const app = await mountWithLogs();

    app.state("error");
    app.log("handshake failed: engine exit 4");
    expect(screen.getByLabelText("1 log entries")).toBeTruthy();

    // supervision.rs re-emits "connecting" for every recovery attempt, so
    // clearing on entry destroyed the record of the failure being recovered.
    app.state("connecting");
    expect(screen.getByLabelText("1 log entries")).toBeTruthy();
  });

  it("clears the previous session's lines when a fresh start begins from idle", async () => {
    const app = await mountWithLogs();

    app.log("old session line");
    expect(screen.getByLabelText("1 log entries")).toBeTruthy();

    app.state("connecting");
    expect(screen.queryByLabelText("1 log entries")).toBeNull();
  });

  it("copies log lines and diagnostics with every address masked", async () => {
    // jsdom has no scrolling model; the Activity console follows its own tail.
    Element.prototype.scrollIntoView = () => {};
    vi.mocked(invoke).mockImplementation(async (command: string) => {
      if (command === "get_settings") return fullSettings;
      if (command === "diagnostics") return { peer: "198.51.100.7:443", location: "Frankfurt" };
      if (command === "app_info") return { version: "1.3.0" };
      if (command === "is_admin") return false;
      return null;
    });
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText } });
    Object.defineProperty(window, "isSecureContext", { configurable: true, value: true });

    const app = await mountWithLogs();
    app.log("peer 104.16.23.19:443 answered");

    fireEvent.click(screen.getByRole("button", { name: /Activity/ }));
    // The label has to say what actually leaves the window.
    fireEvent.click(await screen.findByRole("button", { name: /Copy logs \+ diagnostics/ }));
    await waitFor(() => expect(writeText).toHaveBeenCalledTimes(1));

    const copied = String(writeText.mock.calls[0]?.[0] ?? "");
    expect(copied).toContain("# engine diagnostics");
    // The export is pasted into bug reports: the real edge, the peer and the
    // connection test's address must not travel with it.
    expect(copied).not.toContain("104.16.23.19");
    expect(copied).not.toContain("198.51.100.7");
    expect(copied).toContain("192.0.2.0:443");
  });
});

describe("App scanner direct connect", () => {
  it("reads the WireGuard label the way the phone does", () => {
    // The engine labels rows "WG", "wg" or "WireGuard H3"; the desktop only knew
    // the long spelling, so the same row connected as MASQUE here and WireGuard
    // on Android.
    expect(carrierProtocol("WG")).toBe("wireguard");
    expect(carrierProtocol("wg")).toBe("wireguard");
    expect(carrierProtocol("WireGuard H3")).toBe("wireguard");
    expect(carrierProtocol("MASQUE H3")).toBe("masque");
    expect(carrierProtocol("masque-h2")).toBe("masque");
  });
});

describe("App connection status announcements", () => {
  it("has exactly one polite live region, and the beacon is not a second one", async () => {
    render(<App />);
    await screen.findByRole("heading", { name: "Connection" });

    // Only the hero subtitle carries aria-live="polite"; the visual dot is aria-hidden.
    expect(document.querySelectorAll('[aria-live="polite"]')).toHaveLength(1);
    const indicator = document.querySelector(".hero-status-indicator");
    expect(indicator).not.toBeNull();
    expect(indicator?.getAttribute("role")).not.toBe("status");
    expect(indicator?.getAttribute("aria-live")).not.toBe("polite");
  });

  it("keeps one polite region and the error banner's alert when a session fails", async () => {
    const handlers = capture();
    render(<App />);
    await screen.findByRole("heading", { name: "Connection" });
    await waitFor(() => expect(handlers.has("session://state")).toBe(true));

    act(() => {
      handlers.get("session://state")!({
        payload: { status: "error", detail: "handshake failed", pid: null, endpoint: null },
      });
    });

    expect(document.querySelectorAll('[aria-live="polite"]')).toHaveLength(1);
    expect(document.querySelectorAll('[role="status"]')).toHaveLength(0);
    expect(document.querySelector('[role="alert"]')?.textContent).toContain("handshake failed");
  });
});

describe("App status signalling (FR-033 / WCAG 1.4.1)", () => {
  /*
   * The sheet paints a different accent on `.header-status` for each session
   * state, and colour is exactly what a colour-blind user, a greyscale remote
   * session or a high-contrast override loses, so every state also has to reach
   * the interface as a word. Those words used to live in each app's own hero
   * copy, where the two front-ends could and did name the same state
   * differently; they are one shared map now, so this asserts the map is what
   * the real header renders -- through the listener the shell actually calls,
   * not by reading the constant back.
   */
  it("names each of the four session states in text, not only in colour", async () => {
    const handlers = new Map<string, (e: { payload: unknown }) => void>();
    vi.mocked(listen).mockImplementation(((event: string, handler: (e: { payload: unknown }) => void) => {
      handlers.set(event, handler);
      return Promise.resolve(() => {});
    }) as typeof listen);

    render(<App />);
    await screen.findByRole("heading", { name: "Connection" });

    const emit = handlers.get("session://state");
    if (!emit) throw new Error("useRuntime never registered a session://state listener");

    const seen = new Map<Element, string[]>();
    const statuses = Object.keys(RUNTIME_STATUS_TAGS) as (keyof typeof RUNTIME_STATUS_TAGS)[];
    for (const status of statuses) {
      act(() => emit({ payload: { status, detail: `state is ${status}`, pid: null, endpoint: null } }));
      const titleEl = document.querySelector(".hero-title");
      expect(titleEl, "no state-bearing headline is rendered").not.toBeNull();
      const label = titleEl?.textContent?.replace(/\s+/g, " ").trim() ?? "";
      expect(label, "hero-title signals state with colour only").not.toBe("");
      expect(label).toBe(nordicHeroHeadline(status, "system-proxy", true));
      const list = seen.get(titleEl!) ?? [];
      list.push(label);
      seen.set(titleEl!, list);
    }

    for (const [element, labels] of seen) {
      expect(labels, `${element.className} never reached every state`).toHaveLength(statuses.length);
      expect(new Set(labels).size, `${element.className} says "${labels[0]}" for every state`).toBe(labels.length);
    }
  });

  it("keeps the four tags distinct, so the word carries information the colour alone did not", () => {
    const tags = Object.values(RUNTIME_STATUS_TAGS);
    expect(new Set(tags).size).toBe(tags.length);
    expect(tags.every((t) => /^[A-Z ]{2,12}$/.test(t))).toBe(true);
  });
});
