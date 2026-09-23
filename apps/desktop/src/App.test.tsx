// @vitest-environment jsdom
import { beforeEach, describe, expect, it, vi } from "vitest";
import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import App from "./App";
import { RUNTIME_STATUS_TAGS } from "@aether/ui";
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

    // Every element whose *colour* the sheet changes with the state. A coloured
    // dot is the signal 1.4.1 is about, so each of these has to say the state
    // in words as well - and say it differently per state, which is what an
    // always-present-but-constant label would otherwise pass as.
    const seen = new Map<Element, string[]>();
    const statuses = Object.keys(RUNTIME_STATUS_TAGS);
    for (const status of statuses) {
      act(() => emit({ payload: { status, detail: `state is ${status}`, pid: null, endpoint: null } }));
      const carriers = document.querySelectorAll(".header-status, .switch-status-pill, .beacon-tag");
      expect(carriers.length, "no state-bearing indicator is rendered at all").toBeGreaterThan(2);
      for (const c of carriers) {
        const text = c.textContent?.replace(/\s+/g, " ").trim() ?? "";
        expect(text, `${c.className} signals its state with colour only`).not.toBe("");
        const list = seen.get(c) ?? [];
        list.push(text);
        seen.set(c, list);
      }
    }

    for (const [element, labels] of seen) {
      expect(labels, `${element.className} never reached every state`).toHaveLength(statuses.length);
      expect(new Set(labels).size, `${element.className} says "${labels[0]}" for every state`).toBe(labels.length);
    }

    // And the wording of the tag itself is the shared one, so the phone and the
    // desktop cannot describe the same state in two different words again.
    for (const [status, tag] of statuses.map((s) => [s, RUNTIME_STATUS_TAGS[s as keyof typeof RUNTIME_STATUS_TAGS]] as const)) {
      act(() => emit({ payload: { status, detail: "", pid: null, endpoint: null } }));
      const tags = await screen.findAllByText(tag);
      expect(tags.length, `${status} must appear as the shared word ${tag}`).toBeGreaterThan(0);
    }
  });

  it("keeps the four tags distinct, so the word carries information the colour alone did not", () => {
    const tags = Object.values(RUNTIME_STATUS_TAGS);
    expect(new Set(tags).size).toBe(tags.length);
    expect(tags.every((t) => /^[A-Z ]{2,12}$/.test(t))).toBe(true);
  });
});
