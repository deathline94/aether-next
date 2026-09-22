// @vitest-environment jsdom
import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

/*
 * The phone is the surface where a colour-only state signal hurts most: it is
 * read outdoors, at a glance, on a panel that applies its own saturation. The
 * same claim the desktop test makes, on the markup this app actually ships -
 * the two front-ends were forked for long enough that a passing desktop test is
 * not evidence about the WebView.
 */
const mocks = vi.hoisted(() => {
  const handlers = new Map<string, (e: { payload: unknown }) => void>();
  const mounted: { label?: string; resetKeys?: readonly unknown[]; hasRetry: boolean }[] = [];
  const listen = vi.fn(async (event: string, handler: (e: { payload: unknown }) => void) => {
    handlers.set(event, handler);
    return () => {
      handlers.delete(event);
    };
  });
  const invoke = vi.fn(async (cmd: string) => {
    if (cmd === "get_state") return { status: "disconnected", detail: "Idle", pid: null, endpoint: null };
    return null;
  });
  return { handlers, mounted, listen, invoke };
});

vi.mock("./bridge", async (importOriginal) => ({
  ...(await importOriginal<typeof import("./bridge")>()),
  listen: mocks.listen,
  invoke: mocks.invoke,
}));

// Stub the boundary so the props each tab is mounted with are observable. The
// fallback itself cannot be rendered here (React 19 rethrows a throwing child
// out of act() and unmounts the tree - T186), which is exactly why the claim
// under test is "every tab is guarded and keyed", not "the crash screen shows".
vi.mock("./components/ErrorBoundary", () => ({
  ErrorBoundary: (props: {
    label?: string;
    resetKeys?: readonly unknown[];
    onRetry?: () => void;
    children?: React.ReactNode;
  }) => {
    mocks.mounted.push({
      label: props.label,
      resetKeys: props.resetKeys,
      hasRetry: typeof props.onRetry === "function",
    });
    return props.children ?? null;
  },
}));

import App from "./App";
import { RUNTIME_STATUS_TAGS } from "../../../packages/ui/src";

// jsdom has no scrolling model; the Activity tab autoscrolls its end marker.
beforeAll(() => { Element.prototype.scrollIntoView = () => {}; });

afterEach(() => cleanup());

beforeEach(() => {
  mocks.handlers.clear();
  mocks.mounted.length = 0;
});

describe("App status signalling (FR-033 / WCAG 1.4.1)", () => {
  it("names each of the four session states in text, not only in colour", async () => {
    const { container } = render(<App />);
    await screen.findByRole("heading", { name: "Connection" });

    const emit = mocks.handlers.get("session://state");
    if (!emit) throw new Error("useRuntime never registered a session://state listener");

    const seen = new Map<Element, string[]>();
    const statuses = Object.keys(RUNTIME_STATUS_TAGS);
    for (const status of statuses) {
      act(() => emit({ payload: { status, detail: `state is ${status}`, pid: null, endpoint: null } }));
      const carriers = container.querySelectorAll(".header-status, .switch-status-pill, .beacon-tag");
      expect(carriers.length, "no state-bearing indicator is rendered at all").toBeGreaterThan(0);
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

    for (const status of statuses) {
      act(() => emit({ payload: { status, detail: "", pid: null, endpoint: null } }));
      const tag = RUNTIME_STATUS_TAGS[status as keyof typeof RUNTIME_STATUS_TAGS];
      const tags = await screen.findAllByText(tag);
      expect(tags.length, `${status} must appear as the shared word ${tag}`).toBeGreaterThan(0);
    }
  });
});

describe('App per-tab error boundaries (T186 parity with the desktop)', () => {
  /*
   * Until now the phone mounted one boundary, in main.tsx, with no reset keys:
   * a view that threw on a bad frame offered a 'Try again' that re-rendered the
   * same input and threw again, and the whole UI - tunnel status included - went
   * with it. The desktop had per-tab guarding; the two apps share everything
   * else, so this is the claim that had to be made on the WebView too.
   */
  it('guards each tab with its own named, keyed boundary', async () => {
    render(<App />);
    await screen.findByRole('heading', { name: 'Connection' });
    expect(mocks.mounted.at(-1)?.label).toBe('Connection tab');
    expect(Array.isArray(mocks.mounted.at(-1)?.resetKeys)).toBe(true);

    for (const [tab, label] of [['Scanner', 'Scanner tab'], ['Settings', 'Settings tab'], ['Activity', 'Activity tab']] as const) {
      fireEvent.click(screen.getByRole('button', { name: new RegExp(tab) }));
      await screen.findByRole('heading', { name: tab });
      const last = mocks.mounted.at(-1);
      expect(last?.label).toBe(label);
      expect(Array.isArray(last?.resetKeys), label + ' has no resetKeys, so its fallback can never clear').toBe(true);
    }
  });

  it('gives the Settings boundary a retry that reloads from disk', async () => {
    render(<App />);
    fireEvent.click(screen.getByRole('button', { name: /Settings/ }));
    await screen.findByRole('heading', { name: 'Settings' });
    expect(mocks.mounted.at(-1)?.hasRetry).toBe(true);
  });
});
