// @vitest-environment jsdom
import { act, render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

/*
 * The phone is the surface where a colour-only state signal hurts most: it is
 * read outdoors, at a glance, on a panel that applies its own saturation. The
 * same claim the desktop test makes, on the markup this app actually ships -
 * the two front-ends were forked for long enough that a passing desktop test is
 * not evidence about the WebView.
 */
const mocks = vi.hoisted(() => {
  const handlers = new Map<string, (e: { payload: unknown }) => void>();
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
  return { handlers, listen, invoke };
});

vi.mock("./bridge", async (importOriginal) => ({
  ...(await importOriginal<typeof import("./bridge")>()),
  listen: mocks.listen,
  invoke: mocks.invoke,
}));

import App from "./App";
import { RUNTIME_STATUS_TAGS } from "../../../packages/ui/src";

beforeEach(() => {
  mocks.handlers.clear();
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
