// @vitest-environment jsdom
/*
 * The console's copy, read out of the desktop's own DOM.
 *
 * The phone has had this since the audit (`ActivityTab.copy.test.tsx`); the desktop
 * had assertions about virtualisation and none about what the panel *says*, which is
 * how it kept a fake shell prompt (`aether@daemon`) and an operator's shorthand
 * ("Probed 40 / 100 candidates", "7 working") after the same words had been retired
 * on the other surface. Everything here is compared against the table in
 * `packages/ui`, so the file fails if this app reintroduces a local paraphrase.
 */
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { cleanup, render } from "@testing-library/react";
import { ActivityTab } from "./ActivityTab";
import { initialScanState } from "../types";
import type { DisplayedScanState, LogEntry } from "../types";
import {
  LOG_FILTER_HINT,
  LOG_FILTER_LABELS,
  scanProgressCopy,
  streamLabel,
  TERMINAL_TITLE,
} from "@aether/ui/statusCopy";

afterEach(() => cleanup());

// jsdom has no scrolling model, and the console follows its own tail on mount.
let previousScrollIntoView: typeof Element.prototype.scrollIntoView;
beforeAll(() => {
  previousScrollIntoView = Element.prototype.scrollIntoView;
  Element.prototype.scrollIntoView = () => {};
});
afterAll(() => {
  Element.prototype.scrollIntoView = previousScrollIntoView;
});

const LOGS: LogEntry[] = [
  { id: 1, level: "info", message: "engine started", ts: 1_700_000_000_000, time: "14:15:33" },
];

const scanState: DisplayedScanState = {
  ...initialScanState,
  active: true,
  mode: "balanced",
  phase: "probing",
  scanned: 40,
  total: 100,
  concurrency: 25,
  working: 7,
  bestRtt: "48 ms",
};

const idleScan: DisplayedScanState = { ...initialScanState, bestRtt: null };

function renderTab(over: { status?: string; visibleLogs?: LogEntry[]; raw?: number } = {}) {
  const visibleLogs = over.visibleLogs ?? LOGS;
  const raw = over.raw ?? visibleLogs.length;
  return render(
    <ActivityTab
      visibleLogs={visibleLogs}
      hasMore={false}
      filterCounts={{ milestones: raw, hits: 0, errors: 0, raw }}
      logFilter="raw"
      setLogFilter={vi.fn()}
      logEndRef={{ current: null }}
      autoScroll={false}
      setAutoScroll={vi.fn()}
      exportLogs={async () => true}
      clearLogs={vi.fn()}
      scanState={idleScan}
      status={over.status ?? "connected"}
    />,
  );
}

const text = (el: Element | null | undefined) => (el?.textContent ?? "").trim();

describe("the desktop console renders the shared table", () => {
  it("names the state the log is in, in the table's words and in a live region", () => {
    for (const status of ["connected", "connecting", "error", "disconnected", "reconnecting"]) {
      cleanup();
      const { container } = renderTab({ status });
      const indicator = container.querySelector(".terminal-mode-indicator");
      expect(text(indicator?.querySelector(".mode-tag"))).toBe(streamLabel(status));
      expect(indicator?.getAttribute("aria-live")).toBe("polite");
      expect(indicator?.getAttribute("role")).toBe("status");
    }
  });

  it("labels the four filters with the labels, and counts beside them", () => {
    const { container } = renderTab();
    const chips = Array.from(container.querySelectorAll(".filter-chip span:first-child")).map(text);
    expect(chips).toEqual(LOG_FILTER_LABELS.map((f) => f.label));
    // The stored token is not a label: printing it was the defect.
    expect(chips).not.toContain("Raw");
  });

  it("says the log is read-only instead of dressing as a shell prompt", () => {
    const { container } = renderTab();
    expect(text(container.querySelector(".terminal-title-text"))).toBe(TERMINAL_TITLE);
  });

  it("describes a running scan in the table's words", () => {
    const { container } = render(<ActivityTab
      visibleLogs={LOGS}
      hasMore={false}
      filterCounts={{ milestones: 1, hits: 0, errors: 0, raw: 1 }}
      logFilter="raw"
      setLogFilter={vi.fn()}
      logEndRef={{ current: null }}
      autoScroll={false}
      setAutoScroll={vi.fn()}
      exportLogs={async () => true}
      clearLogs={vi.fn()}
      scanState={scanState}
      status="connected"
    />);
    const copy = scanProgressCopy(scanState);
    const card = container.querySelector(".tactical-scan-card");
    expect(text(card?.querySelector(".scan-title strong"))).toBe(copy.headline);
    expect(text(card?.querySelector(".badge.concurrency"))).toBe(copy.concurrency);
    expect(text(card?.querySelector(".badge.working"))).toBe(copy.working);
    expect(text(card?.querySelector(".badge.rtt"))).toBe(copy.fastest ?? "");
    expect(text(card?.querySelector(".scan-card-footer small"))).toBe(copy.progressLabel);
    // The old words, which named the fields instead of answering with them.
    expect(card?.textContent ?? "").not.toMatch(/workers|candidates|Probed|Active Engine Scan/i);
  });

  it("points the empty console at the chip the hint names", () => {
    const { container } = renderTab({ visibleLogs: [], raw: 0 });
    expect(text(container.querySelector(".activity-hint span"))).toBe(LOG_FILTER_HINT);
    // The hint names the chips by the label actually on screen, so the two cannot
    // be edited apart - the sentence would otherwise point at a button that no
    // longer exists.
    const labelOf = (id: string) => LOG_FILTER_LABELS.find((f) => f.id === id)?.label ?? "";
    expect(LOG_FILTER_HINT).toContain(labelOf("milestones"));
    expect(LOG_FILTER_HINT).toContain(labelOf("raw"));
  });
});
