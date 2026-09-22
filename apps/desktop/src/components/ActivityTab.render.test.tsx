// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { ActivityTab } from "./ActivityTab";
import { initialScanState } from "../types";
import type { DisplayedScanState, LogEntry } from "../types";

/**
 * jsdom has no layout: the real virtualiser measures a 0-height viewport and
 * mounts nothing, so the row markup cannot be observed. This stand-in emulates a
 * 400 px console and honours `count`/`estimateSize`/`overscan` — enough to prove
 * the tab drives the virtualiser (a window of rows, keyed by index, inside a
 * spacer of the full height) rather than painting the whole buffer.
 */
const VIEWPORT_PX = 400;
vi.mock("@tanstack/react-virtual", () => ({
  useVirtualizer: (options: { count: number; estimateSize: () => number; overscan?: number }) => {
    const size = options.estimateSize();
    const shown = Math.min(options.count, Math.ceil(VIEWPORT_PX / size) + (options.overscan ?? 0));
    return {
      getTotalSize: () => options.count * size,
      getVirtualItems: () =>
        Array.from({ length: shown }, (_, index) => ({
          index,
          key: index,
          size,
          start: index * size,
          end: (index + 1) * size,
          lane: 0,
        })),
      measureElement: () => {},
    };
  },
}));

afterEach(() => cleanup());

const scanState: DisplayedScanState = { ...initialScanState, bestRtt: null };

function entries(count: number): LogEntry[] {
  return Array.from({ length: count }, (_, i) => ({
    id: i,
    level: "info" as const,
    message: `candidate ok 104.16.0.${i}:443`,
    ts: 1_700_000_000_000 + i,
    // Deliberately not derivable from `ts`: a row that prints this proves it reads
    // the label computed once at append time, not `toLocaleTimeString(ts)`.
    time: `00:00:${String(i % 60).padStart(2, "0")}.x`,
  }));
}

function renderTab(visibleLogs: LogEntry[]) {
  render(
    <ActivityTab
      visibleLogs={visibleLogs}
      hasMore={visibleLogs.length > 200}
      filterCounts={{
        milestones: visibleLogs.length,
        hits: 0,
        errors: 0,
        raw: visibleLogs.length,
      }}
      logFilter="raw"
      setLogFilter={vi.fn()}
      logEndRef={{ current: null }}
      autoScroll={false}
      setAutoScroll={vi.fn()}
      exportLogs={async () => true}
      clearLogs={vi.fn()}
      scanState={scanState}
      status="connected"
    />,
  );
}

describe("ActivityTab console", () => {
  it("mounts a window of the rows, not the buffer", () => {
    // Every visible line used to be in the DOM at once and rebuilt on every
    // appended line, which is what froze the window during a scan.
    renderTab(entries(200));
    const spacer = screen.getByRole("log", { name: "Log rows" });
    // The scrollbar still describes all 200 rows...
    expect(spacer.style.height).toBe(`${200 * 26}px`);
    // ...while only what fits the viewport, plus the overscan, is mounted.
    const mounted = spacer.querySelectorAll(".terminal-log-row");
    expect(mounted.length).toBeGreaterThan(0);
    expect(mounted.length).toBeLessThan(200);
  });

  it("prints the preformatted clock, not one locale call per row per render", () => {
    renderTab(entries(3));
    // `entry.time` is computed once when the line is appended; the row reads it.
    // (`formatLogTime(ts)` per row per render is what this replaces.)
    expect(screen.getByText("00:00:00.x")).toBeTruthy();
    expect(screen.getByText("00:00:02.x")).toBeTruthy();
  });

  it("is a scroll region the keyboard can enter", () => {
    renderTab(entries(3));
    const consoleRegion = screen.getByRole("region", { name: "Engine log output" });
    expect(consoleRegion.getAttribute("tabindex")).toBe("0");
  });

  it("walks the filter chips with the arrow keys", () => {
    const setLogFilter = vi.fn();
    render(
      <ActivityTab
        visibleLogs={entries(1)}
        hasMore={false}
        filterCounts={{ milestones: 1, hits: 0, errors: 0, raw: 1 }}
        logFilter="milestones"
        setLogFilter={setLogFilter}
        logEndRef={{ current: null }}
        autoScroll={false}
        setAutoScroll={vi.fn()}
        exportLogs={async () => true}
        clearLogs={vi.fn()}
        scanState={scanState}
        status="connected"
      />,
    );
    const chips = screen.getAllByRole("radio");
    expect(chips.map((c) => c.getAttribute("tabindex"))).toEqual(["0", "-1", "-1", "-1"]);
    fireEvent.keyDown(chips[0] as HTMLElement, { key: "ArrowRight" });
    expect(setLogFilter).toHaveBeenCalledWith("hits");
  });
});
