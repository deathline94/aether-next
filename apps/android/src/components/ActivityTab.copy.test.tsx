// @vitest-environment jsdom
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render } from "@testing-library/react";
import { ActivityTab } from "./ActivityTab";
// The console's mode tag is the shared table's, not this app's: the two surfaces
// have to name the same state with the same words.
import { streamLabel } from "@aether/ui/statusCopy";
import { initialScanState } from "../types";
import type { LogEntry, LogFilter, ScanState } from "../types";

/*
 * The console is the panel a user opens to answer "is it doing anything?", so a
 * line of its copy that overstates the state is the worst kind of wrong here: it
 * is believed because it looks like a log. These tests read the rendered text for
 * the claims - a stream described as live with no session behind it, a shell that
 * takes no input offering a prompt, counts named after internal buffers.
 */
afterEach(() => cleanup());

// jsdom has no scrolling model, and the console follows its own tail on mount:
// without the marker the auto-scroll effect throws before a single assertion can
// read the panel. Same stub the app's own suites install.
let previousScrollIntoView: typeof Element.prototype.scrollIntoView;
beforeAll(() => {
  previousScrollIntoView = Element.prototype.scrollIntoView;
  Element.prototype.scrollIntoView = () => {};
});
afterAll(() => {
  Element.prototype.scrollIntoView = previousScrollIntoView;
});

const TS = new Date(2026, 8, 22, 14, 15, 33).getTime();

const LOGS: LogEntry[] = [
  { id: 1, level: "info", message: "engine started", ts: TS, time: "14:15:33" },
  { id: 2, level: "warn", message: "probe timeout", ts: TS + 1000, time: "14:15:34" },
  { id: 3, level: "error", message: "edge unreachable", ts: TS + 2000, time: "14:15:35" },
];

interface Options {
  visibleLogs?: LogEntry[];
  hasMore?: boolean;
  filterCounts?: Record<LogFilter, number>;
  logFilter?: LogFilter;
  status?: string;
  scanState?: ScanState;
}

function renderTab(options: Options = {}) {
  const props = {
    visibleLogs: options.visibleLogs ?? LOGS,
    hasMore: options.hasMore ?? false,
    filterCounts: options.filterCounts ?? { milestones: 1, hits: 1, errors: 1, raw: 3 },
    logFilter: options.logFilter ?? ("raw" as LogFilter),
    setLogFilter: vi.fn(),
    logEndRef: { current: null },
    autoScroll: true,
    setAutoScroll: vi.fn(),
    exportLogs: vi.fn(async () => true),
    clearLogs: vi.fn(),
    scanState: options.scanState ?? initialScanState,
    status: options.status ?? "connected",
  };
  const utils = render(<ActivityTab {...props} />);
  return { ...utils, props };
}

describe("android console stream label", () => {
  it("names the state the log is in instead of claiming a live stream", () => {
    expect(streamLabel("connected")).toBe("Live session logs");
    // The defect: one string for every state, so a disconnected console said the
    // stream was live — on the one panel a user reads to find out if it is.
    expect(streamLabel("disconnected")).toBe("No session running");
    expect(streamLabel("connecting")).toBe("Waiting for the engine to start");
    expect(streamLabel("error")).toBe("Stopped after an error");
  });

  it("distinguishes all four states from each other", () => {
    const labels = ["connected", "connecting", "error", "disconnected"].map(streamLabel);
    expect(new Set(labels).size).toBe(4);
    // Only a session that is up may call itself live.
    for (const status of ["connecting", "error", "disconnected"]) {
      expect(streamLabel(status), `${status} claims a live stream`).not.toMatch(/live/i);
    }
  });

  it("still answers a status the app has never seen", () => {
    expect(streamLabel("paused")).toBe("No session running");
  });

  it("renders the label for the state it was handed, in a live region", () => {
    const { container } = renderTab({ status: "disconnected" });
    const indicator = container.querySelector(".terminal-mode-indicator");
    expect(indicator?.getAttribute("aria-live")).toBe("polite");
    expect(indicator?.textContent).toBe("No session running");
    // And it is the shared table's string, not a local one that happens to match:
    // the desktop's console asserts the same equality for the same status.
    expect(indicator?.textContent).toBe(streamLabel("disconnected"));
    cleanup();

    const connected = renderTab({ status: "connected" });
    expect(connected.container.querySelector(".terminal-mode-indicator")?.textContent).toBe(
      streamLabel("connected"),
    );
  });
});

describe("android console copy (item 21)", () => {
  it("labels the four filters by what they list", () => {
    const { container } = renderTab();
    const chips = Array.from(container.querySelectorAll(".filter-chip span:first-child")).map((s) => s.textContent);
    expect(chips).toEqual(["Key events", "Servers found", "Errors", "All lines"]);
    // The counts sit beside the label they count, and `raw` is no longer a label.
    expect(chips).not.toContain("Raw");
    expect(chips).not.toContain("Hits");
    expect(chips).not.toContain("Milestones");
  });

  it("counts lines, not a buffer", () => {
    const { container } = renderTab({ logFilter: "errors" });
    const count = container.querySelector(".stream-count")?.textContent ?? "";
    expect(count).toBe("1 of 3 lines shown");
    expect(count).not.toMatch(/buffer/i);
  });

  it("says the log is read-only instead of dressing as a shell prompt", () => {
    const { container } = renderTab();
    const title = container.querySelector(".terminal-title-text")?.textContent ?? "";
    expect(title).toContain("read only");
    expect(title).not.toMatch(/@/);
    expect(title).not.toMatch(/\$\s*$/);
  });

  it("names the two log actions after what they do", () => {
    const { container } = renderTab();
    const buttons = Array.from(container.querySelectorAll(".tactile-terminal-btn"));
    const labels = buttons.map((b) => b.textContent);
    expect(labels).toContain("Copy logs");
    expect(labels).toContain("Clear logs");
    expect(labels.join(" ")).not.toMatch(/Buffer|Flush/i);
  });

  it("describes an empty console as waiting, not as a daemon that has not answered", () => {
    const { container } = renderTab({
      visibleLogs: [],
      filterCounts: { milestones: 0, hits: 0, errors: 0, raw: 0 },
      status: "disconnected",
    });
    const empty = container.querySelector(".empty-logs");
    const text = empty?.textContent ?? "";
    expect(text).toContain("No log lines yet");
    expect(text).toMatch(/appear here while Aether runs/i);
    expect(text).not.toMatch(/daemon|upon execution|carrier/i);
  });

  it("tells a filtered-out list which filter to widen", () => {
    const { container } = renderTab({ visibleLogs: [], logFilter: "errors" });
    const text = container.querySelector(".empty-logs")?.textContent ?? "";
    expect(text).toContain("Nothing matches this filter");
    expect(text).toMatch(/"All lines"/);
    expect(text).not.toMatch(/'Raw'|packet and probe streams/i);
  });

  it("points at the button the hint tells the user to press", () => {
    const { container } = renderTab({ hasMore: true });
    const hint = container.querySelector(".log-more-hint")?.textContent ?? "";
    expect(hint).toMatch(/"Copy logs"/);
    expect(hint).not.toMatch(/Copy Buffer/i);
    expect(Array.from(container.querySelectorAll(".tactile-terminal-btn")).map((b) => b.textContent)).toContain("Copy logs");
  });

  it("describes a scan in the words a scan is", () => {
    const { container } = renderTab({
      scanState: {
        ...initialScanState,
        active: true,
        mode: "balanced",
        phase: "probing",
        scanned: 40,
        total: 100,
        concurrency: 25,
        working: 7,
        bestRtt: "48 ms",
      } as ScanState,
    });
    const text = container.querySelector(".tactical-scan-card")?.textContent ?? "";
    expect(text).toContain("Scanning for servers");
    expect(text).toContain("Checked 40 of 100 addresses");
    expect(text).toContain("7 answered");
    expect(text).toContain("25 at once");
    expect(text).toContain("fastest 48 ms");
    expect(text).not.toMatch(/workers|candidates|Probed/i);
  });

  it("keeps no claim about privacy or strength anywhere on the panel", () => {
    const { container } = renderTab({ status: "connected" });
    const text = container.textContent ?? "";
    for (const claim of [/unbreakable/i, /anonymous/i, /100\s*%/, /untraceable/i, /cannot be (?:seen|traced|detected)/i, /military/i, /guarantee/i]) {
      expect(text, `the console prints ${claim}`).not.toMatch(claim);
    }
  });

  it("still filters on the chip the label belongs to", () => {
    const { container, props } = renderTab({ logFilter: "milestones" });
    const chip = Array.from(container.querySelectorAll(".filter-chip")).find((b) => b.textContent?.startsWith("Errors"));
    if (!chip) throw new Error("no Errors chip");
    fireEvent.click(chip);
    expect(props.setLogFilter).toHaveBeenCalledWith("errors");

    // The roving tabindex is on the selected chip, which is still `milestones`:
    // the labels changed, the group's keyboard contract did not.
    const selected = container.querySelector('.filter-chip[aria-checked="true"]');
    expect(selected?.textContent).toMatch(/^Key events/);
    expect(Array.from(container.querySelectorAll(".filter-chip")).filter((c) => c.getAttribute("tabindex") === "0")).toHaveLength(1);
  });
});
