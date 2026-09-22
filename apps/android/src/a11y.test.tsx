// @vitest-environment jsdom
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { cleanup, render } from "@testing-library/react";
import axe from "axe-core";
import { stubViewport } from "./testing/viewport";
import { ActivityTab } from "./components/ActivityTab";
import { ScannerTab } from "./components/ScannerTab";
import { SettingsTab } from "./components/SettingsTab";
import { defaults, initialScanState } from "./types";
import type { DiscoveredEndpoint, LogEntry, LogFilter, ScanState } from "./types";

/**
 * The same axe suite the desktop surface runs (T171), on the copy that this app
 * actually ships. The two front-ends were forked behaviourally for as long as
 * they were forked visually, so an accessibility claim about one is not evidence
 * about the other — the roving tabindex and the shared `nextOptionIndex` both
 * landed on the phone first and on the desktop never, or the reverse.
 *
 * `color-contrast` is the only rule off: jsdom resolves no stylesheet and lays
 * nothing out, so it can answer that rule only with "unknown". Contrast is a
 * tokens.css property and belongs to the gate that reads tokens.
 */
afterEach(() => cleanup());

// jsdom has no scrolling model; `scrollIntoView` exists in every browser this
// ships in, including the WebView. The viewport stub matters for the same
// reason as on desktop: the endpoint panel is windowed, and axe over a list that
// an unmeasured viewport leaves empty proves nothing about the rows.
let restoreViewport: () => void;
beforeAll(() => {
  Element.prototype.scrollIntoView = () => {};
  restoreViewport = stubViewport(420);
});
afterAll(() => restoreViewport());

const TS = new Date(2026, 8, 22, 14, 15, 33).getTime();

const LOGS: LogEntry[] = Array.from({ length: 5 }, (_, i) => ({
  id: i + 1,
  level: i % 3 === 0 ? "error" : i % 3 === 1 ? "warn" : "info",
  message: `engine line ${i}`,
  ts: TS + i * 1000,
  time: "14:15:33",
}));

async function expectAccessible(label: string, ui: React.ReactElement) {
  const { container } = render(ui);
  const results = await axe.run(container, { rules: { "color-contrast": { enabled: false } } });
  const detail = results.violations.map(
    (v) => `${v.id} (${v.impact}): ${v.help} -> ${v.nodes.map((n) => n.target.join(" ")).join(" | ")}`,
  );
  cleanup();
  expect(detail, `axe violations in ${label}`).toEqual([]);
}

describe("android a11y (axe)", () => {
  it("the activity tab is clean with rows and empty", async () => {
    const counts: Record<LogFilter, number> = { milestones: 2, hits: 1, errors: 1, raw: 5 };
    const base = {
      logEndRef: { current: null },
      setLogFilter: () => {},
      setAutoScroll: () => {},
      exportLogs: async () => true,
      clearLogs: () => {},
    };
    await expectAccessible(
      "ActivityTab (populated)",
      <ActivityTab
        {...base}
        visibleLogs={LOGS}
        hasMore={false}
        filterCounts={counts}
        logFilter="raw"
        autoScroll
        scanState={{ ...initialScanState, active: true, scanned: 40, total: 100 } as ScanState}
        status="connected"
      />,
    );
    await expectAccessible(
      "ActivityTab (empty)",
      <ActivityTab
        {...base}
        visibleLogs={[]}
        hasMore={false}
        filterCounts={{ milestones: 0, hits: 0, errors: 0, raw: 0 }}
        logFilter="milestones"
        autoScroll={false}
        scanState={initialScanState}
        status="disconnected"
      />,
    );
  });

  it("the scanner tab is clean with results and with none", async () => {
    const base = {
      protocol: "masque-h3" as const,
      setProtocol: () => {},
      ipScan: "v4" as const,
      setIpScan: () => {},
      concurrency: 250,
      setConcurrency: () => {},
      timeoutMs: 6000,
      setTimeoutMs: () => {},
      noize: "medium",
      setNoize: () => {},
      active: false,
      scanState: initialScanState,
      busy: false,
      startScan: () => {},
      stopScan: () => {},
      connectDirect: () => {},
      connectBusy: false,
    };
    const endpoints: DiscoveredEndpoint[] = [
      { addr: "162.159.193.1:443", rtt: "18 ms", rttMs: 18, protocol: "masque-h3" },
      { addr: "188.114.96.1:443", rtt: "42 ms", rttMs: 42, protocol: "wireguard" },
    ];
    await expectAccessible("ScannerTab (results)", <ScannerTab {...base} endpoints={endpoints} />);
    await expectAccessible("ScannerTab (no results)", <ScannerTab {...base} endpoints={[]} />);
  });

  it("the settings tab is clean unlocked, locked and mid-error", async () => {
    const base = {
      settings: defaults,
      settingsLoaded: true,
      saved: true,
      admin: true,
      patchSettings: () => {},
    };
    await expectAccessible(
      "SettingsTab (editable)",
      <SettingsTab {...base} settingsLocked={false} saveError={null} />,
    );
    await expectAccessible(
      "SettingsTab (locked)",
      <SettingsTab {...base} settingsLocked saveError={null} />,
    );
    await expectAccessible(
      "SettingsTab (rejected save + hydration failure)",
      <SettingsTab
        {...base}
        settingsLocked={false}
        settingsLoadError
        retrySettings={() => {}}
        saveError={{ code: "rejected", message: "port in use", field: "httpPort" }}
      />,
    );
  });
});
