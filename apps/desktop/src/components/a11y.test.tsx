// @vitest-environment jsdom
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { cleanup, render } from "@testing-library/react";
import axe from "axe-core";
import { stubViewport } from "../testing/viewport";
import { ActivityTab } from "./ActivityTab";
import { ScannerTab } from "./ScannerTab";
import { SettingsTab } from "./SettingsTab";
import { defaults, initialScanState } from "../types";
import type { LogEntry, LogFilter } from "../types";
import type { DiscoveredEndpoint } from "../types";

/**
 * The accessibility suite the audit asked for and this app never had (T171).
 *
 * Every a11y claim in the recent history of this surface — roving tabindex,
 * radiogroup semantics, `aria-controls` naming a real panel, no control with two
 * accessible names — was made by a person reading JSX. This runs the same rules a
 * browser's a11y auditor runs over the rendered DOM, on the components as they
 * actually mount, with rows in them.
 *
 * `color-contrast` is the one rule disabled: jsdom performs no layout and resolves
 * no stylesheets, so it can only ever answer "unknown", and a blanket exclusion
 * named here is honest while a silently failing check is not. Contrast is a
 * tokens.css property and is asserted where the values live.
 */
afterEach(() => cleanup());

// jsdom has no scrolling model, so the console's `scrollIntoView` on mount — real
// in every browser, including the WebView this ships in — is simply absent here.
let restoreViewport: () => void;

beforeAll(() => {
  Element.prototype.scrollIntoView = () => {};
  // The endpoint panel is windowed, and axe over a list that jsdom's zero-sized
  // viewport leaves unmounted would say nothing about the rows.
  restoreViewport = stubViewport(420);
});
afterAll(() => restoreViewport());

const HOURS = new Date(2026, 8, 22, 14, 15, 33).getTime();

const LOGS: LogEntry[] = Array.from({ length: 5 }, (_, i) => ({
  id: i + 1,
  level: i % 3 === 0 ? "error" : i % 3 === 1 ? "warn" : "info",
  message: `engine line ${i}`,
  ts: HOURS + i * 1000,
  time: "14:15:33",
}));

async function expectAccessible(label: string, container: HTMLElement) {
  const results = await axe.run(container, {
    rules: { "color-contrast": { enabled: false } },
  });
  const detail = results.violations.map(
    (v) => `${v.id} (${v.impact}): ${v.help} -> ${v.nodes.map((n) => n.target.join(" ")).join(" | ")}`,
  );
  expect(detail, `axe violations in ${label}`).toEqual([]);
}

function renderAndCheck(label: string, ui: React.ReactElement) {
  const { container } = render(ui);
  return expectAccessible(label, container);
}

describe("desktop a11y (axe)", () => {
  it("the activity tab is clean with rows and empty", async () => {
    const counts: Record<LogFilter, number> = { milestones: 2, hits: 1, errors: 1, raw: 5 };
    await renderAndCheck(
      "ActivityTab (populated)",
      <ActivityTab
        visibleLogs={LOGS}
        hasMore={false}
        filterCounts={counts}
        logFilter="raw"
        setLogFilter={() => {}}
        logEndRef={{ current: null }}
        autoScroll
        setAutoScroll={() => {}}
        exportLogs={async () => true}
        clearLogs={() => {}}
        scanState={{ ...initialScanState, active: true, scanned: 40, total: 100, phase: "Probing Pool", bestRtt: null }}
        status="connected"
      />,
    );

    cleanup();
    await renderAndCheck(
      "ActivityTab (empty)",
      <ActivityTab
        visibleLogs={[]}
        hasMore={false}
        filterCounts={{ milestones: 0, hits: 0, errors: 0, raw: 0 }}
        logFilter="milestones"
        setLogFilter={() => {}}
        logEndRef={{ current: null }}
        autoScroll={false}
        setAutoScroll={() => {}}
        exportLogs={async () => true}
        clearLogs={() => {}}
        scanState={{ ...initialScanState, bestRtt: null }}
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
      noize: "medium" as const,
      setNoize: () => {},
      active: false,
      scanState: { ...initialScanState, bestRtt: null },
      busy: false,
      startScan: () => {},
      stopScan: () => {},
      connectDirect: () => {},
      connectBusy: false,
    };
    const endpoints: DiscoveredEndpoint[] = [
      { addr: "162.159.193.1:443", rtt: "18 ms", rttMs: 18, protocol: "masque-h3" },
      { addr: "188.114.96.1:443", rtt: "42 ms", rttMs: 42, protocol: "masque-h2" },
    ];

    await renderAndCheck("ScannerTab (results)", <ScannerTab {...base} endpoints={endpoints} />);
    cleanup();
    // The empty-filter case is where a tab panel disappears while the tabs still
    // name it: `aria-controls` pointing at nothing is a real defect, not a nit.
    await renderAndCheck(
      "ScannerTab (no results)",
      <ScannerTab {...base} endpoints={[]} />,
    );
  });

  it("the settings tab is clean unlocked, locked and mid-error", async () => {
    const base = {
      settings: defaults,
      settingsLoaded: true,
      saved: true,
      dirty: false,
      patchSettings: () => {},
    };
    await renderAndCheck("SettingsTab (editable)", <SettingsTab {...base} settingsLocked={false} saveError={null} />);
    cleanup();
    await renderAndCheck("SettingsTab (locked)", <SettingsTab {...base} settingsLocked saveError={null} />);
    cleanup();
    await renderAndCheck(
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
