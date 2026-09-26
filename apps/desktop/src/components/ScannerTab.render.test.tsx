// @vitest-environment jsdom
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { ScannerTab } from "./ScannerTab";
import {
  SCAN_MAX_CONCURRENCY,
  SCAN_MAX_CONCURRENCY_H3,
  SCAN_MASQUE_MIN_TIMEOUT_MS,
  SCAN_MIN_TIMEOUT_MS,
} from "@aether/ui";
import { initialScanState } from "../types";
import type { DiscoveredEndpoint } from "../types";
import { stubViewport } from "../testing/viewport";

afterEach(() => cleanup());

// The endpoint panel is windowed, and a windowed list with a 0x0 viewport mounts
// nothing at all - so without a measured height every row assertion below would
// pass against an empty DOM.
let restoreViewport: () => void;
beforeAll(() => {
  restoreViewport = stubViewport(420);
});
afterAll(() => restoreViewport());

function renderTab(over: Partial<Parameters<typeof ScannerTab>[0]> = {}) {
  const props = {
    protocol: "masque-h3" as const,
    setProtocol: vi.fn(),
    ipScan: "v4" as const,
    setIpScan: vi.fn(),
    concurrency: 250,
    setConcurrency: vi.fn(),
    timeoutMs: 6000,
    setTimeoutMs: vi.fn(),
    noize: "medium" as const,
    setNoize: vi.fn(),
    endpoints: [] as DiscoveredEndpoint[],
    active: false,
    scanState: { ...initialScanState, bestRtt: null },
    busy: false,
    startScan: vi.fn(),
    stopScan: vi.fn(),
    connectDirect: vi.fn(),
    connectBusy: false,
    running: false,
    ...over,
  };
  render(<ScannerTab {...props} />);
  return props;
}

describe("ScannerTab probe parameters", () => {
  it("offers only the lanes and the timeout the engine will honour, per protocol", () => {
    // Two drifts, both closed by reading the ladder from one place: the field used
    // to allow 2000 while the shells clamp to 500, and an H3 scan never runs more
    // than `SCAN_MAX_CONCURRENCY_H3` lanes because more concurrent BoringSSL
    // handshakes abort the engine. The names asserted here are the *visible* label
    // text on purpose \u2014 an accessible name that drops the words on screen is a
    // WCAG 2.5.3 failure for a speech-input user.
    renderTab({ protocol: "masque-h3" });
    expect(
      screen.getByRole("spinbutton", { name: /concurrency \(workers\)/i }).getAttribute("max"),
    ).toBe(String(SCAN_MAX_CONCURRENCY_H3));
    expect(
      screen.getByRole("spinbutton", { name: /timeout \(ms\)/i }).getAttribute("min"),
    ).toBe(String(SCAN_MASQUE_MIN_TIMEOUT_MS));
    cleanup();

    renderTab({ protocol: "masque-h2" });
    const lanes = screen.getByRole("spinbutton", { name: /concurrency \(workers\)/i });
    expect(lanes.getAttribute("max")).toBe(String(SCAN_MAX_CONCURRENCY));
    expect(lanes.getAttribute("min")).toBe("1");
    // An H2 probe is a TCP+TLS handshake the engine classifies as cheap, so the QUIC
    // floor must not be applied here: `startsWith("masque")` used to give the desktop
    // a 6 s minimum for a protocol the phone happily probes at 3 s.
    expect(
      screen.getByRole("spinbutton", { name: /timeout \(ms\)/i }).getAttribute("min"),
    ).toBe(String(SCAN_MIN_TIMEOUT_MS));
    expect(screen.getByText(/1\u2013500 lanes/)).toBeTruthy();
  });

  it("shows the noise profile that is really being sent", () => {
    // H2 probes are TCP: UDP junk frames cannot be sent. `useScanner` resolves the
    // profile the scan will run and hands *that* here, so the panel shows it verbatim
    // — the select used to substitute "off" in the label while `startScan` still
    // forwarded the stored profile. The parity is asserted in `useScanner.test.ts`.
    const select = () => screen.getByRole("combobox", { name: /obfuscation noise profile/i });
    renderTab({ protocol: "masque-h2", noize: "off" });
    expect(select()).toHaveProperty("value", "off");
    // ...and it cannot be changed into a value the run would ignore.
    expect(select().hasAttribute("disabled")).toBe(true);
    expect(screen.getByText(/not applicable for h2/i)).toBeTruthy();

    cleanup();
    renderTab({ protocol: "masque-h3", noize: "medium" });
    expect(select()).toHaveProperty("value", "medium");
    expect(select().hasAttribute("disabled")).toBe(false);
  });

  it("labels the protocol filter tabs with the panel they control", () => {
    renderTab({
      endpoints: [
        { addr: "104.16.0.1:443", rtt: "12ms", rttMs: 12, protocol: "masque-h3" },
        { addr: "188.114.96.1:443", rtt: "", rttMs: 0, protocol: "wireguard" },
      ],
    });
    const tabs = screen.getAllByRole("tab");
    const panel = screen.getByRole("tabpanel");
    for (const tab of tabs) {
      const controls = tab.getAttribute("aria-controls");
      expect(controls).toBeTruthy();
      expect(panel.id).toBe(controls);
      // A `radiogroup`/`tablist` without a roving tabindex leaves the inactive
      // options in the tab order; only the selected one may be reached.
      expect(tab.getAttribute("tabindex")).toBe(
        tab.getAttribute("aria-selected") === "true" ? "0" : "-1",
      );
    }
    const firstTab = tabs[0];
    if (!firstTab) throw new Error("the protocol filter rendered no tabs");
    fireEvent.keyDown(firstTab, { key: "ArrowRight" });
    expect(screen.getAllByRole("tab")[1]?.getAttribute("aria-selected")).toBe("true");
  });

  it("keeps the panel present when a filter leaves it empty", () => {
    // Every chip declares `aria-controls={resultsId}`. Filtering to a protocol
    // with no rows used to replace the panel with a bare empty-state div, so the
    // id disappeared and each chip pointed at nothing at the exact moment the
    // filter had something to say.
    renderTab({
      endpoints: [{ addr: "104.16.0.1:443", rtt: "12ms", rttMs: 12, protocol: "masque-h3" }],
    });
    const chip = screen
      .getAllByRole("tab")
      .find((t) => /wireguard/i.test(t.textContent ?? ""));
    if (!chip) throw new Error("the wireguard filter chip did not render");
    fireEvent.click(chip);
    expect(screen.getByText(/no endpoints found/i)).toBeTruthy();
    const panel = screen.getByRole("tabpanel");
    for (const tab of screen.getAllByRole("tab")) {
      const target = tab.getAttribute("aria-controls") ?? "";
      expect(document.getElementById(target)).toBe(panel);
    }
  });

  it("prints an unmeasured round-trip as such, not as a blank HIGH LATENCY row", () => {
    renderTab({
      endpoints: [
        { addr: "104.16.0.1:443", rtt: "", rttMs: 0, protocol: "wireguard" },
      ],
    });
    expect(screen.getByText("not measured")).toBeTruthy();
    expect(screen.queryByText("HIGH LATENCY")).toBeNull();
  });

  it("mounts a viewport-sized window of a 2 000-endpoint result, not 2 000 rows", () => {
    // T171/T185's measured half: the heading has to keep telling the truth about
    // the whole result while the DOM carries only what can be seen. A deep scan
    // used to put every row - each with a copy button and a Connect button - in
    // the tree at once.
    const many: DiscoveredEndpoint[] = Array.from({ length: 2000 }, (_, i) => ({
      addr: `162.159.${Math.floor(i / 250)}.${i % 250}:443`,
      rtt: `${10 + (i % 90)} ms`,
      rttMs: 10 + (i % 90),
      protocol: "masque-h3",
    }));
    renderTab({ endpoints: many });

    const mounted = document.querySelectorAll(".discovered-row");
    expect(mounted.length).toBeGreaterThan(0);
    expect(mounted.length).toBeLessThan(60);
    expect(mounted.length).toBeLessThan(many.length / 20);
    // The spacer carries the full height, so the scrollbar still describes 2 000.
    // (row -> absolutely positioned wrapper -> spacer of the total height)
    const spacer = mounted[0]?.parentElement?.parentElement as HTMLElement | undefined;
    const totalPx = Number.parseInt(spacer?.style.height ?? "0", 10);
    expect(totalPx).toBeGreaterThan(2000 * 50);
    // Measured rows can differ from the estimate, so this only rules out the
    // collapse that would make the panel unscrollable: a spacer no taller than a
    // handful of rows.
    expect(totalPx).toBeLessThan(2000 * 80);
    expect(screen.getByText(/Discovered Gateways \(2000\)/)).toBeTruthy();
  });
});

describe("ScannerTab scan start with a live tunnel", () => {
  it("requires a second click before a scan drops the active tunnel", () => {
    // startScan silently `disconnect`ed the running session first: one press on
    // the CTA dropped the VPN with no surface beyond one log line. The first
    // click now arms a confirm; the second commits.
    const startScan = vi.fn();
    renderTab({ running: true, startScan });
    const cta = () => screen.getByRole("button", { name: /disconnect/i });

    expect(cta().textContent).toMatch(/confirm first/i);

    fireEvent.click(cta());
    expect(startScan).not.toHaveBeenCalled();
    expect(screen.getByRole("alert").textContent).toMatch(/disconnects the active tunnel/i);
    expect(cta().textContent).toMatch(/confirm: disconnect vpn & scan/i);

    fireEvent.click(cta());
    expect(startScan).toHaveBeenCalledTimes(1);
  });

  it("does not arm the confirm when no tunnel is running", () => {
    const startScan = vi.fn();
    renderTab({ running: false, startScan });
    fireEvent.click(screen.getByRole("button", { name: /start standalone edge scan/i }));
    expect(startScan).toHaveBeenCalledTimes(1);
  });
});
