// @vitest-environment jsdom
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { ScannerTab } from "./ScannerTab";
import { initialScanState } from "../types";
import type { DiscoveredEndpoint } from "../types";
import { stubViewport } from "../testing/viewport";

afterEach(() => cleanup());

// The panel is windowed, so an unmeasured viewport mounts no rows at all and a
// row assertion would pass against an empty DOM.
let restoreViewport: () => void;
beforeAll(() => {
  restoreViewport = stubViewport(420);
});
afterAll(() => restoreViewport());

const ENDPOINTS: DiscoveredEndpoint[] = [
  { addr: "162.159.193.1:443", rtt: "18 ms", rttMs: 18, protocol: "masque-h3" },
  { addr: "188.114.96.1:443", rtt: "42 ms", rttMs: 42, protocol: "masque-h2" },
  { addr: "192.168.0.9:500", rtt: "7 ms", rttMs: 7, protocol: "wireguard" },
];

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
    noize: "medium",
    setNoize: vi.fn(),
    endpoints: ENDPOINTS,
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

describe("android protocol filter tabs", () => {
  it("gives the tablist one tab stop and names the panel each tab controls", () => {
    // `role="tab"` without a roving tabindex and a panel is markup that claims a
    // pattern the component never implemented — desktop had the handler, this
    // copy rendered four separate stops and no `aria-controls`.
    renderTab();
    const tabs = screen.getAllByRole("tab");
    expect(tabs).toHaveLength(4);
    expect(tabs.map((t) => t.getAttribute("tabindex"))).toEqual(["0", "-1", "-1", "-1"]);
    for (const tab of tabs) expect(tab.getAttribute("aria-controls")).toBeTruthy();

    const panel = screen.getByRole("tabpanel");
    expect(panel.getAttribute("aria-labelledby")).toBe(screen.getAllByRole("tab")[0]?.id);
  });

  it("moves the filter with the arrow keys across the whole group", () => {
    renderTab();
    const first = screen.getAllByRole("tab")[0];
    fireEvent.keyDown(first!, { key: "ArrowRight" });
    const tabs = screen.getAllByRole("tab");
    expect(tabs.map((t) => t.getAttribute("aria-selected"))).toEqual([
      "false",
      "true",
      "false",
      "false",
    ]);
    // Only MASQUE H3 rows survive the filter, so a wrong selection is visible in
    // the list and not just in the attributes.
    expect(screen.queryByText("192.168.0.9:500")).toBeNull();
    expect(screen.getByText("162.159.193.1:443")).toBeTruthy();

    fireEvent.keyDown(screen.getAllByRole("tab")[1]!, { key: "End" });
    expect(screen.getAllByRole("tab")[3]?.getAttribute("aria-selected")).toBe("true");
    expect(screen.getByText("192.168.0.9:500")).toBeTruthy();
  });

  it("mounts a viewport-sized window of a 2 000-endpoint result", () => {
    // The phone runs the same scan the desktop does, on a slower CPU and with no
    // render cap on this list: every row was mounted, each with two buttons.
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
    const spacer = mounted[0]?.parentElement?.parentElement as HTMLElement | undefined;
    const totalPx = Number.parseInt(spacer?.style.height ?? "0", 10);
    expect(totalPx).toBeGreaterThan(2000 * 50);
  });
});

describe("ScannerTab scan start with a live tunnel", () => {
  it("requires a second click before a scan drops the active tunnel", () => {
    // Parity with the desktop twin: startScan silently `disconnect`ed the running
    // session first — one press on the CTA dropped the VPN with no surface beyond
    // one log line. The first click now arms a confirm; the second commits.
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
