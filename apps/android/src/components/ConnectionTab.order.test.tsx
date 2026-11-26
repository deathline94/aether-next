// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from "vitest";
import axe from "axe-core";
import { cleanup, fireEvent, render } from "@testing-library/react";
import { ConnectionTab, START_HINT } from "./ConnectionTab";
import { defaults, initialRuntime } from "../types";
import type { RuntimeState, Settings } from "../types";

/*
 * The phone is the surface where this matters most: the Connection tab is long,
 * `.home-view` lays its children out in source order with no `order:` override,
 * and a 390 px viewport shows roughly one section at a time. So the scroll depth
 * of "is it actually working?" *is* the DOM order of the sections - which is what
 * these tests read. Measured in a browser at 320 px and 390 px, the same order is
 * what the layout gets; asserting it here is what keeps it that way.
 */
afterEach(() => cleanup());

interface RenderOptions {
  settings?: Partial<Settings>;
  runtime?: Partial<RuntimeState>;
  connected?: boolean;
  running?: boolean;
  admin?: boolean;
  online?: boolean;
  testResult?: { detail: string; latencyMs: number | null } | null;
}

function renderTab(options: RenderOptions = {}) {
  const props = {
    settings: { ...defaults, ...options.settings },
    runtime: { ...initialRuntime, ...options.runtime },
    busy: false,
    testBusy: false,
    connected: options.connected ?? false,
    running: options.running ?? false,
    settingsLocked: false,
    settingsLoaded: true,
    admin: options.admin ?? true,
    online: options.online ?? true,
    testResult: options.testResult ?? null,
    appVersion: "1.4.0",
    toggleConnection: vi.fn(),
    patchSettings: vi.fn(),
    runTest: vi.fn(),
    dismissError: vi.fn(),
    appendLog: vi.fn(),
  };
  const utils = render(<ConnectionTab {...props} />);
  return { ...utils, props };
}

/** The tab's top-level sections, in the order a scroll reaches them. */
const sectionOrder = (container: HTMLElement) =>
  Array.from(container.querySelectorAll(".home-view > *")).map((el) => el.className);

const positionOf = (container: HTMLElement, selector: string) =>
  sectionOrder(container).findIndex((classes) => classes.includes(selector));

describe("android connection tab section order (item 20)", () => {
  it("puts the hero stage above the grouped configuration card", () => {
    const { container } = renderTab();
    expect(sectionOrder(container)).toEqual([
      "mobile-hero-stage disconnected",
      "grouped-card",
    ]);
  });

  it("keeps the banners that explain a failed or offline attempt above the grouped rows", () => {
    const { container } = renderTab({
      online: false,
      settings: { peer: "104.16.23.19:443" },
      runtime: { status: "error", detail: "Edge unreachable" },
    });
    expect(sectionOrder(container)).toEqual([
      "offline-banner",
      "error-banner",
      "pinned-peer-bar",
      "mobile-hero-stage error",
      "grouped-card",
    ]);
  });

  it("keeps the hero action ahead of configuration at 320 and 390 px", () => {
    for (const width of [320, 390]) {
      cleanup();
      Object.defineProperty(window, "innerWidth", { value: width, configurable: true });
      const { container } = renderTab({ connected: true, running: true });
      const hero = positionOf(container, "mobile-hero-stage");
      const group = positionOf(container, "grouped-card");
      expect(hero, `${width}px: no hero stage rendered`).toBeGreaterThan(-1);
      expect(group).toBe(hero + 1);
    }
  });

  it("shows connection state, endpoint, configuration rows and test action", () => {
    const { container, props } = renderTab({
      connected: true,
      running: true,
      settings: { routingMode: "proxy-only" },
      runtime: { status: "connected", endpoint: "104.16.23.19:443" },
    });
    const text = container.textContent ?? "";
    expect(text).toContain("Connected");
    expect(text).toContain("Local proxy");
    expect(text).toContain("104.16.23.19:443");
    expect(text).toMatch(/Test route/);

    const testBtn = container.querySelector(".text-action-btn");
    if (!testBtn) throw new Error("the hero stage has no test action");
    fireEvent.click(testBtn);
    expect(props.runTest).toHaveBeenCalledTimes(1);
  });
});

describe("android connection tab controls", () => {
  it("offers exactly one connect control and one test control", () => {
    const { container, props } = renderTab({ connected: true, running: true });
    const connectButtons = Array.from(container.querySelectorAll("button")).filter(
      (b) => b.getAttribute("aria-label") === "Connect Aether" || b.getAttribute("aria-label") === "Disconnect Aether",
    );
    expect(connectButtons).toHaveLength(1);
    fireEvent.click(connectButtons[0] as Element);
    expect(props.toggleConnection).toHaveBeenCalledTimes(1);

    const testButtons = Array.from(container.querySelectorAll(".text-action-btn"));
    expect(testButtons).toHaveLength(1);
  });

  it("names the control for what it does, on both sides", () => {
    const disconnected = renderTab();
    expect(disconnected.container.querySelector(".mobile-hero-cta")?.getAttribute("aria-label")).toBe("Connect Aether");
    expect(disconnected.container.querySelector(".mobile-hero-cta")?.textContent).toBe("Connect");
    cleanup();

    const running = renderTab({ connected: true, running: true });
    expect(running.container.querySelector(".mobile-hero-cta")?.getAttribute("aria-label")).toBe("Disconnect Aether");
    expect(running.container.querySelector(".mobile-hero-cta")?.textContent).toBe("Disconnect");
  });
});

describe("android connection tab copy (item 21)", () => {
  /** Every state x routing mode the tab can render. */
  const cases: [string, RenderOptions][] = [
    ["disconnected / tun", {}],
    ["disconnected / proxy-only", { settings: { routingMode: "proxy-only" as const } }],
    ["connecting / tun", { running: true, runtime: { status: "connecting" as const } }],
    ["connected / tun", { connected: true, running: true, runtime: { status: "connected" as const } }],
    [
      "connected / proxy-only",
      { connected: true, running: true, settings: { routingMode: "proxy-only" as const }, runtime: { status: "connected" as const } },
    ],
    [
      "connected / system-proxy",
      { connected: true, running: true, settings: { routingMode: "system-proxy" as const }, runtime: { status: "connected" as const } },
    ],
    ["error / tun", { runtime: { status: "error" as const, detail: "Edge unreachable" } }],
  ];

  // Nothing the app cannot observe may be printed, and no operator shorthand is
  // left to be read as a claim. `100%` and `UNBREAKABLE` were never in this file,
  // but `VPN ACTIVE`, `SECURITY CIPHER: CHACHA20` for a TLS session, `ALGORITHM:
  // DIRECT CONCURRENT`, `HIGH-PERFORMANCE` and a permanent `PACKET LOSS: not
  // measured` were - all of them properties of a connection this app has no
  // reading on, or words from the protocol's own manual.
  const BANNED = [
    /unbreakable/i,
    /anonymous/i,
    /100\s*%/,
    /untraceable/i,
    /bulletproof/i,
    /military/i,
    /cannot be (?:detected|traced|seen)/i,
    /guarantee/i,
    /high-?performance/i,
    /VPN ACTIVE/i,
    /traffic secure/i,
    /route open/i,
    /PACKET LOSS/i,
    /DIRECT CONCURRENT/i,
    /not observed/i,
  ];

  for (const [name, options] of cases) {
    it(`says nothing unverifiable in ${name}`, () => {
      cleanup();
      const { container } = renderTab(options);
      const text = container.textContent ?? "";
      for (const pattern of BANNED) {
        expect(text, `${name} prints a claim matching ${pattern}`).not.toMatch(pattern);
      }
    });
  }

  it("drops the labels that only an operator would recognise", () => {
    const { container } = renderTab({ connected: true, running: true, runtime: { status: "connected" as const } });
    const text = container.textContent ?? "";
    for (const jargon of [
      "CARRIER & CIPHER",
      "ANTI-DPI FRAG",
      "ROUTING TOPOLOGY",
      "CORE DAEMON SUBSYSTEM",
      "GATEWAY EDGE ROUTE",
      "IP STACK",
      "VPNSERVICE",
      "DORMANT",
      "STANDBY //",
      "TAP TO ENGAGE",
      "NEGOTIATING",
      "EDGE HANDSHAKE",
      "Live Connection Verification",
      "Initialize the tunnel",
      "secure device sockets",
      "Targeting forced endpoint",
      "Scan dynamically",
    ]) {
      expect(text, `the tab still labels something ${jargon}`).not.toContain(jargon);
    }
    // The replacements say what each grouped row controls.
    expect(text).toContain("Protocol");
    expect(text).toContain("Routing");
    expect(text).toContain("Obfuscation");
    expect(text).toContain("Local SOCKS5");
    expect(text).toContain("Test route");
  });

  it("keeps routing mode out of the disconnected headline", () => {
    const proxy = renderTab({ settings: { routingMode: "proxy-only" } });
    expect(proxy.container.querySelector(".mobile-hero-title")?.textContent).toBe("Standby");
    expect(proxy.container.textContent).not.toMatch(/VPN NOT ACTIVE/);
    cleanup();

    const tun = renderTab({ settings: { routingMode: "tun" } });
    expect(tun.container.querySelector(".mobile-hero-title")?.textContent).toBe("Standby");
  });

  it("tells a first run what the button does and where the answer will appear", () => {
    const { container } = renderTab();
    const copy = container.querySelector(".mobile-hero-subtitle")?.textContent ?? "";
    expect(copy).toContain(START_HINT);
    expect(copy).toMatch(/Tap the power button to connect/i);
    expect(copy).toMatch(/connection status shows what that covers/i);
    for (const jargon of ["Initialize the tunnel", "negotiate", "device sockets", "edge telemetry"]) {
      expect(copy.toLowerCase()).not.toContain(jargon.toLowerCase());
    }
  });

  it("does not claim a measurement it never took", () => {
    const untested = renderTab({ connected: true, running: true, runtime: { status: "connected" as const } });
    expect(untested.container.textContent).not.toMatch(/\b\d+\s*ms\b/);
    cleanup();

    const tested = renderTab({
      connected: true,
      running: true,
      runtime: { status: "connected" as const },
      testResult: { detail: "OK 181.49.124.240 (h3) 47 ms", latencyMs: 47 },
    });
    expect(tested.container.textContent).toContain("47 ms");
  });
});

describe("android connection tab accessibility", () => {
  it("is clean with a live session, a pinned peer and a test result", async () => {
    const { container } = renderTab({
      connected: true,
      running: true,
      settings: { routingMode: "proxy-only" as const, peer: "104.16.23.19:443" },
      runtime: { status: "connected" as const, endpoint: "104.16.23.19:443" },
      testResult: { detail: "OK 104.16.23.19 (h3) 47 ms", latencyMs: 47 },
    });
    // `color-contrast` is off for the same reason as the app's axe suite: jsdom
    // resolves no stylesheet, so it can only answer "unknown".
    const results = await axe.run(container, { rules: { "color-contrast": { enabled: false } } });
    const violations = results.violations.map(
      (v) => `${v.id} (${v.impact}): ${v.nodes.map((n) => n.target.join(" ")).join(" | ")}`,
    );
    expect(violations).toEqual([]);
  });
});
