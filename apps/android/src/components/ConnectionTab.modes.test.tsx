// @vitest-environment jsdom
/*
 * Truthfulness of connected routing claims on Android (Nordic Mist layout):
 * `tun` routes the full device via Android VpnService ("Protected" / "Every app routed");
 * `proxy-only` and `system-proxy` only open loopback proxy listeners ("Connected" /
 * "Local proxy ports only" / "Local Proxy Only"). Local-proxy modes must never
 * claim "Protected" or device-wide routing anywhere in the rendered DOM or live region.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import axe from "axe-core";
import { cleanup, render, screen } from "@testing-library/react";
import { ConnectionTab, PLATFORM } from "./ConnectionTab";
import { nordicHeroHeadline, nordicRoutingSummary } from "@aether/ui/statusCopy";
import { defaults, initialRuntime } from "../types";
import type { RuntimeState, Settings } from "../types";

afterEach(() => cleanup());

type Mode = Settings["routingMode"];
type Status = RuntimeState["status"];

function renderConnected(mode: Mode, status: Status = "connected") {
  const props = {
    settings: { ...defaults, routingMode: mode },
    runtime: {
      ...initialRuntime,
      status,
      detail: status === "connected" ? "Session is up." : initialRuntime.detail,
      pid: 4242,
      endpoint: "104.16.23.19:443",
    },
    busy: false,
    testBusy: false,
    connected: status === "connected",
    running: true,
    settingsLocked: false,
    settingsLoaded: true,
    admin: true,
    online: true,
    testResult: null,
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

const text = (el: Element | null | undefined) => (el?.textContent ?? "").trim();

function groupedValue(container: HTMLElement, label: string): string {
  const row = Array.from(container.querySelectorAll(".grouped-row-btn")).find(
    (r) => text(r.querySelector(".grouped-row-label")) === label,
  );
  if (!row) throw new Error(`no grouped row labeled "${label}"`);
  return text(row.querySelector(".grouped-row-value span"));
}

function surfaces(container: HTMLElement) {
  return {
    heroTitle: text(container.querySelector(".mobile-hero-title")),
    badge: text(container.querySelector(".status-rtt-pill")),
    liveBody: text(container.querySelector('.mobile-hero-subtitle[aria-live="polite"]')),
    routingSummary: groupedValue(container, "Routing"),
    socksAddr: text(container.querySelector(".grouped-row-static code")),
  };
}

const NEVER_CLAIMED: RegExp[] = [
  /traffic routed/i,
  /vpn active/i,
  /route open/i,
  /traffic secure/i,
  /all apps are/i,
  /all (of )?your traffic/i,
  /granted by android/i,
  /proxy configured/i,
  /system[- ]wide/i,
];

const LOCAL_MODES: Mode[] = ["proxy-only", "system-proxy"];

describe("android connected VPN mode (item 8)", () => {
  it("describes a session that routes the device", () => {
    const { container } = renderConnected("tun");
    const s = surfaces(container);

    expect(s.heroTitle).toBe("Protected");
    expect(s.liveBody).toMatch(/every app routed/i);
    expect(s.routingSummary).toBe("Full Device VPN");
    expect(s.liveBody).not.toMatch(/local proxy/i);
  });

  it("never makes unverifiable or Windows system-proxy claims in VPN mode", () => {
    const { container } = renderConnected("tun");
    const whole = container.textContent ?? "";
    for (const pattern of [...NEVER_CLAIMED, /system proxy/i]) {
      expect(whole, `the tab claims ${pattern}`).not.toMatch(pattern);
    }
  });
});

describe("android connected local-proxy modes (item 8)", () => {
  it("says listeners are open without claiming full-device routing", () => {
    const { container } = renderConnected("proxy-only");
    const s = surfaces(container);

    expect(s.heroTitle).toBe("Connected");
    expect(s.liveBody).toMatch(/local proxy ports only/i);
    expect(s.routingSummary).toBe("Local Proxy Only");
    expect(s.socksAddr).toBe(`127.0.0.1:${defaults.socksPort}`);
    expect(container.textContent ?? "").not.toMatch(/protected|every app|full device vpn/i);
  });

  it("never claims device-wide routing or blanket safety in local-proxy modes", () => {
    for (const mode of LOCAL_MODES) {
      cleanup();
      const { container } = renderConnected(mode);
      const whole = container.textContent ?? "";
      for (const pattern of [...NEVER_CLAIMED, /protected/i, /full device vpn/i, /every app/i, /system proxy/i]) {
        expect(whole, `${mode} prints a claim matching ${pattern}`).not.toMatch(pattern);
      }
    }
  });

  it("keeps the saved system-proxy profile honest about what Android honours", () => {
    const { container } = renderConnected("system-proxy");
    const s = surfaces(container);

    expect(s.heroTitle).toBe("Connected");
    expect(s.routingSummary).toBe("Local Proxy Only");
    expect(s.liveBody).toMatch(/local proxy ports only/i);
  });
});

describe("android connected surfaces agree with shared helpers", () => {
  const MODES: Mode[] = ["tun", "proxy-only", "system-proxy"];

  it("renders the headline and routing label from @aether/ui", () => {
    for (const mode of MODES) {
      cleanup();
      const { container } = renderConnected(mode);
      const s = surfaces(container);
      expect(s.heroTitle).toBe(nordicHeroHeadline("connected", mode, PLATFORM.canSetSystemProxy));
      expect(s.routingSummary).toBe(nordicRoutingSummary(mode, "android"));
    }
  });

  it("drops the connected headline the moment the session is not up", () => {
    for (const mode of MODES) {
      cleanup();
      const { container } = renderConnected(mode, "connecting");
      const s = surfaces(container);
      expect(s.heroTitle).toBe("Connecting…");
      expect(s.badge).toBe("Connecting");
      expect(s.liveBody).not.toMatch(/every app routed|local proxy ports only/i);
    }
  });
});

describe("android connected modes reach the accessibility tree (item 8)", () => {
  function announced(container: HTMLElement) {
    const live = Array.from(container.querySelectorAll('[aria-live], [role="status"], [role="alert"]'));
    return { live, text: live.map((el) => text(el)).join(" ") };
  }

  it("announces one live sentence matching what is visually rendered", () => {
    for (const mode of ["tun", "proxy-only"] as Mode[]) {
      cleanup();
      const { container } = renderConnected(mode);
      const s = surfaces(container);
      const heard = announced(container);

      expect(heard.live).toHaveLength(1);
      expect(heard.live[0]).toBe(container.querySelector(".mobile-hero-subtitle"));
      expect(heard.text).toBe(s.liveBody);
    }
  });

  it("makes the live announcement itself distinguish the two modes", () => {
    cleanup();
    const vpn = announced(renderConnected("tun").container);
    cleanup();
    const local = announced(renderConnected("proxy-only").container);

    expect(vpn.text).not.toBe(local.text);
    expect(vpn.text).toMatch(/every app routed/i);
    expect(local.text).toMatch(/local proxy ports only/i);
    expect(local.text).not.toMatch(/every app routed/i);
  });

  it("hides none of the claim-bearing surfaces from assistive tech", () => {
    const { container } = renderConnected("proxy-only");
    const claimants = [
      container.querySelector(".status-rtt-pill"),
      container.querySelector('.mobile-hero-subtitle[aria-live="polite"]'),
      container.querySelector(".mobile-hero-title"),
      container.querySelector('section[aria-label="Quick configuration"]'),
    ];
    for (const el of claimants) {
      expect(el).not.toBeNull();
      expect(el?.closest('[aria-hidden="true"]')).toBeNull();
    }
    expect(screen.getByRole("button", { name: "Disconnect Aether" })).not.toBeNull();
  });

  it("stays clean on axe in both connected modes", async () => {
    for (const mode of ["tun", "proxy-only"] as Mode[]) {
      cleanup();
      const { container } = renderConnected(mode);
      const results = await axe.run(container, { rules: { "color-contrast": { enabled: false } } });
      const violations = results.violations.map(
        (v) => `${v.id} (${v.impact}): ${v.nodes.map((n) => n.target.join(" ")).join(" | ")}`,
      );
      expect(violations, `${mode} renders an inaccessible tree`).toEqual([]);
    }
  });
});
