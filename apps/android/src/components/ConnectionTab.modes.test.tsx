// @vitest-environment jsdom
/*
 * Item 8: "connected" is two different claims, and this tab printed the stronger
 * one in both modes. `tun` installs an Android VPN route through `VpnService`;
 * `proxy-only` binds the two loopback listeners the engine is always handed and
 * covers an application only once that application is pointed at them. The hero
 * read "VPN ACTIVE" / "Traffic Routed" with a badge of "CONNECTED" while the body
 * described a local proxy, so a user on a proxy-only session left this tab
 * believing every app on the phone was carried.
 *
 * So these tests mount the real component once per connected state and read the
 * surfaces that make the claim - the badge, the live region, the coverage row, the
 * routing card, the server chip and the two listener tags. Nothing here
 * re-derives the copy from a reimplementation of the component's logic: each
 * expectation is either read back through the helpers the component itself renders
 * from, or pinned to the string that is literally in `ConnectionTab.tsx` today.
 * Both directions are asserted on purpose - the wording is pinned, but a surface
 * that stops distinguishing the modes also stops matching the other mode's
 * expectation, which is the failure that actually happened.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import axe from "axe-core";
import { cleanup, render, screen } from "@testing-library/react";
import {
  ConnectionTab,
  coverageEvidence,
  PLATFORM,
  routingGrantCopy,
} from "./ConnectionTab";
// The connected claim is the shared table's; the phone's own contribution to it is
// the capability record it passes in. Both are asserted, because the pairing of the
// two is what used to be the lie.
import { connectedCopy, portStateCopy } from "@aether/ui/statusCopy";
import { defaults, initialRuntime } from "../types";
import type { RuntimeState, Settings } from "../types";

afterEach(() => cleanup());

type Mode = Settings["routingMode"];
type Status = RuntimeState["status"];

/** A session that is up, in the mode the test names. */
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
    // `admin` true: with the VPN permission ungranted the preset panel appends a
    // note about the *presets* keeping the whole-device mode, and this file's
    // negative assertions are about what the tab says about the live session.
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

function card(container: HTMLElement, category: string): HTMLElement {
  const el = Array.from(container.querySelectorAll(".bento-card")).find(
    (c) => text(c.querySelector(".bento-category")) === category,
  );
  if (!el) throw new Error(`no telemetry card headed "${category}"`);
  return el as HTMLElement;
}

function evidenceRow(container: HTMLElement, label: string): HTMLElement {
  const row = Array.from(container.querySelectorAll(".connection-evidence .endpoint-row")).find(
    (r) => text(r.querySelector("strong")) === label,
  );
  if (!row) throw new Error(`the status panel has no "${label}" row`);
  return row as HTMLElement;
}

/** Every place a connected session states what it covers, as rendered. */
function surfaces(container: HTMLElement) {
  const routing = card(container, "Routing mode");
  const coverage = evidenceRow(container, "What it covers");
  const listenerTag = (which: "HTTP" | "SOCKS") => {
    const tag = Array.from(container.querySelectorAll(".daemon-tag")).find((t) =>
      (t.textContent ?? "").startsWith(which),
    );
    if (!tag) throw new Error(`no ${which} listener tag on the engine card`);
    return text(tag.querySelector("strong"));
  };
  const topologyRow = (label: string) =>
    text(
      Array.from(routing.querySelectorAll(".topology-detail-row")).find((r) =>
        (r.querySelector("span")?.textContent ?? "").trim().startsWith(label),
      )?.querySelector("strong"),
    );

  return {
    eyebrow: text(container.querySelector(".eyebrow span")),
    heroTitle: text(container.querySelector(".connection-copy h2")),
    badge: text(container.querySelector(".switch-status-pill")),
    liveBody: text(container.querySelector('.connection-copy p[aria-live="polite"]')),
    stateValue: text(evidenceRow(container, "Connection").querySelector("code")),
    coverageValue: text(coverage.querySelector("code")),
    coverageDetail: text(coverage.querySelector(".endpoint-kind span")),
    routingHeadline: text(routing.querySelector(".bento-headline")),
    routingChip: text(routing.querySelector(".bento-chip")),
    routingGrant: text(routing.querySelector(".bento-footer")),
    leavesVia: topologyRow("TRAFFIC LEAVES VIA"),
    serverChip: text(card(container, "Server reached").querySelector(".bento-chip")),
    httpTag: listenerTag("HTTP"),
    socksTag: listenerTag("SOCKS"),
  };
}

type Surfaces = ReturnType<typeof surfaces>;
type SurfaceKey = keyof Surfaces;

/**
 * One row per surface that speaks of coverage: what it has to say when the session
 * routes the device, and what it has to say when the session only opened the local
 * listeners. A surface that renders the same string in both modes fails its own row
 * twice over, because the other mode's expectation is asserted as a negation.
 */
const CLAIM_SURFACES: { key: SurfaceKey; device: RegExp; local: RegExp }[] = [
  { key: "badge", device: /whole device vpn/i, local: /local proxy/i },
  { key: "liveBody", device: /every app on this device/i, local: /apps you point/i },
  { key: "coverageValue", device: /whole device/i, local: /apps you set up/i },
  { key: "coverageDetail", device: /android'?s vpn route/i, local: /127\.0\.0\.1:1820/i },
  { key: "routingHeadline", device: /whole device vpn/i, local: /local proxy only/i },
  { key: "routingChip", device: /android vpn/i, local: /local proxy/i },
  { key: "leavesVia", device: /android vpn/i, local: /proxy ports/i },
  { key: "serverChip", device: /vpn routing/i, local: /proxy ports open/i },
  { key: "httpTag", device: /tun routes/i, local: /listener open/i },
  { key: "socksTag", device: /tun routes/i, local: /listener open/i },
  { key: "routingGrant", device: /vpn permission/i, local: /adds no device-wide route/i },
];

/** Claims that are not true of any mode this app can run, so no render may make them. */
const NEVER_CLAIMED: RegExp[] = [
  /traffic routed/i,
  /vpn active/i,
  /route open/i,
  /traffic secure/i,
  /protected/i,
  /all apps are/i,
  /all (of )?your traffic/i,
  /full device routing/i,
  /granted by android/i,
  /proxy configured/i,
  /system[- ]wide/i,
];

/** The blanket routing claims, which belong to the VPN mode alone. */
const VPN_ONLY_CLAIMED: RegExp[] = [
  /whole[- ]device/i,
  /every app on this device/i,
  /all apps/i,
];

const LOCAL_MODES: Mode[] = ["proxy-only", "system-proxy"];

describe("android connected VPN mode (item 8)", () => {
  it("describes a session that routes the device, in the words the component uses", () => {
    const { container } = renderConnected("tun");
    const s = surfaces(container);

    expect(s.badge).toBe("CONNECTED · WHOLE DEVICE VPN");
    expect(s.liveBody).toBe("Every app on this device is going through the Android VPN.");
    expect(s.coverageValue).toBe("Whole device");
    expect(s.coverageDetail).toBe("Android's VPN route carries every app on this device.");
    expect(s.routingHeadline).toBe("Whole device VPN");
    expect(s.routingChip).toBe("ANDROID VPN");
    expect(s.leavesVia).toBe("Android VPN (VpnService)");
    expect(s.serverChip).toBe("VPN ROUTING");
    expect(s.httpTag).toBe("HTTP listener available (TUN routes)");
    expect(s.socksTag).toBe("SOCKS5 listener available (TUN routes)");

    // Every claim surface at once, and no local-proxy wording mixed in.
    for (const { key, device, local } of CLAIM_SURFACES) {
      expect(s[key], `the ${key} surface does not claim device routing`).toMatch(device);
      expect(s[key], `the ${key} surface also describes a local proxy`).not.toMatch(local);
    }
  });

  it("never reaches past what a VPN session can claim", () => {
    const { container } = renderConnected("tun");
    const whole = container.textContent ?? "";
    for (const pattern of [...NEVER_CLAIMED, /system proxy/i]) {
      expect(whole, `the tab claims ${pattern}`).not.toMatch(pattern);
    }
  });
});

describe("android connected local-proxy modes (item 8)", () => {
  it("says the listeners are open and that an app has to be pointed at them", () => {
    const { container } = renderConnected("proxy-only");
    const s = surfaces(container);

    expect(s.badge).toBe("CONNECTED · LOCAL PROXY");
    expect(s.liveBody).toBe(
      "Aether's local proxy ports are open. Only apps you point at them go through it — every other app on this device is untouched.",
    );
    expect(s.coverageValue).toBe("Apps you set up");
    expect(s.coverageDetail).toBe(
      "Give an app the proxy 127.0.0.1:1820 (HTTP) or :1819 (SOCKS5). Other apps keep going directly.",
    );
    expect(s.routingHeadline).toBe("Local proxy only");
    expect(s.routingChip).toBe("LOCAL PROXY");
    expect(s.leavesVia).toBe("Proxy ports on this device");
    expect(s.serverChip).toBe("PROXY PORTS OPEN");
    expect(s.httpTag).toBe("HTTP listener open");
    expect(s.socksTag).toBe("SOCKS5 listener open");

    for (const { key, device, local } of CLAIM_SURFACES) {
      expect(s[key], `the ${key} surface claims device routing in a proxy-only session`).not.toMatch(device);
      expect(s[key], `the ${key} surface does not describe the local proxy`).toMatch(local);
    }
  });

  it("makes no claim of device-wide routing or blanket safety anywhere in a local-proxy session", () => {
    for (const mode of LOCAL_MODES) {
      cleanup();
      const { container } = renderConnected(mode);
      const whole = container.textContent ?? "";
      const banned = mode === "system-proxy" ? NEVER_CLAIMED : [...NEVER_CLAIMED, ...VPN_ONLY_CLAIMED, /system proxy/i];
      for (const pattern of banned) {
        expect(whole, `${mode} prints a claim matching ${pattern}`).not.toMatch(pattern);
      }
    }
  });

  it("keeps the saved system-proxy profile honest about what Android honours", () => {
    const { container } = renderConnected("system-proxy");
    const s = surfaces(container);

    expect(s.badge).toBe("CONNECTED · LOCAL PROXY");
    expect(s.liveBody).toMatch(/does not let an app set the system proxy/i);
    expect(s.liveBody).toMatch(/only apps you point/i);
    expect(s.coverageDetail).toMatch(/no API for an app to set the system proxy/i);
    // Same badge as `proxy-only`, because the coverage really is the same: the
    // difference is only in how the stored mode got there.
    expect(s.coverageValue).toBe("Apps you set up");
    for (const { key, device } of CLAIM_SURFACES) {
      expect(s[key], `the ${key} surface claims device routing`).not.toMatch(device);
    }
  });
});

describe("android connected surfaces agree with each other (item 8)", () => {
  /**
   * The original lie was a *pairing*: the hero and the badge were updated while the
   * body was not, or the other way round, and each surface on its own read as
   * evidence. These read all of them off one render and require them to come from
   * the same source of truth.
   */
  const MODES: Mode[] = ["tun", "proxy-only", "system-proxy"];

  it("renders each surface with the string the component's own helper returns", () => {
    for (const mode of MODES) {
      cleanup();
      const { container } = renderConnected(mode);
      const s = surfaces(container);
      const copy = connectedCopy(mode, PLATFORM);
      const coverage = coverageEvidence(mode, defaults.httpPort, defaults.socksPort);

      expect(s.badge).toBe(copy.badge);
      expect(s.liveBody).toBe(copy.body);
      expect(s.coverageValue).toBe(coverage.value);
      expect(s.coverageDetail).toBe(coverage.detail);
      expect(s.routingGrant).toBe(routingGrantCopy(true, mode));
      expect(s.httpTag).toBe(portStateCopy(true, mode, PLATFORM).http);
      expect(s.socksTag).toBe(portStateCopy(true, mode, PLATFORM).socks);
    }
  });

  it("keeps the hero's own words about the state, never about the coverage", () => {
    for (const mode of MODES) {
      cleanup();
      const { container } = renderConnected(mode);
      const s = surfaces(container);
      // Mode-neutral by design: which of the two it is belongs to the badge and the
      // live body, and the state row repeats the same answer.
      expect(s.eyebrow).toBe("CONNECTED");
      expect(s.heroTitle).toBe("Connected");
      expect(s.stateValue).toBe("Connected");
      expect(s.badge.startsWith("CONNECTED")).toBe(true);
      // So the hero cannot out-claim the badge that sits beside it.
      expect(s.heroTitle).not.toMatch(/vpn|proxy|rout/i);
      expect(s.eyebrow).not.toMatch(/vpn|proxy|rout/i);
    }
  });

  it("drops the mode-specific claim the moment the session is not up", () => {
    for (const mode of MODES) {
      cleanup();
      const { container } = renderConnected(mode, "connecting");
      const s = surfaces(container);
      expect(s.badge).toBe("CONNECTING");
      expect(s.httpTag).toBe("idle");
      expect(s.socksTag).toBe("idle");
      // The coverage row is a property of the saved mode, not of the session, so it
      // may still answer: the claim that has to disappear is the connected one.
      expect(s.liveBody).not.toBe(connectedCopy(mode, PLATFORM).body);
    }
  });
});

describe("android connected modes reach the accessibility tree (item 8)", () => {
  /** What an assistive tech is actually told when the state changes. */
  function announced(container: HTMLElement) {
    const live = Array.from(container.querySelectorAll('[aria-live], [role="status"], [role="alert"]'));
    return { live, text: live.map((el) => text(el)).join(" ") };
  }

  it("announces the same sentence a sighted user reads, per mode", () => {
    for (const mode of ["tun", "proxy-only"] as Mode[]) {
      cleanup();
      const { container } = renderConnected(mode);
      const s = surfaces(container);
      const heard = announced(container);

      // Exactly one live region carries the connected claim, and it is the visible
      // hero paragraph - not a separate string written for screen readers.
      expect(heard.live).toHaveLength(1);
      expect(heard.live[0]).toBe(container.querySelector(".connection-copy p"));
      expect(heard.text).toBe(s.liveBody);
      expect(heard.text).toBe(connectedCopy(mode, PLATFORM).body);
    }
  });

  it("makes the live announcement itself distinguish the two modes", () => {
    cleanup();
    const vpn = announced(renderConnected("tun").container);
    cleanup();
    const local = announced(renderConnected("proxy-only").container);

    expect(vpn.text).not.toBe(local.text);
    expect(vpn.text).toMatch(/every app on this device/i);
    expect(local.text).toMatch(/local proxy ports are open|only apps you point/i);
    expect(local.text).not.toMatch(/every app on this device|whole device/i);
  });

  it("hides none of the claim-bearing surfaces from assistive tech", () => {
    const { container } = renderConnected("proxy-only");
    const claimants = [
      container.querySelector(".switch-status-pill"),
      container.querySelector('.connection-copy p[aria-live="polite"]'),
      container.querySelector(".connection-copy h2"),
      evidenceRow(container, "What it covers"),
      card(container, "Routing mode"),
      card(container, "Server reached"),
    ];
    for (const el of claimants) {
      expect(el, "the surface carrying the connected claim is not rendered").not.toBeNull();
      expect(el?.closest('[aria-hidden="true"]'), `"${text(el)}" is hidden from assistive tech`).toBeNull();
    }
  });

  it("answers the same way inside the landmarks a screen reader jumps to", () => {
    const { container } = renderConnected("proxy-only");
    const s = surfaces(container);

    const status = screen.getByRole("region", { name: "Connection status" });
    const details = screen.getByRole("region", { name: "Connection details" });

    // The landmark text is the visible text: an a11y user gets the coverage answer
    // and the listener tags, not a mode-neutral paraphrase of them.
    expect(status.textContent).toContain(s.coverageValue);
    expect(status.textContent).toContain(s.coverageDetail);
    expect(details.textContent).toContain(s.routingHeadline);
    expect(details.textContent).toContain(s.routingChip);
    expect(details.textContent).toContain(s.httpTag);
    expect(details.textContent).toContain(s.leavesVia);
    // And the connect control's own name says nothing about routing mode either way.
    expect(screen.getByRole("button", { name: "Disconnect Aether" })).not.toBeNull();
  });

  it("stays clean on axe in both connected modes", async () => {
    for (const mode of ["tun", "proxy-only"] as Mode[]) {
      cleanup();
      const { container } = renderConnected(mode);
      // `color-contrast` is off for the same reason as the app's other axe suites:
      // jsdom resolves no stylesheet, so the rule can only answer "unknown".
      const results = await axe.run(container, { rules: { "color-contrast": { enabled: false } } });
      const violations = results.violations.map(
        (v) => `${v.id} (${v.impact}): ${v.nodes.map((n) => n.target.join(" ")).join(" | ")}`,
      );
      expect(violations, `${mode} renders an inaccessible tree`).toEqual([]);
    }
  });
});
