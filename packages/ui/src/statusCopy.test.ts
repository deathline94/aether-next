import { describe, expect, it } from "vitest";
import { RUNTIME_STATUSES } from "./index";
import { ROUTING_MODES, TUNNEL_PROTOCOLS } from "./enums";
import {
  cipherSettingCopy,
  connectedCopy,
  coverageClaim,
  carrierChip,
  endpointClaim,
  engineStateCopy,
  fragSettingCopy,
  heroCopy,
  LOG_FILTER_LABELS,
  noiseSettingCopy,
  portStateCopy,
  processStateCopy,
  protocolHeadline,
  roundTripLabel,
  startHint,
  stateAnswer,
  stateDetail,
  streamLabel,
  transportName,
} from "./statusCopy";
import type { PlatformCapabilities } from "./statusCopy";

/*
 * The table itself, tested as a table: every state, mode and protocol either has
 * an answer or this file says so.
 *
 * It lives in the package because that is where the copy now is, and it is run from
 * both apps' suites (see each `vite.config.ts`'s test include), which is the only
 * way it can mean what it asserts: one definition, two surfaces.
 *
 * The two records below stand in for what each app exports as `PLATFORM`. That
 * coupling is not implicit - each app's own copy test asserts its record's values,
 * so a platform record edited here, there or nowhere fails.
 */
const PHONE: PlatformCapabilities = {
  canSetSystemProxy: false,
  routeName: "the Android VPN",
  routeSubject: "Android's VPN route",
  actionVerb: "Tap",
};

const DESKTOP: PlatformCapabilities = {
  canSetSystemProxy: true,
  routeName: "the tunnel device",
  routeSubject: "The tunnel device",
  actionVerb: "Click",
};

const PLATFORMS: [string, PlatformCapabilities][] = [
  ["phone", PHONE],
  ["desktop", DESKTOP],
];

describe("the status table", () => {
  it("has an answer for every status the shell can report", () => {
    for (const status of RUNTIME_STATUSES) {
      const hero = heroCopy(status);
      expect(hero.eyebrow, `${status} has no eyebrow`).not.toBe("");
      expect(hero.title, `${status} has no title`).not.toBe("");
      expect(hero.badge, `${status} has no badge`).not.toBe("");
      expect(stateAnswer(status), `${status} has no short answer`).not.toBe("");
      expect(stateDetail(status, ""), `${status} has no fallback detail`).not.toBe("");
      expect(streamLabel(status), `${status} has no console tag`).not.toBe("");
    }
  });

  it("tells the four statuses apart, and answers one it has never seen", () => {
    const badges = RUNTIME_STATUSES.map((s) => heroCopy(s).badge);
    expect(new Set(badges).size).toBe(RUNTIME_STATUSES.length);
    // A status the frame guard somehow let through is unknown, not undefined: a
    // miss used to throw during a background event and take the window down.
    expect(heroCopy("reconnecting").badge).toBe("STATE UNKNOWN");
    expect(stateAnswer("reconnecting")).toBe("Unknown");
    expect(streamLabel("reconnecting")).toBe("No session running");
  });

  it("never calls a state that is not up live, active, routed or secure", () => {
    for (const status of ["disconnected", "connecting", "error"]) {
      const said = [heroCopy(status).badge, heroCopy(status).title, streamLabel(status)].join(" ");
      expect(said, `${status} over-claims`).not.toMatch(/live|secure|active|protected|routed/i);
    }
    expect(streamLabel("connected")).toMatch(/live/i);
  });
});

describe("the routing table", () => {
  it("has an answer for every mode on every platform", () => {
    for (const [name, platform] of PLATFORMS) {
      for (const mode of ROUTING_MODES) {
        const copy = connectedCopy(mode, platform);
        const listeners = portStateCopy(true, mode, platform);
        const coverage = coverageClaim(mode, platform, 1820, 1819);
        expect(copy.badge, `${name}/${mode} has no badge`).not.toBe("");
        expect(copy.body, `${name}/${mode} has no body`).not.toBe("");
        expect(listeners.http, `${name}/${mode} has no HTTP line`).not.toBe("");
        expect(listeners.socks, `${name}/${mode} has no SOCKS line`).not.toBe("");
        expect(coverage.value, `${name}/${mode} has no coverage answer`).not.toBe("");
        expect(coverage.detail, `${name}/${mode} has no coverage detail`).not.toBe("");
      }
    }
  });

  it("says a device is covered only in the mode that routes it, on either platform", () => {
    for (const [, platform] of PLATFORMS) {
      expect(connectedCopy("tun", platform).body).toMatch(/every app/i);
      for (const mode of ["proxy-only", "system-proxy"] as const) {
        const said = JSON.stringify([
          connectedCopy(mode, platform),
          coverageClaim(mode, platform, 1820, 1819),
          portStateCopy(true, mode, platform),
        ]);
        expect(said, `${mode} claims device routing`).not.toMatch(/every app|whole device|all apps/i);
      }
    }
  });

  it("keeps the platform difference in the one arm that has one", () => {
    // The listener claim in `tun` and `proxy-only` is the same observable fact on
    // both surfaces, so the strings must be identical...
    for (const mode of ["tun", "proxy-only"] as const) {
      expect(portStateCopy(true, mode, PHONE)).toEqual(portStateCopy(true, mode, DESKTOP));
    }
    // ...and the `system-proxy` arm is the single place a platform may answer
    // differently, because only one of them can write the setting at all.
    expect(portStateCopy(true, "system-proxy", DESKTOP).http).toMatch(/configured/);
    expect(portStateCopy(true, "system-proxy", PHONE).http).not.toMatch(/configured/);
    expect(connectedCopy("system-proxy", PHONE).body).toMatch(/does not let an app set the system proxy/i);
    expect(connectedCopy("system-proxy", DESKTOP).body).toMatch(/system proxy is set/i);
    // An idle port is idle on either platform.
    for (const mode of ROUTING_MODES) {
      expect(portStateCopy(false, mode, PHONE)).toEqual(portStateCopy(false, mode, DESKTOP));
    }
  });
});

describe("the protocol table", () => {
  it("names the protocol, the carrier and the transport of every protocol", () => {
    for (const protocol of TUNNEL_PROTOCOLS) {
      for (const transport of ["h3", "h2"] as const) {
        const settings = { protocol, transport, noize: "medium" as const, quicInitialFrag: true, quicInitialFragSize: 96 };
        expect(protocolHeadline(settings), `${protocol} has no headline`).not.toBe("");
        expect(carrierChip(settings), `${protocol}/${transport} has no carrier`).not.toBe("");
        expect(transportName(settings), `${protocol}/${transport} has no transport`).not.toBe("");
        expect(noiseSettingCopy(settings)).not.toBe("");
        expect(fragSettingCopy(settings)).not.toBe("");
        expect(cipherSettingCopy(protocol)).not.toBe("");
      }
    }
    // A protocol's headline is its name, never the carrier glued onto it.
    expect(protocolHeadline({ protocol: "masque", transport: "h3" })).toBe("MASQUE");
    expect(protocolHeadline({ protocol: "masque", transport: "h2" })).toBe("MASQUE");
    expect(protocolHeadline({ protocol: "gool", transport: "h2" })).not.toMatch(/WARP/);
  });

  it("calls a setting inert when the transport cannot use it", () => {
    expect(noiseSettingCopy({ protocol: "masque", transport: "h2", noize: "aggressive" })).toMatch(/off/i);
    expect(noiseSettingCopy({ protocol: "masque", transport: "h3", noize: "off" })).toBe("Off");
    expect(noiseSettingCopy({ protocol: "masque", transport: "h3", noize: "medium" })).toContain("medium");
    expect(fragSettingCopy({ quicInitialFrag: false, quicInitialFragSize: 96 })).toBe("Off");
  });
});

describe("the process and measurement table", () => {
  it("answers an absent measurement with the absence, not a number", () => {
    expect(roundTripLabel(null)).toBe("not measured");
    expect(roundTripLabel(undefined)).toBe("not measured");
    expect(roundTripLabel(0)).toBe("not measured");
    expect(roundTripLabel(-1)).toBe("not measured");
    expect(roundTripLabel(47.6)).toBe("48 ms");
    expect(endpointClaim(null, false).answer).toBe("Not connected");
    expect(processStateCopy(null).chip).toBe("STOPPED");
    expect(processStateCopy(4242).headline).toContain("4242");
  });

  it("describes the engine as it is, and never as doing work it is not", () => {
    expect(engineStateCopy(false, false)).toMatch(/stopped/i);
    expect(engineStateCopy(true, true)).toMatch(/carrying/i);
    for (const state of [engineStateCopy(false, false), engineStateCopy(false, true)]) {
      expect(state).not.toMatch(/carrying|processing/i);
    }
  });
});

describe("the console table", () => {
  it("labels all four filters, uniquely, without an enum identifier", () => {
    expect(LOG_FILTER_LABELS).toHaveLength(4);
    const ids = LOG_FILTER_LABELS.map((f) => f.id);
    const labels = LOG_FILTER_LABELS.map((f) => f.label);
    expect(new Set(ids).size).toBe(4);
    expect(new Set(labels).size).toBe(4);
    // Three of the four ids are internal names, and printing them *was* the defect
    // this table replaced. `errors` is the one whose label is legitimately also the
    // plain English word, so the check is against the stored token's spelling.
    for (const { id, label } of LOG_FILTER_LABELS) {
      if (id === "errors") continue;
      expect(label.toLowerCase(), `${id} is its own label`).not.toBe(id);
    }
    expect(ids).toEqual(["milestones", "hits", "errors", "raw"]);
  });
});

describe("startHint", () => {
  it("provides location-independent guidance on what connection covers on all platforms", () => {
    for (const [, platform] of PLATFORMS) {
      const hint = startHint(platform);
      expect(hint).toContain(`${platform.actionVerb} the power button to connect.`);
      expect(hint).toContain("connection status shows what that covers on this device.");
      expect(hint).not.toMatch(/below|above|left|right/i);
    }
  });
});
