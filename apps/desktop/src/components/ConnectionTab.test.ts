import { describe, expect, it } from "vitest";
import { defaults } from "../types";
import type { Settings } from "../types";
import { PLATFORM, START_HINT } from "./ConnectionTab";
import {
  cipherSettingCopy,
  connectedCopy,
  coverageClaim,
  endpointClaim,
  heroCopy,
  portStateCopy,
  roundTripLabel,
  startHint,
  stateAnswer,
  transportName,
} from "@aether/ui/statusCopy";
import { RUNTIME_STATUSES } from "@aether/ui";
import { ROUTING_MODES } from "@aether/ui/enums";

/*
 * The desktop half of the shared-copy contract. `ConnectionTab.tsx` renders these
 * functions and nothing else, so this file is not re-testing prose: it asks whether
 * the desktop's own capability record is the one the copy was written for, and
 * whether every state and mode the shell can report has an answer.
 *
 * The same strings are pinned from `packages/ui/src/statusCopy.test.ts` for both
 * platforms at once; what is desktop-specific here is the record (`proxy.rs` really
 * does write the system proxy, so this surface may say "configured") and the fact
 * that the tab renders the shared answer rather than a local one.
 */

const at = (over: Partial<Settings>): Settings => ({ ...defaults, ...over });

describe("the desktop's platform record", () => {
  it("is the one the copy was written for", () => {
    // Windows is the surface that *can* set the system proxy; if this ever flips,
    // the `system-proxy` arms of `connectedCopy`/`portStateCopy` start denying a
    // thing this app genuinely does, and no test on the phone would notice.
    expect(PLATFORM.canSetSystemProxy).toBe(true);
    expect(PLATFORM.actionVerb).toBe("Click");
    expect(PLATFORM.routeName).toBe("the tunnel device");
  });

  it("says what the hero says, in this surface's verb", () => {
    expect(START_HINT).toBe(startHint(PLATFORM));
    expect(START_HINT.startsWith("Click")).toBe(true);
    expect(START_HINT).toContain("power button");
  });
});

describe("every state and mode has an answer", () => {
  it("answers each of the four statuses with three non-empty lines", () => {
    const seen = new Set<string>();
    for (const status of RUNTIME_STATUSES) {
      const hero = heroCopy(status);
      expect(hero.eyebrow.length).toBeGreaterThan(0);
      expect(hero.title.length).toBeGreaterThan(0);
      expect(hero.badge.length).toBeGreaterThan(0);
      seen.add(hero.badge);
    }
    // One badge for "connecting" and "failed" would be the same bug in new clothes.
    expect(seen.size).toBe(RUNTIME_STATUSES.length);
  });

  it("answers each routing mode on this platform, badge and body both", () => {
    for (const mode of ROUTING_MODES) {
      const copy = connectedCopy(mode, PLATFORM);
      expect(copy.badge.length).toBeGreaterThan(0);
      expect(copy.body.length).toBeGreaterThan(0);
      const listeners = portStateCopy(true, mode, PLATFORM);
      expect(listeners.http.length).toBeGreaterThan(0);
      expect(listeners.socks.length).toBeGreaterThan(0);
    }
  });

  it("claims a configured system proxy only where this platform sets one", () => {
    const sys = portStateCopy(true, "system-proxy", PLATFORM);
    expect(sys.http).toBe("HTTP proxy configured");
    const only = portStateCopy(true, "proxy-only", PLATFORM);
    expect(only.http).toMatch(/listener open/);
    expect(only.http).not.toMatch(/configured/);
    const tun = portStateCopy(true, "tun", PLATFORM);
    expect(tun.socks).toMatch(/listener/);
    expect(tun.socks).not.toMatch(/configured/);
    expect(portStateCopy(false, "system-proxy", PLATFORM)).toEqual({ http: "idle", socks: "idle" });
  });

  it("never says every app is covered outside the mode that routes them", () => {
    for (const mode of ["proxy-only", "system-proxy"] as const) {
      expect(connectedCopy(mode, PLATFORM).body).not.toMatch(/every app|whole device/i);
      expect(coverageClaim(mode, PLATFORM, defaults.httpPort, defaults.socksPort).answer).not.toMatch(/whole device/i);
    }
    expect(connectedCopy("tun", PLATFORM).body).toMatch(/every app/i);
  });
});

describe("the tiles that restate a setting", () => {
  it("refuses to name a cipher this app has not observed", () => {
    expect(cipherSettingCopy(at({ protocol: "masque" }).protocol)).toBe("Chosen with the server");
    expect(cipherSettingCopy(at({ protocol: "wireguard" }).protocol)).toContain("ChaCha20");
    expect(cipherSettingCopy(at({ protocol: "gool" }).protocol)).toContain("ChaCha20");
  });

  it("says which server the session carries traffic to, or nothing", () => {
    expect(endpointClaim(null, false).answer).toBe("Not connected");
    expect(endpointClaim(null, true).answer).toBe("Finding one…");
    expect(endpointClaim("104.16.23.19:443", true).answer).toBe("104.16.23.19:443");
    expect(stateAnswer("connected")).toBe("Connected");
  });

  it("prints a measured round-trip, and the honest absence otherwise", () => {
    expect(roundTripLabel(17)).toBe("17 ms");
    // Not 0 ms, which would read as an excellent link: a reading of zero is the
    // shell saying it timed nothing.
    expect(roundTripLabel(0)).toBe("not measured");
    expect(roundTripLabel(null)).toBe("not measured");
    expect(roundTripLabel(Number.NaN)).toBe("not measured");
  });

  it("names the transport each protocol runs on", () => {
    expect(transportName(at({ protocol: "masque", transport: "h3" }))).toBe("HTTP/3");
    expect(transportName(at({ protocol: "gool" }))).toBe("WireGuard in WireGuard");
  });
});
