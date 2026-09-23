// @vitest-environment jsdom
import { describe, expect, it } from "vitest";
import { defaults } from "../types";
import type { Settings } from "../types";
// The claims come from the table; what is asserted here is that *this* app's
// capability record is the one the table was asked about, and that every state and
// mode the phone can report has an answer. The package's own table test makes the
// same calls for the desktop's record and requires the two to agree.
import { PLATFORM } from "./ConnectionTab";
import { coverageEvidence, endpointEvidence, routingGrantCopy, stateEvidence } from "./ConnectionTab";
import { ipFamilyLabel } from "@aether/ui/enums";
import {
  carrierChip,
  connectedCopy,
  portStateCopy,
  protocolHeadline,
  transportName,
} from "@aether/ui/statusCopy";

const withPatch = (patch: Partial<Settings>): Settings => ({ ...defaults, ...patch });

describe("the phone's platform record", () => {
  it("is the one the copy was written for", () => {
    // Android exposes no API by which an app may set the system proxy, so a stored
    // `system-proxy` profile is the local listeners here and the copy may not say
    // anything else. Flip this flag and the shared table starts claiming a Windows
    // behaviour on the phone.
    expect(PLATFORM.canSetSystemProxy).toBe(false);
    expect(PLATFORM.actionVerb).toBe("Tap");
    expect(PLATFORM.routeName).toBe("the Android VPN");
  });
});

describe("android carrier and transport labels", () => {
  it("names the carrier each protocol actually runs", () => {
    expect(carrierChip(withPatch({ protocol: "masque", transport: "h3" }))).toBe("QUIC/UDP");
    expect(carrierChip(withPatch({ protocol: "masque", transport: "h2" }))).toBe("H2/TLS");
    expect(carrierChip(withPatch({ protocol: "wireguard", transport: "h3" }))).toBe("WIREGUARD");
    // The defect: two ternary arms meant every non-masque protocol fell through
    // to WIREGUARD, so a Gool session — headline "WARP-in-WARP" on the very same
    // card — advertised a carrier it is not.
    expect(carrierChip(withPatch({ protocol: "gool", transport: "h3" }))).not.toBe("WIREGUARD");
    expect(carrierChip(withPatch({ protocol: "gool", transport: "h3" }))).toBe("QUIC/UDP x2");
  });

  it("names the transport of each protocol rather than defaulting to WireGuard", () => {
    expect(transportName(withPatch({ protocol: "gool", transport: "h3" }))).toBe("WireGuard in WireGuard");
    expect(transportName(withPatch({ protocol: "masque", transport: "h2" }))).toBe("HTTP/2");
    expect(transportName(withPatch({ protocol: "wireguard", transport: "h2" }))).toBe("UDP WireGuard");
  });

  it("headlines the protocol by name instead of gluing two identifiers together", () => {
    // "MASQUE H3" and "WARP-in-WARP" were the protocol's own shorthand printed as
    // a headline; the carrier it rides is spelled out on the line under it.
    expect(protocolHeadline(withPatch({ protocol: "masque", transport: "h3" }))).toBe("MASQUE");
    expect(protocolHeadline(withPatch({ protocol: "gool", transport: "h3" }))).toBe("Gool (double WireGuard)");
    expect(protocolHeadline(withPatch({ protocol: "wireguard", transport: "h3" }))).toBe("WireGuard");
  });
});

/*
 * The status panel above the fold is built from these lines, so a wrong one is a
 * wrong answer to "am I covered?" — the only question the tab exists to answer.
 * `coverageEvidence` in particular has to name the ports, because the sentence is
 * the instruction the user then carries to another app.
 */
describe("android connection status evidence", () => {
  it("states the reported connection state and never a stronger one", () => {
    expect(stateEvidence("disconnected", "Ready").value).toBe("Not connected");
    expect(stateEvidence("connecting", "").value).toBe("Connecting");
    expect(stateEvidence("connected", "").value).toBe("Connected");
    expect(stateEvidence("error", "Edge unreachable").detail).toBe("Edge unreachable");
    // An empty frame cannot render an empty row.
    expect(stateEvidence("connecting", "   ").detail).toBe("Starting the engine…");
  });

  it("says whole-device coverage only of the mode that installs a route", () => {
    const tun = coverageEvidence("tun", 1820, 1819);
    expect(tun.value).toBe("Whole device");
    expect(tun.detail).toMatch(/every app/i);

    for (const mode of ["proxy-only", "system-proxy"] as const) {
      const local = coverageEvidence(mode, 1820, 1819);
      expect(local.value).toBe("Apps you set up");
      expect(local.detail).toContain("127.0.0.1:1820");
      expect(local.detail).toContain(":1819");
      expect(local.detail).not.toMatch(/every app|whole device|all apps/i);
    }
  });

  it("keeps the system-proxy row honest about what Android lets an app set", () => {
    expect(coverageEvidence("system-proxy", 1820, 1819).detail).toMatch(/no API|does not let/i);
  });

  it("shows the server only once the engine reports one", () => {
    expect(endpointEvidence(null, false).value).toBe("Not connected");
    expect(endpointEvidence(null, true).value).toBe("Finding one…");
    expect(endpointEvidence("104.16.23.19:443", true).value).toBe("104.16.23.19:443");
  });

  it("spells the address family out instead of printing the stored token", () => {
    // `V4` off `settings.ipVersion.toUpperCase()` is a field value, not an answer.
    expect(ipFamilyLabel("v4")).toBe("IPv4");
    expect(ipFamilyLabel("v6")).toBe("IPv6");
    expect(ipFamilyLabel("both")).toBe("IPv4 + IPv6");
  });
});

describe("android connected-state copy", () => {
  it("claims the VPN only in the mode that runs one", () => {
    expect(connectedCopy("tun", PLATFORM).body).toMatch(/every app/i);
    for (const mode of ["proxy-only", "system-proxy"] as const) {
      const copy = connectedCopy(mode, PLATFORM).body;
      expect(copy).toMatch(/apps you point|only apps/i);
      expect(copy).not.toMatch(/routing this device's traffic|whole device/i);
    }
  });

  it("says what a proxy-only grant is not, and what a tun grant is", () => {
    expect(routingGrantCopy(true, "proxy-only")).toMatch(/no device-wide route|adds no route/i);
    expect(routingGrantCopy(true, "tun")).toMatch(/granted/i);
    expect(routingGrantCopy(false, "tun")).toMatch(/asks|when you connect/i);
  });

  it("labels a bound listener as a listener, not as a configured proxy", () => {
    expect(portStateCopy(false, "tun", PLATFORM)).toEqual({ http: "idle", socks: "idle" });
    expect(portStateCopy(true, "proxy-only", PLATFORM).http).toBe("HTTP listener open");
    expect(portStateCopy(true, "tun", PLATFORM).http).toMatch(/TUN routes/);
    // The one arm Android must never take: the OS proxy is not something this
    // platform lets an app write, so "configured" would be a false claim.
    expect(portStateCopy(true, "system-proxy", PLATFORM).http).not.toMatch(/configured/);
  });
});
