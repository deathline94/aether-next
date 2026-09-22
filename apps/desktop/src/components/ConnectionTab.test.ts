import { describe, expect, it } from "vitest";
import {
  carrierChip,
  formatRttMs,
  ipStackCopy,
  portStateCopy,
  transportChip,
} from "./ConnectionTab";
import { defaults } from "../types";
import type { Settings } from "../types";

const at = (over: Partial<Settings>): Settings => ({ ...defaults, ...over });

describe("formatRttMs", () => {
  it("prints a measured round-trip and nothing else", () => {
    expect(formatRttMs(17)).toBe("17 ms");
    expect(formatRttMs(0)).toBe("0 ms");
  });

  it("says 'not measured' when the engine measured nothing", () => {
    // Not 0 ms, which would read as an excellent link.
    expect(formatRttMs(null)).toBe("not measured");
    expect(formatRttMs(undefined as unknown as number | null)).toBe("not measured");
    expect(formatRttMs(Number.NaN)).toBe("not measured");
  });
});

describe("carrierChip / transportChip", () => {
  it("names the carrier the session actually runs", () => {
    // The chip had two arms only, so a Gool session advertised WIREGUARD.
    expect(carrierChip(at({ protocol: "masque", transport: "h3" }))).toBe("QUIC/UDP");
    expect(carrierChip(at({ protocol: "masque", transport: "h2" }))).toBe("H2/TLS");
    expect(carrierChip(at({ protocol: "wireguard" }))).toBe("WIREGUARD/UDP");
    expect(carrierChip(at({ protocol: "gool" }))).toBe("WARP-IN-WARP");
    expect(transportChip(at({ protocol: "gool" }))).toBe("WireGuard (in WARP)");
    expect(transportChip(at({ protocol: "masque", transport: "h3" }))).toBe("HTTP/3");
  });
});

describe("portStateCopy", () => {
  it("is idle until the session is up", () => {
    expect(portStateCopy(false, "system-proxy")).toEqual({ http: "idle", socks: "idle" });
  });

  it("only claims a configured system proxy in system-proxy mode", () => {
    // The tiles keyed on `status === "connected"`, so proxy-only and TUN sessions
    // both read "HTTP proxy configured" while `connectedCopy` on the same screen
    // said nothing is routed until an application points at the listeners.
    const sys = portStateCopy(true, "system-proxy");
    expect(sys.http).toBe("HTTP proxy configured");
    const only = portStateCopy(true, "proxy-only");
    expect(only.http).toMatch(/listener open/);
    expect(only.http).not.toMatch(/configured/);
    const tun = portStateCopy(true, "tun");
    expect(tun.socks).toMatch(/listener/);
    expect(tun.socks).not.toMatch(/configured/);
  });
});

describe("ipStackCopy", () => {
  it("labels every address family the shell can report", () => {
    expect(ipStackCopy("v4")).toBe("IPv4");
    expect(ipStackCopy("v6")).toBe("IPv6");
    expect(ipStackCopy("both")).toBe("IPv4 + IPv6");
  });
});
