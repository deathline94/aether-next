// @vitest-environment jsdom
import { describe, expect, it } from "vitest";
import { carrierChip, transportName } from "./ConnectionTab";
import { defaults } from "../types";
import type { Settings } from "../types";

const withPatch = (patch: Partial<Settings>): Settings => ({ ...defaults, ...patch });

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
});
