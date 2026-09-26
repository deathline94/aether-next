import { describe, expect, it } from "vitest";
import { rttBadge } from "@aether/ui";
import type { DiscoveredEndpoint } from "../types";

const row = (over: Partial<DiscoveredEndpoint>): DiscoveredEndpoint => ({
  addr: "104.16.0.1:443",
  rtt: "12ms",
  rttMs: 12,
  protocol: "masque-h3",
  ...over,
});

describe("rttBadge", () => {
  it("tiers a measured round-trip", () => {
    expect(rttBadge(row({}))).toEqual({
      tierClass: "rtt-ultra-green",
      badgeText: "ULTRA FAST",
      text: "12ms",
    });
    expect(rttBadge(row({ rtt: "80ms", rttMs: 80 })).badgeText).toBe("NORMAL");
    expect(rttBadge(row({ rtt: "240ms", rttMs: 240 })).badgeText).toBe("HIGH LATENCY");
  });

  it("says 'not measured' for the shell's documented blank rtt", () => {
    // A forced peer answers with `rtt: ""` and no measured number. The old row
    // printed an empty cell and `getRttTier(0)` badged it HIGH LATENCY.
    for (const rttMs of [0, Number.NaN, Number.POSITIVE_INFINITY, undefined, null]) {
      const badge = rttBadge(row({ rtt: "", rttMs: rttMs as number }));
      expect(badge.text).toBe("not measured");
      expect(badge.badgeText).toBe("NOT MEASURED");
      // No tier class: a colour here would be a claim about a number nobody has.
      expect(badge.tierClass).toBe("");
    }
  });

  it("falls back to the measured number when the engine sent no text", () => {
    expect(rttBadge(row({ rtt: "", rttMs: 33 })).text).toBe("33 ms");
  });
});
