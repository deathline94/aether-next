import { describe, expect, it } from "vitest";
import { formatLogTime, speedProfiles } from "./types";

/**
 * The log console's time column is a fixed 64 px grid track, so the formatter has
 * to produce a fixed-width string: an 11-character "02:15:33 PM" is wider than
 * the column and the rows stop lining up for half of every day.
 */
describe("android log timestamp", () => {
  const at = (h: number, m = 15, s = 33) => new Date(2026, 8, 22, h, m, s).getTime();

  it("never carries a meridiem marker, at any hour of the day", () => {
    for (let hour = 0; hour < 24; hour += 1) {
      expect(formatLogTime(at(hour))).not.toMatch(/[AP]\.?M\.?/i);
    }
  });

  it("renders the same width before and after noon", () => {
    const morning = formatLogTime(at(2));
    const afternoon = formatLogTime(at(14));
    expect(morning).toMatch(/^\d{2}:\d{2}:\d{2}$/);
    expect(afternoon).toMatch(/^\d{2}:\d{2}:\d{2}$/);
    expect(afternoon.length).toBe(morning.length);
    expect(afternoon.startsWith("14:")).toBe(true);
  });

  it("keeps midnight at the start of the day rather than twelve", () => {
    expect(formatLogTime(at(0))).toMatch(/^00:15:33$/);
  });
});

/**
 * The four one-tap presets, now derived from the table both frontends share
 * (`packages/ui/src/enums.ts`) with only the routing arm per surface.
 *
 * The rows used to be written out twice, and had begun to differ in wording that
 * the user reads ("balanced scan" on one, "balanced" on the other) while the pair
 * that actually matters - which transport each protocol arm is reachable over -
 * was carried in two copies that nothing kept honest.
 */
describe("speed profiles", () => {
  it("pairs each preset with the transport its arm can speak", () => {
    expect(speedProfiles.map((p) => [p.id, p.patch.protocol, p.patch.transport])).toEqual([
      ["masque-h3", "masque", "h3"],
      ["masque-h2", "masque", "h2"],
      ["wireguard", "wireguard", "h2"],
      ["gool", "gool", "h2"],
    ]);
  });

  it("describes itself the way the settings screen reads", () => {
    for (const p of speedProfiles) {
      expect(p.hint).toMatch(/· noise off · balanced scan · full VPN$/);
    }
    expect(speedProfiles.find((p) => p.id === "gool")?.hint).toContain("Gool (WARP-in-WARP)");
    expect(speedProfiles.find((p) => p.id === "masque-h3")?.hint).toContain("MASQUE H3");
  });

  it("leaves no pinned carrier behind on a full-device preset", () => {
    for (const p of speedProfiles) {
      expect(p.patch.routingMode).toBe("tun");
      expect(p.patch.peer).toBe("");
      expect(p.patch.noize).toBe("off");
      expect(p.patch.scanMode).toBe("balanced");
      expect(p.patch.ipVersion).toBe("v4");
    }
  });
});
