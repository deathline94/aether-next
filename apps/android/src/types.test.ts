import { describe, expect, it } from "vitest";
import { formatLogTime } from "./types";

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
