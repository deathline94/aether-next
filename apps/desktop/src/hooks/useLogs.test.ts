// @vitest-environment jsdom
import { describe, expect, it } from "vitest";
import { act, renderHook } from "@testing-library/react";
import { hitKeyOf, useLogs } from "./useLogs";

const hit = (message: string) => ({ level: "info" as const, message });

/** The pre-fix implementation, as the oracle for the incremental one. */
function recomputeHits(logs: { message: string; hitKey?: string }[]): number {
  const seen = new Set<string>();
  let count = 0;
  for (const l of logs) {
    const key = hitKeyOf(l);
    if (key === null || seen.has(key)) continue;
    seen.add(key);
    count += 1;
  }
  return count;
}

describe("useLogs hit counting", () => {
  it("counts an endpoint once however many lines describe it", () => {
    const { result } = renderHook(() => useLogs());

    act(() => {
      // One probe of one endpoint writes all three of these.
      result.current.appendLog(hit('AETHER_EVENT {"type":"scan_hit","addr":"104.16.0.1:443","rtt_ms":12}'));
      result.current.appendLog(hit("candidate ok 104.16.0.1:443 in 12ms"));
      result.current.appendLog(hit("data-plane verified 104.16.0.1:443"));
      result.current.appendLog(hit("candidate ok 104.16.0.9:443 in 31ms"));
      result.current.appendLog(hit("scanning 250 candidates..."));
    });

    expect(result.current.filterCounts.hits).toBe(2);

    act(() => result.current.setLogFilter("hits"));
    // The list under "Hits" and the number beside it are the same fact.
    expect(result.current.filteredLogs).toHaveLength(2);
    expect(result.current.filteredLogs.map((l) => l.message[0])).toEqual(["A", "c"]);
  });

  it("survives a long buffer without double counting", () => {
    const { result } = renderHook(() => useLogs());
    act(() => {
      for (let i = 0; i < 400; i++) {
        const addr = `10.0.0.${i % 251}:443`;
        result.current.appendLog(hit(`AETHER_EVENT {"type":"scan_hit","addr":"${addr}"}`));
        result.current.appendLog(hit(`candidate ok ${addr} in ${i}ms`));
      }
    });
    expect(result.current.filterCounts.hits).toBe(251);
    expect(result.current.logs.length).toBeLessThanOrEqual(1000);
  });

  it("keeps every count equal to a full recompute of the buffer", () => {
    // The counts used to be recomputed from the whole buffer — a regex pass per
    // line plus two filter passes — on *every* appended line, which is what froze
    // the window during a scan. The incremental store must land on exactly the
    // same answer, including while lines age out of the 1000-entry window.
    const { result } = renderHook(() => useLogs());

    act(() => {
      for (let i = 0; i < 1400; i++) {
        const addr = `10.7.0.${i % 300}:443`;
        const level =
          i % 7 === 0 ? ("error" as const) : i % 11 === 0 ? ("warn" as const) : ("info" as const);
        const message =
          i % 5 === 0
            ? `session state -> connected (pass ${i})`
            : i % 3 === 0
              ? "probe timeout on candidate"
              : `AETHER_EVENT {"type":"scan_hit","addr":"${addr}"}`;
        result.current.appendLog({ level, message });
      }
    });

    const { logs, filterCounts } = result.current;
    expect(logs.length).toBe(1000);
    expect(filterCounts.raw).toBe(logs.length);
    expect(filterCounts.hits).toBe(recomputeHits(logs));
    expect(filterCounts.errors).toBe(
      logs.filter((l) => l.level === "error" || l.level === "warn").length,
    );
    expect(filterCounts.milestones).toBe(
      logs.filter((l) => !l.message.includes("probe timeout")).length,
    );

    // The chip beside a filter and the list under it stay one fact.
    for (const filter of ["milestones", "hits", "errors", "raw"] as const) {
      act(() => result.current.setLogFilter(filter));
      expect(result.current.filteredLogs).toHaveLength(result.current.filterCounts[filter]);
    }
  });

  it("promotes a later duplicate when the counted line leaves the buffer", () => {
    const { result } = renderHook(() => useLogs());
    const first = "104.16.0.1:443";
    const later = "104.16.9.9:443";

    act(() => {
      result.current.appendLog(hit(`AETHER_EVENT {"type":"scan_hit","addr":"${first}"}`));
      // Pad enough to push that line out of the 1000-entry window.
      for (let i = 0; i < 1000; i++) {
        result.current.appendLog(hit(`probe ${i} finished`));
      }
      result.current.appendLog(hit(`AETHER_EVENT {"type":"scan_hit","addr":"${later}"}`));
    });

    expect(result.current.logs.some((l) => l.message.includes(first))).toBe(false);
    expect(result.current.filterCounts.hits).toBe(1);

    // A second sighting of the address is what counts now.
    act(() => {
      result.current.appendLog(hit(`AETHER_EVENT {"type":"scan_hit","addr":"${first}"}`));
    });
    expect(result.current.filterCounts.hits).toBe(2);
  });

  it("formats the clock once per line, not once per row per render", () => {
    // `formatLogTime(ts)` ran per row per render — 200 rows times however many
    // lines the scanner pushed. The label is now a field of the entry.
    const { result } = renderHook(() => useLogs());
    act(() => {
      result.current.appendLog(hit("candidate ok 104.16.0.1:443 in 12ms"));
    });
    const [entry] = result.current.logs;
    expect(entry.time).toMatch(/^\d{2}:\d{2}:\d{2}$/);
    const before = entry.time;
    act(() => result.current.setLogFilter("raw"));
    expect(result.current.logs[0].time).toBe(before);
  });
});
