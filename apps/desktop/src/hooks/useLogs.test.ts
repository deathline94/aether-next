// @vitest-environment jsdom
import { describe, expect, it } from "vitest";
import { act, renderHook } from "@testing-library/react";
import { useLogs } from "./useLogs";

const hit = (message: string) => ({ level: "info" as const, message });

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
});
