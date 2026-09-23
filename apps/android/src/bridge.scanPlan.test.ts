// @vitest-environment jsdom
/*
 * ITEM 16: the preview's scanner has to answer the request it was given.
 *
 * `mockScanPlan` replaced a run built from `Math.random()` and a hardcoded
 * `240 targets / 200 workers / "MASQUE H2"`: a WireGuard request answered with MASQUE
 * hits, an H3 request announced more lanes than `clampConcurrency` lets a QUIC
 * handshake carry, and neither could be asserted because the numbers moved. Every
 * value below is now derived from the request, which is what makes "changing the scan
 * settings changed the events" a checkable claim rather than a hope.
 *
 * The version clause is the other half of the same disease: a mock that reports a
 * version its own package does not carry is a UI test reading a number out of the app
 * and believing it, so it is compared against `apps/android/package.json` read off
 * disk, not against the constant the mock imports.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  SCAN_MAX_CONCURRENCY,
  SCAN_MAX_CONCURRENCY_H3,
  clampConcurrency,
} from "@aether/ui";
import { invoke, listen, mockScanPlan } from "./bridge";
import type { MockScanRequest } from "./bridge";
import { parseScanEvent } from "./scanEventPayload";
import type { ScanEvent } from "./types";

const HIT_LABEL: Record<string, string> = {
  "masque-h3": "MASQUE H3",
  "masque-h2": "MASQUE H2",
  wireguard: "WireGuard",
};

function start(plan: ScanEvent[]): ScanEvent {
  const frame = plan[0];
  if (!frame || frame.type !== "scan_start") throw new Error("a plan must open with scan_start");
  return frame;
}

function hits(plan: ScanEvent[]): Extract<ScanEvent, { type: "scan_hit" }>[] {
  return plan.filter((e): e is Extract<ScanEvent, { type: "scan_hit" }> => e.type === "scan_hit");
}

function progress(plan: ScanEvent[]): Extract<ScanEvent, { type: "scan_progress" }>[] {
  return plan.filter(
    (e): e is Extract<ScanEvent, { type: "scan_progress" }> => e.type === "scan_progress",
  );
}

function terminal(plan: ScanEvent[]): Extract<ScanEvent, { type: "scan_done" }> {
  const last = plan[plan.length - 1];
  if (!last || last.type !== "scan_done") throw new Error("a plan must close with scan_done");
  return last;
}

describe("the mock's run is the run that was asked for", () => {
  it("labels every hit with the protocol under scan", () => {
    // The defect this closes: a WireGuard scan whose rows all read "MASQUE H2", so the
    // panel's own results contradicted the protocol above them.
    for (const protocol of ["masque-h3", "masque-h2", "wireguard"] as const) {
      const plan = mockScanPlan({ protocol });
      const found = hits(plan);
      expect(found.length, `${protocol} found nothing to label`).toBeGreaterThan(0);
      for (const hit of found) expect(hit.protocol).toBe(HIT_LABEL[protocol]);
      expect(terminal(plan).protocol).toBe(HIT_LABEL[protocol]);
    }
  });

  it("puts the requested protocol's own lane ceiling on the wire", () => {
    // 500 lanes is the widest the shell will run, and an H3 request asking for them
    // gets the QUIC ceiling: the same clamp the panel shows and the bridge sends.
    const wide = { concurrency: 500 };
    expect(start(mockScanPlan({ ...wide, protocol: "masque-h3" })).concurrency).toBe(
      SCAN_MAX_CONCURRENCY_H3,
    );
    for (const protocol of ["masque-h2", "wireguard"] as const) {
      expect(start(mockScanPlan({ ...wide, protocol })).concurrency).toBe(SCAN_MAX_CONCURRENCY);
    }

    // No arm of the plan may exceed the ceiling for its protocol, not even the frame
    // that announces it — and the number is the shared clamp's, restated independently.
    for (const protocol of ["masque-h3", "masque-h2", "wireguard"] as const) {
      for (const request of [{}, wide, { concurrency: 1 }, { concurrency: 17 }]) {
        const planned = start(mockScanPlan({ ...request, protocol }));
        expect(planned.concurrency).toBe(
          clampConcurrency(request.concurrency ?? 250, protocol),
        );
        expect(planned.concurrency).toBeLessThanOrEqual(
          protocol === "masque-h3" ? SCAN_MAX_CONCURRENCY_H3 : SCAN_MAX_CONCURRENCY,
        );
      }
    }
  });

  it("sizes the pool and the addresses by the family the request named", () => {
    const v4 = start(mockScanPlan({ ipVersion: "v4" }));
    const v6 = start(mockScanPlan({ ipVersion: "v6" }));
    const both = start(mockScanPlan({ ipVersion: "both" }));

    // Three different totals from three different requests, in the order the pools
    // hold: neither number is pinned here, only their relation, so the assertion is
    // about the request being read rather than about a literal nobody can change.
    expect(v4.total).toBeGreaterThan(v6.total);
    expect(both.total).toBe(v4.total + v6.total);

    for (const [family, plan] of [
      ["v4", mockScanPlan({ ipVersion: "v4" })],
      ["v6", mockScanPlan({ ipVersion: "v6" })],
    ] as const) {
      const found = hits(plan);
      expect(found.length).toBeGreaterThan(0);
      for (const hit of found) {
        const isV6 = hit.addr.includes("[") && hit.addr.includes("::");
        expect(isV6, `${family} emitted ${hit.addr}`).toBe(family === "v6");
      }
    }

    // Dual-stack is the one family allowed to interleave, and it does both.
    const dual = hits(mockScanPlan({ ipVersion: "both" })).map((h) => h.addr.includes("::"));
    expect(dual.some((isV6) => isV6)).toBe(true);
    expect(dual.some((isV6) => !isV6)).toBe(true);
  });

  it("walks the whole pool, tallying monotonically to the announced total", () => {
    const plan = mockScanPlan({ ipVersion: "both", concurrency: 64 });
    const frames = progress(plan);
    expect(frames.length).toBeGreaterThan(1);
    let previous = 0;
    for (const frame of frames) {
      expect(frame.total).toBe(start(plan).total);
      expect(frame.scanned).toBeGreaterThan(previous);
      expect(frame.scanned).toBeLessThanOrEqual(frame.total);
      // `working` is the running count of hits, so it can never outgrow them.
      expect(frame.working).toBeLessThanOrEqual(frame.scanned);
      previous = frame.scanned;
    }
    expect(frames[frames.length - 1]?.scanned).toBe(start(plan).total);
  });

  it("reports the endpoint it actually found, or nothing at all", () => {
    const plan = mockScanPlan({ protocol: "masque-h2" });
    const found = hits(plan);
    const done = terminal(plan);
    const fastest = found.reduce((best, hit) => (hit.rttMs < best.rttMs ? hit : best), found[0]!);
    expect(done.addr).toBe(fastest.addr);
    expect(done.rtt).toBe(fastest.rtt);
    expect(done.bestRttMs).toBe(fastest.rttMs);
  });
});

describe("the mock's run is reproducible", () => {
  it("replays the same events for the same request", () => {
    const request: MockScanRequest = {
      protocol: "masque-h3",
      ipVersion: "both",
      concurrency: 9,
      timeoutMs: 7500,
      mode: "thorough",
      runId: "run-a",
    };
    // Deep equality on the whole plan, and a length that proves the comparison has
    // something in it: `[]` vs `[]` would otherwise be a very confident pass.
    const first = mockScanPlan(request);
    expect(first.length).toBeGreaterThan(3);
    expect(mockScanPlan(request)).toEqual(first);
  });

  it("changes the run when the request changes, in every dimension", () => {
    const base = mockScanPlan({ protocol: "masque-h3", ipVersion: "v4", concurrency: 16 });
    const variants: MockScanRequest[] = [
      { protocol: "wireguard", ipVersion: "v4", concurrency: 16 },
      { protocol: "masque-h3", ipVersion: "both", concurrency: 16 },
      { protocol: "masque-h3", ipVersion: "v4", concurrency: 16, timeoutMs: 30_000 },
      { protocol: "masque-h3", ipVersion: "v4", concurrency: 16, mode: "stealth" },
      { protocol: "masque-h3", ipVersion: "v4", concurrency: 16, runId: "another-run" },
    ];
    for (const variant of variants) {
      // Same length or different length, the plans are not the same run; and each
      // variant differs in the one field it changed, which is what "derived from the
      // request" has to mean.
      expect(mockScanPlan(variant)).not.toEqual(base);
    }
    // A request that only renames the run keeps its scan, and scopes every event.
    const scoped = mockScanPlan({ protocol: "masque-h3", ipVersion: "v4", concurrency: 16, runId: "r7" });
    const unscoped = mockScanPlan({ protocol: "masque-h3", ipVersion: "v4", concurrency: 16 });
    expect(scoped.map((e) => ({ ...e, runId: undefined }))).toEqual(
      unscoped.map((e) => ({ ...e, runId: undefined })),
    );
    for (const event of scoped) expect(event.runId).toBe("r7");
  });

  it("reads as a plan the WebView's own guard accepts, on every request", () => {
    // The mock and the device feed the same listener, so a plan that does not parse is
    // a preview whose scanner stops updating with no message at all.
    for (const protocol of ["masque-h3", "masque-h2", "wireguard"] as const) {
      for (const ipVersion of ["v4", "v6", "both"] as const) {
        for (const event of mockScanPlan({ protocol, ipVersion })) {
          const parsed = parseScanEvent(event);
          if (!parsed.ok) throw new Error(`${protocol}/${ipVersion}: ${parsed.reason}`);
          expect(parsed.event).toEqual(event);
        }
      }
    }
  });
});

describe("the mock answers a dispatched scan through the event channel", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  /** Drain the interval `startMockScan` armed and hand back what arrived. */
  async function dispatchedScan(args: Record<string, unknown>): Promise<unknown[]> {
    const seen: unknown[] = [];
    const unlisten = await listen("scan://event", (event) => seen.push(event.payload));
    vi.useFakeTimers();
    await invoke("scan", args);
    // Long enough for the whole plan (one event per 120 ms tick) plus the tail.
    for (let i = 0; i < 400 && seen.length < 20; i += 1) {
      await vi.advanceTimersByTimeAsync(120);
    }
    unlisten();
    return seen;
  }

  it("emits the plan it was asked for, and an H3 run stays inside its ceiling", async () => {
    const events = await dispatchedScan({
      runId: "dispatched",
      protocol: "masque-h3",
      ipVersion: "v4",
      concurrency: 500,
      timeoutMs: 6000,
      noize: "off",
    });
    expect(events.length).toBeGreaterThan(4);
    expect((events[0] as ScanEvent).type).toBe("scan_start");
    const laneCounts = events
      .map((e) => (e as ScanEvent).type === "scan_start" ? (e as { concurrency: number }).concurrency : null)
      .filter((n) => n !== null);
    expect(laneCounts).toEqual([SCAN_MAX_CONCURRENCY_H3]);
    for (const payload of events) {
      const parsed = parseScanEvent(payload);
      if (!parsed.ok) throw new Error(`the bridge forwarded an unreadable event: ${parsed.reason}`);
      // Everything on the channel belongs to the run that was dispatched.
      expect(parsed.event.runId).toBe("dispatched");
    }
    expect(hits(events as ScanEvent[]).length).toBeGreaterThan(0);
    for (const hit of hits(events as ScanEvent[])) expect(hit.protocol).toBe("MASQUE H3");
  });

  it("finishes a stopped scan with the terminal event of the run in flight", async () => {
    const seen: unknown[] = [];
    const unlisten = await listen("scan://event", (event) => seen.push(event.payload));
    vi.useFakeTimers();
    await invoke("scan", { runId: "stopping", protocol: "wireguard", ipVersion: "v6", concurrency: 8 });
    await vi.advanceTimersByTimeAsync(480);
    const midRun = seen.length;
    expect(midRun).toBeGreaterThan(0);
    await invoke("stop_scan");
    const last = seen[seen.length - 1];
    const parsed = parseScanEvent(last);
    if (!parsed.ok) throw new Error(`stop_scan emitted an unreadable frame: ${parsed.reason}`);
    expect(parsed.event.type).toBe("scan_done");
    expect(parsed.event.runId).toBe("stopping");
    unlisten();
  });
});

describe("the mock reports the version this app's own manifest carries", () => {
  it("answers app_info with apps/android/package.json, not a literal in the bridge", async () => {
    // Imported here independently of `bridge.ts`'s own import: the assertion is
    // "what the UI is told == what the manifest says", which a hardcoded `"1.2.9"` in
    // the mock fails while the same literal in both files could not.
    const { version } = await import("../package.json");
    const info = await invoke<{ version: string; name: string }>("app_info");
    expect(info.version).toBe(version);
    expect(info.version).toMatch(/^\d+\.\d+\.\d+/);
  });
});
