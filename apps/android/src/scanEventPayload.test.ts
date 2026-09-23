// @vitest-environment jsdom
/*
 * The `scan://event` guard on its own, before it reaches a hook.
 *
 * ITEM 9's clause this closes: every other native payload had a strict parser
 * (`parseRuntimeState`, `parseSettingsPayload`, `parseTestOutcome`) and this one was an
 * `as ScanEvent` on an unwrapped envelope. A parser that refuses too much is as bad as
 * one that refuses nothing — it drops the events a working device sends — so the two
 * halves below are pinned together: the frames the shells really produce must parse,
 * and the frames that would put garbage into state must not.
 *
 * The producers are named where their shapes come from:
 *   `SessionController.emitScanEvent`  (scan_start/progress/hit/done, via
 *     `optString`/`optLong`/`optDouble`, which answer an absent field with "" and 0)
 *   `SessionController.kt:571`         (the connect path's synthetic `scan_done`, no
 *     `bestRttMs` at all)
 *   `ScanLimits.clampConcurrency`      (the lane ceiling the engine is told to run)
 */
import { describe, expect, it } from "vitest";
import { SCAN_MAX_CONCURRENCY } from "./types";
import { parseScanEvent } from "./scanEventPayload";
import type { ScanEvent } from "./types";
import { mockScanPlan } from "./bridge";

describe("parseScanEvent accepts what the shells actually send", () => {
  /** The frame parses, and parses to *itself*: nothing is coerced or dropped. */
  function parses(payload: unknown) {
    const parsed = parseScanEvent(payload);
    if (!parsed.ok) throw new Error(`refused a frame the shell sends: ${parsed.reason}`);
    expect(parsed.event).toEqual(payload);
    return parsed.event;
  }

  it("reads every arm the engine emits, with the run id it is stamped with", () => {
    parses({ runId: "r1", type: "scan_start", mode: "balanced", total: 240, concurrency: 16 });
    parses({ runId: "r1", type: "scan_progress", scanned: 48, total: 240, working: 3 });
    parses({
      runId: "r1",
      type: "scan_hit",
      addr: "162.159.193.1:443",
      rtt: "18ms",
      rttMs: 18.4,
      protocol: "MASQUE H3",
    });
    parses({ runId: "r1", type: "scan_failed", message: "engine exited" });
  });

  it("keeps an absent run id absent rather than inventing one", () => {
    // `emitScan` only stamps the id once a run has started, so a frame without it is
    // ordinary, and `ev.runId && …` in the hook treats it as "not scoped".
    const event = parses({ type: "scan_progress", scanned: 1, total: 2, working: 0 });
    expect("runId" in event).toBe(false);
  });

  it("reads the shell's absent-field answers (\"\" and 0) as legacy, not corruption", () => {
    // `optString("mode")` is "" and `optLong("total")` is 0 when the engine's line
    // omits them; refusing those would drop every event from an older engine.
    parses({ type: "scan_start", mode: "", total: 0, concurrency: 0 });
    parses({ type: "scan_progress", scanned: 0, total: 0, working: 0 });
    parses({ type: "scan_hit", addr: "", rtt: "", rttMs: 0, protocol: "" });
  });

  it("reads a run that found nothing and a peer forced from config", () => {
    // The mock's `stop_scan` frame and the Kotlin's synthetic terminal event are the
    // two real senders of `""` everywhere; `bestRttMs` is an `Option` and may be
    // absent or null, which both mean "not measured" — never a 0 ms the UI would show.
    parses({ type: "scan_done", addr: "", rtt: "", protocol: "" });
    parses({ type: "scan_done", addr: "1.1.1.1:443", rtt: "9ms", protocol: "WireGuard", bestRttMs: 9 });

    // The two spellings of "not measured" are read as one thing, so a consumer has a
    // single case to handle rather than `!== null && !== undefined` in three places.
    const nullBest = parseScanEvent({ type: "scan_done", addr: "", rtt: "", protocol: "", bestRttMs: null });
    expect(nullBest.ok).toBe(true);
    if (nullBest.ok) expect(nullBest.event).toEqual({ type: "scan_done", addr: "", rtt: "", protocol: "" });
  });

  it("accepts every event the dev mock plans, whatever the request asked for", () => {
    // The mock and the WebView read the same contract, so a plan the parser refuses is
    // a preview whose scanner silently stops updating.
    const requests = [
      { protocol: "masque-h3", ipVersion: "both", concurrency: 16, timeoutMs: 6000 },
      { protocol: "wireguard", ipVersion: "v6", concurrency: 500, timeoutMs: 3000 },
      { runId: "abc", protocol: "masque-h2" },
    ];
    for (const request of requests) {
      const plan = mockScanPlan(request);
      expect(plan.length).toBeGreaterThan(2);
      for (const event of plan) {
        const parsed = parseScanEvent(event);
        if (!parsed.ok) throw new Error(`the mock emits an unreadable event: ${parsed.reason}`);
      }
    }
  });
});

describe("parseScanEvent refuses a frame it cannot put into state", () => {
  /** Refused, and the sentence names the field a user would want named. */
  function refuses(payload: unknown, field: string) {
    const parsed = parseScanEvent(payload);
    expect(parsed.ok).toBe(false);
    if (parsed.ok) return;
    expect(parsed.reason).toContain(field);
  }

  it("refuses a required field that is not there", () => {
    refuses({ type: "scan_progress", scanned: 10, total: 100 }, "working");
    refuses({ type: "scan_start", total: 100, concurrency: 16 }, "mode");
    refuses({ type: "scan_hit", addr: "1.1.1.1:443", rtt: "9ms", protocol: "h3" }, "rttMs");
    refuses({ type: "scan_failed" }, "message");
  });

  it("refuses a value of the wrong type, where the cast used to accept anything", () => {
    // `rttMs` as text is the one that mattered: the hit list is sorted by subtracting
    // it, and `"18" - "9"` is NaN, so the list silently stopped being sorted.
    refuses({ type: "scan_hit", addr: "1.1.1.1:443", rtt: "9ms", rttMs: "9", protocol: "h3" }, "rttMs");
    refuses({ type: "scan_start", mode: 3, total: 100, concurrency: 16 }, "mode");
    refuses({ type: "scan_start", mode: "balanced", total: null, concurrency: 16 }, "total");
    refuses({ type: "scan_hit", addr: ["1.1.1.1"], rtt: "9ms", rttMs: 9, protocol: "h3" }, "addr");
    refuses({ type: "scan_failed", message: { text: "boom" } }, "message");
    refuses({ type: "scan_progress", scanned: "1", total: "2", working: "1" }, "scanned");
  });

  it("refuses a number outside the range the scanner can be running", () => {
    refuses(
      { type: "scan_start", mode: "balanced", total: 100, concurrency: SCAN_MAX_CONCURRENCY + 1 },
      "concurrency",
    );
    refuses({ type: "scan_start", mode: "balanced", total: -1, concurrency: 16 }, "total");
    refuses({ type: "scan_progress", scanned: 50.5, total: 100, working: 1 }, "scanned");
    refuses({ type: "scan_progress", scanned: NaN, total: 100, working: 1 }, "scanned");
    refuses({ type: "scan_progress", scanned: 1, total: Infinity, working: 1 }, "total");
    refuses({ type: "scan_hit", addr: "1.1.1.1:443", rtt: "9ms", rttMs: -1, protocol: "h3" }, "rttMs");
    refuses(
      { type: "scan_done", addr: "1.1.1.1:443", rtt: "9ms", protocol: "h3", bestRttMs: "9" },
      "bestRttMs",
    );
  });

  it("refuses a payload that is not an event at all", () => {
    refuses({ type: "engine_heartbeat", seq: 4 }, "type");
    refuses({ type: "scan_done" }, "addr");
    refuses(null, "expected an event object");
    refuses("scan_done", "expected an event object");
    refuses([{ type: "scan_done", addr: "", rtt: "", protocol: "" }], "list");
    refuses({}, "type");
  });

  it("never throws, whatever the bridge forwards", () => {
    // The guard runs inside a listener the WebView calls; a throw here would be the
    // silent end of scan events (see `window.__aetherEmit`, which only logs).
    const junk: unknown[] = [
      undefined,
      0,
      "",
      true,
      [],
      { type: null },
      { type: "scan_start", total: {}, concurrency: [] },
      { type: "scan_hit", rttMs: -Infinity, addr: 1, rtt: 2, protocol: 3 },
      { type: "scan_progress", scanned: 1e308 * 10, total: 2, working: 1 },
    ];
    for (const payload of junk) {
      const parsed = parseScanEvent(payload);
      expect(parsed.ok).toBe(false);
    }
  });

  it("reports the first unreadable field only, with the tag that carried it", () => {
    const parsed = parseScanEvent({ type: "scan_progress", scanned: -1, total: "x", working: 1 });
    if (parsed.ok) throw new Error("expected a refusal");
    expect(parsed.reason).toMatch(/^scan_progress: /);
    expect(parsed.reason.split(" is ")[0]).toBe("scan_progress: scanned");
  });
});

/**
 * The union the parser hands back has to be the union the hook consumes; a widened
 * return here would let a refused frame through the switch below it.
 */
it("returns a value the ScanEvent union still describes", () => {
  const parsed = parseScanEvent({ type: "scan_start", mode: "turbo", total: 5, concurrency: 5 });
  if (!parsed.ok) throw new Error("a valid frame was refused");
  const event: ScanEvent = parsed.event;
  expect(event.type).toBe("scan_start");
});
