/**
 * The Android `scan://event` guard: the frame the Kotlin shell forwards from the
 * engine, checked before any of it reaches React state.
 *
 * Its own module for the reason `settingsPayload.ts` gives: the `frontend-fork-parity`
 * ratchet measures how much of `apps/android/src/*.ts` is the same code as
 * `apps/desktop/src/*.ts`, and a rule this size living in `types.ts` moves that file
 * below its recorded floor. It is also the natural home — `types.ts` declares the
 * `ScanEvent` union this reads, and the two already cite each other's producers.
 *
 * Why it exists: every other native payload had a strict parser (`parseRuntimeState`,
 * `parseSettingsPayload`, `parseTestOutcome`) and this one was `listen<ScanEvent>` —
 * an `as T` on an unwrapped `{ ok, data }` envelope, which is not a check. The scan
 * panel does arithmetic with what arrives (`rttMs - rttMs` orders the hit list,
 * `scanned / total` drives the progress card), so the shapes that mattered were the
 * numbers under the tag: a `rttMs` that came in as text made the comparator return
 * `NaN`, which is an unsorted list that looks sorted, and a `total` that came in as
 * `null` rendered `0/null`.
 *
 * What may be refused is bounded by what the shells actually send, not by what this
 * file would prefer — a guard that drops the events a working device emits is the
 * worse failure:
 *
 * - `EngineEvents.kt` forwards the engine's own JSON and `SessionController.emitScan`
 *   stamps `runId` on every arm, so `runId` is text or absent.
 * - That shell then reads its fields with `optString` / `optLong` / `optDouble`, whose
 *   answer for an absent field is `""` and `0`. An empty `mode`, `addr`, `rtt` or
 *   `protocol` and a zero count are therefore *legacy*, not corruption: the real
 *   `scan_done` for a run that found nothing is exactly `{addr:"",rtt:"",protocol:""}`,
 *   and the connect path's synthetic terminal frame (`SessionController.kt:571`) sends
 *   no `bestRttMs` at all.
 * - `ScanLimits.clampConcurrency` bounds the lane count the engine is *told* to run to
 *   `1..MAX_CONCURRENCY` before the process starts, so a `concurrency` above
 *   `SCAN_MAX_CONCURRENCY` on the wire is not a run this scanner can perform.
 *
 * A refusal is reported and dropped, never coerced: `useScanner` keeps showing the
 * last frame it could read and says so once per distinct shape. That is the same
 * recoverable path `useRuntime` takes for a rejected `session://state`, and it is the
 * alternative to the move that caused the defect — writing the unvalidated frame
 * through.
 */
import { SCAN_MAX_CONCURRENCY } from "@aether/ui";
import type { ScanEvent, ScanRunScope } from "./types";

/** The five tags the bridge forwards; anything else is not a scan event. */
const SCAN_EVENT_TAGS: readonly ScanEvent["type"][] = [
  "scan_start",
  "scan_progress",
  "scan_hit",
  "scan_done",
  "scan_failed",
];

/** A value as it can only be described to a user: what the shell actually sent. */
function sentValue(value: unknown): string {
  if (value === undefined) return "absent";
  if (value === null) return "null";
  if (Array.isArray(value)) return "a list";
  if (typeof value === "string") return JSON.stringify(value);
  return String(value);
}

/** The tag, or `null` for a payload that is not one of the five arms. */
function scanEventTag(value: unknown): ScanEvent["type"] | null {
  return typeof value === "string" && (SCAN_EVENT_TAGS as readonly string[]).includes(value)
    ? (value as ScanEvent["type"])
    : null;
}

/** One event, read: the event, or the sentence naming why it cannot be read. */
export type ScanEventParse =
  | { ok: true; event: ScanEvent }
  | { ok: false; reason: string };

export function parseScanEvent(payload: unknown): ScanEventParse {
  if (typeof payload !== "object" || payload === null || Array.isArray(payload)) {
    return { ok: false, reason: `expected an event object, found ${sentValue(payload)}` };
  }
  const src = payload as Record<string, unknown>;
  const type = scanEventTag(src.type);
  if (!type) {
    return {
      ok: false,
      reason: `type ${sentValue(src.type)} is not one of ${SCAN_EVENT_TAGS.join(" | ")}`,
    };
  }

  // The first unreadable field wins and the helpers still return a value so the arms
  // below type-check; a refusal discards everything they built. Held in an object
  // because a `let` these closures assign is narrowed to `null` at the check site.
  const refusal: { current: string | null } = { current: null };
  const refuse = (detail: string) => {
    if (!refusal.current) refusal.current = `${type}: ${detail}`;
  };
  /** Text the interface renders verbatim. `""` is a real answer; a number is not. */
  const text = (field: string): string => {
    const value = src[field];
    if (typeof value === "string") return value;
    refuse(`${field} is ${sentValue(value)}, expected text`);
    return "";
  };
  /** A tally or a lane count: whole, non-negative, inside the bounds the run has. */
  const count = (field: string, max: number): number => {
    const value = src[field];
    if (typeof value !== "number" || !Number.isFinite(value) || !Number.isInteger(value)) {
      refuse(`${field} is ${sentValue(value)}, expected a whole number of probes`);
      return 0;
    }
    if (value < 0) {
      refuse(`${field} is ${value}, below 0`);
      return 0;
    }
    if (value > max) {
      refuse(`${field} is ${value}, above the ceiling of ${max}`);
      return 0;
    }
    return value;
  };
  /** A measured round trip: the engine sends a float, and an honest zero is allowed. */
  const measured = (field: string): number => {
    const value = src[field];
    if (typeof value !== "number" || !Number.isFinite(value)) {
      refuse(`${field} is ${sentValue(value)}, expected a measurement in milliseconds`);
      return 0;
    }
    if (value < 0) {
      refuse(`${field} is ${value}, a negative round trip`);
      return 0;
    }
    return value;
  };

  const rawRunId = src.runId;
  if (rawRunId !== undefined && rawRunId !== null && typeof rawRunId !== "string") {
    refuse(`runId is ${sentValue(rawRunId)}, expected the id of the run that emitted this`);
  }
  const scope: ScanRunScope = typeof rawRunId === "string" ? { runId: rawRunId } : {};
  // Where the run itself sets the ceiling (a pool size, a tally of probes) there is no
  // number this file may invent; where the shell's clamp does, it is the shared one.
  const untallied = Number.MAX_SAFE_INTEGER;

  let event: ScanEvent;
  switch (type) {
    case "scan_start": {
      const mode = text("mode");
      const total = count("total", untallied);
      const concurrency = count("concurrency", SCAN_MAX_CONCURRENCY);
      event = { ...scope, type, mode, total, concurrency };
      break;
    }
    case "scan_progress": {
      const scanned = count("scanned", untallied);
      const total = count("total", untallied);
      const working = count("working", untallied);
      event = { ...scope, type, scanned, total, working };
      break;
    }
    case "scan_hit": {
      const addr = text("addr");
      const rtt = text("rtt");
      const rttMs = measured("rttMs");
      const protocol = text("protocol");
      event = { ...scope, type, addr, rtt, rttMs, protocol };
      break;
    }
    case "scan_done": {
      const addr = text("addr");
      const rtt = text("rtt");
      const protocol = text("protocol");
      // `best_rtt_ms` is an `Option` in the engine (`session_event.rs`) and simply
      // absent from the connect path's synthetic frame; absent and null both mean
      // "not measured", which the UI renders as that rather than as 0 ms.
      const best = src.bestRttMs;
      const bestRttMs = best === undefined || best === null ? undefined : measured("bestRttMs");
      event = {
        ...scope,
        type,
        addr,
        rtt,
        protocol,
        ...(bestRttMs === undefined ? {} : { bestRttMs }),
      };
      break;
    }
    case "scan_failed": {
      const message = text("message");
      event = { ...scope, type, message };
      break;
    }
  }

  if (refusal.current) return { ok: false, reason: refusal.current };
  return { ok: true, event };
}
