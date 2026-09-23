/*
 * The console's fact-extraction layer, shared by both front-ends.
 *
 * Everything here is pure: no React, no `window`, no shell. It lives in the
 * shared package rather than in either app because the answers it produces - is
 * this line a hit, which endpoint is it a hit for, does this line count as a
 * milestone - have to be the same answers on both surfaces, and they had
 * drifted: the desktop counted hits from the engine's structured `scan_hit`
 * event with a narrow prose fallback, while the phone still asked "does the
 * text contain one of these seven words *and* an IP-shaped substring", which
 * both double-counts an endpoint the engine announced twice and silently stops
 * counting when the engine rewords a line.
 */

import type { LogLevel } from "./enums";

/** The minimum a log line has to be for this module to reason about it. */
export type LogLine = {
  id: number;
  ts: number;
  level: LogLevel;
  message: string;
  /** Asserted by the producer when the line *is* a fact about one endpoint. */
  hitKey?: string;
};

/** Buffer cap per surface; the export is not limited to it. */
export const MAX_LOGS = 1000;
/** Cap rendered entries; the full buffer stays exportable. */
export const RENDER_CAP = 200;

/** An IPv4/IPv6 socket as the engine prints it, with or without the port. */
const IP_SOCKET = String.raw`\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?|\[?[0-9a-fA-F:]{4,}\]?(?::\d+)?`;

/**
 * The engine lines that announce a working endpoint, each *immediately followed*
 * by the address it is about. Adjacency is the whole point: the previous rule was
 * "the line contains one of these words and contains an address somewhere", so a
 * diagnostic that happened to mention `verified` and an unrelated host on the
 * same line was counted as a hit, and rephrasing a probe log silently stopped
 * counting real ones. This is the fallback for text lines only - see `hitKeyOf`.
 */
const PROSE_HIT = new RegExp(
  `(?:candidate ok|race winner|selected edge|best:)\\s+<?(${IP_SOCKET})>?`,
  "i",
);

/** Marker the engine's structured line carries; the JSON after it is the event. */
const EVENT_MARKER = "AETHER_EVENT ";

/**
 * The key a hit is deduplicated by: the address, as the engine spelled it.
 *
 * Deliberately the address alone and not `addr + protocol` like the Scanner's own
 * rows - this list is a log of *endpoints that answered*, and the prose lines the
 * engine writes carry no protocol to key on, so mixing granularities would let
 * one endpoint appear twice under two spellings of the same fact.
 */
export function hitAddressKey(addr: string): string {
  return addr.trim().toLowerCase();
}

/** `AETHER_EVENT {"type":"scan_hit","addr":"1.1.1.1:443",...}` -> that address. */
function eventHitAddress(message: string): string | null {
  const at = message.indexOf(EVENT_MARKER);
  if (at < 0) return null;
  const body = message.slice(at + EVENT_MARKER.length).trim();
  // The probe lines are emitted as one JSON object per line; anything that fails
  // to parse is not an event and does not get to claim a hit.
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    return null;
  }
  if (typeof parsed !== "object" || parsed === null) return null;
  const event = parsed as { type?: unknown; addr?: unknown };
  if (event.type !== "scan_hit" && event.type !== "endpoint_selected") return null;
  return typeof event.addr === "string" && event.addr.length > 0 ? event.addr : null;
}

/**
 * One place decides whether a log line *is* a hit, so the chip count and the list
 * under it are computed from the same answer and cannot disagree.
 *
 * Ordered by trust: the key the producer asserted, then the structured event
 * embedded in the line, then the narrow prose rule.
 */
export function hitKeyOf(entry: Pick<LogLine, "message"> & Partial<Pick<LogLine, "hitKey">>): string | null {
  if (entry.hitKey) return hitAddressKey(entry.hitKey);
  const addr = eventHitAddress(entry.message);
  if (addr) return hitAddressKey(addr);
  const prose = PROSE_HIT.exec(entry.message);
  const candidate = prose?.[1];
  return candidate ? hitAddressKey(candidate) : null;
}

export const isErrorLine = (l: LogLine) => l.level === "error" || l.level === "warn";

/**
 * The probe chatter that says nothing about a transition.
 *
 * One list, because the console asks the same question twice: "is this line a
 * milestone" (what the `milestones` filter selects) and "should this row wear the
 * DEBUG badge" (what the row itself shows). Written out in both apps, in both
 * places, they are four copies of one rule that can each be edited on their own.
 */
const PROBE_NOISE_MARKERS = ["probe src", "probe timeout", "candidate rejected"] as const;

/** milestones: exclude noisy progress and probe error lines so transitions stand out. */
export const isMilestoneLine = (l: LogLine) =>
  !l.message.includes("scanning...") &&
  !l.message.includes("probe candidate failed") &&
  !PROBE_NOISE_MARKERS.some((marker) => l.message.includes(marker));

/**
 * Which severity a row is drawn as. The engine sends three levels; the fourth,
 * `debug`, is what this module already recognises as probe chatter, so the badge
 * and the milestone filter cannot disagree about which lines are noise.
 */
export type LogSeverity = "info" | "warn" | "error" | "debug";

export function logSeverityOf(entry: Pick<LogLine, "level" | "message">): LogSeverity {
  if (entry.level === "error") return "error";
  if (entry.level === "warn") return "warn";
  const msg = entry.message.toLowerCase();
  if (msg.includes("debug") || msg.includes("trace")) return "debug";
  return PROBE_NOISE_MARKERS.some((marker) => msg.includes(marker)) ? "debug" : "info";
}

/** The badge text, which is not the CSS class name the row is keyed on. */
export const LOG_SEVERITY_LABELS: Record<LogSeverity, string> = {
  info: "INFO",
  warn: "WARN",
  error: "ERR",
  debug: "DEBUG",
};

/**
 * One line plus the three verdicts taken about it.
 *
 * Classifying at append time is the difference between reading a regex over a
 * 1000-entry buffer once per *line* and once per *rendered row per appended
 * line*: the filter chips, the Hits list and the visible window used to
 * re-derive those answers from the text on the same commit that painted 200
 * rows, which is the scan-time freeze - and the phone is the slower surface.
 */
export type Classified<L extends LogLine = LogLine> = {
  entry: L;
  hitKey: string | null;
  isHit: boolean;
  isMilestone: boolean;
  isError: boolean;
};

export type Store<L extends LogLine = LogLine> = {
  /** Oldest first, capped at `MAX_LOGS`. */
  lines: Classified<L>[];
  /**
   * The designated line per address, in buffer order - the list under "Hits".
   * Kept alongside `keyCounts` so the chip beside the filter and the rows under
   * it are one fact and not two computations that can disagree.
   */
  hits: Classified<L>[];
  /** How many lines per address are still in the buffer. */
  keyCounts: Map<string, number>;
  counts: { milestones: number; errors: number };
};

export function emptyStore<L extends LogLine>(): Store<L> {
  return { lines: [], hits: [], keyCounts: new Map(), counts: { milestones: 0, errors: 0 } };
}

export function classify<L extends LogLine>(entry: L): Classified<L> {
  const hitKey = hitKeyOf(entry);
  return {
    entry,
    hitKey,
    isHit: hitKey !== null,
    isMilestone: isMilestoneLine(entry),
    isError: isErrorLine(entry),
  };
}

/**
 * Append one line and move the derived answers forward.
 *
 * Pure in `store` (a fresh object is returned; nothing is mutated), so React may
 * call it twice under StrictMode. A hit is an endpoint, not a line that
 * mentioned one: the engine writes both a structured `scan_hit` and a human
 * "candidate ok" line for the same address, and counting lines counted one
 * endpoint two and three times. When the counted line ages out of the buffer the
 * next surviving line for that address takes its place, so trimming cannot
 * silently lose an endpoint.
 */
export function appendToStore<L extends LogLine>(store: Store<L>, entry: L): Store<L> {
  const line = classify(entry);
  const lines = [...store.lines, line];
  const evicted = lines.length > MAX_LOGS ? lines.splice(0, lines.length - MAX_LOGS) : [];

  const counts = {
    milestones: store.counts.milestones + (line.isMilestone ? 1 : 0),
    errors: store.counts.errors + (line.isError ? 1 : 0),
  };
  const keyCounts = new Map(store.keyCounts);
  const key = line.hitKey;
  // The first line for an address is the one that stands for it.
  const firstOfItsKind = key !== null && !keyCounts.has(key);
  if (key !== null) keyCounts.set(key, (keyCounts.get(key) ?? 0) + 1);
  let hits = firstOfItsKind ? [...store.hits, line] : store.hits;

  for (const gone of evicted) {
    if (gone.isMilestone) counts.milestones -= 1;
    if (gone.isError) counts.errors -= 1;
    const goneKey = gone.hitKey;
    if (goneKey === null) continue;
    const remaining = (keyCounts.get(goneKey) ?? 1) - 1;
    if (remaining <= 0) keyCounts.delete(goneKey);
    else keyCounts.set(goneKey, remaining);
    if (!hits.includes(gone)) continue;
    // The counted line left; promote the next one for the same address, which is
    // the only case that can cost more than O(1). The order is the buffer's, so
    // the Hits list reads top-to-bottom like the console under it.
    const successor = lines.find((l) => l.hitKey === goneKey);
    hits = successor
      ? [...hits.filter((h) => h !== gone), successor].sort((a, b) => a.entry.id - b.entry.id)
      : hits.filter((h) => h !== gone);
  }

  return { lines, hits, keyCounts, counts };
}

/** The last `RENDER_CAP` rows of an already-filtered list, plus what was hidden. */
export function visibleWindow<L>(filtered: L[]): { visible: L[]; hasMore: boolean } {
  if (filtered.length <= RENDER_CAP) return { visible: filtered, hasMore: false };
  return { visible: filtered.slice(filtered.length - RENDER_CAP), hasMore: true };
}
