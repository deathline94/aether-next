import { useCallback, useMemo, useRef, useState } from "react";
import { formatLogTime } from "../types";
import type { LogEntry, LogFilter, LogInput } from "../types";

const MAX_LOGS = 1000;
/** Cap rendered entries for performance. */
export const RENDER_CAP = 200;

/** An IPv4/IPv6 socket as the engine prints it, with or without the port. */
const IP_SOCKET = String.raw`\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?|\[?[0-9a-fA-F:]{4,}\]?(?::\d+)?`;
/**
 * The engine lines that announce a working endpoint, each *immediately followed*
 * by the address it is about. Adjacency is the whole point: the previous rule was
 * "the line contains one of these words and contains an address somewhere", so a
 * diagnostic that happened to mention `verified` and an unrelated host on the same
 * line was counted as a hit, and rephrasing a probe log silently stopped counting
 * real ones. This list is the fallback for text lines only — see `hitKeyOf`.
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
 * rows — this list is a log of *endpoints that answered*, and the prose lines the
 * engine writes carry no protocol to key on, so mixing granularities would let one
 * endpoint appear twice under two spellings of the same fact.
 */
export function hitAddressKey(addr: string): string {
  return addr.trim().toLowerCase();
}

/** `AETHER_EVENT {"type":"scan_hit","addr":"1.1.1.1:443",…}` → that address. */
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
 * embedded in the line, then the narrow prose rule. The Scanner writes the first
 * when it turns a `scan_hit` into a log entry, which is what keeps the Hits view
 * correct if the engine ever rewords its own output.
 */
export function hitKeyOf(entry: Pick<LogEntry, "message"> & Partial<Pick<LogEntry, "hitKey">>): string | null {
  if (entry.hitKey) return hitAddressKey(entry.hitKey);
  const addr = eventHitAddress(entry.message);
  if (addr) return hitAddressKey(addr);
  const prose = PROSE_HIT.exec(entry.message);
  const candidate = prose?.[1];
  return candidate ? hitAddressKey(candidate) : null;
}

const isError = (l: LogEntry) => l.level === "error" || l.level === "warn";
// milestones: exclude noisy progress and probe error lines so high-level transitions stand out
const isMilestone = (l: LogEntry) =>
  !l.message.includes("scanning...") &&
  !l.message.includes("probe src") &&
  !l.message.includes("probe candidate failed") &&
  !l.message.includes("probe timeout") &&
  !l.message.includes("candidate rejected");

/**
 * One line plus the three verdicts taken about it.
 *
 * Classifying at append time is the difference between reading a regex over a
 * 1000-entry buffer once per *line* and once per *rendered row per appended line*:
 * the filter chips, the Hits list and the visible window all used to re-derive
 * those answers from the text on the same commit that painted 200 rows, which is
 * the scan-time freeze.
 */
type Classified = {
  entry: LogEntry;
  hitKey: string | null;
  isHit: boolean;
  isMilestone: boolean;
  isError: boolean;
};

type Store = {
  /** Oldest first, capped at `MAX_LOGS`. */
  lines: Classified[];
  /**
   * The designated line per address, in buffer order — the list under "Hits".
   * Kept alongside `keyCounts` so the chip beside the filter and the rows under it
   * are one fact and not two computations that can disagree.
   */
  hits: Classified[];
  /** How many lines per address are still in the buffer. */
  keyCounts: Map<string, number>;
  counts: { milestones: number; errors: number };
};

const emptyStore: Store = {
  lines: [],
  hits: [],
  keyCounts: new Map(),
  counts: { milestones: 0, errors: 0 },
};

function classify(entry: LogEntry): Classified {
  const hitKey = hitKeyOf(entry);
  return {
    entry,
    hitKey,
    isHit: hitKey !== null,
    isMilestone: isMilestone(entry),
    isError: isError(entry),
  };
}

/**
 * Append one line and move the derived answers forward.
 *
 * Pure in `store` (a fresh object is returned; nothing is mutated), so React may
 * call it twice under StrictMode. A hit is an endpoint, not a line that mentioned
 * one: the engine writes both a structured `scan_hit` and a human "candidate ok"
 * line for the same address, and counting lines counted one endpoint two and three
 * times. When the counted line ages out of the buffer the next surviving line for
 * that address takes its place, so trimming cannot silently lose an endpoint.
 */
export function appendToStore(store: Store, entry: LogEntry): Store {
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
    const key = gone.hitKey;
    if (key === null) continue;
    const remaining = (keyCounts.get(key) ?? 1) - 1;
    if (remaining <= 0) keyCounts.delete(key);
    else keyCounts.set(key, remaining);
    if (!hits.includes(gone)) continue;
    // The counted line left; promote the next one for the same address, which is
    // the only case that can cost more than O(1). The order is the buffer's, so
    // the Hits list reads top-to-bottom like the console under it.
    const successor = lines.find((l) => l.hitKey === key);
    hits = successor
      ? [...hits.filter((h) => h !== gone), successor].sort((a, b) => a.entry.id - b.entry.id)
      : hits.filter((h) => h !== gone);
  }

  return { lines, hits, keyCounts, counts };
}

export function useLogs() {
  const [store, setStore] = useState<Store>(emptyStore);
  const [logFilter, setLogFilter] = useState<LogFilter>("milestones");
  const logEndRef = useRef<HTMLDivElement>(null);
  const [autoScroll, setAutoScroll] = useState(true);
  const nextIdRef = useRef(0);

  const appendLog = useCallback((entry: LogInput) => {
    // Build the entry outside the updater — updaters must stay pure
    // (StrictMode double-invokes them).
    const ts = Date.now();
    const full: LogEntry = { ...entry, id: nextIdRef.current++, ts, time: formatLogTime(ts) };
    setStore((current) => appendToStore(current, full));
  }, []);

  const lines = store.lines;

  const logs = useMemo(() => lines.map((l) => l.entry), [lines]);

  const filteredLogs = useMemo(() => {
    const source = logFilter === "hits" ? store.hits : lines;
    const keep = logFilter === "milestones" || logFilter === "errors"
      ? (l: Classified) => (logFilter === "milestones" ? l.isMilestone : l.isError)
      : null;
    return (keep ? source.filter(keep) : source).map((l) => l.entry);
  }, [lines, store.hits, logFilter]);

  const filterCounts = useMemo(
    () => ({
      milestones: store.counts.milestones,
      hits: store.hits.length,
      errors: store.counts.errors,
      raw: lines.length,
    }),
    [store.counts, store.hits.length, lines.length],
  );

  const visibleLogs = useMemo(() => {
    if (filteredLogs.length <= RENDER_CAP) return filteredLogs;
    return filteredLogs.slice(filteredLogs.length - RENDER_CAP);
  }, [filteredLogs]);

  const clearLogs = useCallback(() => {
    // The id counter is *not* reset: ids are React keys, and a cleared-then-
    // refilled buffer must not hand a new line the key of a line still mounted.
    setStore(emptyStore);
  }, []);

  const hasMore = filteredLogs.length > RENDER_CAP;

  return {
    logs,
    clearLogs,
    logFilter,
    setLogFilter,
    appendLog,
    filteredLogs,
    visibleLogs,
    hasMore,
    filterCounts,
    logEndRef,
    autoScroll,
    setAutoScroll,
  };
}
