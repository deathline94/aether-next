import { useCallback, useMemo, useRef, useState } from "react";
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

/**
 * A hit is an endpoint, not a line that mentioned one. The engine writes both a
 * structured `scan_hit` and a human "candidate ok" line for the same address, so
 * counting lines counted one endpoint two and three times. Keep the first line per
 * address so the list under "Hits" and the number beside it are the same fact.
 */
export function uniqueHits(logs: LogEntry[]): LogEntry[] {
  const seen = new Set<string>();
  const out: LogEntry[] = [];
  for (const l of logs) {
    const key = hitKeyOf(l);
    if (key === null) continue;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(l);
  }
  return out;
}

const isError = (l: LogEntry) => l.level === "error" || l.level === "warn";
// milestones: exclude noisy progress and probe error lines so high-level transitions stand out
const isMilestone = (l: LogEntry) =>
  !l.message.includes("scanning...") &&
  !l.message.includes("probe src") &&
  !l.message.includes("probe candidate failed") &&
  !l.message.includes("probe timeout") &&
  !l.message.includes("candidate rejected");

const predicates: Record<LogFilter, (l: LogEntry) => boolean> = {
  milestones: isMilestone,
  hits: (l) => hitKeyOf(l) !== null,
  errors: isError,
  raw: () => true,
};

export function useLogs() {
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [logFilter, setLogFilter] = useState<LogFilter>("milestones");
  const logEndRef = useRef<HTMLDivElement>(null);
  const [autoScroll, setAutoScroll] = useState(true);
  const nextIdRef = useRef(0);

  const appendLog = useCallback((entry: LogInput) => {
    // Build the entry outside the updater — updaters must stay pure
    // (StrictMode double-invokes them).
    const full: LogEntry = { ...entry, id: nextIdRef.current++, ts: Date.now() };
    setLogs((current) => [...current.slice(-(MAX_LOGS - 1)), full]);
  }, []);

  const hits = useMemo(() => uniqueHits(logs), [logs]);
  const filteredLogs = useMemo(
    () => (logFilter === "hits" ? hits : logs.filter(predicates[logFilter])),
    [logs, logFilter, hits],
  );

  const filterCounts = useMemo(
    () => ({
      milestones: logs.filter(isMilestone).length,
      hits: hits.length,
      errors: logs.filter(isError).length,
      raw: logs.length,
    }),
    [logs, hits],
  );

  const visibleLogs = useMemo(() => {
    if (filteredLogs.length <= RENDER_CAP) return filteredLogs;
    return filteredLogs.slice(filteredLogs.length - RENDER_CAP);
  }, [filteredLogs]);

  const clearLogs = useCallback(() => {
    setLogs([]);
    nextIdRef.current = 0;
  }, []);

  const hasMore = filteredLogs.length > RENDER_CAP;

  return {
    logs,
    setLogs,
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
