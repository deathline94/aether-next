import { useCallback, useMemo, useRef, useState } from "react";
import { formatLogTime } from "../types";
import type { LogEntry, LogFilter, LogInput } from "../types";
import {
  RENDER_CAP,
  appendToStore,
  emptyStore,
  hitKeyOf,
  visibleWindow,
} from "../../../../packages/ui/src/logs";
import type { Classified, Store } from "../../../../packages/ui/src/logs";

/*
 * What is left here is React. The facts - whether a line is a hit, which
 * endpoint it is a hit for, whether it is a milestone, and the incremental store
 * that keeps those answers current without re-scanning the buffer on every
 * render - live in `packages/ui/src/logs.ts`, because the phone has to give the
 * same answers and did not. The re-exports below keep this hook the surface
 * callers and tests read from.
 */
export { hitKeyOf, RENDER_CAP };
export type { Classified, Store };

export function useLogs() {
  const [store, setStore] = useState<Store<LogEntry>>(emptyStore<LogEntry>());
  const [logFilter, setLogFilter] = useState<LogFilter>("milestones");
  const logEndRef = useRef<HTMLDivElement>(null);
  const [autoScroll, setAutoScroll] = useState(true);
  const nextIdRef = useRef(0);

  const appendLog = useCallback((entry: LogInput) => {
    // Build the entry outside the updater - updaters must stay pure
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
      ? (l: Classified<LogEntry>) => (logFilter === "milestones" ? l.isMilestone : l.isError)
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

  const { visible: visibleLogs, hasMore } = useMemo(() => visibleWindow(filteredLogs), [filteredLogs]);

  const clearLogs = useCallback(() => {
    // The id counter is *not* reset: ids are React keys, and a cleared-then-
    // refilled buffer must not hand a new line the key of a line still mounted.
    setStore(emptyStore<LogEntry>());
  }, []);

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
