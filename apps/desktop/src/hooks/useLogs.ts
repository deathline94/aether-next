import { useCallback, useMemo, useRef, useState } from "react";
import type { LogEntry, LogFilter } from "../types";

const MAX_LOGS = 1000;
/** Cap rendered entries for performance. */
export const RENDER_CAP = 200;

const IP_SOCKET_REGEX = /\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b|\[?[0-9a-fA-F:]{4,}\]?(?::\d+)?/;

// Single source of truth for filter predicates — the tab counts and the
// visible list must always agree.
const isHit = (l: LogEntry) => {
  if (!IP_SOCKET_REGEX.test(l.message)) return false;
  return (
    l.message.includes("candidate ok") ||
    l.message.includes("Tier-0") ||
    l.message.includes("scan_hit") ||
    l.message.includes("EndpointSelected") ||
    l.message.includes("verified") ||
    l.message.includes("Selected edge") ||
    l.message.includes("best:")
  );
};
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
  hits: isHit,
  errors: isError,
  raw: () => true,
};

export function useLogs() {
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [logFilter, setLogFilter] = useState<LogFilter>("milestones");
  const logEndRef = useRef<HTMLDivElement>(null);
  const [autoScroll, setAutoScroll] = useState(true);
  const nextIdRef = useRef(0);

  const appendLog = useCallback((entry: Omit<LogEntry, "ts" | "id">) => {
    // Build the entry outside the updater — updaters must stay pure
    // (StrictMode double-invokes them).
    const full: LogEntry = { ...entry, id: nextIdRef.current++, ts: Date.now() };
    setLogs((current) => [...current.slice(-(MAX_LOGS - 1)), full]);
  }, []);

  const filteredLogs = useMemo(() => logs.filter(predicates[logFilter]), [logs, logFilter]);

  const filterCounts = useMemo(
    () => ({
      milestones: logs.filter(isMilestone).length,
      hits: logs.filter(isHit).length,
      errors: logs.filter(isError).length,
      raw: logs.length,
    }),
    [logs],
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
