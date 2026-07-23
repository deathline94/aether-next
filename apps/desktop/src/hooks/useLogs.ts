import { useCallback, useMemo, useRef, useState } from "react";
import type { LogEntry, LogFilter } from "../types";

function now() {
  return new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

let nextId = 0;

export function useLogs() {
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [logFilter, setLogFilter] = useState<LogFilter>("milestones");
  const logEndRef = useRef<HTMLDivElement>(null);
  const [autoScroll, setAutoScroll] = useState(true);

  const appendLog = useCallback((entry: Omit<LogEntry, "time" | "id">) => {
    setLogs((current) => [...current.slice(-999), { ...entry, id: nextId++, time: now() }]);
  }, []);

  const filteredLogs = useMemo(() => {
    if (logFilter === "raw") return logs;
    if (logFilter === "hits") {
      return logs.filter(
        (l) =>
          l.message.includes("candidate ok") ||
          l.message.includes("Tier-0") ||
          l.message.includes("gateway") ||
          l.message.includes("EndpointSelected") ||
          l.message.includes("scan_hit"),
      );
    }
    if (logFilter === "errors") {
      return logs.filter((l) => l.level === "error" || l.level === "warn");
    }
    // milestones: exclude noisy progress lines
    return logs.filter(
      (l) => !l.message.includes("scanning...") && !l.message.includes("probe src"),
    );
  }, [logs, logFilter]);

  const filterCounts = useMemo(
    () => ({
      milestones: logs.filter((l) => !l.message.includes("scanning...") && !l.message.includes("probe src")).length,
      hits: logs.filter((l) => l.message.includes("candidate ok") || l.message.includes("Tier-0") || l.message.includes("scan_hit")).length,
      errors: logs.filter((l) => l.level === "error" || l.level === "warn").length,
      raw: logs.length,
    }),
    [logs],
  );

  // Cap rendered entries for performance
  const RENDER_CAP = 200;
  const visibleLogs = useMemo(() => {
    if (filteredLogs.length <= RENDER_CAP) return filteredLogs;
    return filteredLogs.slice(filteredLogs.length - RENDER_CAP);
  }, [filteredLogs]);

  const hasMore = filteredLogs.length > RENDER_CAP;

  return {
    logs,
    setLogs,
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
