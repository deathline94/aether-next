import { TerminalSquare, Sparkles, ArrowDown } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { RENDER_CAP } from "../hooks/useLogs";
import { formatLogTime } from "../types";
import type { LogEntry, LogFilter, ScanState } from "../types";

interface ActivityTabProps {
  visibleLogs: LogEntry[];
  hasMore: boolean;
  filterCounts: Record<LogFilter, number>;
  logFilter: LogFilter;
  setLogFilter: (f: LogFilter) => void;
  logEndRef: React.RefObject<HTMLDivElement | null>;
  autoScroll: boolean;
  setAutoScroll: (v: boolean) => void;
  exportLogs: () => Promise<boolean>;
  clearLogs: () => void;
  scanState: ScanState;
  status: string;
}

export function ActivityTab({
  visibleLogs, hasMore, filterCounts,
  logFilter, setLogFilter,
  logEndRef, autoScroll, setAutoScroll,
  exportLogs, clearLogs,
  scanState, status,
}: ActivityTabProps) {
  const [copied, setCopied] = useState(false);
  const copyTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const consoleRef = useRef<HTMLElement | null>(null);

  useEffect(() => {
    if (autoScroll) {
      // "auto" instead of "smooth": queued smooth scrolls fight each other
      // at scan-time log rates and jank the console.
      logEndRef.current?.scrollIntoView({ behavior: "auto" });
    }
  }, [visibleLogs, autoScroll, logEndRef]);

  useEffect(() => () => { if (copyTimer.current) clearTimeout(copyTimer.current); }, []);

  // Pause auto-scroll on any scroll gesture away from the bottom (wheel,
  // scrollbar drag, keyboard, touch) and resume when back at the bottom.
  const handleScroll = () => {
    const el = consoleRef.current;
    if (!el) return;
    const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 40;
    if (autoScroll && !atBottom) setAutoScroll(false);
    else if (!autoScroll && atBottom) setAutoScroll(true);
  };

  const handleCopy = async () => {
    const ok = await exportLogs();
    if (!ok) return;
    setCopied(true);
    if (copyTimer.current) clearTimeout(copyTimer.current);
    copyTimer.current = setTimeout(() => setCopied(false), 1500);
  };

  const filters: { id: LogFilter; label: string }[] = [
    { id: "milestones", label: `Milestones (${filterCounts.milestones})` },
    { id: "hits", label: `Hits (${filterCounts.hits})` },
    { id: "errors", label: `Errors (${filterCounts.errors})` },
    { id: "raw", label: `Raw (${filterCounts.raw})` },
  ];

  return (
    <div className="logs-view">
      {scanState.active && (
        <div className="scan-card">
          <div className="scan-card-header">
            <div className="scan-title">
              <Sparkles size={15} className="spin-icon" aria-hidden="true" />
              <strong>Active Engine Scan ({scanState.mode.toUpperCase()})</strong>
              <span className="phase-pill">{scanState.phase}</span>
            </div>
            <div className="scan-badges">
              <span className="badge concurrency">{scanState.concurrency} Workers</span>
              <span className="badge working">{scanState.working} Working</span>
              {scanState.bestRtt && <span className="badge rtt">Best: {scanState.bestRtt}</span>}
            </div>
          </div>
          <div
            className="scan-progress-bar-bg"
            role="progressbar"
            aria-label="Engine scan progress"
            aria-valuemin={0}
            aria-valuemax={scanState.total}
            aria-valuenow={scanState.scanned}
          >
            <div
              className="scan-progress-bar-fill"
              style={{
                width: scanState.total > 0
                  ? `${Math.min(100, Math.round((scanState.scanned / scanState.total) * 100))}%`
                  : "0%",
              }}
            />
          </div>
          <div className="scan-card-footer">
            <small>Probed {scanState.scanned.toLocaleString()} / {scanState.total.toLocaleString()} candidates</small>
            <small>{scanState.total > 0 ? `${Math.round((scanState.scanned / scanState.total) * 100)}%` : "0%"}</small>
          </div>
        </div>
      )}

      <div className="log-toolbar">
        <div>
          <span className={`status-dot ${status}`} aria-hidden="true" />
          <strong>Activity Feed</strong>
          <small>{filterCounts[logFilter]} events</small>
        </div>
        <div className="log-filter-bar" role="radiogroup" aria-label="Log filter">
          {filters.map((f) => (
            <button
              key={f.id}
              role="radio"
              aria-checked={logFilter === f.id}
              className={logFilter === f.id ? "active" : ""}
              onClick={() => setLogFilter(f.id)}
            >
              {f.label}
            </button>
          ))}
        </div>
        <div className="log-actions">
          {!autoScroll && (
            <button onClick={() => setAutoScroll(true)} title="Resume auto-scroll" aria-label="Resume auto-scroll">
              <ArrowDown size={14} aria-hidden="true" />
            </button>
          )}
          <button onClick={handleCopy} disabled={filterCounts.raw === 0}>
            {copied ? "Copied ✓" : "Copy all"}
          </button>
          <button onClick={clearLogs} disabled={filterCounts.raw === 0}>Clear</button>
        </div>
      </div>

      <section
        ref={consoleRef}
        className="log-console"
        onScroll={handleScroll}
        aria-label="Engine log output"
      >
        {hasMore && (
          <div className="log-more-hint">
            <small>Showing the last {RENDER_CAP} matching entries — use "Copy all" to export the full buffer</small>
          </div>
        )}
        {visibleLogs.length === 0 ? (
          <div className="empty-logs">
            <TerminalSquare size={26} aria-hidden="true" />
            <strong>No activity yet</strong>
            <span>Engine events appear here after connection starts.</span>
          </div>
        ) : (
          visibleLogs.map((entry) => (
            <div className={`log-line ${entry.level}`} key={entry.id}>
              <time dateTime={new Date(entry.ts).toISOString()}>{formatLogTime(entry.ts)}</time>
              <span>{entry.level}</span>
              <p>{entry.message}</p>
            </div>
          ))
        )}
        <div ref={logEndRef} />
      </section>
    </div>
  );
}
