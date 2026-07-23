import { TerminalSquare, Sparkles, ArrowDown } from "lucide-react";
import { useEffect } from "react";
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
  exportLogs: () => void;
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
  useEffect(() => {
    if (autoScroll) {
      logEndRef.current?.scrollIntoView({ behavior: "smooth" });
    }
  }, [visibleLogs, autoScroll, logEndRef]);

  const filters: { id: LogFilter; label: string }[] = [
    { id: "milestones", label: `Milestones (${filterCounts.milestones})` },
    { id: "hits", label: `🟢 Hits (${filterCounts.hits})` },
    { id: "errors", label: `⚠️ Errors (${filterCounts.errors})` },
    { id: "raw", label: `📜 Raw (${filterCounts.raw})` },
  ];

  return (
    <div className="logs-view">
      {scanState.active && (
        <div className="scan-card">
          <div className="scan-card-header">
            <div className="scan-title">
              <Sparkles size={15} className="spin-icon" />
              <strong>Active Engine Scan ({scanState.mode.toUpperCase()})</strong>
              <span className="phase-pill">{scanState.phase}</span>
            </div>
            <div className="scan-badges">
              <span className="badge concurrency">⚡ {scanState.concurrency} Workers</span>
              <span className="badge working">🟢 {scanState.working} Working</span>
              {scanState.bestRtt && <span className="badge rtt">⚡ Best: {scanState.bestRtt}</span>}
            </div>
          </div>
          <div className="scan-progress-bar-bg">
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
          <span className={`status-dot ${status}`} />
          <strong>Activity Feed</strong>
          <small>{filterCounts[logFilter]} events</small>
        </div>
        <div className="log-filter-bar">
          {filters.map((f) => (
            <button
              key={f.id}
              className={logFilter === f.id ? "active" : ""}
              onClick={() => setLogFilter(f.id)}
            >
              {f.label}
            </button>
          ))}
        </div>
        <div className="log-actions">
          {!autoScroll && (
            <button onClick={() => setAutoScroll(true)} title="Resume auto-scroll">
              <ArrowDown size={14} />
            </button>
          )}
          <button onClick={exportLogs}>Copy all</button>
          <button onClick={clearLogs}>Clear</button>
        </div>
      </div>

      <section
        className="log-console"
        onWheel={() => { if (autoScroll) setAutoScroll(false); }}
      >
        {hasMore && (
          <div className="log-more-hint">
            <small>Showing last 200 entries — switch to Raw for full history</small>
          </div>
        )}
        {visibleLogs.length === 0 ? (
          <div className="empty-logs">
            <TerminalSquare size={26} />
            <strong>No activity yet</strong>
            <span>Engine events appear here after connection starts.</span>
          </div>
        ) : (
          visibleLogs.map((entry) => (
            <div className={`log-line ${entry.level}`} key={entry.id}>
              <time>{entry.time}</time>
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
