import { ArrowDown, Ban, Copy, Check, ScrollText, Sparkles, TerminalSquare } from "lucide-react";
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

const FILTERS: { id: LogFilter; label: string }[] = [
  { id: "milestones", label: "Milestones" },
  { id: "hits", label: "Hits" },
  { id: "errors", label: "Errors" },
  { id: "raw", label: "Raw" },
];

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
    // "auto" not "smooth": queued smooth scrolls fight each other at scan-time
    // log rates and jank the console.
    if (autoScroll) logEndRef.current?.scrollIntoView({ behavior: "auto" });
  }, [visibleLogs, autoScroll, logEndRef]);

  useEffect(() => () => { if (copyTimer.current) clearTimeout(copyTimer.current); }, []);

  // Pause auto-scroll on any gesture away from the bottom; resume at the bottom.
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

  const empty = filterCounts.raw === 0;
  const pct = scanState.total > 0 ? Math.min(100, Math.round((scanState.scanned / scanState.total) * 100)) : 0;

  return (
    <div className="activity-view">
      {scanState.active && (
        <div className="scan-card">
          <div className="scan-card-header">
            <div className="scan-title">
              <Sparkles size={15} className="spin-icon" aria-hidden="true" />
              <strong>Active Engine Scan ({scanState.mode.toUpperCase()})</strong>
              <span className="phase-pill">{scanState.phase}</span>
            </div>
            <div className="scan-badges">
              <span className="badge concurrency">{scanState.concurrency} workers</span>
              <span className="badge working">{scanState.working} working</span>
              {scanState.bestRtt && <span className="badge rtt">best {scanState.bestRtt}</span>}
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
            <div className="scan-progress-bar-fill" style={{ width: `${pct}%` }} />
          </div>
          <div className="scan-card-footer">
            <small>Probed {scanState.scanned.toLocaleString()} / {scanState.total.toLocaleString()} candidates</small>
            <small>{pct}%</small>
          </div>
        </div>
      )}

      <section className="activity-panel">
        <header className="activity-head">
          <div className="activity-head-title">
            <span className={`status-dot ${status}`} aria-hidden="true" />
            <div>
              <strong>Activity feed</strong>
              <small>{filterCounts[logFilter].toLocaleString()} shown · {filterCounts.raw.toLocaleString()} total</small>
            </div>
          </div>
          <div className="activity-actions">
            {!autoScroll && (
              <button type="button" className="ghost-btn" onClick={() => setAutoScroll(true)} title="Resume auto-scroll" aria-label="Resume auto-scroll">
                <ArrowDown size={14} aria-hidden="true" />
                <span>Follow</span>
              </button>
            )}
            <button type="button" className="ghost-btn" onClick={handleCopy} disabled={empty}>
              {copied ? <Check size={14} aria-hidden="true" /> : <Copy size={14} aria-hidden="true" />}
              <span>{copied ? "Copied" : "Copy"}</span>
            </button>
            <button type="button" className="ghost-btn danger" onClick={clearLogs} disabled={empty}>
              <Ban size={14} aria-hidden="true" />
              <span>Clear</span>
            </button>
          </div>
        </header>

        <div className="activity-filters" role="radiogroup" aria-label="Log filter">
          {FILTERS.map((f) => (
            <button
              key={f.id}
              type="button"
              role="radio"
              aria-checked={logFilter === f.id}
              className={`filter-chip ${logFilter === f.id ? "active" : ""}`}
              onClick={() => setLogFilter(f.id)}
            >
              {f.label}
              <span className="chip-count">{filterCounts[f.id].toLocaleString()}</span>
            </button>
          ))}
        </div>

        <section ref={consoleRef} className="activity-console" onScroll={handleScroll} aria-label="Engine log output">
          {hasMore && (
            <div className="log-more-hint">
              <small>Showing the last {RENDER_CAP} matching entries — use Copy to export the full buffer</small>
            </div>
          )}
          {visibleLogs.length === 0 ? (
            <div className="empty-logs">
              <TerminalSquare size={26} aria-hidden="true" />
              <strong>{empty ? "No activity yet" : "Nothing matches this filter"}</strong>
              <span>{empty ? "Engine events appear here after you connect or scan." : "Try the Raw filter to see every line."}</span>
            </div>
          ) : (
            visibleLogs.map((entry) => (
              <div className={`log-line ${entry.level}`} key={entry.id} title={entry.level}>
                <span className="log-dot" aria-hidden="true" />
                <time dateTime={new Date(entry.ts).toISOString()}>{formatLogTime(entry.ts)}</time>
                <p>{entry.message}</p>
              </div>
            ))
          )}
          <div ref={logEndRef} />
        </section>
      </section>

      {empty && !scanState.active && (
        <div className="activity-hint">
          <ScrollText size={13} aria-hidden="true" />
          <span>Milestones hides progress spam. Switch to Raw for the unfiltered stream.</span>
        </div>
      )}
    </div>
  );
}
