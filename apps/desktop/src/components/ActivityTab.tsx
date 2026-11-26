import { ArrowDown, Ban, Check, Copy, ScrollText, Search, Terminal } from "lucide-react";
import { memo, useEffect, useMemo, useRef, useState } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import { nextOptionIndex } from "@aether/ui";
import {
  LOG_FILTER_HINT,
  LOG_FILTER_LABELS as FILTERS,
  scanProgressCopy,
  streamLabel,
  TERMINAL_TITLE,
} from "@aether/ui/statusCopy";
import { LOG_SEVERITY_LABELS, logSeverityOf } from "@aether/ui/logs";
import { RENDER_CAP } from "../hooks/useLogs";
import type { LogEntry, LogFilter, ScanState } from "../types";

const ESTIMATED_ROW_PX = 26;

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

export function scrollConsoleToBottom(
  panel: { scrollTop: number; scrollHeight: number },
  endMarker: { scrollIntoView: (arg?: ScrollIntoViewOptions | boolean) => void } | null,
  latch: { current: boolean },
): void {
  latch.current = true;
  try {
    panel.scrollTop = panel.scrollHeight;
    endMarker?.scrollIntoView({ behavior: "auto" });
  } finally {
    latch.current = false;
  }
}

function ActivityTabImpl({
  visibleLogs,
  hasMore,
  filterCounts,
  logFilter,
  setLogFilter,
  logEndRef,
  autoScroll,
  setAutoScroll,
  exportLogs,
  clearLogs,
  scanState,
  status,
}: ActivityTabProps) {
  const [copied, setCopied] = useState(false);
  const [query, setQuery] = useState("");
  const copyTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const consoleRef = useRef<HTMLElement | null>(null);
  const isProgrammaticScrollRef = useRef(false);
  const pendingProgrammaticRef = useRef(0);

  const displayedLogs = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return visibleLogs;
    return visibleLogs.filter((entry) => entry.message.toLowerCase().includes(q));
  }, [visibleLogs, query]);

  const rows = useVirtualizer({
    count: displayedLogs.length,
    getScrollElement: () => consoleRef.current,
    estimateSize: () => ESTIMATED_ROW_PX,
    overscan: 16,
  });

  useEffect(() => {
    if (autoScroll && consoleRef.current) {
      scrollConsoleToBottom(consoleRef.current, logEndRef.current, isProgrammaticScrollRef);
      pendingProgrammaticRef.current = Math.min(pendingProgrammaticRef.current + 1, 3);
    }
  }, [displayedLogs, autoScroll, logEndRef]);

  useEffect(() => () => {
    if (copyTimer.current) clearTimeout(copyTimer.current);
  }, []);

  const handleScroll = () => {
    if (isProgrammaticScrollRef.current) return;
    if (pendingProgrammaticRef.current > 0) {
      pendingProgrammaticRef.current -= 1;
      return;
    }
    const el = consoleRef.current;
    if (!el) return;
    const distanceFromBottom = el.scrollHeight - el.scrollTop - el.clientHeight;
    if (autoScroll && distanceFromBottom > 60) setAutoScroll(false);
    else if (!autoScroll && distanceFromBottom <= 20) setAutoScroll(true);
  };

  const handleCopy = async () => {
    const ok = await exportLogs();
    if (!ok) return;
    setCopied(true);
    if (copyTimer.current) clearTimeout(copyTimer.current);
    copyTimer.current = setTimeout(() => setCopied(false), 1500);
  };

  const empty = filterCounts.raw === 0;
  const scan = scanProgressCopy({ ...scanState, bestRtt: scanState.bestRtt ?? null });
  const pct = scanState.total > 0 ? Math.min(100, Math.round((scanState.scanned / scanState.total) * 100)) : 0;

  return (
    <div className="activity-view">
      {scanState.active && (
        <section className="nordic-card" aria-label="Active scan progress">
          <div className="scan-progress-header">
            <strong className="scan-headline">{scan.headline}</strong>
            <span className="tactical-chip emerald">{scanState.phase}</span>
          </div>
          <div
            className="scan-progress-bar-bg"
            role="progressbar"
            aria-label="Server scan progress"
            aria-valuemin={0}
            aria-valuemax={scanState.total}
            aria-valuenow={scanState.scanned}
          >
            <div className="scan-progress-bar-fill" style={{ width: `${pct}%` }} />
          </div>
          <div className="scan-card-footer">
            <small className="tabular-nums">{scan.progressLabel}</small>
            <span className="scan-inline-stats">
              <span className="tactical-chip">{scan.concurrency}</span>
              <span className="tactical-chip emerald">{scan.working}</span>
              {scan.fastest && <span className="tactical-chip cyan">{scan.fastest}</span>}
            </span>
          </div>
        </section>
      )}

      <section className="nordic-card terminal-card">
        <header className="terminal-header-chrome">
          <div className="terminal-title-group">
            <span className={`status-dot ${status}`} aria-hidden="true" />
            <span className="terminal-title-text font-mono" aria-hidden="true">{TERMINAL_TITLE}</span>
            <span className="stream-count tabular-nums">
              {displayedLogs.length.toLocaleString()} of {filterCounts.raw.toLocaleString()} lines shown
            </span>
          </div>

          <div className="terminal-action-buttons">
            {!autoScroll && (
              <button
                type="button"
                className="tactile-terminal-btn"
                onClick={() => {
                  setAutoScroll(true);
                  if (consoleRef.current) consoleRef.current.scrollTop = consoleRef.current.scrollHeight;
                }}
              >
                <ArrowDown size={13} aria-hidden="true" />
                <span>Follow</span>
              </button>
            )}
            <button
              type="button"
              className={`tactile-terminal-btn ${copied ? "copied" : ""}`}
              onClick={handleCopy}
              disabled={empty}
              title="Copy log lines and engine diagnostics, with addresses masked"
            >
              {copied ? <Check size={13} aria-hidden="true" /> : <Copy size={13} aria-hidden="true" />}
              <span>{copied ? "Copied" : "Copy logs + diagnostics"}</span>
            </button>
            <button
              type="button"
              className="tactile-terminal-btn danger"
              onClick={clearLogs}
              disabled={empty}
            >
              <Ban size={13} aria-hidden="true" />
              <span>Clear logs</span>
            </button>
          </div>
        </header>

        <div className="terminal-toolbar">
          <div
            className="filter-pill-group"
            role="radiogroup"
            aria-label="Log filter"
            onKeyDown={(event) => {
              const selected = Math.max(0, FILTERS.findIndex((f) => f.id === logFilter));
              const next = nextOptionIndex(selected, event.key, FILTERS.length);
              if (next === null) return;
              event.preventDefault();
              const filter = FILTERS[next];
              if (filter) setLogFilter(filter.id);
            }}
          >
            {FILTERS.map((f) => (
              <button
                key={f.id}
                type="button"
                role="radio"
                aria-checked={logFilter === f.id}
                tabIndex={logFilter === f.id ? 0 : -1}
                className={`filter-chip ${logFilter === f.id ? "active" : ""}`}
                onClick={() => setLogFilter(f.id)}
              >
                <span>{f.label}</span>
                <span className="chip-count tabular-nums">{filterCounts[f.id].toLocaleString()}</span>
              </button>
            ))}
          </div>

          <div className="terminal-search-box">
            <Search size={14} aria-hidden="true" />
            <input
              type="search"
              aria-label="Search logs"
              placeholder="Filter output…"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
          </div>

          <div className="terminal-mode-indicator" role="status" aria-live="polite">
            <span className="mode-tag font-mono">{streamLabel(status)}</span>
          </div>
        </div>

        <section
          ref={consoleRef}
          className="tactical-terminal-screen font-mono"
          onScroll={handleScroll}
          aria-label="Engine log output"
          tabIndex={0}
        >
          {hasMore && (
            <div className="log-more-hint">
              <small className="tabular-nums">
                Showing the latest {RENDER_CAP} lines. Use "Copy logs + diagnostics" to export the full masked buffer.
              </small>
            </div>
          )}

          {displayedLogs.length === 0 ? (
            <div className="empty-logs">
              <Terminal size={26} aria-hidden="true" />
              <strong>{empty ? "No log lines yet" : "Nothing matches this filter"}</strong>
              <span>
                {empty
                  ? "Engine start-up, server scans and connection events appear here while Aether Next runs."
                  : 'Select "All lines" or clear your search to inspect more lines.'}
              </span>
            </div>
          ) : (
            <div style={{ height: rows.getTotalSize(), position: "relative", width: "100%" }} role="log" aria-label="Log rows">
              {rows.getVirtualItems().map((row) => {
                const entry = displayedLogs[row.index];
                if (!entry) return null;
                const category = logSeverityOf(entry);
                const label = LOG_SEVERITY_LABELS[category];
                return (
                  <div
                    key={entry.id}
                    data-index={row.index}
                    ref={rows.measureElement}
                    style={{
                      position: "absolute",
                      top: 0,
                      left: 0,
                      width: "100%",
                      transform: `translateY(${row.start}px)`,
                    }}
                  >
                    <div className={`terminal-log-row ${category}`}>
                      <time className="tabular-nums font-mono" dateTime={new Date(entry.ts).toISOString()}>
                        {entry.time}
                      </time>
                      <span className={`log-level-badge ${category} font-mono`}>[{label}]</span>
                      <p className="log-message-body font-mono">{entry.message}</p>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
          <div ref={logEndRef} />
        </section>
      </section>

      {empty && !scanState.active && (
        <div className="activity-hint">
          <ScrollText size={13} aria-hidden="true" />
          <span>{LOG_FILTER_HINT}</span>
        </div>
      )}
    </div>
  );
}

export const ActivityTab = memo(ActivityTabImpl);
