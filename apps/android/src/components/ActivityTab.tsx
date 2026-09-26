import {
  ArrowDown,
  Ban,
  Check,
  Copy,
  ScrollText,
  Sparkles,
  Terminal,
} from "lucide-react";
import { useEffect, useRef, useState } from "react";
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

/**
 * Scroll the console to the newest line and leave the "was that us?" latch clear.
 *
 * The reset used to be deferred into `requestAnimationFrame`, which does not run
 * while the window is hidden to the tray — so the latch stayed set, and the next
 * time the window came back the user's own scrolling could no longer pause the
 * follow. Clearing it synchronously is enough: a programmatic scroll lands at the
 * bottom, and the scroll handler only pauses when the viewport is away from it.
 */
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

export function ActivityTab({
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
  const copyTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const consoleRef = useRef<HTMLElement | null>(null);

  const isProgrammaticScrollRef = useRef(false);

  // Each programmatic write dispatches exactly one scroll event, but the event
  // fires in the rendering step — after the task that wrote it. Under a burst
  // append (three-plus rows in one frame) the scroll event for write N could
  // dispatch after write N+1 grew the buffer, so the handler saw a >60 px gap
  // and paused auto-follow mid-scan. The synchronous latch handles the direct
  // case; this counter absorbs the queued late events (capped so a no-op write
  // that fires no event cannot accumulate forever). Parity with the desktop twin.
  const pendingProgrammaticRef = useRef(0);

  useEffect(() => {
    // Direct container scroll lock + programmatic scroll guard so daemon log rates
    // never trigger an accidental auto-scroll pause.
    if (autoScroll && consoleRef.current) {
      scrollConsoleToBottom(consoleRef.current, logEndRef.current, isProgrammaticScrollRef);
      pendingProgrammaticRef.current = Math.min(pendingProgrammaticRef.current + 1, 3);
    }
  }, [visibleLogs, autoScroll, logEndRef]);

  useEffect(() => () => {
    if (copyTimer.current) clearTimeout(copyTimer.current);
  }, []);

  // Pause auto-scroll on any user gesture away from the bottom; resume at the bottom.
  const handleScroll = () => {
    if (isProgrammaticScrollRef.current) return;
    if (pendingProgrammaticRef.current > 0) {
      pendingProgrammaticRef.current -= 1;
      return;
    }
    const el = consoleRef.current;
    if (!el) return;
    const distanceFromBottom = el.scrollHeight - el.scrollTop - el.clientHeight;
    if (autoScroll && distanceFromBottom > 60) {
      setAutoScroll(false);
    } else if (!autoScroll && distanceFromBottom <= 20) {
      setAutoScroll(true);
    }
  };

  const handleCopy = async () => {
    const ok = await exportLogs();
    if (!ok) return;
    setCopied(true);
    if (copyTimer.current) clearTimeout(copyTimer.current);
    copyTimer.current = setTimeout(() => setCopied(false), 1500);
  };

  const empty = filterCounts.raw === 0;
  const scan = scanProgressCopy(scanState);
  const pct =
    scanState.total > 0
      ? Math.min(100, Math.round((scanState.scanned / scanState.total) * 100))
      : 0;

  return (
    <div className="activity-view tactical-activity-view">
      {scanState.active && (
        <div className="tactical-scan-card">
          <div className="scan-card-header">
            <div className="scan-title">
              <Sparkles size={15} className="spin-icon" aria-hidden="true" />
              <strong>{scan.headline}</strong>
              <span className="phase-pill">{scanState.phase}</span>
            </div>
            <div className="scan-badges">
              <span className="badge concurrency">{scan.concurrency}</span>
              <span className="badge working">{scan.working}</span>
              {scan.fastest && <span className="badge rtt">{scan.fastest}</span>}
            </div>
          </div>
          <div
            className="scan-progress-bar-bg"
            role="progressbar"
            aria-label="Server scan progress"
            aria-valuemin={0}
            aria-valuemax={scanState.total}
            aria-valuenow={scanState.scanned}
          >
            <div className="scan-progress-bar-fill active-glow" style={{ width: `${pct}%` }} />
          </div>
          <div className="scan-card-footer">
            <small className="tabular-nums">{scan.progressLabel}</small>
            <small className="tabular-nums">{pct}%</small>
          </div>
        </div>
      )}

      <section className="tactical-terminal-chassis">
        {/* Terminal Window Header Chrome */}
        <header className="terminal-header-chrome">
          <div className="terminal-window-controls">
            <span className="win-dot red" aria-hidden="true" />
            <span className="win-dot yellow" aria-hidden="true" />
            <span className="win-dot green" aria-hidden="true" />
            {/* Decorative window chrome. A shell prompt promises a shell: nothing
                here takes input, and a screen reader would have read the typed
                command as content. The console below carries the real name, and
                this line now says what it is rather than dressing as one. */}
            <span className="terminal-title-text font-mono" aria-hidden="true">{TERMINAL_TITLE}</span>
          </div>

          <div className="terminal-center-telemetry">
            <span className={`status-dot ${status}`} aria-hidden="true" />
            <span className="stream-count tabular-nums">
              {filterCounts[logFilter].toLocaleString()} of {filterCounts.raw.toLocaleString()} lines shown
            </span>
          </div>

          <div className="terminal-action-buttons">
            {!autoScroll && (
              <button
                type="button"
                className="tactile-terminal-btn"
                onClick={() => {
                  setAutoScroll(true);
                  if (consoleRef.current) {
                    consoleRef.current.scrollTop = consoleRef.current.scrollHeight;
                  }
                }}
                title="Resume auto-scroll"
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
              title="Copy these log lines to the clipboard"
            >
              {copied ? <Check size={13} aria-hidden="true" /> : <Copy size={13} aria-hidden="true" />}
              <span>{copied ? "Copied" : "Copy logs"}</span>
            </button>
            <button
              type="button"
              className="tactile-terminal-btn danger"
              onClick={clearLogs}
              disabled={empty}
              title="Empty the log list on this screen"
            >
              <Ban size={13} aria-hidden="true" />
              <span>Clear logs</span>
            </button>
          </div>
        </header>

        {/* Sticky Filter Pill Bar */}
        <div
          className="tactical-filter-dock"
          role="radiogroup"
          aria-label="Log filter"
          onKeyDown={(event) => {
            const selected = Math.max(0, FILTERS.findIndex((f) => f.id === logFilter));
            const next = nextOptionIndex(selected, event.key, FILTERS.length);
            if (next === null) return;
            event.preventDefault();
            const filter = FILTERS[next];
            if (!filter) return;
            setLogFilter(filter.id);
          }}
        >
          <div className="filter-pill-group">
            {FILTERS.map((f) => (
              <button
                key={f.id}
                type="button"
                role="radio"
                aria-checked={logFilter === f.id}
                // One tab stop for the group, arrows between the chips.
                tabIndex={logFilter === f.id ? 0 : -1}
                className={`filter-chip ${logFilter === f.id ? "active" : ""}`}
                onClick={() => setLogFilter(f.id)}
              >
                <span>{f.label}</span>
                <span className="chip-count tabular-nums">{filterCounts[f.id].toLocaleString()}</span>
              </button>
            ))}
          </div>

          <div
            className="terminal-mode-indicator"
            role="status"
            aria-live="polite"
          >
            {/* The terminal is not a TTY either — it cannot be written to, and
                saying so advertised a prompt. What the tag names now is the state
                the log itself is in, the only thing this panel can know. */}
            <span className="mode-tag font-mono">{streamLabel(status)}</span>
          </div>
        </div>

        {/* Terminal Screen Console */}
        <section
          ref={consoleRef}
          className="activity-console tactical-terminal-screen font-mono"
          onScroll={handleScroll}
          // `role="log"` is what tells assistive tech that this region's content is
          // appended as it happens — the same role the desktop console carries, so a
          // new line is announced on both surfaces rather than only seen.
          role="log"
          aria-label="Engine log output"
          // A scroll region the keyboard cannot reach: `tabIndex={0}` is what lets
          // PageUp/PageDown and the arrows read the lines above the fold.
          tabIndex={0}
        >
          {hasMore && (
            <div className="log-more-hint">
              <small className="tabular-nums">
                Only the last {RENDER_CAP} matching lines are shown here. Use "Copy logs" to take everything the buffer holds.
              </small>
            </div>
          )}

          {/* An empty console and a filtered-out console look the same and mean
              opposite things, so they say different sentences: the first is the
              normal state before anything has run, the second a filter to widen. */}
          {visibleLogs.length === 0 ? (
            <div className="empty-logs">
              <Terminal size={32} className="empty-term-icon" aria-hidden="true" />
              <strong>{empty ? "No log lines yet" : "Nothing matches this filter"}</strong>
              <span>
                {empty
                  ? "Engine start-up, server scans and connection events appear here while Aether runs."
                  : "Choose \"All lines\" to see every line the engine has sent."}
              </span>
            </div>
          ) : (
            visibleLogs.map((entry) => {
              const category = logSeverityOf(entry);
              const label = LOG_SEVERITY_LABELS[category];
              return (
                <div className={`terminal-log-row ${category}`} key={entry.id}>
                  <span className="row-gutter">
                    <span className="gutter-dot" aria-hidden="true" />
                  </span>
                  <time className="tabular-nums font-mono" dateTime={new Date(entry.ts).toISOString()}>
                    {entry.time}
                  </time>
                  <span className={`log-level-badge ${category} font-mono`}>
                    [{label}]
                  </span>
                  <p className="log-message-body font-mono">{entry.message}</p>
                </div>
              );
            })
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
