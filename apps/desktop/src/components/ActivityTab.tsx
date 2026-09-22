import {
  ArrowDown,
  Ban,
  Check,
  Copy,
  ScrollText,
  Sparkles,
  Terminal,
} from "lucide-react";
import { useVirtualizer } from "@tanstack/react-virtual";
import { useEffect, useRef, useState } from "react";
import { RENDER_CAP } from "../hooks/useLogs";
import type { DisplayedScanState, LogEntry, LogFilter } from "../types";
import { nextOptionIndex } from "../../../../packages/ui/src";

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
  scanState: DisplayedScanState;
  status: string;
}

/** Row height before it has been measured; the real rows are one line of mono. */
const ESTIMATED_ROW_PX = 26;

const FILTERS: { id: LogFilter; label: string }[] = [
  { id: "milestones", label: "Milestones" },
  { id: "hits", label: "Hits" },
  { id: "errors", label: "Errors" },
  { id: "raw", label: "Raw" },
];

function getLogCategory(entry: LogEntry): "info" | "warn" | "error" | "debug" {
  if (entry.level === "error") return "error";
  if (entry.level === "warn") return "warn";
  const msg = entry.message.toLowerCase();
  if (
    msg.includes("debug") ||
    msg.includes("trace") ||
    msg.includes("probe src") ||
    msg.includes("candidate rejected") ||
    msg.includes("probe timeout")
  ) {
    return "debug";
  }
  return "info";
}

const LEVEL_LABELS: Record<"info" | "warn" | "error" | "debug", string> = {
  info: "INFO",
  warn: "WARN",
  error: "ERR",
  debug: "DEBUG",
};

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

  // A scan writes lines faster than the console can be painted, and the whole
  // visible window was in the DOM at once. Only the rows on screen — plus a small
  // overscan — are mounted now, positioned inside a spacer of the full height so
  // the scrollbar still describes the buffer.
  const rows = useVirtualizer({
    count: visibleLogs.length,
    getScrollElement: () => consoleRef.current,
    estimateSize: () => ESTIMATED_ROW_PX,
    overscan: 10,
  });

  useEffect(() => {
    // Direct container scroll lock + programmatic scroll guard so daemon log rates
    // never trigger an accidental auto-scroll pause.
    if (autoScroll && consoleRef.current) {
      scrollConsoleToBottom(consoleRef.current, logEndRef.current, isProgrammaticScrollRef);
    }
  }, [visibleLogs, autoScroll, logEndRef]);

  useEffect(() => () => {
    if (copyTimer.current) clearTimeout(copyTimer.current);
  }, []);

  // Pause auto-scroll on any user gesture away from the bottom; resume at the bottom.
  const handleScroll = () => {
    if (isProgrammaticScrollRef.current) return;
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
  const pct =
    scanState.total > 0
      ? Math.min(100, Math.round((scanState.scanned / scanState.total) * 100))
      : 0;

  return (
    <div className="tactical-activity-view">
      {scanState.active && (
        <div className="tactical-scan-card">
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
            <div className="scan-progress-bar-fill active-glow" style={{ width: `${pct}%` }} />
          </div>
          <div className="scan-card-footer">
            <small className="tabular-nums">
              Probed {scanState.scanned.toLocaleString()} / {scanState.total.toLocaleString()} candidates
            </small>
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
                command as content. The console below carries the real name. */}
            <span className="terminal-title-text font-mono" aria-hidden="true">session-log · aether@daemon</span>
          </div>

          <div className="terminal-center-telemetry">
            <span className={`status-dot ${status}`} aria-hidden="true" />
            <span className="stream-count tabular-nums">
              {filterCounts[logFilter].toLocaleString()} shown / {filterCounts.raw.toLocaleString()} buffer
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
              title="Copy visible or complete logs to clipboard"
            >
              {copied ? <Check size={13} aria-hidden="true" /> : <Copy size={13} aria-hidden="true" />}
              <span>{copied ? "Copied" : "Copy Buffer"}</span>
            </button>
            <button
              type="button"
              className="tactile-terminal-btn danger"
              onClick={clearLogs}
              disabled={empty}
              title="Flush current session logs"
            >
              <Ban size={13} aria-hidden="true" />
              <span>Clear</span>
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

          <div className="terminal-mode-indicator">
            {/* The stream is live; the terminal is not a TTY — it cannot be
                written to, and saying otherwise advertised a prompt. */}
            <span className="mode-tag font-mono">STREAM: LIVE</span>
          </div>
        </div>

        {/* Terminal Screen Console */}
        <section
          ref={consoleRef}
          className="tactical-terminal-screen font-mono"
          onScroll={handleScroll}
          aria-label="Engine log output"
          // A scroll region the keyboard cannot reach: `tabIndex={0}` is what lets
          // PageUp/PageDown and the arrows read the lines above the fold.
          tabIndex={0}
        >
          {hasMore && (
            <div className="log-more-hint">
              <small className="tabular-nums">
                Buffer truncated for display: showing the last {RENDER_CAP} matching entries. Use "Copy Buffer" for full export.
              </small>
            </div>
          )}

          {visibleLogs.length === 0 ? (
            <div className="empty-logs">
              <Terminal size={32} className="empty-term-icon" aria-hidden="true" />
              <strong>{empty ? "Awaiting Daemon Output" : "No Records In Selected Filter"}</strong>
              <span>
                {empty
                  ? "Carrier daemon and probe events will stream here automatically upon execution."
                  : "Switch to 'Raw' to inspect unfiltered packet and probe streams."}
              </span>
            </div>
          ) : (
            <div
              style={{ height: rows.getTotalSize(), position: "relative", width: "100%" }}
              role="log"
              aria-label="Log rows"
            >
              {rows.getVirtualItems().map((row) => {
                const entry = visibleLogs[row.index];
                if (!entry) return null;
                const category = getLogCategory(entry);
                const label = LEVEL_LABELS[category];
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
                    <div className={`terminal-log-row ${category}`} title={category.toUpperCase()}>
                      <span className="row-gutter">
                        <span className="gutter-dot" aria-hidden="true" />
                      </span>
                      {/* The clock is a field of the entry, formatted once when the
                          line arrived: `toLocaleTimeString()` per row per render was
                          a locale-sensitive call 200 times over on every scan line. */}
                      <time className="tabular-nums font-mono" dateTime={new Date(entry.ts).toISOString()}>
                        {entry.time}
                      </time>
                      <span className={`log-level-badge ${category} font-mono`}>
                        [{label}]
                      </span>
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
          <span>Milestones hides high-frequency network packets. Select "Raw" to inspect full socket traces.</span>
        </div>
      )}
    </div>
  );
}
