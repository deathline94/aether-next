import { Radio, ScrollText, Search, ShieldCheck, SlidersHorizontal } from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import { RUNTIME_STATUS_TAGS } from "@aether/ui";
// Self-hosted faces: Vite hashes the woff2 into dist/ so the UI loads them
// same-origin under `font-src 'self'` and never asks a third party pre-tunnel.
import "@fontsource-variable/geist";
import "@fontsource-variable/geist-mono";
import "./App.css";
import { ActivityTab } from "./components/ActivityTab";
import { ConnectionTab } from "./components/ConnectionTab";
import { ErrorBoundary } from "./components/ErrorBoundary";
import { ScannerTab } from "./components/ScannerTab";
import { SettingsTab } from "./components/SettingsTab";
import { useLogs } from "./hooks/useLogs";
import { engineDiagnostics, useRuntime } from "./hooks/useRuntime";
import { useScanner } from "./hooks/useScanner";
import type { DiscoveredEndpoint, LogFilter, RuntimeState, Settings, View } from "./types";

// Single definition per view — label + heading copy live together so they
// can't drift apart.
const navigation: { id: View; label: string; eyebrow: string; shortcut: string; icon: typeof Radio }[] = [
  { id: "home", label: "Connection", eyebrow: "SECURE ROUTING", shortcut: "1", icon: Radio },
  { id: "scanner", label: "Scanner", eyebrow: "ENDPOINT DISCOVERY", shortcut: "2", icon: Search },
  { id: "settings", label: "Settings", eyebrow: "CONFIGURATION", shortcut: "3", icon: SlidersHorizontal },
  { id: "logs", label: "Activity", eyebrow: "LIVE ENGINE OUTPUT", shortcut: "4", icon: ScrollText },
];

/** Digit → view, for the `1`–`4` navigation keys. */
const VIEW_BY_SHORTCUT: Record<string, View> = {
  "1": "home",
  "2": "scanner",
  "3": "settings",
  "4": "logs",
};

/**
 * Should this keystroke switch tabs?
 *
 * The handler only asked whether focus sat in a field, so Ctrl/Alt/Cmd+1..4 — the
 * browser's and the OS's own tab and workspace keys — drove the view as well. A
 * modified key is never ours.
 */
export function navigationShortcut(event: {
  key: string;
  ctrlKey?: boolean;
  altKey?: boolean;
  metaKey?: boolean;
  shiftKey?: boolean;
  tagName?: string;
  isContentEditable?: boolean;
}): View | null {
  const tag = (event.tagName ?? "").toLowerCase();
  if (tag === "input" || tag === "textarea" || tag === "select") return null;
  if (event.isContentEditable) return null;
  if (event.ctrlKey || event.altKey || event.metaKey) return null;
  return VIEW_BY_SHORTCUT[event.key] ?? null;
}

/**
 * The state a tab's crash can plausibly be blamed on.
 *
 * `resetKeys` is what clears a boundary's fallback, so each tab is keyed on the
 * data it renders: a session frame that arrives after a malformed one heals the
 * Connection tab, a settings reload heals the Settings tab. Switching tabs also
 * heals any of them, because a tab's boundary is mounted with the tab.
 */
function tabResetKeys(view: View, runtime: RuntimeState, settings: Settings, logFilter: LogFilter) {
  switch (view) {
    case "home":
      return [runtime, settings.protocol, settings.transport, settings.routingMode];
    case "scanner":
      return [settings.protocol, runtime.status];
    case "settings":
      return [settings, runtime.status];
    case "logs":
      return [logFilter, runtime.status];
  }
}

function App() {
  const [view, setView] = useState<View>("home");

  const {
    logs, clearLogs, logFilter, setLogFilter, appendLog,
    visibleLogs, hasMore, filterCounts, logEndRef, autoScroll, setAutoScroll,
  } = useLogs();

  const {
    settings, runtime, busy, testBusy, saved, dirty, saveError, admin, testResult, appVersion, updateAvailable,
    connected, running, settingsLocked, settingsLoaded, settingsLoadError, retrySettings,
    patchSettings, toggleConnection, connectToPeer, runTest, dismissError, dismissUpdate,
  } = useRuntime(appendLog);

  const scanner = useScanner(appendLog, running, clearLogs);

  // Global keyboard shortcuts for navigation (1-4 when not inside input elements)
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      const target = e.target as HTMLElement | null;
      const next = navigationShortcut({
        key: e.key,
        ctrlKey: e.ctrlKey,
        altKey: e.altKey,
        metaKey: e.metaKey,
        shiftKey: e.shiftKey,
        tagName: document.activeElement?.tagName ?? target?.tagName,
        isContentEditable: target?.isContentEditable,
      });
      if (next) setView(next);
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, []);

  const connectDirect = useCallback((item: DiscoveredEndpoint) => {
    // Case-insensitive: the engine reports strings like "MASQUE H3" or
    // "masque-h3" depending on the code path.
    const protoLower = item.protocol.toLowerCase();
    const proto = protoLower.includes("wireguard") ? "wireguard" : "masque";
    const trans = protoLower.includes("h3") ? "h3" : "h2";
    appendLog({ level: "info", message: `Direct connecting to gateway: ${item.addr} (${item.protocol})` });
    setView("home");
    void connectToPeer(item.addr, proto, trans);
  }, [connectToPeer, appendLog]);

  const exportLogs = useCallback(async (): Promise<boolean> => {
    if (logs.length === 0) return false;
    const diagnostics = await engineDiagnostics();
    const text = [
      logs
        .map((l) => `${new Date(l.ts).toISOString()}\t${l.level}\t${l.message}`)
        .join("\n"),
      "# engine diagnostics",
      diagnostics,
    ].join("\n\n");
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch {
      appendLog({ level: "warn", message: "Clipboard copy failed — is the window focused?" });
      return false;
    }
  }, [logs, appendLog]);

  const activeNav = navigation.find((n) => n.id === view) ?? navigation[0];
  // The beacon reports what the tunnel is doing, not how safe the user is. "Protected"
  // was a blanket claim in every connected mode, while a local-proxy connection only
  // carries apps pointed at Aether's own ports. `routingMode` is the same value the
  // Connection panel resolves its copy from, so the two surfaces cannot disagree.
  const statusText = connected
    ? settings.routingMode === "tun"
      ? "Routed"
      : "Local proxy"
    : running
      ? "Connecting"
      : runtime.status === "error"
        ? "Error"
        : "Standby";

  return (
    <main className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark">
            <ShieldCheck size={20} strokeWidth={2.2} />
            <span className="brand-ambient-glow" aria-hidden="true" />
          </div>
          <div className="brand-text">
            <strong>AETHER</strong>
            <span>CYBER-TACTICAL NODE</span>
          </div>
        </div>

        <nav aria-label="Main" className="nav-group">
          {navigation.map(({ id, label, shortcut, icon: Icon }) => (
            <button
              key={id}
              className={`nav-pill ${view === id ? "active" : ""}`}
              aria-current={view === id ? "page" : undefined}
              onClick={() => setView(id)}
            >
              <div className="nav-pill-icon">
                <Icon size={16} strokeWidth={2} aria-hidden="true" />
              </div>
              <span className="nav-pill-label">{label}</span>
              <div className="nav-pill-trailing">
                {id === "logs" && logs.length > 0 && (
                  <span className="log-count-badge" aria-label={`${logs.length} log entries`}>
                    {logs.length > 99 ? "99+" : logs.length}
                  </span>
                )}
                <kbd className="nav-shortcut">{shortcut}</kbd>
              </div>
              {view === id && <span className="nav-active-pill" aria-hidden="true" />}
            </button>
          ))}
        </nav>

        <div className="sidebar-bottom">
          <div className={`connection-beacon ${runtime.status}`} role="status" aria-live="polite">
            <div className="beacon-radar">
              <span className="beacon-ring ring-1" aria-hidden="true" />
              <span className="beacon-ring ring-2" aria-hidden="true" />
              <span className="beacon-core" aria-hidden="true" />
            </div>
            <div className="beacon-info">
              <div className="beacon-header">
                <strong className="beacon-status-text">{statusText}</strong>
                <span className="beacon-tag">{RUNTIME_STATUS_TAGS[runtime.status]}</span>
              </div>
              <span className="beacon-detail" title={runtime.detail}>{runtime.detail || "System Ready"}</span>
            </div>
          </div>
          <div className="version-bar">
            <span>AETHER PROTOCOL</span>
            <span className="version-tag">v{appVersion}</span>
          </div>
        </div>
      </aside>

      <section className="workspace">
        <header className="topbar">
          <div className="topbar-titles">
            <p className="topbar-eyebrow">{activeNav?.eyebrow}</p>
            <h1 className="topbar-heading">{activeNav?.label}</h1>
          </div>
          <div className="topbar-actions">
            <div className={`header-status ${runtime.status}`} title={runtime.detail}>
              <span className="status-dot" aria-hidden="true" />
              <span>{RUNTIME_STATUS_TAGS[runtime.status]}</span>
            </div>
          </div>
        </header>

        {/* One boundary per tab, mounted with the tab: a view that cannot be drawn
            used to take the whole window — and the tunnel status with it — because
            the only boundary in the tree sat above `App` with no reset keys, so the
            per-tab `resetKeys`/`onRetry` machinery below it could never fire. */}
        {view === "home" && (
          <ErrorBoundary label="Connection tab" resetKeys={tabResetKeys("home", runtime, settings, logFilter)}>
            <ConnectionTab
              settings={settings} runtime={runtime} busy={busy} testBusy={testBusy}
              connected={connected} running={running} settingsLocked={settingsLocked}
              settingsLoaded={settingsLoaded}
              admin={admin} testResult={testResult} appVersion={appVersion}
              updateAvailable={updateAvailable} dismissUpdate={dismissUpdate}
              toggleConnection={toggleConnection} patchSettings={patchSettings}
              runTest={runTest} dismissError={dismissError} appendLog={appendLog}
            />
          </ErrorBoundary>
        )}

        {view === "scanner" && (
          <ErrorBoundary label="Scanner tab" resetKeys={tabResetKeys("scanner", runtime, settings, logFilter)}>
            <ScannerTab
              protocol={scanner.protocol} setProtocol={scanner.setProtocol}
              ipScan={scanner.ipScan} setIpScan={scanner.setIpScan}
              concurrency={scanner.concurrency} setConcurrency={scanner.setConcurrency}
              timeoutMs={scanner.timeoutMs} setTimeoutMs={scanner.setTimeoutMs}
              noize={scanner.noize} setNoize={scanner.setNoize}
              endpoints={scanner.endpoints} active={scanner.active}
              scanState={scanner.scanState} busy={scanner.busy}
              startScan={scanner.startScan} stopScan={scanner.stopScan}
              connectDirect={connectDirect} connectBusy={busy}
            />
          </ErrorBoundary>
        )}

        {view === "settings" && (
          <ErrorBoundary
            label="Settings tab"
            resetKeys={tabResetKeys("settings", runtime, settings, logFilter)}
            // The one retry that can genuinely fix this view: re-read the profile
            // from disk rather than re-render the input that crashed.
            onRetry={() => void retrySettings()}
          >
            <SettingsTab
              settings={settings} settingsLocked={settingsLocked}
              settingsLoaded={settingsLoaded}
              settingsLoadError={settingsLoadError}
              retrySettings={retrySettings}
              saved={saved} dirty={dirty} saveError={saveError} patchSettings={patchSettings}
            />
          </ErrorBoundary>
        )}

        {view === "logs" && (
          <ErrorBoundary label="Activity tab" resetKeys={tabResetKeys("logs", runtime, settings, logFilter)}>
            <ActivityTab
              visibleLogs={visibleLogs} hasMore={hasMore}
              filterCounts={filterCounts} logFilter={logFilter} setLogFilter={setLogFilter}
              logEndRef={logEndRef} autoScroll={autoScroll} setAutoScroll={setAutoScroll}
              exportLogs={exportLogs} clearLogs={clearLogs}
              scanState={scanner.scanState} status={runtime.status}
            />
          </ErrorBoundary>
        )}
      </section>
    </main>
  );
}

export default App;
