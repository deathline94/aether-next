import { AlertTriangle, Radio, ScrollText, Search, SlidersHorizontal } from "lucide-react";
import { useCallback, useEffect, useRef, useState } from "react";
import { RUNTIME_STATUS_TAGS } from "@aether/ui";
// Same self-hosted faces as the desktop app (T187): Vite hashes the woff2
// into the bundled assets, so the WebView never reaches a third party.
import "@fontsource-variable/geist";
import "@fontsource-variable/geist-mono";
import "./App.css";
import { ActivityTab } from "./components/ActivityTab";
import { ConnectionTab } from "./components/ConnectionTab";
import { ErrorBoundary } from "./components/ErrorBoundary";
import { ScannerTab } from "./components/ScannerTab";
import { SettingsTab } from "./components/SettingsTab";
import { useLogs } from "./hooks/useLogs";
import { useOnline } from "./hooks/useOnline";
import { useRuntime } from "./hooks/useRuntime";
import { useScanner } from "./hooks/useScanner";
import type { DiscoveredEndpoint, LogFilter, RuntimeState, Settings, View } from "./types";

/**
 * The state a tab's crash can plausibly be blamed on - see the desktop `App.tsx`,
 * which this mirrors deliberately. The phone used to mount one boundary in
 * `main.tsx` with no reset keys, so a view that threw on a bad session frame
 * offered a "Try again" that re-rendered the same input and threw again, and the
 * only way back was reloading the WebView.
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

// One definition per view — label + eyebrow copy live together so they can't drift.
const navigation: { id: View; label: string; eyebrow: string; icon: typeof Radio }[] = [
  { id: "home", label: "Connection", eyebrow: "SECURE ROUTING", icon: Radio },
  { id: "scanner", label: "Scanner", eyebrow: "ENDPOINT DISCOVERY", icon: Search },
  { id: "settings", label: "Settings", eyebrow: "CONFIGURATION", icon: SlidersHorizontal },
  { id: "logs", label: "Activity", eyebrow: "LIVE ENGINE OUTPUT", icon: ScrollText },
];

function App() {
  const [view, setView] = useState<View>("home");
  const online = useOnline();

  const {
    logs, logFilter, setLogFilter, appendLog, clearLogs,
    visibleLogs, hasMore, filterCounts, logEndRef, autoScroll, setAutoScroll,
  } = useLogs();

  const {
    settings, runtime, busy, testBusy, saved, saveError, admin, testResult, appVersion,
    settingsCorrupt, settingsCorruptionNotice, resetSettings, resetSettingsBusy, resetSettingsError,
    connected, running, settingsLocked, settingsLoaded, settingsLoadError, retrySettings,
    patchSettings, toggleConnection, connectToPeer, runTest, dismissError,
  } = useRuntime(appendLog);

  const scanner = useScanner(appendLog, running, clearLogs);

  const connectDirect = useCallback(async (item: DiscoveredEndpoint) => {
    // Case-insensitive: the engine reports "MASQUE H3", "masque-h3", etc.
    const proto = item.protocol.toLowerCase();
    const protocol = proto.includes("wireguard") || proto.includes("wg") ? "wireguard" : "masque";
    const transport = proto.includes("h3") ? "h3" : "h2";
    // A tap that would do nothing must say so: connectToPeer refuses silently
    // while a transition is already in flight or settings are still loading, and
    // a silent no-op read as a dead button.
    if (busy) {
      appendLog({ level: "warn", message: "A connect or scan stop is already in flight; wait for it to settle." });
      return;
    }
    if (!settingsLoaded) {
      appendLog({ level: "warn", message: "Settings are still loading; try the direct connect again in a moment." });
      return;
    }
    appendLog({ level: "info", message: `Direct connecting to gateway: ${item.addr} (${item.protocol})` });
    if (scanner.active || scanner.busy) {
      // The Kotlin scan lane already enforces stopAndWait before the engine is
      // reused, so a fixed sleep after stopScan only added latency.
      await scanner.stopScan();
    }
    void connectToPeer(item.addr, protocol, transport);
    setView("home");
  }, [busy, settingsLoaded, connectToPeer, appendLog, scanner.active, scanner.busy, scanner.stopScan]);

  // Auto-clear logs when a *fresh* session starts (from an idle status) or a
  // clean disconnect lands. The shell reuses "connecting" for supervised tunnel
  // recovery, and clearing on every entry into "connecting" wiped the diagnostic
  // record of the very failure being recovered from — the evidence died with the
  // recovery. Only a transition out of an idle status is a user-initiated start.
  const prevStatusRef = useRef(runtime.status);
  useEffect(() => {
    const prev = prevStatusRef.current;
    if (prev !== runtime.status) {
      const idle = prev === "disconnected" || prev === "error";
      if (runtime.status === "connecting" && idle) {
        clearLogs();
      } else if (runtime.status === "disconnected" && prev !== "disconnected") {
        clearLogs();
      }
      prevStatusRef.current = runtime.status;
    }
  }, [runtime.status, clearLogs]);

  const exportLogs = useCallback(async (): Promise<boolean> => {
    if (logs.length === 0) return false;
    const text = logs.map((l) => `${new Date(l.ts).toISOString()}\t${l.level}\t${l.message}`).join("\n");

    // 1. Try modern clipboard API
    if (navigator.clipboard && window.isSecureContext) {
      try {
        await navigator.clipboard.writeText(text);
        return true;
      } catch {
        // Fall back to execCommand
      }
    }

    // 2. Fallback using temporary textarea
    try {
      const textarea = document.createElement("textarea");
      textarea.value = text;
      textarea.style.position = "fixed";
      textarea.style.top = "0";
      textarea.style.left = "0";
      textarea.style.opacity = "0";
      textarea.style.pointerEvents = "none";
      document.body.appendChild(textarea);
      textarea.focus();
      textarea.select();
      const success = document.execCommand("copy");
      document.body.removeChild(textarea);
      if (success) return true;
    } catch {
      // Fallback failed
    }

    appendLog({ level: "warn", message: "Clipboard copy failed" });
    return false;
  }, [logs, appendLog]);

  const activeNav = navigation.find((n) => n.id === view) ?? navigation[0];
  // The beacon reports what the tunnel is doing, not how safe the user is. "Protected"
  // was a blanket claim in every connected mode, while a local-proxy connection only
  // carries apps pointed at Aether's own ports. `routingMode` is the same value the
  // Connection hero resolves its copy from, so the two surfaces cannot disagree.
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
            <img src="./aether.png" alt="Aether" className="brand-mark-img" />
            <span className="brand-ambient-glow" aria-hidden="true" />
          </div>
          <div className="brand-text">
            <strong>AETHER</strong>
            <span>CYBER-TACTICAL NODE</span>
          </div>
        </div>

        <nav aria-label="Main" className="nav-group">
          {navigation.map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              className={`nav-pill ${view === id ? "active" : ""}`}
              aria-current={view === id ? "page" : undefined}
              onClick={() => setView(id)}
            >
              <div className="nav-pill-icon">
                <Icon size={18} strokeWidth={2} aria-hidden="true" />
              </div>
              <span className="nav-pill-label">{label}</span>
              <div className="nav-pill-trailing">
                {id === "logs" && logs.length > 0 && (
                  <span className="log-count-badge" aria-label={`${logs.length} log entries`}>
                    {logs.length > 99 ? "99+" : logs.length}
                  </span>
                )}
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
            <span>AETHER ANDROID</span>
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

        {/* The stored profile is corrupt (ITEM 10). This is said here, on whatever tab
            the user is on, rather than inside the Settings panel: the same refused write
            stops `connect`, so an explanation only the Settings tab carries is an
            explanation a user who just pressed Connect never sees — and the one action
            that clears the state has to be next to it. */}
        {settingsCorrupt && (
          <div className="error-banner" role="alert">
            <div className="error-banner-content">
              <AlertTriangle size={18} aria-hidden="true" />
              <div>
                <strong>SAVED SETTINGS CORRUPT</strong>
                <span>{settingsCorruptionNotice}</span>
                {resetSettingsError && (
                  <span>RESET REFUSED — {resetSettingsError.message}</span>
                )}
              </div>
            </div>
            <button
              type="button"
              className="banner-action"
              onClick={() => void resetSettings()}
              disabled={resetSettingsBusy}
            >
              {resetSettingsBusy ? "Resetting…" : "Reset settings"}
            </button>
          </div>
        )}

        {view === "home" && (
          <ErrorBoundary label="Connection tab" resetKeys={tabResetKeys("home", runtime, settings, logFilter)}>
            <ConnectionTab
              settings={settings} runtime={runtime} busy={busy} testBusy={testBusy}
              connected={connected} running={running} settingsLocked={settingsLocked}
              settingsLoaded={settingsLoaded} admin={admin} online={online}
              testResult={testResult} appVersion={appVersion}
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
              running={running}
              startScan={scanner.startScan} stopScan={scanner.stopScan}
              connectDirect={connectDirect} connectBusy={busy}
            />
          </ErrorBoundary>
        )}

        {view === "settings" && (
          <ErrorBoundary
            label="Settings tab"
            resetKeys={tabResetKeys("settings", runtime, settings, logFilter)}
            onRetry={() => void retrySettings()}
          >
            <SettingsTab
              settings={settings} settingsLocked={settingsLocked}
              settingsLoaded={settingsLoaded}
              settingsLoadError={settingsLoadError}
              retrySettings={retrySettings}
              saved={saved} saveError={saveError} admin={admin}
              patchSettings={patchSettings}
              // ITEM 10's last visible piece, finally wired: the panel the user
              // navigates to in order to fix a corrupt profile has to agree with
              // this banner, or it is the one screen that says nothing is wrong.
              corrupt={settingsCorrupt
                ? { notice: settingsCorruptionNotice ?? "", busy: resetSettingsBusy, onReset: () => void resetSettings() }
                : undefined}
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
