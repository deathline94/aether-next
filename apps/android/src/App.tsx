import { Activity, AlertTriangle, KeyRound, Search, Settings as SettingsIcon } from "lucide-react";
import { useCallback, useEffect, useRef, useState } from "react";
import { useOnline } from "@aether/ui";
import { shouldClearLogs } from "@aether/ui/logs";
import "@fontsource-variable/geist";
import "@fontsource-variable/geist-mono";
import "@aether/ui/shared.css";
import "./App.css";
import { ActivityTab } from "./components/ActivityTab";
import { ConnectionTab } from "./components/ConnectionTab";
import { ErrorBoundary } from "./components/ErrorBoundary";
import { ScannerTab } from "./components/ScannerTab";
import { SettingsTab } from "./components/SettingsTab";
import { redactExport, useLogs } from "./hooks/useLogs";
import { useRuntime } from "./hooks/useRuntime";
import { useScanner } from "./hooks/useScanner";
import type { DiscoveredEndpoint, LogFilter, RuntimeState, Settings, View } from "./types";

function tabResetKeys(view: View, runtime: RuntimeState, settings: Settings, logFilter: LogFilter) {
  switch (view) {
    case "home":
      return [
        runtime.status,
        runtime.detail,
        runtime.endpoint,
        settings.protocol,
        settings.transport,
        settings.routingMode,
      ];
    case "scanner":
      return [settings.protocol, runtime.status];
    case "settings":
      return [
        settings.protocol,
        settings.transport,
        settings.routingMode,
        settings.httpPort,
        settings.socksPort,
        runtime.status,
      ];
    case "logs":
      return [logFilter, runtime.status];
  }
}

export function directTarget(label: string): Pick<Settings, "protocol" | "transport"> {
  const proto = label.toLowerCase();
  return {
    protocol: proto.includes("wireguard") || proto.includes("wg") ? "wireguard" : "masque",
    transport: proto.includes("h3") ? "h3" : "h2",
  };
}

const navigation: { id: View; label: string; icon: typeof KeyRound }[] = [
  { id: "home", label: "Connection", icon: KeyRound },
  { id: "scanner", label: "Scanner", icon: Search },
  { id: "logs", label: "Activity", icon: Activity },
  { id: "settings", label: "Settings", icon: SettingsIcon },
];

function App() {
  const [view, setView] = useState<View>("home");
  const online = useOnline();

  const {
    logs,
    logFilter,
    setLogFilter,
    appendLog,
    clearLogs,
    visibleLogs,
    hasMore,
    filterCounts,
    logEndRef,
    autoScroll,
    setAutoScroll,
  } = useLogs();

  const {
    settings,
    runtime,
    stats,
    busy,
    testBusy,
    saved,
    saveError,
    admin,
    testResult,
    appVersion,
    settingsCorrupt,
    settingsCorruptionNotice,
    resetSettings,
    resetSettingsBusy,
    resetSettingsError,
    connected,
    running,
    settingsLocked,
    settingsLoaded,
    settingsLoadError,
    retrySettings,
    patchSettings,
    toggleConnection,
    connectToPeer,
    runTest,
    dismissError,
  } = useRuntime(appendLog);

  const scanner = useScanner(appendLog, running, clearLogs);

  const connectDirect = useCallback(
    async (item: DiscoveredEndpoint) => {
      const { protocol, transport } = directTarget(item.protocol);
      if (busy) {
        appendLog({ level: "warn", message: "A connect or scan stop is already in flight; wait for it to settle." });
        return;
      }
      if (!settingsLoaded) {
        appendLog({ level: "warn", message: "Settings are still loading; try direct connect again in a moment." });
        return;
      }
      appendLog({ level: "info", message: `Direct connecting to gateway: ${item.addr} (${item.protocol})` });
      if (scanner.active || scanner.busy) {
        await scanner.stopScan();
      }
      void connectToPeer(item.addr, protocol, transport);
      setView("home");
    },
    [busy, settingsLoaded, connectToPeer, appendLog, scanner],
  );

  const prevStatusRef = useRef(runtime.status);
  useEffect(() => {
    const prev = prevStatusRef.current;
    if (shouldClearLogs(prev, runtime.status)) clearLogs();
    prevStatusRef.current = runtime.status;
  }, [runtime.status, clearLogs]);

  const exportLogs = useCallback(async (): Promise<boolean> => {
    if (logs.length === 0) return false;
    const text = redactExport(
      logs.map((l) => `${new Date(l.ts).toISOString()}\t${l.level}\t${l.message}`).join("\n"),
    );
    if (navigator.clipboard && window.isSecureContext) {
      try {
        await navigator.clipboard.writeText(text);
        return true;
      } catch {
        // Fallback below
      }
    }
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

  return (
    <div className="android-shell">
      <main className="mobile-workspace">
        <h1 className="sr-only">{navigation.find((n) => n.id === view)?.label ?? "Connection"}</h1>
        {settingsCorrupt && (
          <div className="error-banner" role="alert">
            <div className="error-banner-content">
              <AlertTriangle size={16} aria-hidden="true" />
              <div>
                <strong>Saved Settings Corrupt</strong>
                <span>{settingsCorruptionNotice}</span>
                {resetSettingsError && <span>Reset refused — {resetSettingsError.message}</span>}
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
              settings={settings}
              runtime={runtime}
              stats={stats}
              busy={busy}
              testBusy={testBusy}
              connected={connected}
              running={running}
              settingsLocked={settingsLocked}
              settingsLoaded={settingsLoaded}
              admin={admin}
              online={online}
              testResult={testResult}
              appVersion={appVersion}
              toggleConnection={toggleConnection}
              patchSettings={patchSettings}
              runTest={runTest}
              dismissError={dismissError}
              appendLog={appendLog}
            />
          </ErrorBoundary>
        )}

        {view === "scanner" && (
          <ErrorBoundary label="Scanner tab" resetKeys={tabResetKeys("scanner", runtime, settings, logFilter)}>
            <ScannerTab
              protocol={scanner.protocol}
              setProtocol={scanner.setProtocol}
              ipScan={scanner.ipScan}
              setIpScan={scanner.setIpScan}
              concurrency={scanner.concurrency}
              setConcurrency={scanner.setConcurrency}
              timeoutMs={scanner.timeoutMs}
              setTimeoutMs={scanner.setTimeoutMs}
              noize={scanner.noize}
              setNoize={scanner.setNoize}
              endpoints={scanner.endpoints}
              active={scanner.active}
              scanState={scanner.scanState}
              busy={scanner.busy}
              running={running}
              startScan={scanner.startScan}
              stopScan={scanner.stopScan}
              connectDirect={connectDirect}
              connectBusy={busy}
            />
          </ErrorBoundary>
        )}

        {view === "logs" && (
          <ErrorBoundary label="Activity tab" resetKeys={tabResetKeys("logs", runtime, settings, logFilter)}>
            <ActivityTab
              visibleLogs={visibleLogs}
              hasMore={hasMore}
              filterCounts={filterCounts}
              logFilter={logFilter}
              setLogFilter={setLogFilter}
              logEndRef={logEndRef}
              autoScroll={autoScroll}
              setAutoScroll={setAutoScroll}
              exportLogs={exportLogs}
              clearLogs={clearLogs}
              scanState={scanner.scanState}
              status={runtime.status}
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
              settings={settings}
              settingsLocked={settingsLocked}
              settingsLoaded={settingsLoaded}
              settingsLoadError={settingsLoadError}
              retrySettings={retrySettings}
              saved={saved}
              saveError={saveError}
              admin={admin}
              appVersion={appVersion}
              patchSettings={patchSettings}
              corrupt={
                settingsCorrupt
                  ? {
                      notice: settingsCorruptionNotice ?? "",
                      busy: resetSettingsBusy,
                      onReset: () => void resetSettings(),
                    }
                  : undefined
              }
            />
          </ErrorBoundary>
        )}
      </main>

      <nav className="mobile-bottom-nav" aria-label="Primary navigation">
        {navigation.map(({ id, label, icon: Icon }) => {
          const active = view === id;
          return (
            <button
              key={id}
              type="button"
              className={`bottom-nav-tab ${active ? "active" : ""}`}
              aria-current={active ? "page" : undefined}
              onClick={() => setView(id)}
            >
              <span className="bottom-nav-pill">
                <Icon size={18} strokeWidth={2} aria-hidden="true" />
                {id === "logs" && logs.length > 0 && (
                  <span className="nav-dot-badge" aria-label={`${logs.length} log entries`} />
                )}
              </span>
              <span className="bottom-nav-label">{label}</span>
            </button>
          );
        })}
      </nav>
    </div>
  );
}

export default App;
