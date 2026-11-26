import { getCurrentWindow } from "@tauri-apps/api/window";
import { Radio, ScrollText, Search, Settings as SettingsIcon } from "lucide-react";
import { useCallback, useEffect, useRef, useState } from "react";
import { useOnline } from "@aether/ui";
import { AetherMark } from "@aether/ui/components/ui";
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

export function carrierProtocol(label: string): Settings["protocol"] {
  const proto = label.toLowerCase();
  if (proto.includes("wireguard") || proto.includes("wg")) return "wireguard";
  if (proto.includes("gool")) return "gool";
  if (proto.includes("mim") || proto.includes("in-masque")) return "mim";
  return "masque";
}

const navigation: { id: View; label: string; icon: typeof Radio }[] = [
  { id: "home", label: "Connection", icon: Radio },
  { id: "scanner", label: "Scanner", icon: Search },
  { id: "logs", label: "Activity", icon: ScrollText },
  { id: "settings", label: "Settings", icon: SettingsIcon },
];

const isTauriEnv = () =>
  typeof window !== "undefined" &&
  Boolean((window as { __TAURI_INTERNALS__?: unknown }).__TAURI_INTERNALS__);

export function App() {
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
    dirty,
    saveError,
    admin,
    testResult,
    appVersion,
    updateAvailable,
    updateInfo,
    updateProgress,
    updateChecking,
    updateCheckError,
    checkForUpdates,
    installUpdate,
    connected,
    running,
    settingsLocked,
    settingsLoaded,
    settingsLoadError,
    retrySettings,
    resetSettings,
    patchSettings,
    toggleConnection,
    connectToPeer,
    runTest,
    dismissError,
    dismissUpdate,
  } = useRuntime(appendLog);
  const scanner = useScanner(appendLog, running, clearLogs);

  const connectDirect = useCallback(
    async (item: DiscoveredEndpoint) => {
      const { protocol, transport } = directTarget(item.protocol);
      if (busy) {
        appendLog({ level: "warn", message: "A connect is already in flight; wait for it to finish." });
        return;
      }
      if (!settingsLoaded) {
        appendLog({ level: "warn", message: "Settings are still loading; try direct connect again in a moment." });
        return;
      }
      appendLog({ level: "info", message: `Direct connecting to endpoint: ${item.addr} (${item.protocol})` });
      await scanner.stopScan();
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

  const viewHeadingRef = useRef<HTMLHeadingElement>(null);
  const previousViewRef = useRef(view);
  useEffect(() => {
    if (previousViewRef.current === view) return;
    previousViewRef.current = view;
    viewHeadingRef.current?.focus();
  }, [view]);

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.ctrlKey || event.altKey || event.metaKey || event.shiftKey) return;
      const tag = (event.target as HTMLElement | null)?.tagName;
      if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT") return;
      const targetView = navigation[Number(event.key) - 1]?.id;
      if (targetView) setView(targetView);
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, []);

  const exportLogs = useCallback(async (): Promise<boolean> => {
    if (logs.length === 0) return false;
    const headerLines = [
      `Aether Next ${appVersion} — Diagnostics`,
      `Status: ${runtime.status}${runtime.endpoint ? ` (${runtime.endpoint})` : ""}`,
      `Protocol: ${settings.protocol}/${settings.transport} | Routing: ${settings.routingMode}`,
    ];
    let engineDiag = "";
    try {
      const { invoke } = await import("@tauri-apps/api/core");
      const rawDiag = await invoke<unknown>("diagnostics");
      engineDiag = typeof rawDiag === "string" ? rawDiag : JSON.stringify(rawDiag ?? "");
    } catch {
      engineDiag = "(diagnostics unavailable)";
    }
    const logLines = logs.map((l) => `${new Date(l.ts).toISOString()}\t${l.level}\t${l.message}`);
    const full = [
      ...headerLines,
      ...(engineDiag ? ["# engine diagnostics", engineDiag] : []),
      "--- Log ---",
      ...logLines,
    ].join("\n");
    const redacted = redactExport(full);
    try {
      await navigator.clipboard.writeText(redacted);
      return true;
    } catch {
      appendLog({ level: "warn", message: "Clipboard copy failed" });
      return false;
    }
  }, [logs, appVersion, runtime, settings, appendLog]);

  const winMinimize = () => {
    if (!isTauriEnv()) return;
    void getCurrentWindow().minimize().catch(() => {});
  };
  const winMaximize = () => {
    if (!isTauriEnv()) return;
    void getCurrentWindow().toggleMaximize().catch(() => {});
  };
  const winClose = () => {
    if (!isTauriEnv()) return;
    void getCurrentWindow().close().catch(() => {});
  };

  return (
    <div className="desktop-frame">
      <header className="titlebar-strip" data-tauri-drag-region>
        <div className="titlebar-drag" data-tauri-drag-region />
        <div className="window-controls">
          <button type="button" className="window-ctrl-btn" onClick={winMinimize} aria-label="Minimize window">
            <span aria-hidden="true">—</span>
          </button>
          <button type="button" className="window-ctrl-btn" onClick={winMaximize} aria-label="Maximize window">
            <span aria-hidden="true">□</span>
          </button>
          <button type="button" className="window-ctrl-btn close" onClick={winClose} aria-label="Close window">
            <span aria-hidden="true">×</span>
          </button>
        </div>
      </header>

      <main className="app-shell">
        <aside className="sidebar">
          <div className="brand">
            <AetherMark size={28} />
            <strong className="brand-title">Aether Next</strong>
          </div>

          <nav aria-label="Main" className="nav-group">
            {navigation.map(({ id, label, icon: Icon }) => {
              const active = view === id;
              return (
                <button
                  key={id}
                  type="button"
                  className={`nav-pill ${active ? "active" : ""}`}
                  aria-current={active ? "page" : undefined}
                  onClick={() => setView(id)}
                >
                  <span className="nav-pill-icon">
                    <Icon size={15} strokeWidth={2} aria-hidden="true" />
                  </span>
                  <span className="nav-pill-label">{label}</span>
                  {id === "logs" && logs.length > 0 && (
                    <span className="log-count-badge tabular-nums" aria-label={`${logs.length} log entries`}>
                      {logs.length > 99 ? "99+" : logs.length}
                    </span>
                  )}
                </button>
              );
            })}
          </nav>

          <div className="sidebar-footer">
            <span className="version-tag tabular-nums">v{appVersion}</span>
          </div>
        </aside>

        <section className="workspace" aria-label={navigation.find((n) => n.id === view)?.label}>
          <h1 className="sr-only" ref={viewHeadingRef} tabIndex={-1}>
            {navigation.find((n) => n.id === view)?.label ?? "Connection"}
          </h1>
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
                updateAvailable={updateAvailable}
                updateInfo={updateInfo}
                updateProgress={updateProgress}
                installUpdate={installUpdate}
                dismissUpdate={dismissUpdate}
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
                resetSettings={resetSettings}
                saved={saved}
                dirty={dirty}
                saveError={saveError}
                appVersion={appVersion}
                updateInfo={updateInfo}
                updateProgress={updateProgress}
                updateChecking={updateChecking}
                updateCheckError={updateCheckError}
                onCheckUpdates={checkForUpdates}
                onInstallUpdate={installUpdate}
                patchSettings={patchSettings}
              />
            </ErrorBoundary>
          )}
        </section>
      </main>
    </div>
  );
}

export default App;
