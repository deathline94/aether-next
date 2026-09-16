import { Radio, ScrollText, Search, ShieldCheck, SlidersHorizontal } from "lucide-react";
import { useCallback, useState } from "react";
import "./App.css";
import { ActivityTab } from "./components/ActivityTab";
import { ConnectionTab } from "./components/ConnectionTab";
import { ScannerTab } from "./components/ScannerTab";
import { SettingsTab } from "./components/SettingsTab";
import { useLogs } from "./hooks/useLogs";
import { useRuntime } from "./hooks/useRuntime";
import { useScanner } from "./hooks/useScanner";
import type { DiscoveredEndpoint, View } from "./types";

// Single definition per view — label + heading copy live together so they
// can't drift apart.
const navigation: { id: View; label: string; eyebrow: string; icon: typeof Radio }[] = [
  { id: "home", label: "Connection", eyebrow: "SECURE ROUTING", icon: Radio },
  { id: "scanner", label: "Scanner", eyebrow: "ENDPOINT DISCOVERY", icon: Search },
  { id: "settings", label: "Settings", eyebrow: "CONFIGURATION", icon: SlidersHorizontal },
  { id: "logs", label: "Activity", eyebrow: "LIVE ENGINE OUTPUT", icon: ScrollText },
];

function App() {
  const [view, setView] = useState<View>("home");

  const {
    logs, setLogs, logFilter, setLogFilter, appendLog,
    visibleLogs, hasMore, filterCounts, logEndRef, autoScroll, setAutoScroll,
  } = useLogs();

  const {
    settings, runtime, busy, testBusy, saved, admin, testResult, appVersion, updateAvailable,
    connected, running, settingsLocked, settingsLoaded,
    patchSettings, toggleConnection, connectToPeer, runTest, dismissError, dismissUpdate,
  } = useRuntime(appendLog);

  const scanner = useScanner(appendLog, running);

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
    const text = logs
      .map((l) => `${new Date(l.ts).toISOString()}\t${l.level}\t${l.message}`)
      .join("\n");
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch {
      appendLog({ level: "warn", message: "Clipboard copy failed — is the window focused?" });
      return false;
    }
  }, [logs, appendLog]);

  const activeNav = navigation.find((n) => n.id === view) ?? navigation[0];
  const statusText = connected ? "Protected" : running ? "Connecting" : runtime.status === "error" ? "Error" : "Unprotected";

  return (
    <main className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark"><ShieldCheck size={22} strokeWidth={1.8} /></div>
          <div><strong>Aether Next</strong><span>by deathline94</span></div>
        </div>

        <nav aria-label="Main">
          {navigation.map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              className={view === id ? "active" : ""}
              aria-current={view === id ? "page" : undefined}
              onClick={() => setView(id)}
            >
              <Icon size={18} aria-hidden="true" />
              <span>{label}</span>
              {id === "logs" && logs.length > 0 && (
                <small aria-label={`${logs.length} log entries`}>
                  {logs.length > 99 ? "99+" : logs.length}
                </small>
              )}
            </button>
          ))}
        </nav>

        <div className="sidebar-bottom">
          <div className={`mini-status ${runtime.status}`} role="status" aria-live="polite">
            <span className="status-dot" aria-hidden="true" />
            <div>
              <strong>{statusText}</strong>
              <span title={runtime.detail}>{runtime.detail}</span>
            </div>
          </div>
          <div className="version">AETHER NEXT <span>v{appVersion}</span></div>
        </div>
      </aside>

      <section className="workspace">
        <header className="topbar">
          <div><p>{activeNav.eyebrow}</p><h1>{activeNav.label}</h1></div>
          <div className={`header-status ${runtime.status}`} title={runtime.detail}>
            <span className="status-dot" aria-hidden="true" />
            {runtime.status}
          </div>
        </header>

        {view === "home" && (
          <ConnectionTab
            settings={settings} runtime={runtime} busy={busy} testBusy={testBusy}
            connected={connected} running={running} settingsLocked={settingsLocked}
            settingsLoaded={settingsLoaded}
            admin={admin} testResult={testResult} appVersion={appVersion}
            updateAvailable={updateAvailable} dismissUpdate={dismissUpdate}
            toggleConnection={toggleConnection} patchSettings={patchSettings}
            runTest={runTest} dismissError={dismissError} appendLog={appendLog}
          />
        )}

        {view === "scanner" && (
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
        )}

        {view === "settings" && (
          <SettingsTab
            settings={settings} settingsLocked={settingsLocked}
            settingsLoaded={settingsLoaded}
            saved={saved} patchSettings={patchSettings}
          />
        )}

        {view === "logs" && (
          <ActivityTab
            visibleLogs={visibleLogs} hasMore={hasMore}
            filterCounts={filterCounts} logFilter={logFilter} setLogFilter={setLogFilter}
            logEndRef={logEndRef} autoScroll={autoScroll} setAutoScroll={setAutoScroll}
            exportLogs={exportLogs} clearLogs={() => setLogs([])}
            scanState={scanner.scanState} status={runtime.status}
          />
        )}
      </section>
    </main>
  );
}

export default App;
