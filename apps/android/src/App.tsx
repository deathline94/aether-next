import { Radio, ScrollText, Search, ShieldCheck, SlidersHorizontal } from "lucide-react";
import { useCallback, useState } from "react";
import "./App.css";
import { ActivityTab } from "./components/ActivityTab";
import { ConnectionTab } from "./components/ConnectionTab";
import { ScannerTab } from "./components/ScannerTab";
import { SettingsTab } from "./components/SettingsTab";
import { useLogs } from "./hooks/useLogs";
import { useOnline } from "./hooks/useOnline";
import { useRuntime } from "./hooks/useRuntime";
import { useScanner } from "./hooks/useScanner";
import type { DiscoveredEndpoint, View } from "./types";

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
    settings, runtime, busy, testBusy, saved, admin, testResult, appVersion,
    connected, running, settingsLocked, settingsLoaded, settingsLoadError, retrySettings,
    patchSettings, toggleConnection, connectToPeer, runTest, dismissError,
  } = useRuntime(appendLog, clearLogs);

  const scanner = useScanner(appendLog, running, clearLogs);

  const connectDirect = useCallback(async (item: DiscoveredEndpoint) => {
    // Case-insensitive: the engine reports "MASQUE H3", "masque-h3", etc.
    const proto = item.protocol.toLowerCase();
    const protocol = proto.includes("wireguard") || proto.includes("wg") ? "wireguard" : "masque";
    const transport = proto.includes("h3") ? "h3" : "h2";
    appendLog({ level: "info", message: `Direct connecting to gateway: ${item.addr} (${item.protocol})` });
    if (scanner.active || scanner.busy) {
      await scanner.stopScan();
      await new Promise((r) => setTimeout(r, 200));
    }
    void connectToPeer(item.addr, protocol, transport);
    setView("home");
  }, [connectToPeer, appendLog, scanner.active, scanner.busy, scanner.stopScan]);

  const exportLogs = useCallback(async (): Promise<boolean> => {
    if (logs.length === 0) return false;
    const text = logs.map((l) => `${new Date(l.ts).toISOString()}\t${l.level}\t${l.message}`).join("\n");
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch {
      appendLog({ level: "warn", message: "Clipboard copy failed" });
      return false;
    }
  }, [logs, appendLog]);

  const activeNav = navigation.find((n) => n.id === view) ?? navigation[0];
  const statusText = connected ? "Protected" : running ? "Connecting" : runtime.status === "error" ? "Error" : "Standby";

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
                <span className="beacon-tag">{connected ? "ACTIVE" : running ? "HANDSHAKE" : runtime.status === "error" ? "ALERT" : "STANDBY"}</span>
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
            <p className="topbar-eyebrow">{activeNav.eyebrow}</p>
            <h1 className="topbar-heading">{activeNav.label}</h1>
          </div>
          <div className="topbar-actions">
            <div className={`header-status ${runtime.status}`} title={runtime.detail}>
              <span className="status-dot" aria-hidden="true" />
              <span>{runtime.status}</span>
            </div>
          </div>
        </header>

        {view === "home" && (
          <ConnectionTab
            settings={settings} runtime={runtime} busy={busy} testBusy={testBusy}
            connected={connected} running={running} settingsLocked={settingsLocked}
            settingsLoaded={settingsLoaded} admin={admin} online={online}
            testResult={testResult} appVersion={appVersion}
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
            settingsLoadError={settingsLoadError}
            retrySettings={retrySettings}
            saved={saved} admin={admin}
            patchSettings={patchSettings}
          />
        )}

        {view === "logs" && (
          <ActivityTab
            visibleLogs={visibleLogs} hasMore={hasMore}
            filterCounts={filterCounts} logFilter={logFilter} setLogFilter={setLogFilter}
            logEndRef={logEndRef} autoScroll={autoScroll} setAutoScroll={setAutoScroll}
            exportLogs={exportLogs} clearLogs={clearLogs}
            scanState={scanner.scanState} status={runtime.status}
          />
        )}
      </section>
    </main>
  );
}

export default App;
