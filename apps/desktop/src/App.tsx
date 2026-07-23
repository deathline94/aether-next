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

const navigation = [
  { id: "home" as const, label: "Connection", icon: Radio },
  { id: "scanner" as const, label: "Scanner", icon: Search },
  { id: "settings" as const, label: "Settings", icon: SlidersHorizontal },
  { id: "logs" as const, label: "Activity", icon: ScrollText },
];

const viewTitles: Record<View, { eyebrow: string; title: string }> = {
  home: { eyebrow: "SECURE ROUTING", title: "Connection" },
  scanner: { eyebrow: "ENDPOINT DISCOVERY", title: "Scanner" },
  settings: { eyebrow: "CONFIGURATION", title: "Settings" },
  logs: { eyebrow: "LIVE ENGINE OUTPUT", title: "Activity" },
};

function App() {
  const [view, setView] = useState<View>("home");

  const {
    logs, setLogs, logFilter, setLogFilter, appendLog,
    visibleLogs, hasMore, filterCounts, logEndRef, autoScroll, setAutoScroll,
  } = useLogs();

  const {
    settings, runtime, busy, saved, admin, testResult, appVersion, updateAvailable,
    connected, running, settingsLocked,
    patchSettings, toggleConnection, connectToPeer, runTest, dismissError,
  } = useRuntime(appendLog);

  const scanner = useScanner(appendLog, running);

  const connectDirect = useCallback((item: DiscoveredEndpoint) => {
    const proto = item.protocol.toLowerCase().includes("wireguard") ? "wireguard" : "masque";
    const trans = item.protocol.includes("H3") ? "h3" : "h2";
    appendLog({ level: "info", message: `Direct connecting to gateway: ${item.addr} (${item.protocol})` });
    void connectToPeer(item.addr, proto, trans);
  }, [connectToPeer, appendLog]);

  const exportLogs = useCallback(() => {
    const text = logs.map((l) => `${l.time}\t${l.level}\t${l.message}`).join("\n");
    void navigator.clipboard.writeText(text || "(no logs)");
  }, [logs]);

  const { eyebrow, title } = viewTitles[view];

  return (
    <main className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark"><ShieldCheck size={22} strokeWidth={1.8} /></div>
          <div><strong>Aether Next</strong><span>by deathline94</span></div>
        </div>

        <nav>
          {navigation.map(({ id, label, icon: Icon }) => (
            <button key={id} className={view === id ? "active" : ""} onClick={() => setView(id)}>
              <Icon size={18} />
              <span>{label}</span>
              {id === "logs" && logs.length > 0 && <small>{Math.min(logs.length, 99)}</small>}
            </button>
          ))}
        </nav>

        <div className="sidebar-bottom">
          <div className={`mini-status ${runtime.status}`}>
            <span className="status-dot" />
            <div>
              <strong>{connected ? "Protected" : running ? "Connecting" : "Unprotected"}</strong>
              <span>{runtime.detail}</span>
            </div>
          </div>
          <div className="version">AETHER NEXT <span>v{appVersion}</span></div>
        </div>
      </aside>

      <section className="workspace">
        <header className="topbar">
          <div><p>{eyebrow}</p><h1>{title}</h1></div>
          <div className={`header-status ${runtime.status}`}>
            <span className="status-dot" />
            {runtime.status}
          </div>
        </header>

        {view === "home" && (
          <ConnectionTab
            settings={settings} runtime={runtime} busy={busy}
            connected={connected} running={running} settingsLocked={settingsLocked}
            admin={admin} testResult={testResult} appVersion={appVersion}
            updateAvailable={updateAvailable}
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
            endpoints={scanner.endpoints} active={scanner.active}
            scanState={scanner.scanState} busy={scanner.busy}
            startScan={scanner.startScan} stopScan={scanner.stopScan}
            connectDirect={connectDirect} connectBusy={busy}
          />
        )}

        {view === "settings" && (
          <SettingsTab
            settings={settings} settingsLocked={settingsLocked}
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
