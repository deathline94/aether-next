import {
  Activity,
  Cable,
  Check,
  ChevronRight,
  CircleAlert,
  Copy,
  FlaskConical,
  Gauge,
  Globe2,
  ListRestart,
  LockKeyhole,
  Network,
  Power,
  Radio,
  Route,
  ScrollText,
  Settings2,
  ShieldCheck,
  SlidersHorizontal,
  TerminalSquare,
  Wifi,
  X,
} from "lucide-react";
import { useCallback, useEffect, useRef, useState } from "react";
import { invoke, listen, platformLabel } from "./bridge";
import "./App.css";

type View = "home" | "settings" | "logs";
type Status = "disconnected" | "connecting" | "connected" | "error";

type Settings = {
  protocol: "masque" | "wireguard" | "gool";
  transport: "h2" | "h3";
  scanMode: "turbo" | "balanced" | "thorough" | "stealth";
  ipVersion: "v4" | "v6" | "both";
  noize: string;
  noizeJc: number;
  noizeJmin: number;
  noizeJmax: number;
  noizeIntervalMs: number;
  routingMode: "system-proxy" | "proxy-only" | "tun";
  socksPort: number;
  httpPort: number;
  startMinimized: boolean;
  launchAtLogin: boolean;
  enginePath: string;
};

type RuntimeState = {
  status: Status;
  detail: string;
  pid: number | null;
  endpoint: string | null;
};

type LogEntry = {
  level: "info" | "warn" | "error";
  message: string;
  time: string;
};

const defaults: Settings = {
  protocol: "masque",
  transport: "h2",
  scanMode: "balanced",
  ipVersion: "v4",
  noize: "off",
  noizeJc: 4,
  noizeJmin: 48,
  noizeJmax: 190,
  noizeIntervalMs: 4,
  // Android default: full-device VPN (VpnService + hev tun2socks).
  routingMode: "tun",
  socksPort: 1819,
  httpPort: 1820,
  startMinimized: false,
  launchAtLogin: false,
  enginePath: "",
};

const initialRuntime: RuntimeState = {
  status: "disconnected",
  detail: "Ready",
  pid: null,
  endpoint: null,
};

const navigation = [
  { id: "home" as const, label: "Connection", icon: Radio },
  { id: "settings" as const, label: "Settings", icon: SlidersHorizontal },
  { id: "logs" as const, label: "Activity", icon: ScrollText },
];

/** One-click speed profile presets in exact order. */
const speedProfiles: {
  id: string;
  label: string;
  hint: string;
  patch: Partial<Settings>;
}[] = [
  {
    id: "masque-h3",
    label: "MASQUE H3",
    hint: "MASQUE h3 · noise off · balanced scan · system vpn",
    patch: {
      protocol: "masque",
      transport: "h3",
      noize: "off",
      scanMode: "balanced",
      ipVersion: "v4",
      routingMode: "tun",
    },
  },
  {
    id: "masque-h2",
    label: "MASQUE H2 (Default)",
    hint: "MASQUE h2 · noise off · balanced scan · system vpn",
    patch: {
      protocol: "masque",
      transport: "h2",
      noize: "off",
      scanMode: "balanced",
      ipVersion: "v4",
      routingMode: "tun",
    },
  },
  {
    id: "wireguard",
    label: "WireGuard",
    hint: "WireGuard · noise off · balanced scan · system vpn",
    patch: {
      protocol: "wireguard",
      transport: "h2",
      noize: "off",
      scanMode: "balanced",
      ipVersion: "v4",
      routingMode: "tun",
    },
  },
  {
    id: "gool",
    label: "Gool",
    hint: "Gool (WARP-in-WARP) · noise off · balanced scan · system vpn",
    patch: {
      protocol: "gool",
      transport: "h2",
      noize: "off",
      scanMode: "balanced",
      ipVersion: "v4",
      routingMode: "tun",
    },
  },
];

function now() {
  return new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function profileActive(settings: Settings, patch: Partial<Settings>) {
  return (Object.keys(patch) as (keyof Settings)[]).every((k) => settings[k] === patch[k]);
}

function clampPort(value: number) {
  if (!Number.isFinite(value)) return 1024;
  return Math.min(65535, Math.max(1024, Math.trunc(value)));
}

function Segmented<T extends string>({
  value,
  options,
  onChange,
  disabled,
}: {
  value: T;
  options: { value: T; label: string }[];
  onChange: (value: T) => void;
  disabled?: boolean;
}) {
  return (
    <div className={`segmented ${disabled ? "disabled" : ""}`}>
      {options.map((option) => (
        <button
          type="button"
          key={option.value}
          disabled={disabled}
          className={value === option.value ? "active" : ""}
          onClick={() => onChange(option.value)}
        >
          {option.label}
        </button>
      ))}
    </div>
  );
}

function Toggle({
  checked,
  onChange,
  disabled,
}: {
  checked: boolean;
  onChange: (checked: boolean) => void;
  disabled?: boolean;
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      disabled={disabled}
      className={`toggle ${checked ? "on" : ""}`}
      onClick={() => !disabled && onChange(!checked)}
    >
      <span />
    </button>
  );
}

function App() {
  const [view, setView] = useState<View>("home");
  const [settings, setSettings] = useState<Settings>(defaults);
  const [runtime, setRuntime] = useState<RuntimeState>(initialRuntime);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [busy, setBusy] = useState(false);
  const [saved, setSaved] = useState(false);
  const [admin, setAdmin] = useState(false);
  const [testResult, setTestResult] = useState<string | null>(null);
  const [appVersion, setAppVersion] = useState("1.0.4");
  const logEndRef = useRef<HTMLDivElement>(null);
  const connected = runtime.status === "connected";
  const running = runtime.status === "connecting" || connected;
  const settingsLocked = running;

  const appendLog = useCallback((entry: Omit<LogEntry, "time">) => {
    setLogs((current) => [...current.slice(-499), { ...entry, time: now() }]);
  }, []);

  useEffect(() => {
    let disposed = false;
    const cleanup: Array<() => void> = [];
    Promise.all([
      invoke<Settings>("get_settings"),
      invoke<RuntimeState>("get_state"),
      invoke<boolean>("is_admin").catch(() => false),
      invoke<{ version?: string }>("app_info").catch(() => ({ version: "1.0.4" })),
      listen<RuntimeState>("session://state", (event) => setRuntime(event.payload)),
      listen<{ level: LogEntry["level"]; message: string }>("session://log", (event) =>
        appendLog(event.payload),
      ),
    ])
      .then(([loadedSettings, state, isAdmin, info, unlistenState, unlistenLog]) => {
        if (disposed) {
          unlistenState();
          unlistenLog();
          return;
        }
        setSettings(loadedSettings);
        setRuntime(state);
        setAdmin(isAdmin);
        if (info?.version) setAppVersion(String(info.version));
        cleanup.push(unlistenState, unlistenLog);
      })
      .catch((error) => appendLog({ level: "warn", message: String(error) }));
    return () => {
      disposed = true;
      cleanup.forEach((fn) => fn());
    };
  }, []);

  useEffect(() => {
    logEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [logs]);

  async function persistSettings(next: Settings) {
    try {
      await invoke("save_settings", { settings: next });
      setSaved(true);
      setTimeout(() => setSaved(false), 1200);
    } catch (error) {
      appendLog({ level: "error", message: String(error) });
    }
  }

  function patchSettings(patch: Partial<Settings>) {
    if (settingsLocked) return;
    setSettings((prev) => {
      const next = { ...prev, ...patch };
      void persistSettings(next);
      return next;
    });
  }

  async function toggleConnection() {
    setBusy(true);
    setTestResult(null);
    try {
      if (running) {
        await invoke("disconnect");
      } else {
        setRuntime({ status: "connecting", detail: "Starting engine", pid: null, endpoint: null });
        await invoke("connect", { settings });
      }
    } catch (error) {
      const detail = String(error);
      setRuntime({ status: "error", detail, pid: null, endpoint: null });
      appendLog({ level: "error", message: detail });
    } finally {
      setBusy(false);
    }
  }

  async function runTest() {
    setBusy(true);
    setTestResult(null);
    try {
      const result = await invoke<string>("test_connection", { settings });
      setTestResult(result);
      appendLog({ level: "info", message: result });
    } catch (error) {
      const msg = String(error);
      setTestResult(msg);
      appendLog({ level: "error", message: msg });
    } finally {
      setBusy(false);
    }
  }

  async function copyEndpoint(value: string) {
    try {
      await navigator.clipboard.writeText(value);
      appendLog({ level: "info", message: `Copied ${value}` });
    } catch {
      appendLog({ level: "warn", message: "Clipboard copy failed" });
    }
  }

  function exportLogs() {
    const text = logs.map((l) => `${l.time}\t${l.level}\t${l.message}`).join("\n");
    void copyEndpoint(text || "(no logs)");
  }

  return (
    <main className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark">
            <ShieldCheck size={22} strokeWidth={1.8} />
          </div>
          <div>
            <strong>Aether Next</strong>
            <span>by deathline94</span>
          </div>
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
          <div className="version">
            AETHER NEXT <span>v{appVersion}</span>
          </div>
        </div>
      </aside>

      <section className="workspace">
        <header className="topbar">
          <div>
            <p>
              {view === "home"
                ? "SECURE ROUTING"
                : view === "settings"
                  ? "CONFIGURATION"
                  : "LIVE ENGINE OUTPUT"}
            </p>
            <h1>{view === "home" ? "Connection" : view === "settings" ? "Settings" : "Activity"}</h1>
          </div>
          <div className={`header-status ${runtime.status}`}>
            <span className="status-dot" />
            {runtime.status}
          </div>
        </header>

        {view === "home" && (
          <div className="home-view">
            <section className={`connection-stage ${runtime.status}`}>
              <div className="signal-field" aria-hidden="true">
                <span />
                <span />
                <span />
              </div>
              <div className="connection-copy">
                <div className="eyebrow">
                  <LockKeyhole size={15} />{" "}
                  {connected
                    ? "TUNNEL ESTABLISHED"
                    : running
                      ? "NEGOTIATING ROUTE"
                      : "READY TO CONNECT"}
                </div>
                <h2>
                  {connected
                    ? "Traffic protected"
                    : running
                      ? "Finding a clear path"
                      : "Your route is open"}
                </h2>
                <p>
                  {connected
                    ? `Aether Next is routing ${platformLabel()} traffic through ${settings.protocol.toUpperCase()}${runtime.endpoint ? ` via ${runtime.endpoint}` : ""}.`
                    : running
                      ? runtime.detail
                      : "Connect to discover a reachable Cloudflare edge and secure your traffic."}
                </p>
              </div>
              <button
                className={`power-button ${running ? "stop" : ""}`}
                onClick={toggleConnection}
                disabled={busy}
                aria-label={running ? "Disconnect" : "Connect"}
              >
                {busy ? <ListRestart className="spin" size={30} /> : <Power size={31} />}
              </button>
              <span className="power-label">{running ? "DISCONNECT" : "CONNECT"}</span>
            </section>

            {runtime.status === "error" && (
              <div className="error-banner">
                <CircleAlert size={18} />
                <span>{runtime.detail}</span>
                <button onClick={() => setRuntime(initialRuntime)} aria-label="Dismiss">
                  <X size={17} />
                </button>
              </div>
            )}

            <section className="profiles-panel">
              <div className="section-heading">
                <div>
                  <p>PRESETS</p>
                  <h3>Speed profiles</h3>
                </div>
                <Gauge size={20} />
              </div>
              <div className="profile-grid">
                {speedProfiles.map((profile) => {
                  const active = profileActive(settings, profile.patch);
                  return (
                    <button
                      key={profile.id}
                      type="button"
                      className={`profile-card ${active ? "active" : ""}`}
                      disabled={settingsLocked}
                      onClick={() => {
                        if (settingsLocked) return;
                        patchSettings(profile.patch);
                        appendLog({
                          level: "info",
                          message: `Applied profile: ${profile.label} - ${profile.hint}`,
                        });
                      }}
                    >
                      <strong>{profile.label}</strong>
                      <span>{profile.hint}</span>
                      {active && <small>ACTIVE</small>}
                    </button>
                  );
                })}
              </div>
              {!admin && (
                <p className="profile-note">
                  Max (VPN) needs the Android VPN permission. Use Speed for local SOCKS/HTTP proxy mode.
                </p>
              )}
            </section>

            <section className="metrics-grid">
              <article>
                <div className="metric-icon coral">
                  <Route size={19} />
                </div>
                <span>Protocol</span>
                <strong>
                  {settings.protocol === "gool" ? "WARP-in-WARP" : settings.protocol.toUpperCase()}
                </strong>
                <small>
                  {settings.protocol === "masque"
                    ? `HTTP/${settings.transport === "h2" ? "2" : "3"}`
                    : settings.noize}
                </small>
              </article>
              <article>
                <div className="metric-icon green">
                  <Globe2 size={19} />
                </div>
                <span>Routing</span>
                <strong>
                  {settings.routingMode === "system-proxy"
                    ? "App proxy"
                    : settings.routingMode === "tun"
                      ? "Full VPN"
                      : "Proxy only"}
                </strong>
                <small>{settings.routingMode === "tun" ? "VpnService" : "Local ports"}</small>
              </article>
              <article>
                <div className="metric-icon blue">
                  <Gauge size={19} />
                </div>
                <span>Endpoint</span>
                <strong>{runtime.endpoint || (running ? "Scanning..." : "-")}</strong>
                <small>
                  {settings.scanMode} - {settings.ipVersion.toUpperCase()}
                </small>
              </article>
              <article>
                <div className="metric-icon yellow">
                  <Activity size={19} />
                </div>
                <span>Process</span>
                <strong>{runtime.pid ? `PID ${runtime.pid}` : "Standby"}</strong>
                <small>{connected ? "Healthy" : "Not running"}</small>
              </article>
            </section>

            <section className="proxy-panel">
              <div className="section-heading">
                <div>
                  <p>LOCAL ACCESS</p>
                  <h3>Proxy endpoints</h3>
                </div>
                <Network size={20} />
              </div>
              <div className="endpoint-row">
                <div className="endpoint-kind">
                  <TerminalSquare size={18} />
                  <div>
                    <strong>HTTP / HTTPS</strong>
                    <span>HTTP CONNECT proxy</span>
                  </div>
                </div>
                <code>127.0.0.1:{settings.httpPort}</code>
                <button
                  onClick={() => copyEndpoint(`127.0.0.1:${settings.httpPort}`)}
                  title="Copy HTTP proxy"
                >
                  <Copy size={16} />
                </button>
              </div>
              <div className="endpoint-row">
                <div className="endpoint-kind">
                  <Cable size={18} />
                  <div>
                    <strong>SOCKS5</strong>
                    <span>Direct application access</span>
                  </div>
                </div>
                <code>127.0.0.1:{settings.socksPort}</code>
                <button
                  onClick={() => copyEndpoint(`127.0.0.1:${settings.socksPort}`)}
                  title="Copy SOCKS5 proxy"
                >
                  <Copy size={16} />
                </button>
              </div>
            </section>

            <section className="test-panel">
              <div className="section-heading">
                <div>
                  <p>VERIFY</p>
                  <h3>Live connection test</h3>
                </div>
                <FlaskConical size={20} />
              </div>
              <div className="test-row">
                <span>
                  {connected
                    ? "Hits Cloudflare via local HTTP proxy"
                    : "Connect first, then verify the path"}
                </span>
                <button onClick={runTest} disabled={busy || !connected}>
                  Test connection
                </button>
              </div>
              {testResult && <code className="test-result">{testResult}</code>}
            </section>

            <section className="about-panel">
              <div>
                <p>ANDROID</p>
                <h3>Aether Next</h3>
                <span>
                  Built by <strong>deathline94</strong> - full rework, not a fork
                </span>
              </div>
              <code>v{appVersion}</code>
            </section>
          </div>
        )}

        {view === "settings" && (
          <div className="settings-view">
            {settingsLocked && (
              <div className="lock-banner">
                Settings locked while connected. Disconnect to change tunnel options.
              </div>
            )}
            <section className="settings-section">
              <div className="section-heading">
                <div>
                  <p>TRANSPORT</p>
                  <h3>Tunnel behavior</h3>
                </div>
                <Wifi size={20} />
              </div>
              <div className="setting-row">
                <div>
                  <strong>Protocol</strong>
                  <span>Carrier used to reach Cloudflare</span>
                </div>
                <Segmented
                  disabled={settingsLocked}
                  value={settings.protocol}
                  options={[
                    { value: "masque", label: "MASQUE" },
                    { value: "wireguard", label: "WireGuard" },
                    { value: "gool", label: "Gool" },
                  ]}
                  onChange={(protocol) => patchSettings({ protocol })}
                />
              </div>
              {settings.protocol === "masque" && (
                <div className="setting-row">
                  <div>
                    <strong>MASQUE transport</strong>
                    <span>HTTP/2 works on networks blocking QUIC</span>
                  </div>
                  <Segmented
                    disabled={settingsLocked}
                    value={settings.transport}
                    options={[
                      { value: "h2", label: "HTTP/2" },
                      { value: "h3", label: "HTTP/3" },
                    ]}
                    onChange={(transport) => patchSettings({ transport })}
                  />
                </div>
              )}
              <div className="setting-row">
                <div>
                  <strong>Obfuscation</strong>
                  <span>Noise before handshake (low → high)</span>
                </div>
                <select
                  disabled={settingsLocked}
                  value={
                    ["off", "light", "medium", "high", "max", "custom"].includes(settings.noize)
                      ? settings.noize
                      : settings.noize === "firewall" || settings.noize === "balanced"
                        ? "medium"
                        : settings.noize === "gfw"
                          ? "high"
                          : settings.noize === "aggressive" || settings.noize === "heavy"
                            ? "max"
                            : "medium"
                  }
                  onChange={(event) => patchSettings({ noize: event.target.value })}
                >
                  <option value="off">Off — no noise</option>
                  <option value="light">Light — low noise</option>
                  <option value="medium">Medium — default</option>
                  <option value="high">High — stronger</option>
                  <option value="max">Max — highest noise</option>
                  <option value="custom">Custom — manual values</option>
                </select>
              </div>
              {settings.noize === "custom" && (
                <div className="setting-stack" style={{ gap: 10, marginTop: 8 }}>
                  <div className="setting-row">
                    <div>
                      <strong>Junk count</strong>
                      <span>Packets before handshake (0–64)</span>
                    </div>
                    <input
                      type="number"
                      min={0}
                      max={64}
                      disabled={settingsLocked}
                      value={settings.noizeJc}
                      onChange={(e) =>
                        patchSettings({
                          noizeJc: Math.max(0, Math.min(64, Number(e.target.value) || 0)),
                        })
                      }
                    />
                  </div>
                  <div className="setting-row">
                    <div>
                      <strong>Min size</strong>
                      <span>Bytes</span>
                    </div>
                    <input
                      type="number"
                      min={0}
                      max={2048}
                      disabled={settingsLocked}
                      value={settings.noizeJmin}
                      onChange={(e) =>
                        patchSettings({
                          noizeJmin: Math.max(0, Math.min(2048, Number(e.target.value) || 0)),
                        })
                      }
                    />
                  </div>
                  <div className="setting-row">
                    <div>
                      <strong>Max size</strong>
                      <span>Bytes (≥ min)</span>
                    </div>
                    <input
                      type="number"
                      min={0}
                      max={2048}
                      disabled={settingsLocked}
                      value={settings.noizeJmax}
                      onChange={(e) =>
                        patchSettings({
                          noizeJmax: Math.max(0, Math.min(2048, Number(e.target.value) || 0)),
                        })
                      }
                    />
                  </div>
                  <div className="setting-row">
                    <div>
                      <strong>Interval</strong>
                      <span>Milliseconds between junk</span>
                    </div>
                    <input
                      type="number"
                      min={0}
                      max={5000}
                      disabled={settingsLocked}
                      value={settings.noizeIntervalMs}
                      onChange={(e) =>
                        patchSettings({
                          noizeIntervalMs: Math.max(
                            0,
                            Math.min(5000, Number(e.target.value) || 0),
                          ),
                        })
                      }
                    />
                  </div>
                </div>
              )}
            </section>

            <section className="settings-section">
              <div className="section-heading">
                <div>
                  <p>DISCOVERY</p>
                  <h3>Endpoint scanning</h3>
                </div>
                <Radio size={20} />
              </div>
              <div className="setting-row">
                <div>
                  <strong>Scan mode</strong>
                  <span>Balance startup time and route quality</span>
                </div>
                <select
                  disabled={settingsLocked}
                  value={settings.scanMode}
                  onChange={(event) =>
                    patchSettings({ scanMode: event.target.value as Settings["scanMode"] })
                  }
                >
                  <option value="turbo">Turbo</option>
                  <option value="balanced">Balanced</option>
                  <option value="thorough">Thorough</option>
                  <option value="stealth">Stealth</option>
                </select>
              </div>
              <div className="setting-row">
                <div>
                  <strong>IP version</strong>
                  <span>Address families included in search</span>
                </div>
                <Segmented
                  disabled={settingsLocked}
                  value={settings.ipVersion}
                  options={[
                    { value: "v4", label: "IPv4" },
                    { value: "v6", label: "IPv6" },
                    { value: "both", label: "Both" },
                  ]}
                  onChange={(ipVersion) => patchSettings({ ipVersion })}
                />
              </div>
            </section>

            <section className="settings-section">
              <div className="section-heading">
                <div>
                  <p>ANDROID</p>
                  <h3>Routing</h3>
                </div>
                <Settings2 size={20} />
              </div>
              <div className="setting-row">
                <div>
                  <strong>Routing mode</strong>
                  <span>
                    {settings.routingMode === "tun"
                      ? admin
                        ? "VPN permission granted - full device tunnel"
                        : "Will request Android VPN permission"
                      : "Local SOCKS5/HTTP for apps that support a proxy"}
                  </span>
                </div>
                <select
                  disabled={settingsLocked}
                  value={settings.routingMode}
                  onChange={(event) =>
                    patchSettings({
                      routingMode: event.target.value as Settings["routingMode"],
                    })
                  }
                >
                  <option value="proxy-only">Proxy only</option>
                  <option value="tun">Full VPN (VpnService)</option>
                </select>
              </div>
            </section>

            <section className="settings-section advanced">
              <div className="section-heading">
                <div>
                  <p>ADVANCED</p>
                  <h3>Local ports</h3>
                </div>
                <ChevronRight size={20} />
              </div>
              <div className="setting-row input-row">
                <label>
                  <span>HTTP port (1024-65535)</span>
                  <input
                    type="number"
                    min={1024}
                    max={65535}
                    disabled={settingsLocked}
                    value={settings.httpPort}
                    onChange={(event) =>
                      patchSettings({ httpPort: clampPort(Number(event.target.value)) })
                    }
                  />
                </label>
                <label>
                  <span>SOCKS5 port (1024-65535)</span>
                  <input
                    type="number"
                    min={1024}
                    max={65535}
                    disabled={settingsLocked}
                    value={settings.socksPort}
                    onChange={(event) =>
                      patchSettings({ socksPort: clampPort(Number(event.target.value)) })
                    }
                  />
                </label>
              </div>
            </section>

            <div className="save-bar">
              <span>
                {settingsLocked
                  ? "Locked while connected"
                  : saved
                    ? "Saved automatically"
                    : "Changes save automatically · Aether Next"}
              </span>
              <button disabled className="ghost">
                {saved ? <Check size={17} /> : null}
                {saved ? "Saved" : "Auto-save on"}
              </button>
            </div>
          </div>
        )}

        {view === "logs" && (
          <div className="logs-view">
            <div className="log-toolbar">
              <div>
                <span className={`status-dot ${runtime.status}`} />
                <strong>Engine output</strong>
                <small>{logs.length} events</small>
              </div>
              <div className="log-actions">
                <button onClick={exportLogs}>Copy all</button>
                <button onClick={() => setLogs([])}>Clear</button>
              </div>
            </div>
            <section className="log-console">
              {logs.length === 0 ? (
                <div className="empty-logs">
                  <TerminalSquare size={26} />
                  <strong>No activity yet</strong>
                  <span>Engine events appear here after connection starts.</span>
                </div>
              ) : (
                logs.map((entry, index) => (
                  <div className={`log-line ${entry.level}`} key={`${entry.time}-${index}`}>
                    <time>{entry.time}</time>
                    <span>{entry.level}</span>
                    <p>{entry.message}</p>
                  </div>
                ))
              )}
              <div ref={logEndRef} />
            </section>
          </div>
        )}
      </section>
    </main>
  );
}

export default App;


