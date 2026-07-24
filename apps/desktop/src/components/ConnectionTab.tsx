import { invoke } from "@tauri-apps/api/core";
import {
  Activity, Cable, CircleAlert, Copy, FlaskConical, Gauge, Globe2,
  ListRestart, LockKeyhole, Network, Power, Route,
  Sparkles, TerminalSquare, X,
} from "lucide-react";
import type { RuntimeState, Settings } from "../types";

const speedProfiles: { id: string; label: string; hint: string; patch: Partial<Settings> }[] = [
  { id: "masque-h3", label: "MASQUE H3", hint: "MASQUE h3 · noise off · balanced scan · system proxy", patch: { protocol: "masque", transport: "h3", noize: "off", scanMode: "balanced", ipVersion: "v4", routingMode: "system-proxy" } },
  { id: "masque-h2", label: "MASQUE H2 (Default)", hint: "MASQUE h2 · noise off · balanced scan · system proxy", patch: { protocol: "masque", transport: "h2", noize: "off", scanMode: "balanced", ipVersion: "v4", routingMode: "system-proxy" } },
  { id: "wireguard", label: "WireGuard", hint: "WireGuard · noise off · balanced scan · system proxy", patch: { protocol: "wireguard", transport: "h2", noize: "off", scanMode: "balanced", ipVersion: "v4", routingMode: "system-proxy" } },
  { id: "gool", label: "Gool", hint: "Gool (WARP-in-WARP) · noise off · balanced scan · system proxy", patch: { protocol: "gool", transport: "h2", noize: "off", scanMode: "balanced", ipVersion: "v4", routingMode: "system-proxy" } },
];

function profileActive(settings: Settings, patch: Partial<Settings>) {
  return (Object.keys(patch) as (keyof Settings)[]).every((k) => settings[k] === patch[k]);
}

interface ConnectionTabProps {
  settings: Settings;
  runtime: RuntimeState;
  busy: boolean;
  connected: boolean;
  running: boolean;
  settingsLocked: boolean;
  admin: boolean;
  testResult: string | null;
  appVersion: string;
  updateAvailable: { version: string; url: string } | null;
  toggleConnection: () => void;
  patchSettings: (patch: Partial<Settings>) => void;
  runTest: () => void;
  dismissError: () => void;
  appendLog: (entry: { level: "info" | "warn" | "error"; message: string }) => void;
}

export function ConnectionTab({
  settings, runtime, busy, connected, running, settingsLocked, admin,
  testResult, appVersion, updateAvailable,
  toggleConnection, patchSettings, runTest, dismissError, appendLog,
}: ConnectionTabProps) {
  async function copyEndpoint(value: string) {
    try {
      await navigator.clipboard.writeText(value);
      appendLog({ level: "info", message: `Copied ${value}` });
    } catch {
      appendLog({ level: "warn", message: "Clipboard copy failed" });
    }
  }

  return (
    <div className="home-view">
      <section className={`connection-stage ${runtime.status}`}>
        <div className="signal-field" aria-hidden="true"><span /><span /><span /></div>
        <div className="connection-copy">
          <div className="eyebrow">
            <LockKeyhole size={15} />{" "}
            {connected ? "TUNNEL ESTABLISHED" : running ? "NEGOTIATING ROUTE" : "READY TO CONNECT"}
          </div>
          <h2>{connected ? "Traffic protected" : running ? "Finding a clear path" : "Your route is open"}</h2>
          <p>
            {connected
              ? `Aether Next is routing Windows traffic through ${settings.protocol.toUpperCase()}${runtime.endpoint ? ` via ${runtime.endpoint}` : ""}.`
              : running ? runtime.detail : "Connect to discover a reachable Cloudflare edge and secure your traffic."}
          </p>
        </div>
        <button className={`power-button ${running ? "stop" : ""}`} onClick={toggleConnection} disabled={busy} aria-label={running ? "Disconnect" : "Connect"}>
          {busy ? <ListRestart className="spin" size={30} /> : <Power size={31} />}
        </button>
        <span className="power-label">{running ? "DISCONNECT" : "CONNECT"}</span>
      </section>

      {runtime.status === "error" && (
        <div className="error-banner">
          <CircleAlert size={18} />
          <span>{runtime.detail}</span>
          <button type="button" onClick={() => void dismissError()} aria-label="Dismiss"><X size={17} /></button>
        </div>
      )}

      {updateAvailable && (
        <div className="update-banner">
          <Sparkles size={18} />
          <span>Aether {updateAvailable.version} is ready. Restart or click to update!</span>
          <button type="button" onClick={() => invoke("plugin:opener|open_url", { url: updateAvailable.url }).catch(() => window.open(updateAvailable.url, "_blank"))}>
            Update Now
          </button>
        </div>
      )}

      <section className="profiles-panel">
        <div className="section-heading">
          <div><p>PRESETS</p><h3>Speed profiles</h3></div>
          <Gauge size={20} />
        </div>
        <div className="profile-grid">
          {speedProfiles.map((profile) => {
            const active = profileActive(settings, profile.patch);
            return (
              <button key={profile.id} type="button" className={`profile-card ${active ? "active" : ""}`} disabled={settingsLocked}
                onClick={() => { if (settingsLocked) return; patchSettings(profile.patch); appendLog({ level: "info", message: `Applied profile: ${profile.label} — ${profile.hint}` }); }}>
                <strong>{profile.label}</strong>
                <span>{profile.hint}</span>
                {active && <small>ACTIVE</small>}
              </button>
            );
          })}
        </div>
        {!admin && <p className="profile-note">Max (TUN) needs Run as administrator and wintun.dll. Use Speed for everyday proxy mode.</p>}
      </section>

      <section className="metrics-grid">
        <article>
          <div className="metric-icon coral"><Route size={19} /></div>
          <span>Protocol</span>
          <strong>{settings.protocol === "gool" ? "WARP-in-WARP" : settings.protocol.toUpperCase()}</strong>
          <small>{settings.protocol === "masque" ? `HTTP/${settings.transport === "h2" ? "2" : "3"}` : settings.noize}</small>
        </article>
        <article>
          <div className="metric-icon green"><Globe2 size={19} /></div>
          <span>Routing</span>
          <strong>{settings.routingMode === "system-proxy" ? "System proxy" : settings.routingMode === "tun" ? "Full tunnel" : "Proxy only"}</strong>
          <small>{settings.routingMode === "tun" ? "Administrator" : "Per-user"}</small>
        </article>
        <article>
          <div className="metric-icon blue"><Gauge size={19} /></div>
          <span>Endpoint</span>
          <strong>{runtime.endpoint || (running ? "Scanning…" : "—")}</strong>
          <small>{settings.scanMode} · {settings.ipVersion.toUpperCase()}</small>
        </article>
        <article>
          <div className="metric-icon yellow"><Activity size={19} /></div>
          <span>Process</span>
          <strong>{runtime.pid ? `PID ${runtime.pid}` : "Standby"}</strong>
          <small>{connected ? "Healthy" : "Not running"}</small>
        </article>
      </section>

      <section className="proxy-panel">
        <div className="section-heading">
          <div><p>LOCAL ACCESS</p><h3>Proxy endpoints</h3></div>
          <Network size={20} />
        </div>
        <div className="endpoint-row">
          <div className="endpoint-kind"><TerminalSquare size={18} /><div><strong>HTTP / HTTPS</strong><span>Windows system proxy</span></div></div>
          <code>127.0.0.1:{settings.httpPort}</code>
          <button onClick={() => copyEndpoint(`127.0.0.1:${settings.httpPort}`)} title="Copy HTTP proxy"><Copy size={16} /></button>
        </div>
        <div className="endpoint-row">
          <div className="endpoint-kind"><Cable size={18} /><div><strong>SOCKS5</strong><span>Direct application access</span></div></div>
          <code>127.0.0.1:{settings.socksPort}</code>
          <button onClick={() => copyEndpoint(`127.0.0.1:${settings.socksPort}`)} title="Copy SOCKS5 proxy"><Copy size={16} /></button>
        </div>
      </section>

      <section className="test-panel">
        <div className="section-heading">
          <div><p>VERIFY</p><h3>Live connection test</h3></div>
          <FlaskConical size={20} />
        </div>
        <div className="test-row">
          <span>{connected ? "Hits Cloudflare via local HTTP proxy" : "Connect first, then verify the path"}</span>
          <button onClick={runTest} disabled={busy || !connected}>Test connection</button>
        </div>
        {testResult && <code className="test-result">{testResult}</code>}
      </section>

      <section className="about-panel">
        <div>
          <p>WINDOWS PORT</p>
          <h3>Aether Next</h3>
          <span>Built by <strong>deathline94</strong> · full rework, not a fork</span>
        </div>
        <code>v{appVersion}</code>
      </section>
    </div>
  );
}
