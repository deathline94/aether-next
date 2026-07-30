import {
  Activity, Cable, Check, CircleAlert, Copy, FlaskConical, Gauge, Globe2,
  ListRestart, LockKeyhole, Network, Power, Route, TerminalSquare, WifiOff, X,
} from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { platformLabel } from "../bridge";
import { profileActive, speedProfiles } from "../types";
import type { RuntimeState, Settings } from "../types";

const heroCopy: Record<RuntimeState["status"], { eyebrow: string; title: string }> = {
  disconnected: { eyebrow: "READY TO CONNECT", title: "Your route is open" },
  connecting: { eyebrow: "NEGOTIATING ROUTE", title: "Finding a clear path" },
  connected: { eyebrow: "TUNNEL ESTABLISHED", title: "Traffic protected" },
  error: { eyebrow: "CONNECTION FAILED", title: "Route hit a wall" },
};

interface ConnectionTabProps {
  settings: Settings;
  runtime: RuntimeState;
  busy: boolean;
  testBusy: boolean;
  connected: boolean;
  running: boolean;
  settingsLocked: boolean;
  settingsLoaded: boolean;
  admin: boolean;
  online: boolean;
  testResult: string | null;
  appVersion: string;
  toggleConnection: () => void;
  patchSettings: (patch: Partial<Settings>) => void;
  runTest: () => void;
  dismissError: () => void;
  appendLog: (entry: { level: "info" | "warn" | "error"; message: string }) => void;
}

/** Copy button that confirms in place — feedback where the user is looking. */
function CopyButton({ value, label, appendLog }: {
  value: string;
  label: string;
  appendLog: ConnectionTabProps["appendLog"];
}) {
  const [copied, setCopied] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  useEffect(() => () => { if (timer.current) clearTimeout(timer.current); }, []);

  return (
    <button
      type="button"
      aria-label={copied ? "Copied" : label}
      title={copied ? "Copied" : label}
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(value);
          setCopied(true);
          if (timer.current) clearTimeout(timer.current);
          timer.current = setTimeout(() => setCopied(false), 1500);
        } catch {
          appendLog({ level: "warn", message: "Clipboard copy failed" });
        }
      }}
    >
      {copied ? <Check size={16} aria-hidden="true" /> : <Copy size={16} aria-hidden="true" />}
    </button>
  );
}

export function ConnectionTab({
  settings, runtime, busy, testBusy, connected, running, settingsLocked, settingsLoaded,
  admin, online, testResult, appVersion,
  toggleConnection, patchSettings, runTest, dismissError, appendLog,
}: ConnectionTabProps) {
  const hero = heroCopy[runtime.status];
  const routingLabel = settings.routingMode === "tun" ? "Full VPN" : settings.routingMode === "system-proxy" ? "App proxy" : "Proxy only";
  const routingSub = settings.routingMode === "tun" ? "VpnService" : "Local ports";

  return (
    <div className="home-view">
      {!online && (
        <div className="offline-banner" role="status">
          <WifiOff size={16} aria-hidden="true" />
          <span>You appear to be offline. Aether needs a working network to reach Cloudflare edges.</span>
        </div>
      )}

      <section className={`connection-stage ${runtime.status}`}>
        <div className="signal-field" aria-hidden="true"><span /><span /><span /></div>
        <div className="connection-copy">
          <div className="eyebrow">
            {runtime.status === "error" ? <CircleAlert size={15} aria-hidden="true" /> : <LockKeyhole size={15} aria-hidden="true" />}{" "}
            {hero.eyebrow}
          </div>
          <h2>{hero.title}</h2>
          <p aria-live="polite">
            {connected
              ? `Aether Next is routing ${platformLabel()} traffic through ${settings.protocol.toUpperCase()}${runtime.endpoint ? ` via ${runtime.endpoint}` : ""}.`
              : running || runtime.status === "error"
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
          {busy ? <ListRestart className="spin" size={30} aria-hidden="true" /> : <Power size={31} aria-hidden="true" />}
        </button>
        <span className="power-label" aria-hidden="true">{running ? "DISCONNECT" : "CONNECT"}</span>
      </section>

      {runtime.status === "error" && (
        <div className="error-banner" role="alert">
          <CircleAlert size={18} aria-hidden="true" />
          <span>{runtime.detail}</span>
          <button type="button" onClick={() => void dismissError()} aria-label="Dismiss error"><X size={17} aria-hidden="true" /></button>
        </div>
      )}

      <section className="profiles-panel">
        <div className="section-heading">
          <div><p>PRESETS</p><h3>Speed profiles</h3></div>
          <Gauge size={20} aria-hidden="true" />
        </div>
        <div className="profile-grid">
          {speedProfiles.map((profile) => {
            const active = settingsLoaded && profileActive(settings, profile.patch);
            return (
              <button
                key={profile.id}
                type="button"
                className={`profile-card ${active ? "active" : ""}`}
                disabled={settingsLocked}
                aria-pressed={active}
                onClick={() => {
                  if (settingsLocked || active) return;
                  patchSettings(profile.patch);
                  appendLog({ level: "info", message: `Applied profile: ${profile.label} — ${profile.hint}` });
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
            Full VPN needs the Android VPN permission (granted on first connect). Proxy only exposes local SOCKS/HTTP for apps that support a proxy.
          </p>
        )}
      </section>

      <section className="metrics-grid">
        <article>
          <div className="metric-icon coral"><Route size={19} aria-hidden="true" /></div>
          <span>Protocol</span>
          <strong>{settings.protocol === "gool" ? "WARP-in-WARP" : settings.protocol.toUpperCase()}</strong>
          <small>{settings.protocol === "masque" ? `HTTP/${settings.transport === "h2" ? "2" : "3"}` : settings.noize}</small>
        </article>
        <article>
          <div className="metric-icon green"><Globe2 size={19} aria-hidden="true" /></div>
          <span>Routing</span>
          <strong>{routingLabel}</strong>
          <small>{routingSub}</small>
        </article>
        <article>
          <div className="metric-icon blue"><Gauge size={19} aria-hidden="true" /></div>
          <span>Endpoint</span>
          <strong title={runtime.endpoint ?? undefined}>{runtime.endpoint || (running ? "Scanning…" : "—")}</strong>
          <small>{settings.scanMode} · {settings.ipVersion.toUpperCase()}</small>
        </article>
        <article>
          <div className="metric-icon yellow"><Activity size={19} aria-hidden="true" /></div>
          <span>Process</span>
          <strong>{runtime.pid ? `PID ${runtime.pid}` : "Standby"}</strong>
          <small>{connected ? "Healthy" : "Not running"}</small>
        </article>
      </section>

      <section className="proxy-panel">
        <div className="section-heading">
          <div><p>LOCAL ACCESS</p><h3>Proxy endpoints</h3></div>
          <Network size={20} aria-hidden="true" />
        </div>
        <div className="endpoint-row">
          <div className="endpoint-kind"><TerminalSquare size={18} aria-hidden="true" /><div><strong>HTTP / HTTPS</strong><span>HTTP CONNECT proxy</span></div></div>
          <code>127.0.0.1:{settings.httpPort}</code>
          <CopyButton value={`127.0.0.1:${settings.httpPort}`} label="Copy HTTP proxy address" appendLog={appendLog} />
        </div>
        <div className="endpoint-row">
          <div className="endpoint-kind"><Cable size={18} aria-hidden="true" /><div><strong>SOCKS5</strong><span>Direct application access</span></div></div>
          <code>127.0.0.1:{settings.socksPort}</code>
          <CopyButton value={`127.0.0.1:${settings.socksPort}`} label="Copy SOCKS5 proxy address" appendLog={appendLog} />
        </div>
      </section>

      <section className="test-panel">
        <div className="section-heading">
          <div><p>VERIFY</p><h3>Live connection test</h3></div>
          <FlaskConical size={20} aria-hidden="true" />
        </div>
        <div className="test-row">
          <span>{connected ? "Hits Cloudflare via local HTTP proxy" : "Connect first, then verify the path"}</span>
          <button onClick={runTest} disabled={testBusy || busy || !connected}>{testBusy ? "Testing…" : "Test connection"}</button>
        </div>
        {testResult && <code className="test-result">{testResult}</code>}
      </section>

      <section className="about-panel">
        <div>
          <p>ANDROID</p>
          <h3>Aether Next</h3>
          <span>Built by <strong>deathline94</strong> · full rework, not a fork</span>
        </div>
        <code>v{appVersion}</code>
      </section>
    </div>
  );
}
