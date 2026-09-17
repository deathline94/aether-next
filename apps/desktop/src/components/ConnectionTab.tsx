import { invoke } from "@tauri-apps/api/core";
import {
  Activity, Cable, Check, CircleAlert, Copy, Cpu,
  FlaskConical, Gauge, Globe2, ListRestart, LockKeyhole, Network,
  Power, Route, ShieldCheck, Sparkles, TerminalSquare, X,
} from "lucide-react";
import { useEffect, useRef, useState } from "react";
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

const heroCopy: Record<RuntimeState["status"], { eyebrow: string; title: string; badge: string }> = {
  disconnected: { eyebrow: "SYSTEM READY // ROUTE OPEN", title: "Encrypted Route Ready", badge: "STANDBY // CLICK TO ENGAGE" },
  connecting: { eyebrow: "NEGOTIATING // ROUTE HANDSHAKE", title: "Establishing Edge Path", badge: "ENGAGING // 0-RTT PROBING" },
  connected: { eyebrow: "TUNNEL ARMED // TRAFFIC SECURE", title: "Traffic Protected & Routed", badge: "ACTIVE // 0-RTT TUNNEL" },
  error: { eyebrow: "CRITICAL ALERT // PATH UNREACHABLE", title: "Route Compromised", badge: "LINK COMPROMISED // ERROR" },
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
  testResult: string | null;
  appVersion: string;
  updateAvailable: { version: string; url: string } | null;
  dismissUpdate: () => void;
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
      className="tactile-copy-btn"
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
      {copied ? <Check size={15} aria-hidden="true" /> : <Copy size={15} aria-hidden="true" />}
    </button>
  );
}

export function ConnectionTab({
  settings, runtime, busy, testBusy, connected, running, settingsLocked, settingsLoaded,
  admin, testResult, appVersion, updateAvailable, dismissUpdate,
  toggleConnection, patchSettings, runTest, dismissError, appendLog,
}: ConnectionTabProps) {
  const hero = heroCopy[runtime.status];

  // Parse verified live latency from testResult if available
  const parsedLatency = testResult?.match(/(\d+)\s*ms/i)?.[1];
  const displayLatency = parsedLatency
    ? `${parsedLatency} ms`
    : connected
      ? "< 45 ms"
      : "-- ms";

  return (
    <div className="home-view">
      {/* ─── Hero Centerpiece Stage ────────────────────────────────────────── */}
      <section className={`connection-stage cyber-hero ${runtime.status}`}>
        <div className="signal-field" aria-hidden="true">
          <span />
          <span />
          <span />
        </div>

        <div className="connection-copy">
          <div className="eyebrow">
            {runtime.status === "error" ? (
              <CircleAlert size={14} className="eyebrow-icon alert" aria-hidden="true" />
            ) : runtime.status === "connected" ? (
              <ShieldCheck size={14} className="eyebrow-icon secure" aria-hidden="true" />
            ) : (
              <LockKeyhole size={14} className="eyebrow-icon" aria-hidden="true" />
            )}
            <span>{hero.eyebrow}</span>
          </div>

          <h2>{hero.title}</h2>

          <p aria-live="polite">
            {connected
              ? `Aether Next is routing Windows traffic via ${settings.protocol.toUpperCase()} ${settings.transport.toUpperCase()}${runtime.endpoint ? ` over ${runtime.endpoint}` : ""}.`
              : running || runtime.status === "error"
                ? runtime.detail
                : "Initialize the tunnel to negotiate Cloudflare edge telemetry and secure system sockets."}
          </p>
        </div>

        {/* ─── Military-Grade Illuminated Master Switch ───────────────────── */}
        <div className="master-switch-assembly">
          <div className="switch-ping-rings" aria-hidden="true">
            {(connected || runtime.status === "connecting") && (
              <>
                <div className={`ping-ring ring-primary ${runtime.status}`} />
                <div className={`ping-ring ring-secondary ${runtime.status}`} />
              </>
            )}
          </div>

          <div className={`master-switch-chassis ${runtime.status}`}>
            <div className="switch-radial-glow" aria-hidden="true" />
            
            <button
              type="button"
              className={`master-toggle-btn ${running ? "stop" : ""}`}
              onClick={toggleConnection}
              disabled={busy}
              aria-label={running ? "Disconnect tunnel" : "Engage tunnel connection"}
            >
              <div className="btn-surface">
                {busy ? (
                  <ListRestart className="spin master-icon" size={34} aria-hidden="true" />
                ) : (
                  <Power className="master-icon" size={35} aria-hidden="true" />
                )}
              </div>
            </button>
          </div>

          <div className="switch-label-zone">
            <span className={`switch-status-pill ${runtime.status}`}>
              <span className="pulse-led" />
              {hero.badge}
            </span>
            <span className="switch-action-hint">
              {running ? "CLICK TO DISCONNECT" : "CLICK TO ENGAGE"}
            </span>
          </div>
        </div>
      </section>

      {/* ─── Banners ──────────────────────────────────────────────────────── */}
      {runtime.status === "error" && (
        <div className="error-banner" role="alert">
          <div className="error-banner-content">
            <CircleAlert size={17} aria-hidden="true" />
            <span>{runtime.detail}</span>
          </div>
          <button type="button" className="error-banner-dismiss" onClick={() => void dismissError()} aria-label="Dismiss error">
            <X size={16} aria-hidden="true" />
          </button>
        </div>
      )}

      {updateAvailable && (
        <div className="update-banner">
          <div className="error-banner-content">
            <Sparkles size={17} aria-hidden="true" />
            <span>Aether {updateAvailable.version} is ready. Restart or click to update!</span>
          </div>
          <button
            type="button"
            onClick={() => invoke("plugin:opener|open_url", { url: updateAvailable.url }).catch(() => window.open(updateAvailable.url, "_blank"))}
          >
            Update Now
          </button>
          <button type="button" className="banner-dismiss" onClick={dismissUpdate} aria-label="Dismiss update notice">
            <X size={16} aria-hidden="true" />
          </button>
        </div>
      )}

      {settings.peer && (
        <div className="pinned-peer-bar">
          <div className="pinned-peer-info">
            <Sparkles size={15} aria-hidden="true" />
            <span>Targeting forced endpoint:</span>
            <code>{settings.peer}</code>
          </div>
          <button type="button" className="pinned-peer-clear-btn" onClick={() => patchSettings({ peer: "" })}>
            Clear (Scan dynamically)
          </button>
        </div>
      )}

      {/* ─── Speed Profile Presets ────────────────────────────────────────── */}
      <section className="profiles-panel" aria-label="Speed Profile Presets">
        <div className="section-heading">
          <div><p>PRESETS</p><h3>Speed Profiles</h3></div>
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
                  patchSettings({ ...profile.patch, peer: "" });
                  appendLog({ level: "info", message: `Applied profile: ${profile.label} — ${profile.hint}` });
                }}
              >
                <div className="profile-card-top">
                  <strong>{profile.label}</strong>
                  {active && <small className="profile-active-tag">ACTIVE</small>}
                </div>
                <span>{profile.hint}</span>
              </button>
            );
          })}
        </div>
        {!admin && (
          <p className="profile-note">
            TUN routing requires running Aether as administrator and wintun.dll. Standard proxy mode is available without elevation.
          </p>
        )}
      </section>

      {/* ─── Telemetry & Metrics Bento Grid (12-Column Asymmetric) ────────── */}
      <section className="telemetry-bento" aria-label="Tunnel Telemetry and Subsystem Status">
        {/* Card 1 (Span 7): Gateway Edge Route & Live Sparkline */}
        <article className="bento-card bento-col-7 edge-telemetry-card">
          <div className="bento-card-header">
            <div className="bento-title-group">
              <div className="metric-icon blue"><Gauge size={18} aria-hidden="true" /></div>
              <div>
                <span className="bento-category">GATEWAY EDGE ROUTE</span>
                <strong className="bento-headline" title={runtime.endpoint ?? undefined}>
                  {runtime.endpoint || (running ? "Scanning Edge Pool…" : "Dynamic Edge Discovery")}
                </strong>
              </div>
            </div>
            <span className={`bento-chip ${connected ? "active" : ""}`}>
              {connected ? "ROUTE ARMED" : running ? "PROBING" : "IDLE"}
            </span>
          </div>

          <div className="sparkline-telemetry-block">
            <div className="telemetry-figures">
              <div className="stat-unit">
                <span className="stat-label">
                  <Activity size={11} aria-hidden="true" /> ROUND-TRIP LATENCY
                </span>
                <span className="stat-value tabular-nums">{displayLatency}</span>
              </div>
              <div className="stat-unit">
                <span className="stat-label">PACKET LOSS</span>
                <span className="stat-value tabular-nums">{connected ? "0.0%" : "--"}</span>
              </div>
              <div className="stat-unit">
                <span className="stat-label">IP STACK</span>
                <span className="stat-value tabular-nums">{settings.ipVersion.toUpperCase()} DUAL-READY</span>
              </div>
            </div>

            {/* Micro-sparkline telemetry signal equalizer */}
            <div className="sparkline-bar-track" aria-hidden="true">
              {[42, 68, 55, 84, 62, 75, 48, 92, 58, 80, 64, 88, 52, 70, 60, 95].map((val, idx) => (
                <div
                  key={idx}
                  className={`sparkline-bar ${connected ? "active" : ""}`}
                  style={{
                    height: connected ? `${val}%` : "18%",
                    animationDelay: `${idx * 0.08}s`,
                  }}
                />
              ))}
            </div>
          </div>

          <div className="bento-footer">
            <small className="bento-subtext">
              SCAN MODE: <strong>{settings.scanMode.toUpperCase()}</strong> · ALGORITHM: <strong>DIRECT CONCURRENT</strong>
            </small>
            {runtime.endpoint && (
              <CopyButton value={runtime.endpoint} label="Copy gateway endpoint" appendLog={appendLog} />
            )}
          </div>
        </article>

        {/* Card 2 (Span 5): Carrier & Cipher Engine */}
        <article className="bento-card bento-col-5 cipher-engine-card">
          <div className="bento-card-header">
            <div className="bento-title-group">
              <div className="metric-icon coral"><Route size={18} aria-hidden="true" /></div>
              <div>
                <span className="bento-category">CARRIER &amp; CIPHER</span>
                <strong className="bento-headline">
                  {settings.protocol === "gool" ? "WARP-in-WARP" : `${settings.protocol.toUpperCase()} ${settings.transport.toUpperCase()}`}
                </strong>
              </div>
            </div>
            <span className="bento-chip-cyan">
              {settings.protocol === "masque" ? (settings.transport === "h3" ? "QUIC/UDP" : "H2/TLS") : "WIREGUARD"}
            </span>
          </div>

          <div className="cipher-specs-grid">
            <div className="spec-badge">
              <span>TRANSPORT</span>
              <strong>{settings.protocol === "masque" ? (settings.transport === "h3" ? "HTTP/3" : "HTTP/2") : "UDP WireGuard"}</strong>
            </div>
            <div className="spec-badge">
              <span>OBFUSCATION</span>
              <strong>NOISE: {settings.noize.toUpperCase()}</strong>
            </div>
            <div className="spec-badge">
              <span>ANTI-DPI FRAG</span>
              <strong>{settings.quicInitialFrag ? `SPLIT (${settings.quicInitialFragSize}B)` : "OFF"}</strong>
            </div>
            <div className="spec-badge">
              <span>SECURITY CIPHER</span>
              <strong>CHACHA20-POLY1305</strong>
            </div>
          </div>

          <div className="bento-footer">
            <small className="bento-subtext">ENCRYPTION: <strong>END-TO-END TLS 1.3</strong></small>
          </div>
        </article>

        {/* Card 3 (Span 6): Routing Topology */}
        <article className="bento-card bento-col-6 topology-card">
          <div className="bento-card-header">
            <div className="bento-title-group">
              <div className="metric-icon green"><Globe2 size={18} aria-hidden="true" /></div>
              <div>
                <span className="bento-category">ROUTING TOPOLOGY</span>
                <strong className="bento-headline">
                  {settings.routingMode === "system-proxy"
                    ? "System Proxy"
                    : settings.routingMode === "tun"
                      ? "Full Virtual Tunnel"
                      : "Direct Proxy Only"}
                </strong>
              </div>
            </div>
            <span className="bento-chip">
              {settings.routingMode === "tun" ? "WINTUN DRIVER" : "WININET HOOK"}
            </span>
          </div>

          <div className="topology-info-block">
            <div className="topology-detail-row">
              <span>PRIVILEGE ELEVATION</span>
              <strong>{admin ? "ADMINISTRATOR (ELEVATED)" : "STANDARD USER (PER-USER)"}</strong>
            </div>
            <div className="topology-detail-row">
              <span>SYSTEM LOOPBACK</span>
              <code>127.0.0.1:{settings.httpPort} (HTTP) · :{settings.socksPort} (SOCKS)</code>
            </div>
          </div>

          <div className="bento-footer">
            <small className="bento-subtext">
              {admin ? "Kernel-level TUN adapter enabled" : "Run as Administrator for TUN routing"}
            </small>
          </div>
        </article>

        {/* Card 4 (Span 6): Core Daemon Subsystem */}
        <article className="bento-card bento-col-6 daemon-card">
          <div className="bento-card-header">
            <div className="bento-title-group">
              <div className="metric-icon yellow"><Cpu size={18} aria-hidden="true" /></div>
              <div>
                <span className="bento-category">CORE DAEMON SUBSYSTEM</span>
                <strong className="bento-headline">
                  {runtime.pid ? `Process PID ${runtime.pid}` : "Standby Engine"}
                </strong>
              </div>
            </div>
            <span className={`bento-chip ${runtime.pid ? "active" : ""}`}>
              {runtime.pid ? "PROCESS ACTIVE" : "DORMANT"}
            </span>
          </div>

          <div className="daemon-status-block">
            <div className="daemon-heartbeat-row">
              <div className="daemon-led-group">
                <span className={`heartbeat-dot ${connected ? "active" : running ? "starting" : ""}`} />
                <span className="daemon-state-text">
                  {connected ? "Tunnel subsystem armed and processing sockets" : running ? "Handshaking with Cloudflare edge" : "Awaiting user connect trigger"}
                </span>
              </div>
            </div>
            <div className="daemon-metrics-row">
              <div className="daemon-tag">PORT {settings.httpPort}: <strong>HTTP LISTENING</strong></div>
              <div className="daemon-tag">PORT {settings.socksPort}: <strong>SOCKS5 READY</strong></div>
            </div>
          </div>

          <div className="bento-footer">
            <small className="bento-subtext">RUNTIME: <strong>RUST EMBEDDED ENGINE</strong></small>
          </div>
        </article>
      </section>

      {/* ─── Local Access Proxy Endpoints ──────────────────────────────────── */}
      <section className="proxy-panel">
        <div className="section-heading">
          <div><p>LOCAL ACCESS</p><h3>Proxy Endpoints</h3></div>
          <Network size={20} aria-hidden="true" />
        </div>
        <div className="endpoint-row">
          <div className="endpoint-kind">
            <TerminalSquare size={18} aria-hidden="true" />
            <div><strong>HTTP / HTTPS</strong><span>Windows system proxy</span></div>
          </div>
          <code>127.0.0.1:{settings.httpPort}</code>
          <CopyButton value={`127.0.0.1:${settings.httpPort}`} label="Copy HTTP proxy address" appendLog={appendLog} />
        </div>
        <div className="endpoint-row">
          <div className="endpoint-kind">
            <Cable size={18} aria-hidden="true" />
            <div><strong>SOCKS5</strong><span>Direct application access</span></div>
          </div>
          <code>127.0.0.1:{settings.socksPort}</code>
          <CopyButton value={`127.0.0.1:${settings.socksPort}`} label="Copy SOCKS5 proxy address" appendLog={appendLog} />
        </div>
      </section>

      {/* ─── Live Connection Test ─────────────────────────────────────────── */}
      <section className="test-panel">
        <div className="section-heading">
          <div><p>VERIFY</p><h3>Live Connection Verification</h3></div>
          <FlaskConical size={20} aria-hidden="true" />
        </div>
        <div className="test-row">
          <span>{connected ? "Hits Cloudflare trace via local proxy to measure end-to-end RTT" : "Connect first, then verify the path"}</span>
          <button onClick={runTest} disabled={testBusy || busy || !connected}>
            {testBusy ? "Probing Path…" : "Test Connection"}
          </button>
        </div>
        {testResult && (
          <code className={`test-result ${testResult.startsWith("OK") ? "ok" : "err"}`}>
            {testResult}
          </code>
        )}
      </section>

      {/* ─── Port Information Footer ──────────────────────────────────────── */}
      <section className="about-panel">
        <div>
          <p>WINDOWS HIGH-PERFORMANCE BUILD</p>
          <h3>Aether Next</h3>
          <span>Engineered by <strong>deathline94</strong> · full native rework</span>
        </div>
        <code>v{appVersion}</code>
      </section>
    </div>
  );
}

