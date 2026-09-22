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

/**
 * The measured round-trip, or the honest absence.
 *
 * This tile used to be `testResult.match(/(\d+)\s*ms/i)` — prose scraped for a
 * number. `test_connection` answers with sentences that contain no `ms` at all, so
 * the tile was permanently "not measured" while the shell sent a real
 * `handshakeRttMs` on every `session://state` that nothing read; and on a *failed*
 * test the same regex could catch a timeout figure and print it as latency. Read
 * the typed field, or say nothing.
 */
export function formatRttMs(rttMs: number | null): string {
  return typeof rttMs === "number" && Number.isFinite(rttMs) ? `${Math.round(rttMs)} ms` : "not measured";
}

/** Every carrier the shell can report, keyed so a new arm fails to compile. */
type CarrierCopy = {
  chip: (t: Settings["transport"]) => string;
  transport: (t: Settings["transport"]) => string;
};

const CARRIER_CHIP: Record<Settings["protocol"], CarrierCopy> = {
  masque: {
    chip: (t) => (t === "h3" ? "QUIC/UDP" : "H2/TLS"),
    transport: (t) => (t === "h3" ? "HTTP/3" : "HTTP/2"),
  },
  wireguard: { chip: () => "WIREGUARD/UDP", transport: () => "UDP WireGuard" },
  gool: { chip: () => "WARP-IN-WARP", transport: () => "WireGuard (in WARP)" },
};

export function carrierChip(settings: Settings): string {
  // Two arms only, so a Gool session advertised WIREGUARD.
  return CARRIER_CHIP[settings.protocol].chip(settings.transport);
}

export function transportChip(settings: Settings): string {
  return CARRIER_CHIP[settings.protocol].transport(settings.transport);
}

/** Exhaustive by construction: adding an `IpVersion` arm breaks the build here. */
const IP_STACK_COPY: Record<Settings["ipVersion"], string> = {
  v4: "IPv4",
  v6: "IPv6",
  both: "IPv4 + IPv6",
};

export function ipStackCopy(ipVersion: Settings["ipVersion"]): string {
  return IP_STACK_COPY[ipVersion];
}

/**
 * What the two listener tiles may claim.
 *
 * Both were keyed on `status === "connected"` and shouted "HTTP proxy configured"
 * in every routing mode, which contradicts `connectedCopy` a few pixels away: in
 * `proxy-only` nothing is configured system-wide until an application points at
 * the listeners, and in `tun` the route is the tunnel device, not the proxy.
 */
export function portStateCopy(
  connected: boolean,
  routingMode: Settings["routingMode"],
): { http: string; socks: string } {
  if (!connected) return { http: "idle", socks: "idle" };
  switch (routingMode) {
    case "system-proxy":
      return { http: "HTTP proxy configured", socks: "SOCKS5 configured" };
    case "proxy-only":
      return { http: "HTTP listener open", socks: "SOCKS5 listener open" };
    case "tun":
      return { http: "HTTP listener available (TUN routes)", socks: "SOCKS5 listener available (TUN routes)" };
  }
}

const heroCopy: Record<RuntimeState["status"], { eyebrow: string; title: string; badge: string }> = {
  disconnected: { eyebrow: "LOCAL LISTENERS CLOSED", title: "Not Connected", badge: "STANDBY // CLICK TO ENGAGE" },
  connecting: { eyebrow: "NEGOTIATING // EDGE HANDSHAKE", title: "Establishing Edge Path", badge: "CONNECTING" },
  connected: { eyebrow: "SESSION ACTIVE", title: "Connected", badge: "ACTIVE" },
  error: { eyebrow: "CONNECTION FAILED", title: "Route Unavailable", badge: "ERROR" },
};

/**
 * What "connected" covers depends on the routing mode, and the copy used to claim
 * the widest version of it in all three: "routing Windows traffic" is false in
 * `proxy-only`, where an application has to point at the local listener itself,
 * and the early-data claim the badge made is not something the engine reports at
 * all, so it was never a measurement — it was decoration on a security claim.
 */
function connectedCopy(routingMode: Settings["routingMode"]): { badge: string; body: string } {
  switch (routingMode) {
    case "tun":
      return {
        badge: "ACTIVE // TUN ROUTE",
        body: "Aether Next is routing Windows traffic through the tunnel device.",
      };
    case "system-proxy":
      return {
        badge: "ACTIVE // SYSTEM PROXY",
        body: "Windows is set to the local proxies, so applications that follow the system proxy are covered.",
      };
    default:
      return {
        badge: "ACTIVE // LOCAL PROXIES",
        body: "The local listeners are open. Nothing is routed until an application points at them.",
      };
  }
}

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
  const active = connectedCopy(settings.routingMode);
  const badge = runtime.status === "connected" ? active.badge : hero.badge;

  // The only latency this app has is the shell's measurement of the probe that
  // proved the endpoint; `testResult` is a sentence, not a reading.
  const displayLatency = formatRttMs(runtime.handshakeRttMs);
  const displayLoss = "not measured";
  const listeners = portStateCopy(connected, settings.routingMode);

  return (
    <div className="home-view">
      {/* ─── Hero Centerpiece Stage ────────────────────────────────────────── */}
      <section className={`connection-stage ${runtime.status}`}>
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
              ? `${active.body}${runtime.endpoint ? ` Edge: ${runtime.endpoint}.` : ""}`
              : running || runtime.status === "error"
                ? runtime.detail
                : "Connect to raise the local listeners and negotiate the edge."}
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
              {badge}
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
            <span>A new version is available: {updateAvailable.version}</span>
          </div>
          <button
            type="button"
            onClick={() => invoke("plugin:opener|open_url", { url: updateAvailable.url }).catch(() => window.open(updateAvailable.url, "_blank"))}
          >
            View release
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
          <button
            type="button"
            className="pinned-peer-clear-btn"
            onClick={() => patchSettings({ peer: "" })}
            // `patchSettings` is a no-op while a session runs or before hydration,
            // so the control has to look like it is: a visible button that does
            // nothing is worse than a disabled one that says why.
            disabled={settingsLocked}
            title={settingsLocked ? "Disconnect the tunnel to change the target endpoint" : "Stop targeting this endpoint"}
          >
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
        <article className="bento-card bento-col-7">
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
                <span className="stat-value tabular-nums">{displayLoss}</span>
              </div>
              <div className="stat-unit">
                <span className="stat-label">IP STACK</span>
                <span className="stat-value tabular-nums">{ipStackCopy(settings.ipVersion)}</span>
              </div>
            </div>

            {/* No bar chart here: the engine reports no per-packet series, so the
                previous equalizer drew a fixed array of made-up samples and only
                animated because a session was up. A graph of nothing is how
                invented telemetry gets believed. `test_connection`'s round-trip and
                the endpoint below are the measurements this panel has. */}
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
        <article className="bento-card bento-col-5">
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
            <span className="bento-chip-cyan">{carrierChip(settings)}</span>
          </div>

          <div className="cipher-specs-grid">
            <div className="spec-badge">
              <span>TRANSPORT</span>
              <strong>{transportChip(settings)}</strong>
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
              {/* WireGuard's suite is fixed by the protocol; MASQUE negotiates a
                  TLS 1.3 suite with the peer and nothing here observes which one,
                  so naming ChaCha20-Poly1305 was a claim about an unmeasured
                  property. Identical text lived in the Android sheet's twin. */}
              <strong>{settings.protocol === "masque" ? "NEGOTIATED (not observed)" : "CHACHA20-POLY1305"}</strong>
            </div>
          </div>

          <div className="bento-footer">
            <small className="bento-subtext">EDGE TLS: <strong>TLS 1.3 to the MASQUE edge</strong> · beyond the edge this app cannot observe your TLS</small>
          </div>
        </article>

        {/* Card 3 (Span 6): Routing Topology */}
        <article className="bento-card bento-col-6">
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
        <article className="bento-card bento-col-6">
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
              <div className="daemon-tag">PORT {settings.httpPort}: <strong>{listeners.http}</strong></div>
              <div className="daemon-tag">PORT {settings.socksPort}: <strong>{listeners.socks}</strong></div>
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

