import {
  Activity, Cable, Check, CircleAlert, Copy, Cpu,
  FlaskConical, Gauge, Globe2, ListRestart, LockKeyhole, Network,
  Power, Route, ShieldCheck, Sparkles, TerminalSquare, WifiOff, X,
} from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { platformLabel } from "../bridge";
import { profileActive, speedProfiles } from "../types";
import type { RuntimeState, Settings } from "../types";
import type { TestOutcome } from "../hooks/useRuntime";
import { noiseIsInert } from "../../../../packages/ui/src";

/**
 * Carrier and transport wording, exhaustive by construction.
 *
 * Both tiles used two ternary arms, so anything that was not `masque` fell to
 * "WIREGUARD" — a Gool session whose own headline says WARP-in-WARP advertised a
 * carrier it is not, on the same card. A Record keyed on the protocol union makes
 * a new protocol a compile error instead of a wrong label.
 */
const CARRIER_CHIP: Record<
  Settings["protocol"],
  { chip: (t: Settings["transport"]) => string; transport: (t: Settings["transport"]) => string }
> = {
  masque: {
    chip: (t) => (t === "h3" ? "QUIC/UDP" : "H2/TLS"),
    transport: (t) => (t === "h3" ? "HTTP/3" : "HTTP/2"),
  },
  gool: {
    chip: () => "QUIC/UDP x2",
    transport: () => "WireGuard in WireGuard",
  },
  wireguard: {
    chip: () => "WIREGUARD",
    transport: () => "UDP WireGuard",
  },
};

export function carrierChip(settings: Settings): string {
  return CARRIER_CHIP[settings.protocol].chip(settings.transport);
}

export function transportName(settings: Settings): string {
  return CARRIER_CHIP[settings.protocol].transport(settings.transport);
}

/**
 * Nothing here may claim a property the app has not observed: the engine reports
 * no early-data result, so the previous badge asserted a resumed handshake that
 * nobody measured, and "Route Open"/"Traffic Secure" were shown while disconnected
 * and while failed. The VPN does route once it is up, which is what `connected`
 * says now.
 */
const heroCopy: Record<RuntimeState["status"], { eyebrow: string; title: string; badge: string }> = {
  disconnected: { eyebrow: "VPN NOT ACTIVE", title: "Not Connected", badge: "STANDBY // TAP TO ENGAGE" },
  connecting: { eyebrow: "NEGOTIATING // EDGE HANDSHAKE", title: "Establishing Edge Path", badge: "CONNECTING" },
  connected: { eyebrow: "VPN ACTIVE", title: "Traffic Routed", badge: "CONNECTED" },
  error: { eyebrow: "CONNECTION FAILED", title: "Not Connected", badge: "ERROR" },
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
  testResult: TestOutcome | null;
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
  admin, online, testResult, appVersion,
  toggleConnection, patchSettings, runTest, dismissError, appendLog,
}: ConnectionTabProps) {
  const hero = heroCopy[runtime.status];
  const routingLabel = settings.routingMode === "tun" ? "Full Device VPN" : "Local Proxy Only";
  const routingSub = settings.routingMode === "tun" ? "VpnService + TUN" : "Local Loopback SOCKS5/HTTP";

  // Only a measured round-trip may be shown as a number: the value is now a field
  // the native layer sets when it timed something, never a digit scraped out of a
  // sentence.
  const measured = testResult?.latencyMs;
  const displayLatency =
    typeof measured === "number" && Number.isFinite(measured) && measured > 0
      ? `${Math.round(measured)} ms`
      : "not measured";
  const displayLoss = "not measured";

  return (
    <div className="home-view">
      {!online && (
        <div className="offline-banner" role="status">
          <WifiOff size={16} aria-hidden="true" />
          <span>You appear to be offline. Aether needs a working network connection to reach Cloudflare edges.</span>
        </div>
      )}

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
              ? `Aether Next is routing ${platformLabel()} traffic via ${settings.protocol.toUpperCase()} ${settings.transport.toUpperCase()}${runtime.endpoint ? ` over ${runtime.endpoint}` : ""}.`
              : running || runtime.status === "error"
                ? runtime.detail
                : "Initialize the tunnel to negotiate Cloudflare edge telemetry and secure device sockets."}
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
              {running ? "TAP TO DISCONNECT" : "TAP TO ENGAGE"}
            </span>
          </div>
        </div>
      </section>

      {/* ─── Error Banner ─────────────────────────────────────────────────── */}
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
            Full VPN routing uses Android VpnService (prompted on first connection). Proxy only exposes local SOCKS/HTTP ports for apps configured with proxy settings.
          </p>
        )}
      </section>

      {/* ─── Telemetry & Metrics Bento Grid (12-Column Asymmetric) ────────── */}
      <section className="telemetry-bento" aria-label="Tunnel Telemetry and Subsystem Status">
        {/* Card 1: Gateway Edge Route & Live Sparkline */}
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
                <span className="stat-value tabular-nums">{settings.ipVersion.toUpperCase()}</span>
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

        {/* Card 2: Carrier & Cipher Engine */}
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
              <strong>{transportName(settings)}</strong>
            </div>
            <div className="spec-badge">
              <span>OBFUSCATION</span>
              {/* MASQUE over HTTP/2 is a TCP CONNECT tunnel: no QUIC Initial to
                  fragment and no handshake for junk frames to precede, so the
                  stored profile is inert. Showing it as active claimed an effect
                  the transport cannot have. Same predicate as the desktop tile. */}
              <strong>
                {noiseIsInert(settings.protocol, settings.transport)
                  ? "INACTIVE (H2 tunnel)"
                  : `NOISE: ${settings.noize.toUpperCase()}`}
              </strong>
            </div>
            <div className="spec-badge">
              <span>ANTI-DPI FRAG</span>
              <strong>{settings.quicInitialFrag ? `SPLIT (${settings.quicInitialFragSize}B)` : "OFF"}</strong>
            </div>
            <div className="spec-badge">
              <span>SECURITY CIPHER</span>
              {/* WireGuard's cipher suite is fixed by the protocol, so naming it is
                  a statement about the transport. MASQUE runs TLS 1.3 over QUIC or
                  H2: the suite is negotiated by the peer (frequently an AES-GCM one)
                  and nothing here observes which, so asserting ChaCha20 was a
                  property the app never measured — the same class of invention as
                  scraping a latency out of a sentence that has no number in it. */}
              <strong>{settings.protocol === "masque" ? "NEGOTIATED (not observed)" : "CHACHA20-POLY1305"}</strong>
            </div>
          </div>

          <div className="bento-footer">
            <small className="bento-subtext">EDGE TLS: <strong>TLS 1.3 to the MASQUE edge</strong> · beyond the edge this app cannot observe your TLS</small>
          </div>
        </article>

        {/* Card 3: Routing Topology */}
        <article className="bento-card bento-col-6">
          <div className="bento-card-header">
            <div className="bento-title-group">
              <div className="metric-icon green"><Globe2 size={18} aria-hidden="true" /></div>
              <div>
                <span className="bento-category">ROUTING TOPOLOGY</span>
                <strong className="bento-headline">{routingLabel}</strong>
              </div>
            </div>
            <span className="bento-chip">
              {settings.routingMode === "tun" ? "VPNSERVICE" : "LOCAL PROXY"}
            </span>
          </div>

          <div className="topology-info-block">
            <div className="topology-detail-row">
              <span>ANDROID ROUTING</span>
              <strong>{routingSub}</strong>
            </div>
            <div className="topology-detail-row">
              <span>LOOPBACK LISTENERS</span>
              <code>127.0.0.1:{settings.httpPort} (HTTP) · :{settings.socksPort} (SOCKS)</code>
            </div>
          </div>

          <div className="bento-footer">
            <small className="bento-subtext">
              {admin ? "Full device routing granted by Android VpnService" : "VpnService permission requested on connect"}
            </small>
          </div>
        </article>

        {/* Card 4: Core Daemon Subsystem */}
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
              <div className="daemon-tag">PORT {settings.httpPort}: <strong>{runtime.status === "connected" ? "HTTP proxy configured" : "idle"}</strong></div>
              <div className="daemon-tag">PORT {settings.socksPort}: <strong>{runtime.status === "connected" ? "SOCKS5 configured" : "idle"}</strong></div>
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
            <div><strong>HTTP / HTTPS</strong><span>Local HTTP CONNECT proxy</span></div>
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
          <code className={`test-result ${testResult.detail.startsWith("OK") ? "ok" : "err"}`}>
            {testResult.detail}
          </code>
        )}
      </section>

      {/* ─── Port Information Footer ──────────────────────────────────────── */}
      <section className="about-panel">
        <div>
          <p>ANDROID HIGH-PERFORMANCE BUILD</p>
          <h3>Aether Next</h3>
          <span>Engineered by <strong>deathline94</strong> · native Android rework</span>
        </div>
        <code>v{appVersion}</code>
      </section>
    </div>
  );
}
