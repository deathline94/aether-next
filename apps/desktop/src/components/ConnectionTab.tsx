import { invoke } from "@tauri-apps/api/core";
import {
  Activity, Cable, CircleAlert, Cpu,
  FlaskConical, Gauge, Globe2, ListRestart, LockKeyhole, Network,
  Power, Route, ShieldCheck, Sparkles, TerminalSquare, X,
} from "lucide-react";
import { CopyButton } from "./ui";
import type { RuntimeState, Settings } from "../types";
import { SPEED_PROFILES, ipFamilyLabel, speedProfileHint } from "@aether/ui/enums";
import {
  cipherSettingCopy,
  connectionTestCopy,
  connectedCopy,
  carrierChip,
  endpointClaim,
  engineStateCopy,
  fragSettingCopy,
  heroCopy,
  noiseSettingCopy,
  PINNED_PEER_CLEAR_LABEL,
  PINNED_PEER_LABEL,
  portStateCopy,
  powerControlLabel,
  powerHint,
  processStateCopy,
  protocolHeadline,
  roundTripLabel,
  startHint,
  trafficChip,
  transportName,
} from "@aether/ui/statusCopy";
import type { PlatformCapabilities } from "@aether/ui/statusCopy";

/**
 * What this platform may do, which is what the shared copy needs to say the truth.
 *
 * Windows can be pointed at a system proxy — `src-tauri/src/proxy.rs` writes it, so
 * the saved `system-proxy` mode is honoured here and the copy may say so, which it
 * may not on Android. The route is the wintun adapter, and the surface is clicked.
 */
export const PLATFORM: PlatformCapabilities = {
  canSetSystemProxy: true,
  routeName: "the tunnel device",
  routeSubject: "The tunnel device",
  actionVerb: "Click",
};

/** What the hero says before anything has run, in the verb this surface uses. */
export const START_HINT = startHint(PLATFORM);

const speedProfiles: { id: string; label: string; hint: string; patch: Partial<Settings> }[] = SPEED_PROFILES.map((profile) => ({
  id: profile.id,
  label: profile.label,
  hint: speedProfileHint(profile, "system proxy"),
  patch: {
    protocol: profile.protocol,
    transport: profile.transport,
    noize: "off",
    scanMode: "balanced",
    ipVersion: "v4",
    routingMode: "system-proxy",
  },
}));

function profileActive(settings: Settings, patch: Partial<Settings>) {
  return (Object.keys(patch) as (keyof Settings)[]).every((k) => settings[k] === patch[k]);
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

export function ConnectionTab({
  settings, runtime, busy, testBusy, connected, running, settingsLocked, settingsLoaded,
  admin, testResult, appVersion, updateAvailable, dismissUpdate,
  toggleConnection, patchSettings, runTest, dismissError, appendLog,
}: ConnectionTabProps) {
  const hero = heroCopy(runtime.status);
  const active = connectedCopy(settings.routingMode, PLATFORM);
  const badge = runtime.status === "connected" ? active.badge : hero.badge;
  const listeners = portStateCopy(connected, settings.routingMode, PLATFORM);
  const test = connectionTestCopy(connected, testBusy);

  // The only latency this app has is the shell's measurement of the probe that
  // proved the endpoint; `testResult` is a sentence, not a reading.
  const displayLatency = roundTripLabel(runtime.handshakeRttMs);
  const engine = processStateCopy(runtime.pid);

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
                : START_HINT}
          </p>
        </div>

        {/* ─── Military-Grade Illuminated Master Switch ───────────────────── */}
        <div className="master-switch-assembly">
          <div className={`switch-ping-rings ${connected || runtime.status === "connecting" ? "active" : ""}`} aria-hidden="true">
            <div className={`ping-ring ring-primary ${runtime.status}`} />
            <div className={`ping-ring ring-secondary ${runtime.status}`} />
          </div>

          <div className={`master-switch-chassis ${runtime.status}`}>
            <div className="switch-radial-glow" aria-hidden="true" />
            
            <button
              type="button"
              className={`master-toggle-btn ${running ? "stop" : ""}`}
              onClick={toggleConnection}
              // Disconnecting a live tunnel stays possible even when settings
              // have not loaded (or failed to); only the connect arm waits.
              disabled={busy || (!running && !settingsLoaded)}
              aria-label={powerControlLabel(running)}
            >
              <div className="btn-surface">
                <div className="master-icon-slot">
                  {busy ? (
                    <ListRestart className="spin master-icon" size={36} aria-hidden="true" />
                  ) : (
                    <Power className="master-icon" size={36} aria-hidden="true" />
                  )}
                </div>
              </div>
            </button>
          </div>

          <div className="switch-label-zone">
            <span className={`switch-status-pill ${runtime.status}`}>
              <span className="pulse-led" />
              {badge}
            </span>
            <span className="switch-action-hint">
              {powerHint(running, PLATFORM)}
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
            <span>{PINNED_PEER_LABEL}</span>
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
            {PINNED_PEER_CLEAR_LABEL}
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
                  appendLog({ level: "info", message: `Applied preset: ${profile.label} — ${profile.hint}` });
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
                  {endpointClaim(runtime.endpoint, running).answer}
                </strong>
              </div>
            </div>
            <span className={`bento-chip ${connected ? "active" : ""}`}>
              {trafficChip(connected, running, settings.routingMode)}
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
                <span className="stat-label">IP STACK</span>
                <span className="stat-value tabular-nums">{ipFamilyLabel(settings.ipVersion)}</span>
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
              <CopyButton value={runtime.endpoint} label="Copy gateway endpoint" onCopyFailed={() => appendLog({ level: "warn", message: "Clipboard copy failed" })} />
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
                <strong className="bento-headline">{protocolHeadline(settings)}</strong>
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
              {/* On MASQUE/H2 there is no QUIC Initial to hide and no handshake for
                  junk frames to precede, so the stored profile does nothing: naming
                  it as if it were active was a claim about an inert setting. One
                  rule and one wording, both surfaces. */}
              <strong>{noiseSettingCopy(settings)}</strong>
            </div>
            <div className="spec-badge">
              <span>ANTI-DPI FRAG</span>
              <strong>{fragSettingCopy(settings)}</strong>
            </div>
            <div className="spec-badge">
              <span>SECURITY CIPHER</span>
              {/* WireGuard's suite is fixed by the protocol; MASQUE negotiates a
                  TLS 1.3 suite with the peer and nothing here observes which one,
                  so naming ChaCha20-Poly1305 was a claim about an unmeasured
                  property. Identical text lived in the Android sheet's twin. */}
              <strong>{cipherSettingCopy(settings.protocol)}</strong>
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
                <strong className="bento-headline">{engine.headline}</strong>
              </div>
            </div>
            <span className={`bento-chip ${runtime.pid ? "active" : ""}`}>
              {engine.chip}
            </span>
          </div>

          <div className="daemon-status-block">
            <div className="daemon-heartbeat-row">
              <div className="daemon-led-group">
                <span className={`heartbeat-dot ${connected ? "active" : running ? "starting" : ""}`} />
                <span className="daemon-state-text">{engineStateCopy(connected, running)}</span>
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
          <CopyButton value={`127.0.0.1:${settings.httpPort}`} label="Copy HTTP proxy address" onCopyFailed={() => appendLog({ level: "warn", message: "Clipboard copy failed" })} />
        </div>
        <div className="endpoint-row">
          <div className="endpoint-kind">
            <Cable size={18} aria-hidden="true" />
            <div><strong>SOCKS5</strong><span>Direct application access</span></div>
          </div>
          <code>127.0.0.1:{settings.socksPort}</code>
          <CopyButton value={`127.0.0.1:${settings.socksPort}`} label="Copy SOCKS5 proxy address" onCopyFailed={() => appendLog({ level: "warn", message: "Clipboard copy failed" })} />
        </div>
      </section>

      {/* ─── Live Connection Test ─────────────────────────────────────────── */}
      <section className="test-panel">
        <div className="section-heading">
          <div><p>VERIFY</p><h3>Live Connection Verification</h3></div>
          <FlaskConical size={20} aria-hidden="true" />
        </div>
        <div className="test-row">
          <span>{test.prompt}</span>
          <button onClick={runTest} disabled={testBusy || busy || !connected}>
            {test.button}
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

