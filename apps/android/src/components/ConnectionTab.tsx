import {
  Activity, Cable, Check, CircleAlert, Copy, Cpu,
  FlaskConical, Gauge, Globe2, ListRestart, LockKeyhole, Network,
  Power, Route, ShieldCheck, Sparkles, TerminalSquare, WifiOff, X,
} from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { profileActive, speedProfiles } from "../types";
import type { RuntimeState, Settings } from "../types";
import type { TestOutcome } from "../hooks/useRuntime";
import { ipFamilyLabel } from "@aether/ui/enums";
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
// The status panel is this app's own surface; its answers are not.
import { coverageClaim, stateAnswer, stateDetail } from "@aether/ui/statusCopy";

/**
 * What this platform may do, which is what the shared copy needs to say the truth.
 *
 * `VpnService` installs the route; the system proxy is not reachable at all —
 * Android exposes no API by which an app may set it, which is what `SettingsTab`
 * says of a stored `system-proxy` profile, so the hero and the listener tiles have
 * to say the same. And the surface is touched, not clicked.
 */
export const PLATFORM: PlatformCapabilities = {
  canSetSystemProxy: false,
  routeName: "the Android VPN",
  routeSubject: "Android's VPN route",
  actionVerb: "Tap",
};

/** What the hero says before anything has run, in the verb this surface uses. */
export const START_HINT = startHint(PLATFORM);


/**
 * The routing card's footer, which used to read "Full device routing granted by
 * Android VpnService" in proxy-only mode: `admin` is whether the VPN permission was
 * ever granted, not whether this session is using it.
 */
export function routingGrantCopy(admin: boolean, routingMode: Settings["routingMode"]): string {
  if (routingMode !== "tun") return "This mode adds no device-wide route — coverage depends on which apps use the ports below";
  return admin ? "Android granted this app the VPN permission" : "Android asks for the VPN permission when you connect";
}

/** One line of the status panel: which fact, its label, the answer, the detail. */
export interface EvidenceRow {
  id: "state" | "coverage" | "endpoint";
  label: string;
  value: string;
  detail: string;
}

/**
 * The status panel's three rows. Each answer comes from `@aether/ui/statusCopy`, so
 * the phone cannot say "Connected" in one panel and "ACTIVE" in the next; what lives
 * here is only the assembly - which fact, its label, and where it sits.
 */
export function stateEvidence(status: RuntimeState["status"], detail: string): EvidenceRow {
  return {
    id: "state",
    label: "Connection",
    value: stateAnswer(status),
    detail: stateDetail(status, detail),
  };
}

/**
 * Routing coverage — the question "is my phone actually protected?" reduced to what
 * this app can observe, which is the same reduction the desktop's copy makes.
 */
export function coverageEvidence(
  routingMode: Settings["routingMode"],
  httpPort: number,
  socksPort: number,
): EvidenceRow {
  const claim = coverageClaim(routingMode, PLATFORM, httpPort, socksPort);
  return { id: "coverage", label: "What it covers", value: claim.answer, detail: claim.detail };
}

/**
 * The server this session is actually carrying traffic to: the one piece of evidence
 * a user can take to the scanner and the Activity tab and check.
 */
export function endpointEvidence(endpoint: string | null, running: boolean): EvidenceRow {
  const claim = endpointClaim(endpoint, running);
  return { id: "endpoint", label: "Server reached", value: claim.answer, detail: claim.detail };
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
  const hero = heroCopy(runtime.status);
  const active = connectedCopy(settings.routingMode, PLATFORM);
  const badge = runtime.status === "connected" ? active.badge : hero.badge;
  const listeners = portStateCopy(connected, settings.routingMode, PLATFORM);
  const test = connectionTestCopy(connected, testBusy);
  const routingLabel = settings.routingMode === "tun" ? "Whole device VPN" : "Local proxy only";
  const routingSub = settings.routingMode === "tun" ? "Android VPN (VpnService)" : "Proxy ports on this device";

  // Only a measured round-trip may be shown as a number: the value is a field the
  // native layer sets when it timed something, never a digit scraped out of a
  // sentence.
  const displayLatency = roundTripLabel(testResult?.latencyMs);
  const engine = processStateCopy(runtime.pid);

  const rows: EvidenceRow[] = [
    stateEvidence(runtime.status, runtime.detail),
    coverageEvidence(settings.routingMode, settings.httpPort, settings.socksPort),
    endpointEvidence(runtime.endpoint, running),
  ];

  return (
    <div className="home-view">
      {!online && (
        <div className="offline-banner" role="status">
          <WifiOff size={16} aria-hidden="true" />
          <span>You appear to be offline. Aether needs a working network connection to reach Cloudflare's servers.</span>
        </div>
      )}

      {/* The primary connection control. Presets follow it on the phone. */}
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
              ? active.body
              : running || runtime.status === "error"
                ? runtime.detail
                : START_HINT}
          </p>
        </div>

        {/* ─── Connect / disconnect control ──────────────────────────────── */}
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
              // Disconnecting must stay possible even while settings have not
              // loaded (or failed to load); only the connect arm waits.
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
            <span>{PINNED_PEER_LABEL}</span>
            <code>{settings.peer}</code>
          </div>
          <button
            type="button"
            className="pinned-peer-clear-btn"
            onClick={() => patchSettings({ peer: "" })}
            // Parity with the desktop twin: patchSettings is a no-op while a
            // session runs or before hydration, and a visible button that does
            // nothing is worse than a disabled one that says why.
            disabled={settingsLocked}
            title={settingsLocked ? "Disconnect the tunnel to change the target endpoint" : "Stop targeting this endpoint"}
          >
            {PINNED_PEER_CLEAR_LABEL}
          </button>
        </div>
      )}

      {/* Presets belong with the connect control they configure. */}
      <section className="profiles-panel" aria-label="Connection presets">
        <div className="section-heading">
          <div><p>Presets</p><h3>Change how it connects</h3></div>
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
            Every preset here keeps the whole-device VPN mode; Android asks for permission the first time you connect.
            Switching to the local proxy in Settings routes nothing by itself — an app is covered only once you point
            it at Aether's ports.
          </p>
        )}
      </section>

      {/* Connection evidence follows the presets, ahead of telemetry. */}
      <section className="test-panel connection-evidence" aria-label="Connection status">
        <div className="section-heading">
          <div><p>right now</p><h3>Connection status</h3></div>
          <FlaskConical size={20} aria-hidden="true" />
        </div>

        {rows.map((row) => (
          <div className="endpoint-row" key={row.id}>
            <div className="endpoint-kind">
              {row.id === "state" ? (
                <ShieldCheck size={18} aria-hidden="true" />
              ) : row.id === "coverage" ? (
                <Globe2 size={18} aria-hidden="true" />
              ) : (
                <Network size={18} aria-hidden="true" />
              )}
              <div><strong>{row.label}</strong><span>{row.detail}</span></div>
            </div>
            <code title={row.value}>{row.value}</code>
            {row.id === "endpoint" && runtime.endpoint ? (
              <CopyButton value={runtime.endpoint} label="Copy server address" appendLog={appendLog} />
            ) : null}
          </div>
        ))}

        <div className="test-row">
          <span>{test.prompt}</span>
          <button onClick={runTest} disabled={testBusy || busy || !connected}>
            {test.button}
          </button>
        </div>
        {testResult && (
          <code className={`test-result ${testResult.detail.startsWith("OK") ? "ok" : "err"}`}>
            {testResult.detail}
          </code>
        )}
      </section>

      {/* ─── The two addresses an app has to be pointed at ─────────────────
          Only usable with the local proxy, and in that mode they are the whole
          story: this is the action the status row above is describing. */}
      <section className="proxy-panel" aria-label="Proxy addresses">
        <div className="section-heading">
          <div><p>For one app</p><h3>Proxy addresses</h3></div>
          <Network size={20} aria-hidden="true" />
        </div>
        <div className="endpoint-row">
          <div className="endpoint-kind">
            <TerminalSquare size={18} aria-hidden="true" />
            <div><strong>HTTP / HTTPS</strong><span>Paste this into an app's proxy settings</span></div>
          </div>
          <code>127.0.0.1:{settings.httpPort}</code>
          <CopyButton value={`127.0.0.1:${settings.httpPort}`} label="Copy HTTP proxy address" appendLog={appendLog} />
        </div>
        <div className="endpoint-row">
          <div className="endpoint-kind">
            <Cable size={18} aria-hidden="true" />
            <div><strong>SOCKS5</strong><span>For apps and tools that take a SOCKS proxy</span></div>
          </div>
          <code>127.0.0.1:{settings.socksPort}</code>
          <CopyButton value={`127.0.0.1:${settings.socksPort}`} label="Copy SOCKS5 proxy address" appendLog={appendLog} />
        </div>
      </section>

      {/* ─── Secondary detail, below the evidence ────────────────────────── */}
      <section className="telemetry-bento" aria-label="Connection details">
        {/* Card 1: the server and the one number measured against it */}
        <article className="bento-card bento-col-7">
          <div className="bento-card-header">
            <div className="bento-title-group">
              <div className="metric-icon blue"><Gauge size={18} aria-hidden="true" /></div>
              <div>
                <span className="bento-category">Server reached</span>
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
                  <Activity size={11} aria-hidden="true" /> ROUND TRIP
                </span>
                <span className="stat-value tabular-nums">{displayLatency}</span>
              </div>
              <div className="stat-unit">
                <span className="stat-label">PROXY PORTS</span>
                <span className="stat-value tabular-nums">{settings.httpPort} / {settings.socksPort}</span>
              </div>
              <div className="stat-unit">
                <span className="stat-label">ADDRESS FAMILY</span>
                <span className="stat-value tabular-nums">{ipFamilyLabel(settings.ipVersion)}</span>
              </div>
            </div>

            {/* No packet-loss row and no bar chart here: the engine reports no
                per-packet series at all, so the previous equalizer drew a fixed
                array of made-up samples and the loss figure was a permanent
                "not measured". `test_connection`'s round trip is the only
                measurement this panel has. */}
          </div>

          <div className="bento-footer">
            <small className="bento-subtext">
              Scanner: <strong>{settings.scanMode}</strong> mode · servers picked by latency
            </small>
            {runtime.endpoint && (
              <CopyButton value={runtime.endpoint} label="Copy server address" appendLog={appendLog} />
            )}
          </div>
        </article>

        {/* Card 2: how the path is built and what hides it */}
        <article className="bento-card bento-col-5">
          <div className="bento-card-header">
            <div className="bento-title-group">
              <div className="metric-icon coral"><Route size={18} aria-hidden="true" /></div>
              <div>
                <span className="bento-category">Protocol &amp; encryption</span>
                <strong className="bento-headline">{protocolHeadline(settings)}</strong>
              </div>
            </div>
            <span className="bento-chip-cyan">{carrierChip(settings)}</span>
          </div>

          <div className="cipher-specs-grid">
            <div className="spec-badge">
              <span>RUNS OVER</span>
              <strong>{transportName(settings)}</strong>
            </div>
            <div className="spec-badge">
              <span>HANDSHAKE OBFUSCATION</span>
              {/* MASQUE over HTTP/2 is a TCP CONNECT tunnel: no QUIC Initial to
                  fragment and no handshake for junk frames to precede, so the
                  stored profile is inert. Showing it as active claimed an effect
                  the transport cannot have. One rule, both surfaces. */}
              <strong>{noiseSettingCopy(settings)}</strong>
            </div>
            <div className="spec-badge">
              <span>SPLITS THE FIRST PACKET</span>
              <strong>{fragSettingCopy(settings)}</strong>
            </div>
            <div className="spec-badge">
              <span>ENCRYPTION</span>
              {/* WireGuard's cipher suite is fixed by the protocol, so naming it is
                  a statement about the transport. MASQUE runs TLS 1.3 over QUIC or
                  H2: the suite is negotiated by the peer (frequently an AES-GCM one)
                  and nothing here observes which, so asserting ChaCha20 was a
                  property the app never measured — the same class of invention as
                  scraping a latency out of a sentence that has no number in it. */}
              <strong>{cipherSettingCopy(settings.protocol)}</strong>
            </div>
          </div>

          <div className="bento-footer">
            <small className="bento-subtext">TLS 1.3 to Cloudflare's edge · <strong>past the edge this app cannot see your traffic</strong></small>
          </div>
        </article>

        {/* Card 3: Routing Topology */}
        <article className="bento-card bento-col-6">
          <div className="bento-card-header">
            <div className="bento-title-group">
              <div className="metric-icon green"><Globe2 size={18} aria-hidden="true" /></div>
              <div>
                <span className="bento-category">Routing mode</span>
                <strong className="bento-headline">{routingLabel}</strong>
              </div>
            </div>
            <span className="bento-chip">
              {settings.routingMode === "tun" ? "ANDROID VPN" : "LOCAL PROXY"}
            </span>
          </div>

          <div className="topology-info-block">
            <div className="topology-detail-row">
              <span>TRAFFIC LEAVES VIA</span>
              <strong>{routingSub}</strong>
            </div>
            <div className="topology-detail-row">
              <span>PROXY ADDRESSES</span>
              <code>127.0.0.1:{settings.httpPort} (HTTP) · :{settings.socksPort} (SOCKS)</code>
            </div>
          </div>

          <div className="bento-footer">
            <small className="bento-subtext">
              {routingGrantCopy(admin, settings.routingMode)}
            </small>
          </div>
        </article>

        {/* Card 4: the background engine and the ports it opened */}
        <article className="bento-card bento-col-6">
          <div className="bento-card-header">
            <div className="bento-title-group">
              <div className="metric-icon yellow"><Cpu size={18} aria-hidden="true" /></div>
              <div>
                <span className="bento-category">Background engine</span>
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
              <div className="daemon-tag">HTTP :{settings.httpPort} <strong>{listeners.http}</strong></div>
              <div className="daemon-tag">SOCKS :{settings.socksPort} <strong>{listeners.socks}</strong></div>
            </div>
          </div>

          <div className="bento-footer">
            <small className="bento-subtext">Engine: <strong>bundled Rust binary</strong></small>
          </div>
        </article>
      </section>

      {/* ─── About ────────────────────────────────────────────────────────── */}
      <section className="about-panel">
        <div>
          <p>ANDROID BUILD</p>
          <h3>Aether Next</h3>
          <span>By <strong>deathline94</strong> · native Android rework</span>
        </div>
        <code>v{appVersion}</code>
      </section>
    </div>
  );
}
