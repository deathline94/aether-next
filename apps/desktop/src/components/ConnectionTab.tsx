import { invoke } from "@tauri-apps/api/core";
import { Check, CircleAlert, WifiOff, X } from "lucide-react";
import { memo } from "react";
import {
  formatThroughputRate,
  formatUptimeClock,
  InlineUpdateBanner,
  releasePageUrl,
  type SessionStats,
  type UpdateInfo,
  type UpdateProgress,
} from "@aether/ui";
import { CopyButton } from "./ui";
import {
  connectionTestCopy,
  matchProtocolChoice,
  noiseSettingCopy,
  NORDIC_PROTOCOL_CHOICES,
  nordicHeroHeadline,
  nordicRoutingSummary,
  powerControlLabel,
  roundTripLabel,
  startHint,
} from "@aether/ui/statusCopy";
import type { PlatformCapabilities } from "@aether/ui/statusCopy";
import type { RuntimeState, Settings } from "../types";

export const PLATFORM: PlatformCapabilities = {
  canSetSystemProxy: true,
  routeName: "the tunnel device",
  routeSubject: "The tunnel device",
  actionVerb: "Click",
};

export const START_HINT = startHint(PLATFORM);

interface ConnectionTabProps {
  settings: Settings;
  runtime: RuntimeState;
  stats?: SessionStats | null;
  busy: boolean;
  testBusy: boolean;
  connected: boolean;
  running: boolean;
  settingsLocked: boolean;
  settingsLoaded: boolean;
  admin: boolean;
  online?: boolean;
  testResult: string | null;
  appVersion?: string;
  updateAvailable?: { version: string; url: string } | null;
  updateInfo?: UpdateInfo | null;
  updateProgress?: UpdateProgress | null;
  installUpdate?: () => void | Promise<void>;
  dismissUpdate?: () => void;
  toggleConnection: () => void;
  patchSettings: (patch: Partial<Settings>) => void;
  runTest: () => void;
  dismissError: () => void;
  appendLog: (entry: { level: "info" | "warn" | "error"; message: string }) => void;
}

function heroSubtitle(
  status: RuntimeState["status"],
  routingMode: Settings["routingMode"],
  detail: string,
  activeTitle: string,
): string {
  if (status === "connected") {
    if (routingMode === "tun") return "Traffic routed through Cloudflare Edge (WinTUN)";
    if (routingMode === "system-proxy") return "Traffic routed through Cloudflare Edge";
    return "Local proxy ports open — configure apps to use 127.0.0.1";
  }
  if (status === "connecting" || status === "error") {
    return detail.trim() || `Negotiating ${activeTitle} route…`;
  }
  return START_HINT;
}

function ConnectionTabImpl({
  settings,
  runtime,
  stats = null,
  busy,
  testBusy,
  connected,
  running,
  settingsLocked,
  settingsLoaded,
  online = true,
  testResult,
  appVersion = "0.0.0",
  updateAvailable = null,
  updateInfo = null,
  updateProgress = null,
  installUpdate,
  dismissUpdate,
  toggleConnection,
  patchSettings,
  runTest,
  dismissError,
  appendLog,
}: ConnectionTabProps) {
  const activeChoice = matchProtocolChoice(settings.protocol, settings.transport);
  const { button: testLabel } = connectionTestCopy(connected, testBusy);
  const rttDisplay = roundTripLabel(runtime.handshakeRttMs);
  const rttText = rttDisplay === "not measured" ? "—" : rttDisplay;
  const uptimeText = stats ? formatUptimeClock(stats.uptimeSecs) : "—";
  const endpointText = runtime.endpoint ?? "—";
  const throughputText = stats
    ? `${formatThroughputRate(stats.downBps)} ↓ · ${formatThroughputRate(stats.upBps)} ↑`
    : "—";

  const effectiveUpdate: UpdateInfo | null =
    updateInfo ??
    (updateAvailable
      ? {
          available: true,
          currentVersion: appVersion,
          latestVersion: updateAvailable.version.replace(/^v/, ""),
          releaseUrl: updateAvailable.url,
          assetName: "",
          assetUrl: "",
          assetSize: 0,
          sha256: null,
          notes: "",
        }
      : null);

  return (
    <div className="home-view">
      {!online && (
        <div className="offline-banner" role="status">
          <div className="error-banner-content">
            <WifiOff size={16} aria-hidden="true" />
            <span>No active internet link detected. Aether Next needs connectivity to reach Cloudflare.</span>
          </div>
        </div>
      )}

      <InlineUpdateBanner
        updateInfo={effectiveUpdate}
        updateProgress={updateProgress}
        onInstall={effectiveUpdate?.assetUrl && installUpdate ? installUpdate : undefined}
        onOpenRelease={(url) => void invoke("plugin:opener|open_url", { url: releasePageUrl(url) })}
        onDismiss={dismissUpdate}
      />

      {runtime.status === "error" && (
        <div className="error-banner" role="alert">
          <div className="error-banner-content">
            <CircleAlert size={16} aria-hidden="true" />
            <span>{runtime.detail}</span>
          </div>
          <button type="button" className="error-banner-dismiss" onClick={() => void dismissError()} aria-label="Dismiss error">
            <X size={14} aria-hidden="true" />
          </button>
        </div>
      )}

      {settings.peer && (
        <div className="pinned-peer-bar">
          <div className="pinned-peer-info">
            <span>Pinned server:</span>
            <code className="font-mono">{settings.peer}</code>
          </div>
          <button
            type="button"
            className="pinned-peer-clear-btn"
            disabled={settingsLocked}
            onClick={() => patchSettings({ peer: "" })}
          >
            Clear
          </button>
        </div>
      )}

      {/* Nordic Mist Hero Card */}
      <section className={`hero-card ${runtime.status}`} aria-label="Tunnel Status">
        <div className="hero-contour-bg" aria-hidden="true">
          <svg viewBox="0 0 420 220" fill="none" preserveAspectRatio="none">
            <path d="M10 180 C90 120, 150 210, 240 130 C320 60, 380 110, 430 40" stroke="var(--edge)" strokeWidth="1.2" />
            <path d="M0 140 C80 70, 170 170, 250 95 C330 25, 390 85, 430 15" stroke="var(--edge)" strokeWidth="1.2" />
            <path d="M30 210 C120 155, 190 225, 280 165 C350 120, 395 145, 430 95" stroke="var(--edge)" strokeWidth="1.2" />
            <path d="M60 40 C130 90, 210 10, 300 55 C365 88, 395 45, 430 70" stroke="var(--edge)" strokeWidth="1.2" />
          </svg>
        </div>

        <div className="hero-left">
          <div className="hero-status-indicator">
            <span className={`hero-dot ${runtime.status}`} aria-hidden="true" />
          </div>
          <h2 className="hero-title">{nordicHeroHeadline(runtime.status, settings.routingMode, PLATFORM.canSetSystemProxy)}</h2>
          <p className="hero-subtitle" aria-live="polite">
            {heroSubtitle(runtime.status, settings.routingMode, runtime.detail, activeChoice.title)}
          </p>
          <div className="hero-metrics font-mono tabular-nums" aria-label="Session telemetry">
            <span>{endpointText}</span>
            <span aria-hidden="true">·</span>
            <span>{rttText}</span>
            <span aria-hidden="true">·</span>
            <span>{uptimeText}</span>
          </div>
        </div>

        <div className="hero-right">
          <div className="route-arc-stage" aria-hidden="true">
            <svg className={`route-arc-svg ${connected ? "active" : ""}`} viewBox="0 0 280 86" fill="none">
              <path
                d="M 48 64 Q 140 -6 232 64"
                stroke={connected ? "var(--emerald)" : "var(--edge-interactive)"}
                strokeWidth="2.4"
                strokeLinecap="round"
                strokeDasharray={connected ? undefined : "5 5"}
              />
              <circle cx="48" cy="64" r="5" fill="var(--panel)" stroke={connected ? "var(--emerald)" : "var(--edge-interactive)"} strokeWidth="2.5" />
              <circle cx="232" cy="64" r="5" fill="var(--panel)" stroke={connected ? "var(--emerald)" : "var(--edge-interactive)"} strokeWidth="2.5" />
            </svg>
            <div className="route-arc-labels">
              <span>Local Device</span>
              <span>Encrypted Edge</span>
            </div>
          </div>

          <div className="hero-actions">
            <button
              type="button"
              className="primary-cta"
              onClick={toggleConnection}
              disabled={busy || (!running && !settingsLoaded)}
              aria-label={powerControlLabel(running)}
            >
              {busy ? "Working…" : running ? "Disconnect" : "Connect"}
            </button>
            <button
              type="button"
              className="text-action-btn"
              onClick={runTest}
              disabled={testBusy || busy || !connected}
            >
              {testBusy ? testLabel : "Test route"}
            </button>
          </div>

          {testResult && (
            <p className={`hero-test-note ${testResult.startsWith("OK") ? "ok" : "err"}`}>
              {testResult}
            </p>
          )}
        </div>
      </section>

      {/* Lower Two-Column Bento Grid */}
      <div className="nordic-grid">
        <section className="nordic-card" aria-label="Protocol & Transport">
          <h2 className="nordic-card-title">Protocol &amp; Transport</h2>
          <div className="protocol-list" role="radiogroup" aria-label="Tunnel protocol">
            {NORDIC_PROTOCOL_CHOICES.map((choice) => {
              const selected = activeChoice.id === choice.id;
              return (
                <button
                  key={choice.id}
                  type="button"
                  role="radio"
                  aria-checked={selected}
                  disabled={settingsLocked}
                  className={`protocol-row-btn ${selected ? "active" : ""}`}
                  onClick={() => {
                    if (settingsLocked || selected) return;
                    patchSettings({
                      protocol: choice.protocol,
                      transport: choice.transport,
                      peer: "",
                    });
                    appendLog({ level: "info", message: `Selected ${choice.title}` });
                  }}
                >
                  <div className="protocol-row-copy">
                    <strong>{choice.title}</strong>
                    <span>{choice.subtitle}</span>
                  </div>
                  {selected && (
                    <span className="protocol-check" aria-hidden="true">
                      <Check size={13} strokeWidth={2.6} />
                    </span>
                  )}
                </button>
              );
            })}
          </div>
        </section>

        <div className="nordic-right-stack">
          <section className="nordic-card" aria-label="Routing & Obfuscation">
            <h2 className="nordic-card-title">Routing &amp; Obfuscation</h2>
            <div className="kv-list">
              <div className="kv-row">
                <span className="kv-label">Tunnel Mode</span>
                <strong className="kv-value">{nordicRoutingSummary(settings.routingMode, "desktop")}</strong>
              </div>
              <div className="kv-row">
                <span className="kv-label">Obfuscation</span>
                <strong className="kv-value">{noiseSettingCopy(settings)}</strong>
              </div>
              <div className="kv-row">
                <span className="kv-label">Throughput</span>
                <strong className="kv-value tabular-nums">{throughputText}</strong>
              </div>
            </div>
          </section>

          <section className="nordic-card" aria-label="Local Proxies">
            <h2 className="nordic-card-title">Local Proxies</h2>
            <div className="proxy-list">
              <div className="proxy-item">
                <span className="proxy-proto">SOCKS5</span>
                <code className="proxy-addr font-mono tabular-nums">127.0.0.1:{settings.socksPort}</code>
                <CopyButton
                  value={`127.0.0.1:${settings.socksPort}`}
                  label="Copy SOCKS5 proxy address"
                  text="Copy"
                  onCopyFailed={() => appendLog({ level: "warn", message: "Clipboard copy failed" })}
                />
              </div>
              <div className="proxy-item">
                <span className="proxy-proto">HTTP</span>
                <code className="proxy-addr font-mono tabular-nums">127.0.0.1:{settings.httpPort}</code>
                <CopyButton
                  value={`127.0.0.1:${settings.httpPort}`}
                  label="Copy HTTP proxy address"
                  text="Copy"
                  onCopyFailed={() => appendLog({ level: "warn", message: "Clipboard copy failed" })}
                />
              </div>
            </div>
          </section>
        </div>
      </div>
    </div>
  );
}

export const ConnectionTab = memo(ConnectionTabImpl);
