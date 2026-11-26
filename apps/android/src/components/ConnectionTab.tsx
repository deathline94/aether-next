import { ChevronRight, CircleAlert, WifiOff, X } from "lucide-react";
import { memo, useEffect, useState } from "react";
import {
  formatThroughputRate,
  formatUptimeClock,
  InlineUpdateBanner,
  noiseIsInert,
  type SessionStats,
  type UpdateInfo,
  type UpdateProgress,
} from "@aether/ui";
import { AetherMark, CopyButton } from "./ui";
import {
  connectionTestCopy,
  coverageClaim,
  endpointClaim,
  matchProtocolChoice,
  nordicHeroHeadline,
  nordicRoutingSummary,
  powerControlLabel,
  roundTripLabel,
  startHint,
  stateAnswer,
  stateDetail,
} from "@aether/ui/statusCopy";
import type { PlatformCapabilities } from "@aether/ui/statusCopy";
import type { RuntimeState, Settings } from "../types";
import type { TestOutcome } from "../hooks/useRuntime";
import { QuickPickSheet, type SheetKind } from "./QuickPickSheet";

export const PLATFORM: PlatformCapabilities = {
  canSetSystemProxy: false,
  routeName: "the Android VPN",
  routeSubject: "Android's VPN route",
  actionVerb: "Tap",
};

export const START_HINT = startHint(PLATFORM);

export interface EvidenceRow {
  id: "state" | "coverage" | "endpoint";
  label: string;
  value: string;
  detail: string;
}

export function stateEvidence(status: RuntimeState["status"], detail: string): EvidenceRow {
  return { id: "state", label: "Connection", value: stateAnswer(status), detail: stateDetail(status, detail) };
}

export function coverageEvidence(
  routingMode: Settings["routingMode"],
  httpPort: number,
  socksPort: number,
): EvidenceRow {
  const claim = coverageClaim(routingMode, PLATFORM, httpPort, socksPort);
  return { id: "coverage", label: "What it covers", value: claim.answer, detail: claim.detail };
}

export function endpointEvidence(endpoint: string | null, running: boolean): EvidenceRow {
  const claim = endpointClaim(endpoint, running);
  return { id: "endpoint", label: "Server reached", value: claim.answer, detail: claim.detail };
}

export function routingGrantCopy(admin: boolean, routingMode: Settings["routingMode"]): string {
  if (routingMode !== "tun") {
    return "This mode adds no device-wide route — coverage depends on which apps use the ports below";
  }
  return admin
    ? "Android granted this app the VPN permission"
    : "Android asks for the VPN permission when you connect";
}

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
  testResult: TestOutcome | null;
  appVersion?: string;
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
  const [openSheet, setOpenSheet] = useState<SheetKind>(null);
  const activeChoice = matchProtocolChoice(settings.protocol, settings.transport);
  const test = connectionTestCopy(connected, testBusy);
  const latencyLabel = roundTripLabel(testResult?.latencyMs);
  const badgeText =
    latencyLabel !== "not measured"
      ? latencyLabel
      : connected
        ? "Connected"
        : running
          ? "Connecting"
          : runtime.status === "error"
            ? "Error"
            : "Standby";

  const routingShortLabel = nordicRoutingSummary(settings.routingMode, "android");
  const noiseBlocked = noiseIsInert(settings.protocol, settings.transport);
  const noiseShortLabel = noiseBlocked
    ? "Off (TCP H2)"
    : settings.noize === "off"
      ? "Off"
      : settings.noize.charAt(0).toUpperCase() + settings.noize.slice(1);

  useEffect(() => {
    if (!openSheet) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpenSheet(null);
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [openSheet]);

  return (
    <div className="home-view">
      {!online && (
        <div className="offline-banner" role="status">
          <div className="error-banner-content">
            <WifiOff size={16} aria-hidden="true" />
            <span>You appear to be offline. Connectivity is required to reach Cloudflare.</span>
          </div>
        </div>
      )}

      <InlineUpdateBanner
        updateInfo={updateInfo}
        updateProgress={updateProgress}
        onInstall={updateInfo?.assetUrl && installUpdate ? installUpdate : undefined}
        onDismiss={dismissUpdate}
      />

      {runtime.status === "error" && (
        <div className="error-banner" role="alert">
          <div className="error-banner-content">
            <CircleAlert size={16} aria-hidden="true" />
            <span>{runtime.detail}</span>
          </div>
          <button
            type="button"
            className="error-banner-dismiss"
            onClick={() => void dismissError()}
            aria-label="Dismiss error"
          >
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

      <section className={`mobile-hero-stage ${runtime.status}`} aria-label="Tunnel Status">
        <div className="mobile-hero-contour" aria-hidden="true">
          <svg viewBox="0 0 390 240" fill="none" preserveAspectRatio="none">
            <path d="M-20 110 C60 65, 130 140, 220 75 C300 20, 355 80, 410 35" stroke="var(--edge)" strokeWidth="1.2" />
            <path d="M-10 65 C75 25, 150 95, 240 40 C315 -5, 360 45, 410 15" stroke="var(--edge)" strokeWidth="1.2" />
            <path d="M0 165 C90 115, 175 190, 265 130 C330 85, 365 120, 410 95" stroke="var(--edge)" strokeWidth="1.2" />
            <path d="M20 215 C110 175, 200 225, 290 180 C340 155, 370 175, 410 150" stroke="var(--edge)" strokeWidth="1.2" />
          </svg>
        </div>

        <header className="mobile-top-bar">
          <div className="mobile-brand">
            <AetherMark size={26} />
            <strong className="mobile-brand-name">Aether Next</strong>
          </div>
          <div className="status-rtt-pill" title={runtime.detail}>
            <span className={`status-dot ${runtime.status}`} aria-hidden="true" />
            <span className="tabular-nums">{badgeText}</span>
          </div>
        </header>

        <div className="mobile-hero-center">
          <h2 className="mobile-hero-title">{nordicHeroHeadline(runtime.status, settings.routingMode, PLATFORM.canSetSystemProxy)}</h2>
          <p className="mobile-hero-subtitle" aria-live="polite">
            {connected
              ? settings.routingMode === "tun"
                ? `${runtime.endpoint ?? "Cloudflare Edge"} · Every app routed (${activeChoice.title})`
                : `${runtime.endpoint ?? "127.0.0.1"} · Local proxy ports only (${activeChoice.title})`
              : running || runtime.status === "error"
                ? runtime.detail
                : `${activeChoice.title} · ${START_HINT}`}
          </p>

          <button
            type="button"
            className="primary-cta mobile-hero-cta"
            onClick={toggleConnection}
            disabled={busy || (!running && !settingsLoaded)}
            aria-label={powerControlLabel(running)}
          >
            {busy ? "Working…" : running ? "Disconnect" : "Connect"}
          </button>

          <div className="mobile-hero-metrics font-mono tabular-nums">
            {stats ? (
              <span>
                {formatThroughputRate(stats.downBps)} ↓ · {formatThroughputRate(stats.upBps)} ↑ ·{" "}
                {formatUptimeClock(stats.uptimeSecs)}
              </span>
            ) : (
              <span>{testResult?.detail ?? "— ↓ · — ↑ · —"}</span>
            )}
          </div>

          <button
            type="button"
            className="text-action-btn"
            onClick={runTest}
            disabled={testBusy || busy || !connected}
          >
            {testBusy ? "Testing…" : connected ? "Test route" : test.button}
          </button>
        </div>
      </section>

      <section className="grouped-card" aria-label="Quick configuration">
        <button
          type="button"
          className="grouped-row-btn"
          disabled={settingsLocked}
          onClick={() => setOpenSheet("protocol")}
        >
          <span className="grouped-row-label">Protocol</span>
          <span className="grouped-row-value">
            <span>{activeChoice.title}</span>
            <ChevronRight size={16} aria-hidden="true" />
          </span>
        </button>

        <button
          type="button"
          className="grouped-row-btn"
          disabled={settingsLocked}
          onClick={() => setOpenSheet("routing")}
        >
          <span className="grouped-row-label">Routing</span>
          <span className="grouped-row-value">
            <span>{routingShortLabel}</span>
            <ChevronRight size={16} aria-hidden="true" />
          </span>
        </button>

        <button
          type="button"
          className="grouped-row-btn"
          disabled={settingsLocked || noiseBlocked}
          onClick={() => setOpenSheet("obfuscation")}
        >
          <span className="grouped-row-label">Obfuscation</span>
          <span className="grouped-row-value">
            <span>{noiseShortLabel}</span>
            <ChevronRight size={16} aria-hidden="true" />
          </span>
        </button>

        <div className="grouped-row-static">
          <span className="grouped-row-label">Local SOCKS5</span>
          <div className="grouped-row-copy">
            <code className="font-mono tabular-nums">127.0.0.1:{settings.socksPort}</code>
            <CopyButton
              value={`127.0.0.1:${settings.socksPort}`}
              label="Copy SOCKS5 proxy address"
              text="Copy"
              onCopyFailed={() => appendLog({ level: "warn", message: "Clipboard copy failed" })}
            />
          </div>
        </div>
      </section>

      <QuickPickSheet
        sheet={openSheet}
        settings={settings}
        activeChoice={activeChoice}
        onClose={() => setOpenSheet(null)}
        onPatch={patchSettings}
      />
    </div>
  );
}

export const ConnectionTab = memo(ConnectionTabImpl);
