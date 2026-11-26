import {
  AlertTriangle,
  Check,
  FolderGit2,
  HardDrive,
  Lock,
  Radio,
  RotateCcw,
  Shield,
  SlidersHorizontal,
  Wifi,
  X,
} from "lucide-react";
import { memo, useEffect, useState } from "react";
import {
  noiseIsInert,
  UpdateSettingsRow,
  type UpdateInfo,
  type UpdateProgress,
} from "@aether/ui";
import {
  IP_FAMILY_OPTIONS,
  NOIZE_OPTIONS,
  NOIZE_PROFILES,
  oneOf,
  ROUTING_MODE_OPTIONS,
  SCAN_MODE_OPTIONS,
  TRANSPORT_OPTIONS,
  TUNNEL_PROTOCOL_OPTIONS,
} from "@aether/ui/enums";
import type { NoizeProfile } from "@aether/ui/enums";
import type { IpcError } from "../ipcError";
import type { Settings } from "../types";
import { NumberField, Segmented, Toggle } from "./ui";

const ROUTING_LABELS: Record<string, string> = {
  "system-proxy": "System Proxy (automatic)",
  tun: "Full Device TUN (admin)",
  "proxy-only": "Proxy Only (ports only)",
};

export function commitPath(draft: string, saved: string): string | null {
  const trimmed = draft.trim();
  return trimmed === saved ? null : trimmed;
}

export function noiseUiState(settings: Pick<Settings, "protocol" | "transport" | "noize">) {
  const blocked = noiseIsInert(settings.protocol, settings.transport);
  return { blocked, showMatrix: !blocked && settings.noize === "custom" };
}

export const noiseFieldState = noiseUiState;

interface SettingsTabProps {
  settings: Settings;
  settingsLocked: boolean;
  settingsLoaded: boolean;
  settingsLoadError?: boolean;
  retrySettings?: () => void | Promise<void>;
  resetSettings?: () => void | Promise<void>;
  saved: boolean;
  dirty?: boolean;
  saveError?: IpcError | null;
  appVersion?: string;
  isDark?: boolean;
  onToggleTheme?: () => void;
  updateInfo?: UpdateInfo | null;
  updateProgress?: UpdateProgress | null;
  updateChecking?: boolean;
  updateCheckError?: string | null;
  onCheckUpdates?: () => void | Promise<void>;
  onInstallUpdate?: () => void | Promise<void>;
  patchSettings: (patch: Partial<Settings>) => void;
}

function SettingsTabImpl({
  settings,
  settingsLocked,
  settingsLoaded,
  settingsLoadError,
  retrySettings,
  resetSettings,
  saved,
  dirty = false,
  saveError,
  appVersion = "1.3.22",
  isDark = false,
  onToggleTheme,
  updateInfo = null,
  updateProgress = null,
  updateChecking = false,
  updateCheckError = null,
  onCheckUpdates,
  onInstallUpdate,
  patchSettings,
}: SettingsTabProps) {
  const portsCollide = settings.httpPort === settings.socksPort;
  const rejected = (field: string) => saveError?.field === field;
  const noise = noiseUiState(settings);
  const [pathDraft, setPathDraft] = useState(settings.enginePath);
  const [peerDraft, setPeerDraft] = useState(settings.peer);
  useEffect(() => { setPathDraft(settings.enginePath); }, [settings.enginePath]);
  useEffect(() => { setPeerDraft(settings.peer); }, [settings.peer]);

  return (
    <div className="settings-view">
      {settingsLoadError && (
        <div className="error-banner" role="alert">
          <div className="error-banner-content">
            <AlertTriangle size={16} aria-hidden="true" />
            <div>
              <strong>Settings Hydration Failed</strong>
              <span>Could not read settings from disk; defaults shown read-only until Retry succeeds.</span>
            </div>
          </div>
          {retrySettings && (
            <button type="button" onClick={() => void retrySettings()} className="banner-action">
              Retry
            </button>
          )}
        </div>
      )}

      {settingsLocked && (
        <div className="tactical-lock-banner" role="status">
          <div className="error-banner-content">
            <Lock size={15} aria-hidden="true" />
            <div>
              <strong>Configuration Locked</strong>
              <span>
                {settingsLoaded
                  ? "Disconnect the active tunnel to modify protocols or port bindings."
                  : "Loading saved profile…"}
              </span>
            </div>
          </div>
        </div>
      )}

      <section className="nordic-card">
        <div className="section-heading">
          <div>
            <p className="panel-eyebrow">TRANSPORT &amp; ANTI-DPI</p>
            <h2 className="nordic-card-title">Protocol Engine</h2>
          </div>
          <Wifi size={18} className="panel-head-icon" aria-hidden="true" />
        </div>

        <div className="setting-row">
          <div>
            <strong>Carrier Protocol</strong>
            <span>Network protocol used for Cloudflare egress</span>
          </div>
          <Segmented
            label="Carrier protocol"
            disabled={settingsLocked}
            value={settings.protocol}
            options={TUNNEL_PROTOCOL_OPTIONS}
            onChange={(protocol) => patchSettings({ protocol })}
          />
        </div>

        {(settings.protocol === "masque" || settings.protocol === "mim") && (
          <div className="setting-row">
            <div>
              <strong>MASQUE Framing</strong>
              <span>HTTP/2 provides TCP fallback where UDP/QUIC is throttled</span>
            </div>
            <Segmented
              label="MASQUE transport"
              disabled={settingsLocked}
              value={settings.transport}
              options={TRANSPORT_OPTIONS}
              onChange={(transport) => patchSettings({ transport })}
            />
          </div>
        )}

        {(settings.protocol === "masque" || settings.protocol === "mim") && settings.transport === "h3" && (
          <div className="setting-row">
            <div>
              <strong>QUIC Initial Fragmentation</strong>
              <span>Split ClientHello across two datagrams to bypass SNI inspection</span>
            </div>
            <Toggle
              label="QUIC Initial fragmentation"
              checked={settings.quicInitialFrag}
              disabled={settingsLocked}
              onChange={(quicInitialFrag) => patchSettings({ quicInitialFrag })}
            />
          </div>
        )}

        {(settings.protocol === "masque" || settings.protocol === "mim") &&
          settings.transport === "h3" &&
          settings.quicInitialFrag && (
            <div className="setting-row">
              <div>
                <strong>Initial Fragment Length</strong>
                <span>Bytes carried in the first ClientHello datagram (16–512)</span>
              </div>
              <NumberField
                label="QUIC Initial first fragment size"
                min={16}
                max={512}
                step={16}
                suffix="B"
                disabled={settingsLocked}
                value={settings.quicInitialFragSize}
                onCommit={(quicInitialFragSize) => patchSettings({ quicInitialFragSize })}
              />
            </div>
          )}

        <div className="setting-row">
          <div>
            <strong>Handshake Obfuscation</strong>
            <span>
              {noise.blocked
                ? "UDP junk frames do not apply to HTTP/2 TCP streams"
                : "Pre-handshake padding to prevent active DPI fingerprinting"}
            </span>
          </div>
          <select
            disabled={settingsLocked || noise.blocked}
            aria-label="Obfuscation noise profile"
            className="tactical-select"
            value={NOIZE_PROFILES.includes(settings.noize as NoizeProfile) ? settings.noize : "medium"}
            onChange={(e) => patchSettings({ noize: oneOf(e.target.value, NOIZE_PROFILES, "medium") })}
          >
            {NOIZE_OPTIONS.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
        </div>

        {noise.showMatrix && (
          <div className="custom-noise-matrix">
            <div className="matrix-title">
              <SlidersHorizontal size={14} aria-hidden="true" />
              <span>Custom Noise Parameters</span>
            </div>
            <div className="matrix-grid">
              <div className="matrix-cell">
                <label htmlFor="field-junk-packet-count">Junk Packet Count</label>
                <NumberField
                  id="field-junk-packet-count"
                  label="Junk packet count"
                  min={0}
                  max={64}
                  step={1}
                  suffix="pkts"
                  disabled={settingsLocked}
                  value={settings.noizeJc}
                  onCommit={(noizeJc) => patchSettings({ noizeJc })}
                />
              </div>
              <div className="matrix-cell">
                <label htmlFor="field-min-payload-size-bytes">Min Payload Size</label>
                <NumberField
                  id="field-min-payload-size-bytes"
                  label="Min payload size (bytes)"
                  min={0}
                  max={2048}
                  step={16}
                  suffix="B"
                  disabled={settingsLocked}
                  value={settings.noizeJmin}
                  onCommit={(noizeJmin) =>
                    patchSettings({
                      noizeJmin,
                      ...(noizeJmin > settings.noizeJmax ? { noizeJmax: noizeJmin } : {}),
                    })
                  }
                />
              </div>
              <div className="matrix-cell">
                <label htmlFor="field-max-payload-size-bytes">Max Payload Size</label>
                <NumberField
                  id="field-max-payload-size-bytes"
                  label="Max payload size (bytes)"
                  min={0}
                  max={2048}
                  step={16}
                  suffix="B"
                  disabled={settingsLocked}
                  value={settings.noizeJmax}
                  onCommit={(noizeJmax) =>
                    patchSettings({
                      noizeJmax,
                      ...(noizeJmax < settings.noizeJmin ? { noizeJmin: noizeJmax } : {}),
                    })
                  }
                />
              </div>
              <div className="matrix-cell">
                <label htmlFor="field-burst-interval-ms">Burst Interval</label>
                <NumberField
                  id="field-burst-interval-ms"
                  label="Burst interval (ms)"
                  min={0}
                  max={5000}
                  step={10}
                  suffix="ms"
                  disabled={settingsLocked}
                  value={settings.noizeIntervalMs}
                  onCommit={(noizeIntervalMs) => patchSettings({ noizeIntervalMs })}
                />
              </div>
            </div>
          </div>
        )}
      </section>

      <section className="nordic-card">
        <div className="section-heading">
          <div>
            <p className="panel-eyebrow">ENDPOINT DISCOVERY</p>
            <h2 className="nordic-card-title">Scanner &amp; Pinned Peer</h2>
          </div>
          <Radio size={18} className="panel-head-icon" aria-hidden="true" />
        </div>

        <div className="setting-row">
          <div>
            <strong>Probe Velocity Profile</strong>
            <span>Concurrency and probe depth during edge selection</span>
          </div>
          <select
            disabled={settingsLocked}
            aria-label="Scan mode"
            className="tactical-select"
            value={SCAN_MODE_OPTIONS.some((o) => o.value === settings.scanMode) ? settings.scanMode : "balanced"}
            onChange={(e) => patchSettings({ scanMode: e.target.value as Settings["scanMode"] })}
          >
            {SCAN_MODE_OPTIONS.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
        </div>

        <div className="setting-row">
          <div>
            <strong>IP Pool Family</strong>
            <span>Address families probed when discovering endpoints</span>
          </div>
          <Segmented
            label="IP version"
            disabled={settingsLocked}
            value={settings.ipVersion}
            options={IP_FAMILY_OPTIONS}
            onChange={(ipVersion) => patchSettings({ ipVersion })}
          />
        </div>

        <div className="setting-row">
          <div>
            <strong>Pinned Endpoint</strong>
            <span>Optional fixed IP:port override (leave blank for automatic selection)</span>
          </div>
          <div className="tactical-input-wrapper">
            <input
              disabled={settingsLocked}
              aria-label="Pinned endpoint"
              placeholder="Auto-select best edge"
              className="tactical-text-input font-mono"
              value={peerDraft}
              onChange={(e) => setPeerDraft(e.target.value)}
              onBlur={() => {
                const next = commitPath(peerDraft, settings.peer);
                if (next !== null) patchSettings({ peer: next });
              }}
              onKeyDown={(e) => {
                if (e.key !== "Enter") return;
                const next = commitPath(peerDraft, settings.peer);
                if (next !== null) patchSettings({ peer: next });
              }}
            />
          </div>
        </div>
      </section>

      <section className="nordic-card">
        <div className="section-heading">
          <div>
            <p className="panel-eyebrow">WINDOWS INTEGRATION</p>
            <h2 className="nordic-card-title">Routing &amp; Startup</h2>
          </div>
          <Shield size={18} className="panel-head-icon" aria-hidden="true" />
        </div>

        <div className="setting-row">
          <div>
            <strong>Dark Mode</strong>
            <span>Switch between Nordic Mist light and dark slate surfaces</span>
          </div>
          <Toggle
            label="Dark mode"
            checked={isDark}
            onChange={() => onToggleTheme?.()}
          />
        </div>

        <div className="setting-row">
          <div>
            <strong>Routing Mode</strong>
            <span>
              {settings.routingMode === "system-proxy"
                ? "Configures Windows system proxy for browsers and standard apps"
                : settings.routingMode === "tun"
                  ? "Routes all device packets through WinTUN (requires Administrator)"
                  : "Opens local proxy listeners without touching Windows system proxy"}
            </span>
          </div>
          <select
            disabled={settingsLocked}
            aria-label="Routing mode"
            className="tactical-select"
            value={settings.routingMode}
            onChange={(e) => patchSettings({ routingMode: e.target.value as Settings["routingMode"] })}
          >
            {ROUTING_MODE_OPTIONS.map((option) => (
              <option key={option.value} value={option.value}>
                {ROUTING_LABELS[option.value] ?? option.label}
              </option>
            ))}
          </select>
        </div>

        <div className="setting-row">
          <div>
            <strong>Launch at Login</strong>
            <span>Start Aether Next automatically when signing into Windows</span>
          </div>
          <Toggle
            label="Launch at login"
            checked={settings.launchAtLogin}
            disabled={settingsLocked}
            onChange={(launchAtLogin) => patchSettings({ launchAtLogin })}
          />
        </div>

        <div className="setting-row">
          <div>
            <strong>Start Minimized to Tray</strong>
            <span>Open directly to the system tray on startup</span>
          </div>
          <Toggle
            label="Start minimized"
            checked={settings.startMinimized}
            disabled={settingsLocked}
            onChange={(startMinimized) => patchSettings({ startMinimized })}
          />
        </div>
      </section>

      <section className="nordic-card">
        <div className="section-heading">
          <div>
            <p className="panel-eyebrow">LOCAL PORTS &amp; ENGINE</p>
            <h2 className="nordic-card-title">Proxy Bindings</h2>
          </div>
          <HardDrive size={18} className="panel-head-icon" aria-hidden="true" />
        </div>

        <div className="setting-row input-row">
          <div className="port-field-block">
            <label htmlFor="field-http-proxy-port">
              <strong>HTTP Proxy Port</strong>
              <span className="field-hint">1024–65535</span>
            </label>
            <NumberField
              id="field-http-proxy-port"
              label="HTTP proxy port"
              min={1024}
              max={65535}
              step={1}
              disabled={settingsLocked}
              value={settings.httpPort}
              invalid={rejected("httpPort")}
              onCommit={(httpPort) => patchSettings({ httpPort })}
            />
          </div>
          <div className="port-field-block">
            <label htmlFor="field-socks5-proxy-port">
              <strong>SOCKS5 Proxy Port</strong>
              <span className="field-hint">1024–65535</span>
            </label>
            <NumberField
              id="field-socks5-proxy-port"
              label="SOCKS5 proxy port"
              min={1024}
              max={65535}
              step={1}
              disabled={settingsLocked}
              value={settings.socksPort}
              invalid={rejected("socksPort")}
              onCommit={(socksPort) => patchSettings({ socksPort })}
            />
          </div>
        </div>

        {portsCollide && (
          <div className="port-collision-alert" role="alert">
            <AlertTriangle size={16} aria-hidden="true" />
            <span>HTTP and SOCKS5 ports cannot share port {settings.httpPort}.</span>
          </div>
        )}

        <div className="setting-row">
          <div>
            <strong>Engine Binary Path</strong>
            <span>Optional path to aether.exe (blank uses the bundled verified binary)</span>
          </div>
          <div className="tactical-input-wrapper">
            <FolderGit2 size={15} className="input-affix-icon" aria-hidden="true" />
            <input
              disabled={settingsLocked}
              aria-label="Engine path"
              placeholder="Auto-detect bundled binary"
              className="tactical-text-input"
              value={pathDraft}
              onChange={(e) => setPathDraft(e.target.value)}
              onBlur={() => {
                const next = commitPath(pathDraft, settings.enginePath);
                if (next !== null) patchSettings({ enginePath: next });
              }}
              onKeyDown={(e) => {
                if (e.key !== "Enter") return;
                const next = commitPath(pathDraft, settings.enginePath);
                if (next !== null) patchSettings({ enginePath: next });
              }}
            />
          </div>
        </div>

        {onCheckUpdates && (
          <UpdateSettingsRow
            appVersion={appVersion}
            updateInfo={updateInfo}
            updateProgress={updateProgress}
            updateChecking={updateChecking}
            updateCheckError={updateCheckError}
            onCheck={onCheckUpdates}
            onInstall={onInstallUpdate}
          />
        )}
      </section>

      {saveError && (
        <div className="error-banner" role="alert">
          <div className="error-banner-content">
            <X size={16} aria-hidden="true" />
            <span>AUTO-SAVE REJECTED — {saveError.message}</span>
          </div>
        </div>
      )}

      <div className="tactical-save-dock">
        <div className="save-bar-status" role="status" aria-live="polite">
          <span className="save-status-text">
            {!settingsLoaded
              ? "Reading configuration profile from disk…"
              : settingsLocked
                ? "Interface locked — disconnect tunnel to commit changes"
                : portsCollide
                  ? "Save blocked — resolve HTTP/SOCKS port collision"
                  : saveError
                    ? "Last save was rejected — see the message above"
                    : saved
                      ? "All parameters synchronized with runtime daemon"
                      : dirty
                        ? "Synchronizing changes…"
                        : "No changes pending — the form matches the profile on disk"}
          </span>
        </div>

        <div className="save-dock-actions">
          {resetSettings && (
            <button
              type="button"
              className="banner-action"
              disabled={settingsLocked}
              onClick={() => void resetSettings()}
            >
              <RotateCcw size={13} aria-hidden="true" />
              <span>Reset defaults</span>
            </button>
          )}
          <div className={`save-indicator ${portsCollide || saveError ? "blocked" : dirty ? "" : "idle"}`}>
            {portsCollide ? (
              <span>Collision Conflict</span>
            ) : saveError ? (
              <span>Save Rejected</span>
            ) : saved ? (
              <>
                <Check size={14} aria-hidden="true" />
                <span>Synchronized</span>
              </>
            ) : dirty ? (
              <span>Auto-Saving</span>
            ) : (
              <span>Idle</span>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

export const SettingsTab = memo(SettingsTabImpl);
