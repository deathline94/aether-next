import {
  AlertTriangle,
  Check,
  HardDrive,
  Lock,
  Radio,
  RotateCcw,
  Settings2,
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
  ROUTING_MODE_OPTIONS,
  SCAN_MODE_OPTIONS,
  TRANSPORT_OPTIONS,
  TUNNEL_PROTOCOL_OPTIONS,
} from "@aether/ui/enums";
import type { IpcError } from "../ipcError";
import { saveDockCopy, saveStateOf } from "../saveState";
import type { SaveState } from "../saveState";
import { normalizeNoize } from "../settingsPayload";
import type { Settings } from "../types";
import { NumberField, Segmented, Toggle } from "./ui";

const ROUTING_LABELS: Record<string, string> = {
  tun: "Full VPN (Android VpnService)",
  "proxy-only": "Proxy Only (Local Listeners)",
};

interface SettingsTabProps {
  settings: Settings;
  settingsLocked: boolean;
  settingsLoaded: boolean;
  settingsLoadError?: boolean;
  retrySettings?: () => void | Promise<void>;
  saved: SaveState | boolean;
  saveError?: IpcError | null;
  corrupt?: { notice: string; busy: boolean; onReset: () => void };
  admin: boolean;
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
  saved,
  saveError,
  corrupt,
  admin,
  appVersion = "1.3.19",
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
  const dock = saveDockCopy(saveStateOf(saved));
  const rejected = (field: string) => saveError?.field === field;
  const noiseBlocked = noiseIsInert(settings.protocol, settings.transport);
  const [peerDraft, setPeerDraft] = useState(settings.peer);
  useEffect(() => { setPeerDraft(settings.peer); }, [settings.peer]);

  const commitPeer = () => {
    const trimmed = peerDraft.trim();
    if (trimmed !== settings.peer) patchSettings({ peer: trimmed });
  };

  return (
    <div className="settings-view">
      {settingsLoadError && (
        <div className="error-banner" role="alert">
          <div className="error-banner-content">
            <AlertTriangle size={16} aria-hidden="true" />
            <div>
              <strong>SETTINGS HYDRATION FAILED</strong>
              <span>Could not read settings from disk; defaults are shown read-only until Retry succeeds.</span>
            </div>
          </div>
          {retrySettings && (
            <button type="button" onClick={() => void retrySettings()} className="banner-action">
              Retry
            </button>
          )}
        </div>
      )}

      {corrupt && (
        <div className="error-banner" role="alert">
          <div className="error-banner-content">
            <AlertTriangle size={16} aria-hidden="true" />
            <div>
              <strong>SAVED SETTINGS CORRUPT</strong>
              <span>{corrupt.notice}</span>
            </div>
          </div>
          <button
            type="button"
            onClick={() => void corrupt.onReset()}
            className="banner-action"
            disabled={corrupt.busy}
          >
            {corrupt.busy ? "Resetting…" : "Reset settings"}
          </button>
        </div>
      )}

      {settingsLocked && (
        <div className="tactical-lock-banner" role="status">
          <div className="error-banner-content">
            <Lock size={15} aria-hidden="true" />
            <div>
              <strong>TUNNEL OPERATIONAL — CONFIGURATION LOCKED</strong>
              <span>
                {settingsLoaded
                  ? "Disconnect the active VPN tunnel to modify protocols or ports."
                  : "Synchronizing saved configuration…"}
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
              <span>HTTP/2 provides TCP fallback where UDP/QUIC is blocked</span>
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
              <span>Split ClientHello across two datagrams to bypass DPI inspection</span>
            </div>
            <div className="toggle-hit-area">
              <Toggle
                label="QUIC Initial fragmentation"
                checked={settings.quicInitialFrag}
                disabled={settingsLocked}
                onChange={(quicInitialFrag) => patchSettings({ quicInitialFrag })}
              />
            </div>
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
              {noiseBlocked
                ? "UDP junk frames do not apply to HTTP/2 TCP streams"
                : "Pre-handshake padding to prevent active DPI fingerprinting"}
            </span>
          </div>
          <select
            disabled={settingsLocked || noiseBlocked}
            aria-label="Obfuscation noise profile"
            className="tactical-select"
            value={normalizeNoize(settings.noize) ?? settings.noize}
            onChange={(e) => patchSettings({ noize: e.target.value })}
          >
            {NOIZE_OPTIONS.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
        </div>

        {settings.noize === "custom" && !noiseBlocked && (
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
            <strong>Scan Thoroughness</strong>
            <span>Concurrency and probe depth during edge selection</span>
          </div>
          <select
            disabled={settingsLocked}
            aria-label="Scan mode"
            className="tactical-select"
            value={settings.scanMode}
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
            <span>Optional fixed IP:port override (blank chooses best scanned edge)</span>
          </div>
          <div className="tactical-input-wrapper">
            <input
              disabled={settingsLocked}
              aria-label="Pinned endpoint"
              placeholder="Auto-select best edge"
              className="tactical-text-input font-mono"
              value={peerDraft}
              onChange={(e) => setPeerDraft(e.target.value)}
              onBlur={commitPeer}
              onKeyDown={(e) => {
                if (e.key === "Enter") commitPeer();
              }}
            />
          </div>
        </div>
      </section>

      <section className="nordic-card">
        <div className="section-heading">
          <div>
            <p className="panel-eyebrow">ANDROID PLATFORM</p>
            <h2 className="nordic-card-title">Android Routing</h2>
          </div>
          <Settings2 size={18} className="panel-head-icon" aria-hidden="true" />
        </div>

        <div className="setting-row">
          <div>
            <strong>Dark Mode</strong>
            <span>Switch between Nordic Mist light and dark slate surfaces</span>
          </div>
          <div className="toggle-hit-area">
            <Toggle
              label="Dark mode"
              checked={isDark}
              onChange={() => onToggleTheme?.()}
            />
          </div>
        </div>

        <div className="setting-row">
          <div>
            <strong>Routing Mode</strong>
            <span>
              {settings.routingMode === "tun"
                ? admin
                  ? "VPN permission granted — routes all apps via VpnService"
                  : "Routes all device traffic via Android VpnService"
                : "Opens local SOCKS5/HTTP listeners without device VPN routing"}
            </span>
          </div>
          <select
            disabled={settingsLocked}
            aria-label="Routing mode"
            className="tactical-select"
            value={settings.routingMode}
            onChange={(e) => patchSettings({ routingMode: e.target.value as Settings["routingMode"] })}
          >
            {ROUTING_MODE_OPTIONS.map((option) => {
              if (option.value === "system-proxy") {
                return settings.routingMode === "system-proxy" ? (
                  <option key={option.value} value={option.value} disabled>
                    System Proxy — stored, not available on Android
                  </option>
                ) : null;
              }
              return (
                <option key={option.value} value={option.value}>
                  {ROUTING_LABELS[option.value] ?? option.label}
                </option>
              );
            })}
          </select>
        </div>

        <div className="setting-row">
          <div>
            <strong>Resume After Reboot</strong>
            <span>Post a tap-to-start notification when Android finishes booting</span>
          </div>
          <div className="toggle-hit-area">
            <Toggle
              label="Resume after reboot"
              checked={settings.launchAtLogin}
              disabled={settingsLocked}
              onChange={(launchAtLogin) => patchSettings({ launchAtLogin })}
            />
          </div>
        </div>
      </section>

      <section className="nordic-card">
        <div className="section-heading">
          <div>
            <p className="panel-eyebrow">LOCAL PORTS</p>
            <h2 className="nordic-card-title">Proxy Endpoints</h2>
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
            <span>Save rejected — {saveError.message}</span>
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
                    : dock.text}
          </span>
        </div>

        <div className="save-dock-actions">
          <button
            type="button"
            className="banner-action"
            disabled={settingsLocked}
            onClick={() =>
              patchSettings({
                protocol: "masque",
                transport: "h2",
                scanMode: "balanced",
                ipVersion: "v4",
                noize: "off",
                noizeJc: 5,
                noizeJmin: 50,
                noizeJmax: 128,
                noizeIntervalMs: 0,
                routingMode: "tun",
                socksPort: 1819,
                httpPort: 1820,
                launchAtLogin: false,
                peer: "",
                quicInitialFrag: false,
                quicInitialFragSize: 96,
              })
            }
          >
            <RotateCcw size={13} aria-hidden="true" />
            <span>Reset defaults</span>
          </button>

          <div className={`save-indicator ${portsCollide || saveError ? "blocked" : dock.icon === "pulse" ? "" : "idle"}`}>
            {portsCollide ? (
              <span>Conflict</span>
            ) : saveError ? (
              <span>Rejected</span>
            ) : dock.icon === "check" ? (
              <>
                <Check size={14} aria-hidden="true" />
                <span>Saved</span>
              </>
            ) : dock.icon === "pulse" ? (
              <span>Saving…</span>
            ) : dock.icon === "pending" ? (
              <span>Pending</span>
            ) : (
              <span>Synced</span>
            )}
          </div>
        </div>
      </div>

      <footer className="mobile-about-footer">
        <span>Aether Next</span>
        <span className="tabular-nums">v{appVersion}</span>
      </footer>
    </div>
  );
}

export const SettingsTab = memo(SettingsTabImpl);
