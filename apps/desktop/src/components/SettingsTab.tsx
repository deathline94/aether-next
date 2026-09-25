import {
  AlertTriangle,
  Check,
  FolderGit2,
  HardDrive,
  Lock,
  Radio,
  Shield,
  SlidersHorizontal,
  Wifi,
  X,
} from "lucide-react";
import { useEffect, useState } from "react";
import type { NoizeProfile, Settings } from "../types";
import { NOIZE_OPTIONS, NOIZE_PROFILES, SCAN_MODE_OPTIONS, oneOf } from "@aether/ui/enums";
import { noiseIsInert } from "@aether/ui";
import type { IpcError } from "../ipcError";
import { NumberField, Segmented, Toggle } from "./ui";

/**
 * A free-text path commits on blur or Enter, not on every keystroke.
 *
 * The form auto-saves 400 ms after the last change, so per-character patching
 * wrote "C:", then "C:\Use", then the real path to disk: an aborted edit
 * left a nonsense engine path saved, and the next connect failed over a
 * half-typed string nobody meant to keep. Null means nothing changed, so a blur
 * on an untouched field does not write at all.
 */
export function commitPath(draft: string, current: string): string | null {
  const next = draft.trim();
  return next === current.trim() ? null : next;
}

/**
 * Which of the two noise controls the transport can carry.
 *
 * UDP junk frames have nowhere to go on an HTTP/2 TCP stream, so the profile
 * select is disabled there — but only for MASQUE. WireGuard and Gool ride UDP
 * whatever `transport` says, so their select stayed live and accepted `custom`
 * while the parameter matrix rendered only for `transport !== "h2"`: the profile
 * went to disk with four numbers nobody could see or edit. Both halves now read
 * the same predicate, so a profile is only pickable where its parameters are
 * showable.
 */
export function noiseFieldState(settings: Settings): { blocked: boolean; showMatrix: boolean } {
  const blocked = noiseIsInert(settings.protocol, settings.transport);
  return { blocked, showMatrix: !blocked && settings.noize === "custom" };
}

interface SettingsTabProps {
  settings: Settings;
  settingsLocked: boolean;
  settingsLoaded: boolean;
  settingsLoadError?: boolean;
  retrySettings?: () => void | Promise<void>;
  /** The shell has just accepted a write; the dock flashes "Synchronized". */
  saved: boolean;
  /**
   * An edit of ours has not been accepted yet — queued, in flight, or refused.
   * Without it the dock had no idle state: `!saved` was the only test, so it pulsed
   * "Auto-Saving / Synchronizing changes…" from first paint.
   */
  dirty: boolean;
  /** The last save the shell refused, if one is still outstanding. */
  saveError?: IpcError | null;
  patchSettings: (patch: Partial<Settings>) => void;
}

export function SettingsTab({
  settings,
  settingsLocked,
  settingsLoaded,
  settingsLoadError,
  retrySettings,
  saved,
  dirty,
  saveError,
  patchSettings,
}: SettingsTabProps) {
  const portsCollide = settings.httpPort === settings.socksPort;
  const noise = noiseFieldState(settings);
  // `field` is the machine-readable half of the rejection: the shell says which
  // setting it refused, so the input itself can be marked, not just the log.
  const rejected = (field: string) => saveError?.field === field;
  const [pathDraft, setPathDraft] = useState(settings.enginePath);
  // Keep the draft honest when something else moves the value (hydration, a
  // retry, a profile preset); leave it alone while the user is editing it.
  useEffect(() => {
    setPathDraft((draft) =>
      commitPath(draft, settings.enginePath) === null ? settings.enginePath : draft,
    );
  }, [settings.enginePath]);

  return (
    <div className="settings-view">
      {settingsLoadError && (
        <div className="error-banner" role="alert">
          <div className="error-banner-content">
            <AlertTriangle size={18} aria-hidden="true" />
            <div>
              <strong>SETTINGS HYDRATION FAILED</strong>
              <span>Could not load configuration from disk. Defaults are active.</span>
            </div>
          </div>
          {retrySettings && (
            <button
              type="button"
              onClick={() => void retrySettings()}
              className="banner-action"
            >
              Retry
            </button>
          )}
        </div>
      )}
      {/* A rejected save used to be only a log line, so the status text below
          stayed on "Synchronizing changes…" over a value that would never be
          accepted. The shell's own sentence is the message; `field` marks the
          input it is about. */}
      {saveError && (
        <div className="error-banner" role="alert">
          <div className="error-banner-content">
            <AlertTriangle size={18} aria-hidden="true" />
            <span>AUTO-SAVE REJECTED — {saveError.message}</span>
          </div>
        </div>
      )}
      {settingsLocked && (
        <div className="tactical-lock-banner" role="status">
          <div className="lock-banner-icon">
            <Lock size={16} aria-hidden="true" />
          </div>
          <div className="lock-banner-text">
            <strong>TUNNEL OPERATIONAL — CONFIGURATION LOCKED</strong>
            <span>
              {settingsLoaded
                ? "Active egress route is protected. Disconnect the tunnel to modify network protocols or port bindings."
                : "Synchronizing engine daemon parameters…"}
            </span>
          </div>
        </div>
      )}

      {/* ─── Panel 1: Transport & Carrier Engine ─────────────────────────── */}
      <section className="settings-section">
        <div className="section-heading">
          <div>
            <p className="panel-eyebrow">CARRIER PROTOCOL & ANTI-DPI</p>
            <h3>Transport Engine</h3>
          </div>
          <Wifi size={20} className="panel-head-icon" aria-hidden="true" />
        </div>

        <div className="setting-row">
          <div>
            <div className="setting-label-row">
              <strong>Carrier Protocol</strong>
              <span className="tactical-chip">EGRESS LAYER</span>
            </div>
            <span>Underlying network protocol used to bridge outbound traffic</span>
          </div>
          <Segmented
            label="Carrier protocol"
            disabled={settingsLocked}
            value={settings.protocol}
            options={[
              { value: "masque", label: "MASQUE" },
              { value: "wireguard", label: "WireGuard" },
              { value: "gool", label: "Gool" },
              { value: "mim", label: "MASQUE-in-MASQUE" },
            ]}
            onChange={(protocol) => patchSettings({ protocol })}
          />
        </div>

        {(settings.protocol === "masque" || settings.protocol === "mim") && (
          <div className="setting-row">
            <div>
              <div className="setting-label-row">
                <strong>MASQUE Transport Framing</strong>
                <span className="tactical-chip cyan">HTTP/3 / H2</span>
              </div>
              <span>HTTP/2 provides reliable fallback on restricted networks that block UDP/QUIC</span>
            </div>
            <Segmented
              label="MASQUE transport"
              disabled={settingsLocked}
              value={settings.transport}
              options={[
                { value: "h3", label: "HTTP/3 (QUIC)" },
                { value: "h2", label: "HTTP/2 (TCP)" },
              ]}
              onChange={(transport) => patchSettings({ transport })}
            />
          </div>
        )}

        {(settings.protocol === "masque" || settings.protocol === "mim") && settings.transport === "h3" && (
          <div className="setting-row">
            <div>
              <div className="setting-label-row">
                <strong>QUIC Initial Fragmentation</strong>
                <span className="tactical-chip emerald">ANTI-DPI</span>
              </div>
              <span>Split the TLS ClientHello across fragmented datagrams to bypass SNI inspect filters</span>
            </div>
            <Toggle
              label="QUIC Initial fragmentation"
              checked={settings.quicInitialFrag}
              disabled={settingsLocked}
              onChange={(quicInitialFrag) => patchSettings({ quicInitialFrag })}
            />
          </div>
        )}

        {(settings.protocol === "masque" || settings.protocol === "mim") && settings.transport === "h3" && settings.quicInitialFrag && (
          <div className="setting-row">
            <div>
              <div className="setting-label-row">
                <strong>Initial Fragment Length</strong>
                <span className="tactical-chip">16–512 BYTES</span>
              </div>
              <span>Exact size of the ClientHello packet dispatched in the first datagram</span>
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
            <div className="setting-label-row">
              <strong>Handshake Obfuscation</strong>
              {settings.noize !== "off" && !noise.blocked && <span className="tactical-chip amber">ACTIVE JUNK</span>}
            </div>
            <span>
              {noise.blocked
                ? "UDP junk frames are not applicable for HTTP/2 TCP streams"
                : "Inject randomized pre-handshake padding to prevent active protocol fingerprinting"}
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
              <span>CUSTOM NOISE PARAMETERS</span>
            </div>
            <div className="matrix-grid">
              <div className="matrix-cell">
                <label htmlFor="field-junk-packet-count">
                  <span>Junk Packet Count</span>
                </label>
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
                <label htmlFor="field-min-payload-size-bytes">
                  <span>Min Payload Size</span>
                </label>
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
                <label htmlFor="field-max-payload-size-bytes">
                  <span>Max Payload Size</span>
                </label>
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
                <label htmlFor="field-burst-interval-ms">
                  <span>Burst Interval</span>
                </label>
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

      {/* ─── Panel 2: Discovery & Topology ───────────────────────────────── */}
      <section className="settings-section">
        <div className="section-heading">
          <div>
            <p className="panel-eyebrow">AUTO-DISCOVERY & LATENCY SEARCH</p>
            <h3>Topology Scanner</h3>
          </div>
          <Radio size={20} className="panel-head-icon" aria-hidden="true" />
        </div>

        <div className="setting-row">
          <div>
            <div className="setting-label-row">
              <strong>Probe Velocity Profile</strong>
              <span className="tactical-chip cyan">{settings.scanMode.toUpperCase()}</span>
            </div>
            <span>Dictates worker concurrency and RTT probe thoroughness during edge search</span>
          </div>
          <select
            disabled={settingsLocked}
            aria-label="Scan mode"
            className="tactical-select"
            // Every mode the shell accepts, from the shared list: `ironclad` was a
            // legal wire value with no option, so a config that carried it showed a
            // blank selection and the next patch silently changed it.
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
            <div className="setting-label-row">
              <strong>IP Pool Family</strong>
              <span className="tactical-chip">NETWORK TARGET</span>
            </div>
            <span>IP address versions scanned and benchmarked for edge ingress</span>
          </div>
          <Segmented
            label="IP version"
            disabled={settingsLocked}
            value={settings.ipVersion}
            options={[
              { value: "v4", label: "IPv4 Only" },
              { value: "v6", label: "IPv6 Only" },
              { value: "both", label: "Dual-Stack" },
            ]}
            onChange={(ipVersion) => patchSettings({ ipVersion })}
          />
        </div>
      </section>

      {/* ─── Panel 3: Windows Integration & Routing Policy ───────────────── */}
      <section className="settings-section">
        <div className="section-heading">
          <div>
            <p className="panel-eyebrow">PLATFORM & OS INTEGRATION</p>
            <h3>Routing & Startup</h3>
          </div>
          <Shield size={20} className="panel-head-icon" aria-hidden="true" />
        </div>

        <div className="setting-row">
          <div>
            <div className="setting-label-row">
              <strong>Routing Pipeline</strong>
              <span className={`tactical-chip ${settings.routingMode === "tun" ? "coral" : "emerald"}`}>
                {settings.routingMode === "tun" ? "ADMIN TUN" : "USER-SPACE"}
              </span>
            </div>
            <span>
              {settings.routingMode === "system-proxy"
                ? "Directs Windows system proxy settings so all browser and standard applications route transparently"
                : settings.routingMode === "tun"
                ? "Installs a virtual Wintun network adapter for universal, system-wide packet routing (requires admin)"
                : "Keeps ports listening locally without altering global Windows network proxy settings"}
            </span>
          </div>
          <select
            disabled={settingsLocked}
            aria-label="Routing mode"
            className="tactical-select"
            value={settings.routingMode}
            onChange={(e) => patchSettings({ routingMode: e.target.value as Settings["routingMode"] })}
          >
            <option value="system-proxy">System Proxy (Standard Windows Proxy)</option>
            <option value="proxy-only">Proxy Only (Local Listeners Only)</option>
            <option value="tun">TUN Virtual Device (Elevated System-Wide)</option>
          </select>
        </div>

        <div className="setting-row">
          <div>
            <strong>Launch at Login</strong>
            <span>Automatically initialize Aether daemon when Windows boots</span>
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
            <span>Launch silently into the Windows system tray without popping the window</span>
          </div>
          <Toggle
            label="Start minimized"
            checked={settings.startMinimized}
            disabled={settingsLocked}
            onChange={(startMinimized) => patchSettings({ startMinimized })}
          />
        </div>
      </section>

      {/* ─── Panel 4: Local Ports & Daemon Binary ────────────────────────── */}
      <section className="settings-section">
        <div className="section-heading">
          <div>
            <p className="panel-eyebrow">LOCAL LISTENERS & BINARY HOOKS</p>
            <h3>Proxy Endpoints</h3>
          </div>
          <HardDrive size={20} className="panel-head-icon" aria-hidden="true" />
        </div>

        <div className="setting-row">
          <div className="port-field-block">
            <label htmlFor="field-http-proxy-port">
              <div className="field-meta">
                <strong>HTTP Proxy Port</strong>
                <span className="field-hint">1024–65535</span>
              </div>
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
              <div className="field-meta">
                <strong>SOCKS5 Proxy Port</strong>
                <span className="field-hint">1024–65535</span>
              </div>
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
            <div>
              <strong>Port Collision Detected</strong>
              <p>HTTP and SOCKS5 listeners cannot bind to the identical port ({settings.httpPort}). Modify one port to re-enable saving.</p>
            </div>
          </div>
        )}

        <div className="setting-row">
          <div>
            <div className="setting-label-row">
              <strong>Engine Binary Path</strong>
              <span className="tactical-chip">OVERRIDE</span>
            </div>
            <span>Custom executable path to aether.exe (leave blank for bundled auto-detection)</span>
          </div>
          <div className="tactical-input-wrapper">
            <FolderGit2 size={16} className="input-affix-icon" aria-hidden="true" />
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
      </section>

      {/* ─── Save Dock ───────────────────────────────────────────────────── */}
      <div className="tactical-save-dock">
        <div className="save-bar-status" role="status" aria-live="polite">
          <span className="save-status-indicator-dot" />
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

        {/* Four states, and the pulse only on the one that is pulsing: this branch
            used to be `!saved`, so "Auto-Saving" spun from first paint until the
            first 1.2 s "Synchronized" flash — a save indicator that lied about a
            write in progress. */}
        <div className={`save-indicator ${portsCollide || saveError ? "blocked" : dirty ? "" : "idle"}`}>
          {portsCollide ? (
            <>
              <X size={15} aria-hidden="true" />
              <span>Collision Conflict</span>
            </>
          ) : saveError ? (
            <>
              <X size={15} aria-hidden="true" />
              <span>Save Rejected</span>
            </>
          ) : saved ? (
            <>
              <Check size={15} aria-hidden="true" />
              <span>Synchronized</span>
            </>
          ) : dirty ? (
            <>
              <div className="save-sync-pulse" aria-hidden="true" />
              <span>Auto-Saving</span>
            </>
          ) : (
            <>
              <span className="save-idle-dot" aria-hidden="true" />
              <span>Idle</span>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
