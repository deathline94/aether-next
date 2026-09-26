import {
  AlertTriangle,
  Check,
  HardDrive,
  Lock,
  Radio,
  Settings2,
  SlidersHorizontal,
  Wifi,
  X,
} from "lucide-react";
import type { Settings } from "../types";
import { normalizeNoize } from "../settingsPayload";
import { saveDockCopy, saveStateOf } from "../saveState";
import type { SaveState } from "../saveState";
import { noiseIsInert } from "@aether/ui";
import {
  IP_FAMILY_OPTIONS,
  NOIZE_OPTIONS,
  ROUTING_MODE_OPTIONS,
  SCAN_MODE_OPTIONS,
  TUNNEL_PROTOCOL_OPTIONS,
  TRANSPORT_OPTIONS,
} from "@aether/ui/enums";

/** This platform's wording for the shared routing-mode values; the value list
    itself is `ROUTING_MODE_OPTIONS`, so a new mode still surfaces here. */
const ROUTING_LABELS: Record<string, string> = {
  tun: "Full VPN (Android VpnService)",
  "proxy-only": "Proxy Only (Local Listeners)",
};
import { NumberField, Segmented, Toggle } from "./ui";
import type { IpcError } from "../ipcError";

interface SettingsTabProps {
  settings: Settings;
  settingsLocked: boolean;
  settingsLoaded: boolean;
  settingsLoadError?: boolean;
  retrySettings?: () => void | Promise<void>;
  /**
   * The save lifecycle, as the runtime hook reports it. A boolean is the shape a
   * call site that predates it can pass, and `saveStateOf` reads it for the only two
   * things it can honestly mean — never for "saving", which is a claim only a write
   * the app has actually started may make.
   */
  saved: SaveState | boolean;
  /** The last save the shell refused, if one is still outstanding. */
  saveError?: IpcError | null;
  /**
   * The stored profile is corrupt or unreadable (ITEM 10), as the shell reported it:
   * the sentence that says so and the one action that clears it. `App.tsx` renders the
   * same pair as the workspace banner, because the refused write also stops `connect()`
   * — the panel has to agree with it, or the screen a user comes to in order to fix the
   * profile is the one screen that says nothing is wrong. Markup only: the copy is
   * `describeSettingsReport`'s and the action is `resetSettings`, both from the hook.
   */
  corrupt?: { notice: string; busy: boolean; onReset: () => void };
  admin: boolean;
  patchSettings: (patch: Partial<Settings>) => void;
}

import { memo } from "react";

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
  patchSettings,
}: SettingsTabProps) {
  const portsCollide = settings.httpPort === settings.socksPort;
  const dock = saveDockCopy(saveStateOf(saved));
  // Which input the shell complained about, so the field itself can say so.
  const rejected = (field: string) => saveError?.field === field;

  return (
    <div className="settings-view">
      {settingsLoadError && (
        <div className="error-banner" role="alert">
          <div className="error-banner-content">
            <AlertTriangle size={18} aria-hidden="true" />
            <div>
              <strong>SETTINGS HYDRATION FAILED</strong>
              <span>
                Could not read the configuration from disk. What is on screen is not
                confirmed against it, and nothing here has been saved.
              </span>
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
      {/* ITEM 10's last visible piece: the panel agrees with the app-level banner. */}
      {corrupt && (
        <div className="error-banner" role="alert">
          <div className="error-banner-content">
            <AlertTriangle size={18} aria-hidden="true" />
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
            options={TUNNEL_PROTOCOL_OPTIONS}
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
              <span>HTTP/2 provides reliable fallback on networks blocking UDP/QUIC</span>
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
              <div className="setting-label-row">
                <strong>QUIC Initial Fragmentation</strong>
                <span className="tactical-chip emerald">ANTI-DPI</span>
              </div>
              <span>Split the TLS ClientHello across fragmented datagrams to bypass DPI inspect filters</span>
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
              {settings.noize !== "off" && !noiseIsInert(settings.protocol, settings.transport) && <span className="tactical-chip amber">ACTIVE JUNK</span>}
            </div>
            <span>
              {noiseIsInert(settings.protocol, settings.transport)
                ? "UDP junk frames are not applicable for HTTP/2 TCP streams"
                : "Inject randomized pre-handshake padding to prevent active protocol fingerprinting"}
            </span>
          </div>
          <select
            disabled={settingsLocked || noiseIsInert(settings.protocol, settings.transport)}
            aria-label="Obfuscation noise profile"
            className="tactical-select"
            value={normalizeNoize(settings.noize) ?? settings.noize}
            onChange={(e) => patchSettings({ noize: e.target.value })}
          >
            {NOIZE_OPTIONS.map((option) => (
              <option key={option.value} value={option.value}>{option.label}</option>
            ))}
          </select>
        </div>

        {settings.noize === "custom" && !noiseIsInert(settings.protocol, settings.transport) && (
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
            value={settings.scanMode}
            onChange={(e) => patchSettings({ scanMode: e.target.value as Settings["scanMode"] })}
          >
            {/* The shared list is the one vocabulary: the phone's Turbo row used
                to print different words for the same wire value than desktop. */}
            {SCAN_MODE_OPTIONS.map((option) => (
              <option key={option.value} value={option.value}>{option.label}</option>
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
            options={IP_FAMILY_OPTIONS}
            onChange={(ipVersion) => patchSettings({ ipVersion })}
          />
        </div>
      </section>

      {/* ─── Panel 3: Android Platform & Routing ─────────────────────────── */}
      <section className="settings-section">
        <div className="section-heading">
          <div>
            <p className="panel-eyebrow">PLATFORM & OS INTEGRATION</p>
            <h3>Android Routing</h3>
          </div>
          <Settings2 size={20} className="panel-head-icon" aria-hidden="true" />
        </div>

        <div className="setting-row">
          <div>
            <div className="setting-label-row">
              <strong>Routing Mode</strong>
              <span className={`tactical-chip ${settings.routingMode === "tun" ? "emerald" : "cyan"}`}>
                {settings.routingMode === "tun" ? "VPNSERVICE" : "LOCAL PROXY"}
              </span>
            </div>
            <span>
              {settings.routingMode === "tun"
                ? admin ? "Android VPN permission active — routes all app traffic system-wide" : "Routes all device traffic via Android VpnService (prompted on connect)"
                : "Exposes local SOCKS5/HTTP listeners for apps configured with proxy settings"}
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
              /* A config written on desktop can carry `system-proxy`, which
                 Android cannot do (no API to set the OS proxy from an app
                 without WRITE_SECURE_SETTINGS). The select used to *render* it
                 as "Full VPN" by coercion, so the stored mode and the label
                 disagreed, and the chip beside it — correctly reading the
                 stored value as not `tun` — said "LOCAL PROXY" on the same
                 row. Showing the stored value honestly, and naming it
                 unsupported, keeps the three widgets telling one story. */
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

        {/* `launchAtLogin` was persisted, validated and honoured by BootReceiver
            while nothing in the app could turn it on — the feature existed only
            for a config hand-edited onto the device. The wording matters: after a
            boot the receiver posts a notification to tap, it cannot start a VPN
            on its own. */}
        <div className="setting-row">
          <div>
            <div className="setting-label-row">
              <strong>Resume After Reboot</strong>
              <span className="tactical-chip">BOOT</span>
            </div>
            <span>
              Post a “tap to start” notification when the device boots — Android does not let an
              app open the tunnel by itself
            </span>
          </div>
          <Toggle
            label="Resume after reboot"
            checked={settings.launchAtLogin}
            disabled={settingsLocked}
            onChange={(launchAtLogin) => patchSettings({ launchAtLogin })}
          />
        </div>
      </section>

      {/* ─── Panel 4: Local Ports & Listeners ────────────────────────────── */}
      <section className="settings-section">
        <div className="section-heading">
          <div>
            <p className="panel-eyebrow">LOCAL LISTENERS</p>
            <h3>Proxy Endpoints</h3>
          </div>
          <HardDrive size={20} className="panel-head-icon" aria-hidden="true" />
        </div>

        <div className="setting-row input-row">
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
      </section>

      {/* ─── Save Dock ───────────────────────────────────────────────────── */}
      {/* A rejected save used to be only a log line, so the status text stayed on
          "Synchronizing changes…" over a value that would never be accepted. */}
      {saveError && (
        <div className="error-banner" role="alert">
          <div className="error-banner-content">
            <X size={18} aria-hidden="true" />
            <span>AUTO-SAVE REJECTED — {saveError.message}</span>
          </div>
        </div>
      )}
      <div className="save-bar tactical-save-dock">
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
              : dock.text}
          </span>
        </div>

        {/* Four states, and the pulse only on the one that is pulsing: this branch
            used to be `!saved`, so "Auto-Saving" spun from first paint until the
            first 1.2 s "Synchronized" flash — an indicator claiming a write nobody
            had asked for. `saveDockCopy` owns the sentence; the icon is this file's. */}
        <div className={`save-indicator ${portsCollide || saveError ? "blocked" : dock.icon === "pulse" ? "" : "idle"}`}>
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
          ) : dock.icon === "check" ? (
            <>
              <Check size={15} aria-hidden="true" />
              <span>Synchronized</span>
            </>
          ) : dock.icon === "pulse" ? (
            <>
              <div className="save-sync-pulse" aria-hidden="true" />
              <span>Auto-Saving</span>
            </>
          ) : dock.icon === "pending" ? (
            <>
              <span className="save-pending-dot" aria-hidden="true" />
              <span>Write pending</span>
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

// Memoized at the boundary: the log and scan buffers live in App, so every
// appended line re-rendered all four tabs even when nothing they read changed.
export const SettingsTab = memo(SettingsTabImpl);
