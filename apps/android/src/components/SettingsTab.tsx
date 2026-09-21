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
import { NumberField, Segmented, Toggle } from "./ui";

interface SettingsTabProps {
  settings: Settings;
  settingsLocked: boolean;
  settingsLoaded: boolean;
  settingsLoadError?: boolean;
  retrySettings?: () => void | Promise<void>;
  saved: boolean;
  admin: boolean;
  patchSettings: (patch: Partial<Settings>) => void;
}

const KNOWN_NOIZE = ["off", "light", "medium", "high", "max", "custom"];

/** Map legacy engine profile names onto the UI's canonical set. */
function noizeValue(raw: string): string {
  if (KNOWN_NOIZE.includes(raw)) return raw;
  if (raw === "firewall" || raw === "balanced") return "medium";
  if (raw === "gfw") return "high";
  if (raw === "aggressive" || raw === "heavy") return "max";
  return "medium";
}

export function SettingsTab({
  settings,
  settingsLocked,
  settingsLoaded,
  settingsLoadError,
  retrySettings,
  saved,
  admin,
  patchSettings,
}: SettingsTabProps) {
  const portsCollide = settings.httpPort === settings.socksPort;

  return (
    <div className="settings-view">
      {settingsLoadError && (
        <div className="error-banner" role="alert" style={{ marginBottom: "1rem", display: "flex", alignItems: "center", justifyContent: "space-between", padding: "0.75rem 1rem", borderRadius: "8px", background: "rgba(239, 68, 68, 0.15)", border: "1px solid rgba(239, 68, 68, 0.4)" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "0.75rem" }}>
            <AlertTriangle size={18} className="text-red-400" aria-hidden="true" />
            <div>
              <strong style={{ display: "block", fontSize: "0.875rem", color: "#f87171" }}>SETTINGS HYDRATION FAILED</strong>
              <span style={{ fontSize: "0.75rem", color: "#fca5a5" }}>
                Could not load configuration from disk. Defaults are active.
              </span>
            </div>
          </div>
          {retrySettings && (
            <button
              type="button"
              onClick={() => void retrySettings()}
              className="banner-dismiss"
              style={{ padding: "0.35rem 0.75rem", fontSize: "0.75rem", cursor: "pointer" }}
            >
              Retry
            </button>
          )}
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
      <section className="settings-section tactical-panel">
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
            ]}
            onChange={(protocol) => patchSettings({ protocol })}
          />
        </div>

        {settings.protocol === "masque" && (
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
              options={[
                { value: "h3", label: "HTTP/3 (QUIC)" },
                { value: "h2", label: "HTTP/2 (TCP)" },
              ]}
              onChange={(transport) => patchSettings({ transport })}
            />
          </div>
        )}

        {settings.protocol === "masque" && settings.transport === "h3" && (
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

        {settings.protocol === "masque" && settings.transport === "h3" && settings.quicInitialFrag && (
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
              {settings.noize !== "off" && <span className="tactical-chip amber">ACTIVE JUNK</span>}
            </div>
            <span>
              {settings.protocol === "masque" && settings.transport === "h2"
                ? "UDP junk frames are not applicable for HTTP/2 TCP streams"
                : "Inject randomized pre-handshake padding to prevent active protocol fingerprinting"}
            </span>
          </div>
          <select
            disabled={settingsLocked || (settings.protocol === "masque" && settings.transport === "h2")}
            aria-label="Obfuscation noise profile"
            className="tactical-select"
            value={noizeValue(settings.noize)}
            onChange={(e) => patchSettings({ noize: e.target.value })}
          >
            <option value="off">Off — Zero Noise</option>
            <option value="light">Light — Subtle Disruption</option>
            <option value="medium">Medium — Standard Defense</option>
            <option value="high">High — Heavy Resistance</option>
            <option value="max">Max — Maximum Entropy</option>
            <option value="custom">Custom — Parameter Matrix</option>
          </select>
        </div>

        {settings.noize === "custom" && settings.transport !== "h2" && (
          <div className="custom-noise-matrix">
            <div className="matrix-title">
              <SlidersHorizontal size={14} aria-hidden="true" />
              <span>CUSTOM NOISE PARAMETERS</span>
            </div>
            <div className="matrix-grid">
              <div className="matrix-cell">
                <label>
                  <span>Junk Packet Count</span>
                  <NumberField
                    label="Junk count"
                    min={0}
                    max={64}
                    step={1}
                    suffix="pkts"
                    disabled={settingsLocked}
                    value={settings.noizeJc}
                    onCommit={(noizeJc) => patchSettings({ noizeJc })}
                  />
                </label>
              </div>

              <div className="matrix-cell">
                <label>
                  <span>Min Payload Size</span>
                  <NumberField
                    label="Junk minimum size in bytes"
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
                </label>
              </div>

              <div className="matrix-cell">
                <label>
                  <span>Max Payload Size</span>
                  <NumberField
                    label="Junk maximum size in bytes"
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
                </label>
              </div>

              <div className="matrix-cell">
                <label>
                  <span>Burst Interval</span>
                  <NumberField
                    label="Junk interval in milliseconds"
                    min={0}
                    max={5000}
                    step={10}
                    suffix="ms"
                    disabled={settingsLocked}
                    value={settings.noizeIntervalMs}
                    onCommit={(noizeIntervalMs) => patchSettings({ noizeIntervalMs })}
                  />
                </label>
              </div>
            </div>
          </div>
        )}
      </section>

      {/* ─── Panel 2: Discovery & Topology ───────────────────────────────── */}
      <section className="settings-section tactical-panel">
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
            <option value="turbo">Turbo (Fastest startup, high concurrency)</option>
            <option value="balanced">Balanced (Optimal speed and route fidelity)</option>
            <option value="thorough">Thorough (Deep probe across extensive pools)</option>
            <option value="stealth">Stealth (Low rate to minimize traffic anomaly)</option>
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

      {/* ─── Panel 3: Android Platform & Routing ─────────────────────────── */}
      <section className="settings-section tactical-panel">
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
            value={settings.routingMode === "system-proxy" ? "tun" : settings.routingMode}
            onChange={(e) => patchSettings({ routingMode: e.target.value as Settings["routingMode"] })}
          >
            <option value="tun">Full VPN (Android VpnService)</option>
            <option value="proxy-only">Proxy Only (Local Listeners)</option>
          </select>
        </div>
      </section>

      {/* ─── Panel 4: Local Ports & Listeners ────────────────────────────── */}
      <section className="settings-section tactical-panel">
        <div className="section-heading">
          <div>
            <p className="panel-eyebrow">LOCAL LISTENERS</p>
            <h3>Proxy Endpoints</h3>
          </div>
          <HardDrive size={20} className="panel-head-icon" aria-hidden="true" />
        </div>

        <div className="setting-row input-row">
          <div className="port-field-block">
            <label>
              <div className="field-meta">
                <strong>HTTP Proxy Port</strong>
                <span className="field-hint">1024–65535</span>
              </div>
              <NumberField
                label="HTTP proxy port"
                min={1024}
                max={65535}
                step={1}
                disabled={settingsLocked}
                value={settings.httpPort}
                onCommit={(httpPort) => patchSettings({ httpPort })}
              />
            </label>
          </div>

          <div className="port-field-block">
            <label>
              <div className="field-meta">
                <strong>SOCKS5 Proxy Port</strong>
                <span className="field-hint">1024–65535</span>
              </div>
              <NumberField
                label="SOCKS5 proxy port"
                min={1024}
                max={65535}
                step={1}
                disabled={settingsLocked}
                value={settings.socksPort}
                onCommit={(socksPort) => patchSettings({ socksPort })}
              />
            </label>
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
              : saved
              ? "All parameters synchronized with runtime daemon"
              : "Synchronizing changes…"}
          </span>
        </div>

        <div className={`save-indicator ${portsCollide ? "blocked" : ""}`}>
          {portsCollide ? (
            <>
              <X size={15} aria-hidden="true" />
              <span>Collision Conflict</span>
            </>
          ) : saved ? (
            <>
              <Check size={15} aria-hidden="true" />
              <span>Synchronized</span>
            </>
          ) : (
            <>
              <div className="save-sync-pulse" aria-hidden="true" />
              <span>Auto-Saving</span>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
