import { Check, ChevronRight, Radio, Settings2, Wifi } from "lucide-react";
import type { Settings } from "../types";
import { NumberField, Segmented } from "./ui";

interface SettingsTabProps {
  settings: Settings;
  settingsLocked: boolean;
  settingsLoaded: boolean;
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

export function SettingsTab({ settings, settingsLocked, settingsLoaded, saved, admin, patchSettings }: SettingsTabProps) {
  const portsCollide = settings.httpPort === settings.socksPort;

  return (
    <div className="settings-view">
      {settingsLocked && (
        <div className="lock-banner" role="status">
          {settingsLoaded
            ? "Settings locked while connected. Disconnect to change tunnel options."
            : "Loading saved settings…"}
        </div>
      )}

      <section className="settings-section">
        <div className="section-heading">
          <div><p>TRANSPORT</p><h3>Tunnel behavior</h3></div>
          <Wifi size={20} aria-hidden="true" />
        </div>
        <div className="setting-row">
          <div><strong>Protocol</strong><span>Carrier used to reach Cloudflare</span></div>
          <Segmented label="Protocol" disabled={settingsLocked} value={settings.protocol}
            options={[{ value: "masque", label: "MASQUE" }, { value: "wireguard", label: "WireGuard" }, { value: "gool", label: "Gool" }]}
            onChange={(protocol) => patchSettings({ protocol })} />
        </div>
        {settings.protocol === "masque" && (
          <div className="setting-row">
            <div><strong>MASQUE transport</strong><span>HTTP/2 works on networks blocking QUIC</span></div>
            <Segmented label="MASQUE transport" disabled={settingsLocked} value={settings.transport}
              options={[{ value: "h2", label: "HTTP/2" }, { value: "h3", label: "HTTP/3" }]}
              onChange={(transport) => patchSettings({ transport })} />
          </div>
        )}
        <div className="setting-row">
          <div><strong>Obfuscation</strong><span>Noise before handshake (low → high)</span></div>
          <select disabled={settingsLocked} aria-label="Obfuscation noise profile"
            value={noizeValue(settings.noize)}
            onChange={(e) => patchSettings({ noize: e.target.value })}>
            <option value="off">Off — no noise</option>
            <option value="light">Light — low noise</option>
            <option value="medium">Medium — default</option>
            <option value="high">High — stronger</option>
            <option value="max">Max — highest noise</option>
            <option value="custom">Custom — manual values</option>
          </select>
        </div>
        {settings.noize === "custom" && (
          <div className="setting-stack">
            <div className="setting-row">
              <div><strong>Junk count</strong><span>Packets before handshake (0–64)</span></div>
              <NumberField label="Junk count" min={0} max={64} disabled={settingsLocked}
                value={settings.noizeJc} onCommit={(noizeJc) => patchSettings({ noizeJc })} />
            </div>
            <div className="setting-row">
              <div><strong>Min size</strong><span>Bytes (≤ max)</span></div>
              <NumberField label="Junk minimum size in bytes" min={0} max={2048} disabled={settingsLocked}
                value={settings.noizeJmin}
                onCommit={(noizeJmin) => patchSettings({ noizeJmin, ...(noizeJmin > settings.noizeJmax ? { noizeJmax: noizeJmin } : {}) })} />
            </div>
            <div className="setting-row">
              <div><strong>Max size</strong><span>Bytes (≥ min)</span></div>
              <NumberField label="Junk maximum size in bytes" min={0} max={2048} disabled={settingsLocked}
                value={settings.noizeJmax}
                onCommit={(noizeJmax) => patchSettings({ noizeJmax, ...(noizeJmax < settings.noizeJmin ? { noizeJmin: noizeJmax } : {}) })} />
            </div>
            <div className="setting-row">
              <div><strong>Interval</strong><span>Milliseconds between junk</span></div>
              <NumberField label="Junk interval in milliseconds" min={0} max={5000} disabled={settingsLocked}
                value={settings.noizeIntervalMs} onCommit={(noizeIntervalMs) => patchSettings({ noizeIntervalMs })} />
            </div>
          </div>
        )}
      </section>

      <section className="settings-section">
        <div className="section-heading">
          <div><p>DISCOVERY</p><h3>Endpoint scanning</h3></div>
          <Radio size={20} aria-hidden="true" />
        </div>
        <div className="setting-row">
          <div><strong>Scan mode</strong><span>Balance startup time and route quality</span></div>
          <select disabled={settingsLocked} aria-label="Scan mode" value={settings.scanMode}
            onChange={(e) => patchSettings({ scanMode: e.target.value as Settings["scanMode"] })}>
            <option value="turbo">Turbo</option>
            <option value="balanced">Balanced</option>
            <option value="thorough">Thorough</option>
            <option value="stealth">Stealth</option>
          </select>
        </div>
        <div className="setting-row">
          <div><strong>IP version</strong><span>Address families included in search</span></div>
          <Segmented label="IP version" disabled={settingsLocked} value={settings.ipVersion}
            options={[{ value: "v4", label: "IPv4" }, { value: "v6", label: "IPv6" }, { value: "both", label: "Both" }]}
            onChange={(ipVersion) => patchSettings({ ipVersion })} />
        </div>
      </section>

      <section className="settings-section">
        <div className="section-heading">
          <div><p>ANDROID</p><h3>Routing</h3></div>
          <Settings2 size={20} aria-hidden="true" />
        </div>
        <div className="setting-row">
          <div>
            <strong>Routing mode</strong>
            <span>
              {settings.routingMode === "tun"
                ? admin ? "VPN permission granted — full device tunnel" : "Will request Android VPN permission"
                : "Local SOCKS5/HTTP for apps that support a proxy"}
            </span>
          </div>
          <select disabled={settingsLocked} aria-label="Routing mode" value={settings.routingMode === "system-proxy" ? "tun" : settings.routingMode}
            onChange={(e) => patchSettings({ routingMode: e.target.value as Settings["routingMode"] })}>
            <option value="proxy-only">Proxy only</option>
            <option value="tun">Full VPN (VpnService)</option>
          </select>
        </div>
      </section>

      <section className="settings-section advanced">
        <div className="section-heading">
          <div><p>ADVANCED</p><h3>Local ports</h3></div>
          <ChevronRight size={20} aria-hidden="true" />
        </div>
        <div className="setting-row input-row">
          <label><span>HTTP port (1024–65535)</span>
            <NumberField label="HTTP proxy port" min={1024} max={65535} disabled={settingsLocked}
              value={settings.httpPort} onCommit={(httpPort) => patchSettings({ httpPort })} />
          </label>
          <label><span>SOCKS5 port (1024–65535)</span>
            <NumberField label="SOCKS5 proxy port" min={1024} max={65535} disabled={settingsLocked}
              value={settings.socksPort} onCommit={(socksPort) => patchSettings({ socksPort })} />
          </label>
        </div>
        {portsCollide && (
          <p className="setting-error" role="alert">HTTP and SOCKS5 ports must be different — both services cannot bind the same port.</p>
        )}
      </section>

      <div className="save-bar">
        <span role="status" aria-live="polite">
          {!settingsLoaded ? "Loading settings…" : settingsLocked ? "Locked while connected" : saved ? "Saved automatically" : "Changes save automatically"}
        </span>
        <span className="save-indicator">{saved && <Check size={17} aria-hidden="true" />}{saved ? "Saved" : "Auto-save on"}</span>
      </div>
    </div>
  );
}
