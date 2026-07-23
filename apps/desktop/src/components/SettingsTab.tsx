import { Check, ChevronRight, Radio, Settings2, Wifi } from "lucide-react";
import type { Settings } from "../types";
import { Segmented, Toggle } from "./ui";

function clampPort(value: number) {
  if (!Number.isFinite(value)) return 1024;
  return Math.min(65535, Math.max(1024, Math.trunc(value)));
}

interface SettingsTabProps {
  settings: Settings;
  settingsLocked: boolean;
  saved: boolean;
  patchSettings: (patch: Partial<Settings>) => void;
}

export function SettingsTab({ settings, settingsLocked, saved, patchSettings }: SettingsTabProps) {
  return (
    <div className="settings-view">
      {settingsLocked && (
        <div className="lock-banner">Settings locked while connected. Disconnect to change tunnel options.</div>
      )}

      <section className="settings-section">
        <div className="section-heading">
          <div><p>TRANSPORT</p><h3>Tunnel behavior</h3></div>
          <Wifi size={20} />
        </div>
        <div className="setting-row">
          <div><strong>Protocol</strong><span>Carrier used to reach Cloudflare</span></div>
          <Segmented disabled={settingsLocked} value={settings.protocol}
            options={[{ value: "masque", label: "MASQUE" }, { value: "wireguard", label: "WireGuard" }, { value: "gool", label: "Gool" }]}
            onChange={(protocol) => patchSettings({ protocol })} />
        </div>
        {settings.protocol === "masque" && (
          <div className="setting-row">
            <div><strong>MASQUE transport</strong><span>HTTP/2 works on networks blocking QUIC</span></div>
            <Segmented disabled={settingsLocked} value={settings.transport}
              options={[{ value: "h2", label: "HTTP/2" }, { value: "h3", label: "HTTP/3" }]}
              onChange={(transport) => patchSettings({ transport })} />
          </div>
        )}
        <div className="setting-row">
          <div><strong>Obfuscation</strong><span>Noise before handshake (low → high)</span></div>
          <select disabled={settingsLocked}
            value={["off", "light", "medium", "high", "max", "custom"].includes(settings.noize) ? settings.noize : "medium"}
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
          <div className="setting-stack" style={{ gap: 10, marginTop: 8 }}>
            <div className="setting-row">
              <div><strong>Junk count</strong><span>Packets before handshake (0–64)</span></div>
              <input type="number" min={0} max={64} disabled={settingsLocked} value={settings.noizeJc}
                onChange={(e) => patchSettings({ noizeJc: Math.max(0, Math.min(64, Number(e.target.value) || 0)) })} />
            </div>
            <div className="setting-row">
              <div><strong>Min size</strong><span>Bytes</span></div>
              <input type="number" min={0} max={2048} disabled={settingsLocked} value={settings.noizeJmin}
                onChange={(e) => patchSettings({ noizeJmin: Math.max(0, Math.min(2048, Number(e.target.value) || 0)) })} />
            </div>
            <div className="setting-row">
              <div><strong>Max size</strong><span>Bytes (≥ min)</span></div>
              <input type="number" min={0} max={2048} disabled={settingsLocked} value={settings.noizeJmax}
                onChange={(e) => patchSettings({ noizeJmax: Math.max(0, Math.min(2048, Number(e.target.value) || 0)) })} />
            </div>
            <div className="setting-row">
              <div><strong>Interval</strong><span>Milliseconds between junk</span></div>
              <input type="number" min={0} max={5000} disabled={settingsLocked} value={settings.noizeIntervalMs}
                onChange={(e) => patchSettings({ noizeIntervalMs: Math.max(0, Math.min(5000, Number(e.target.value) || 0)) })} />
            </div>
          </div>
        )}
      </section>

      <section className="settings-section">
        <div className="section-heading">
          <div><p>DISCOVERY</p><h3>Endpoint scanning</h3></div>
          <Radio size={20} />
        </div>
        <div className="setting-row">
          <div><strong>Scan mode</strong><span>Balance startup time and route quality</span></div>
          <select disabled={settingsLocked} value={settings.scanMode}
            onChange={(e) => patchSettings({ scanMode: e.target.value as Settings["scanMode"] })}>
            <option value="turbo">Turbo</option>
            <option value="balanced">Balanced</option>
            <option value="thorough">Thorough</option>
            <option value="stealth">Stealth</option>
          </select>
        </div>
        <div className="setting-row">
          <div><strong>IP version</strong><span>Address families included in search</span></div>
          <Segmented disabled={settingsLocked} value={settings.ipVersion}
            options={[{ value: "v4", label: "IPv4" }, { value: "v6", label: "IPv6" }, { value: "both", label: "Both" }]}
            onChange={(ipVersion) => patchSettings({ ipVersion })} />
        </div>
      </section>

      <section className="settings-section">
        <div className="section-heading">
          <div><p>WINDOWS</p><h3>Routing and startup</h3></div>
          <Settings2 size={20} />
        </div>
        <div className="setting-row">
          <div><strong>Routing mode</strong><span>System proxy covers proxy-aware Windows apps</span></div>
          <select disabled={settingsLocked} value={settings.routingMode}
            onChange={(e) => patchSettings({ routingMode: e.target.value as Settings["routingMode"] })}>
            <option value="system-proxy">System proxy</option>
            <option value="proxy-only">Proxy only</option>
            <option value="tun">TUN (admin)</option>
          </select>
        </div>
        <div className="setting-row">
          <div><strong>Launch at login</strong><span>Start Aether Next with Windows</span></div>
          <Toggle checked={settings.launchAtLogin} disabled={settingsLocked} onChange={(launchAtLogin) => patchSettings({ launchAtLogin })} />
        </div>
        <div className="setting-row">
          <div><strong>Start minimized</strong><span>Open directly in system tray</span></div>
          <Toggle checked={settings.startMinimized} disabled={settingsLocked} onChange={(startMinimized) => patchSettings({ startMinimized })} />
        </div>
      </section>

      <section className="settings-section advanced">
        <div className="section-heading">
          <div><p>ADVANCED</p><h3>Local services</h3></div>
          <ChevronRight size={20} />
        </div>
        <div className="setting-row input-row">
          <label><span>HTTP port (1024–65535)</span>
            <input type="number" min={1024} max={65535} disabled={settingsLocked} value={settings.httpPort}
              onChange={(e) => patchSettings({ httpPort: clampPort(Number(e.target.value)) })} />
          </label>
          <label><span>SOCKS5 port (1024–65535)</span>
            <input type="number" min={1024} max={65535} disabled={settingsLocked} value={settings.socksPort}
              onChange={(e) => patchSettings({ socksPort: clampPort(Number(e.target.value)) })} />
          </label>
        </div>
        <div className="setting-row path-row">
          <div><strong>Engine path</strong><span>Optional path to aether.exe</span></div>
          <input disabled={settingsLocked} placeholder="Auto-detect" value={settings.enginePath}
            onChange={(e) => patchSettings({ enginePath: e.target.value })} />
        </div>
      </section>

      <div className="save-bar">
        <span>{settingsLocked ? "Locked while connected" : saved ? "Saved automatically" : "Changes save automatically · Aether Next"}</span>
        <button disabled className="ghost">{saved ? <Check size={17} /> : null}{saved ? "Saved" : "Auto-save on"}</button>
      </div>
    </div>
  );
}
