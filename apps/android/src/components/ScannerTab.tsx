import { Check, Copy, Network, Radio, Search, X, Zap } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import type { DiscoveredEndpoint, ScanState } from "../types";
import { NumberField, Segmented } from "./ui";

interface ScannerTabProps {
  protocol: "masque-h3" | "masque-h2" | "wireguard";
  setProtocol: (v: "masque-h3" | "masque-h2" | "wireguard") => void;
  ipScan: "v4" | "v6" | "both";
  setIpScan: (v: "v4" | "v6" | "both") => void;
  concurrency: number;
  setConcurrency: (v: number) => void;
  timeoutMs: number;
  setTimeoutMs: (v: number) => void;
  noize: string;
  setNoize: (v: string) => void;
  endpoints: DiscoveredEndpoint[];
  active: boolean;
  scanState: ScanState;
  busy: boolean;
  startScan: () => void;
  stopScan: () => void;
  connectDirect: (item: DiscoveredEndpoint) => void;
  connectBusy: boolean;
}

function getRttTier(rttMs: number): { tierClass: string; badgeText: string } {
  if (rttMs < 20) return { tierClass: "rtt-ultra-green", badgeText: "ULTRA FAST" };
  if (rttMs <= 60) return { tierClass: "rtt-optimal-cyan", badgeText: "OPTIMAL" };
  if (rttMs <= 100) return { tierClass: "rtt-acceptable-amber", badgeText: "NORMAL" };
  return { tierClass: "rtt-high-coral", badgeText: "HIGH LATENCY" };
}

function CopyIpButton({ addr }: { addr: string }) {
  const [copied, setCopied] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  useEffect(() => () => { if (timer.current) clearTimeout(timer.current); }, []);

  return (
    <button
      type="button"
      className="tactile-copy-btn"
      title={copied ? "Copied" : "Copy IP address"}
      aria-label={copied ? "Copied" : "Copy IP address"}
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(addr);
          setCopied(true);
          if (timer.current) clearTimeout(timer.current);
          timer.current = setTimeout(() => setCopied(false), 1500);
        } catch {
          // Clipboard fallback
        }
      }}
    >
      {copied ? <Check size={14} aria-hidden="true" /> : <Copy size={14} aria-hidden="true" />}
    </button>
  );
}

export function ScannerTab({
  protocol, setProtocol,
  ipScan, setIpScan,
  concurrency, setConcurrency,
  timeoutMs, setTimeoutMs,
  noize, setNoize,
  endpoints, active, scanState, busy,
  startScan, stopScan,
  connectDirect, connectBusy,
}: ScannerTabProps) {
  const progressPct = scanState.total > 0
    ? Math.min(100, Math.round((scanState.scanned / scanState.total) * 100))
    : 0;

  return (
    <div className="scanner-view">
      {/* ─── Scanner Radar HUD Panel ───────────────────────────────────────── */}
      <section className="settings-section radar-hud-container">
        <div className="section-heading">
          <div>
            <p>STANDALONE ENGINE PROBER</p>
            <h3>Cloudflare Edge Scanner</h3>
          </div>
          <Radio size={20} className={active ? "spin-icon" : ""} aria-hidden="true" />
        </div>

        {/* Tactical HUD Header */}
        <div className="radar-telemetry-banner">
          <div className="radar-radar-scope" aria-hidden="true">
            <div className={`radar-sweep-reticle ${active ? "active-sweep" : ""}`}>
              <div className="radar-crosshair-h" />
              <div className="radar-crosshair-v" />
              <div className="radar-circle circle-1" />
              <div className="radar-circle circle-2" />
              {active && <div className="radar-sweep-beam" />}
            </div>
          </div>
          <div className="radar-scope-meta">
            <div className="scope-status-line">
              <span className={`scope-led ${active ? "active" : ""}`} />
              <strong>{active ? `PROBING POOL (${scanState.mode.toUpperCase()})` : "RADAR ENGINE DORMANT"}</strong>
              <span className="scope-phase-tag">{scanState.phase}</span>
            </div>
            <p>
              {active
                ? `Dispatching concurrent datagram probes across Cloudflare ${ipScan.toUpperCase()} edge ranges.`
                : "Probe Cloudflare IP pools directly to find zero-loss, low-latency edge endpoints before establishing the tunnel."}
            </p>
          </div>
        </div>

        {/* Configuration Controls */}
        <div className="setting-row">
          <div>
            <strong>Target Protocol</strong>
            <span>Service carrier used for probing edge handshakes</span>
          </div>
          <Segmented
            label="Target protocol"
            value={protocol}
            options={[
              { value: "masque-h3", label: "MASQUE H3" },
              { value: "masque-h2", label: "MASQUE H2" },
              { value: "wireguard", label: "WireGuard" },
            ]}
            onChange={setProtocol}
            disabled={active}
          />
        </div>

        <div className="setting-row">
          <div>
            <strong>IP Family</strong>
            <span>Address family pool to enumerate and probe</span>
          </div>
          <Segmented
            label="IP family"
            value={ipScan}
            options={[
              { value: "v4", label: "IPv4 Only" },
              { value: "v6", label: "IPv6 Only" },
              { value: "both", label: "Dual-Stack" },
            ]}
            onChange={setIpScan}
            disabled={active}
          />
        </div>

        <div className="setting-row input-row">
          <label>
            <span>Concurrency (Workers)</span>
            <NumberField
              label="Scan concurrency"
              min={1}
              max={2000}
              step={10}
              value={concurrency}
              disabled={active}
              onCommit={setConcurrency}
            />
          </label>
          <label>
            <span>Timeout (ms)</span>
            <NumberField
              label="Per-probe timeout in milliseconds"
              min={100}
              max={30000}
              step={100}
              value={timeoutMs}
              disabled={active}
              onCommit={setTimeoutMs}
            />
          </label>
        </div>

        <div className="setting-row">
          <div>
            <strong>Handshake Obfuscation</strong>
            <span>{protocol === "masque-h2" ? "UDP noise is not applicable for H2 (TCP)" : "Anti-DPI noise profile injected during probe"}</span>
          </div>
          <select
            aria-label="Obfuscation noise profile for probes"
            className="tactical-select"
            value={protocol === "masque-h2" ? "off" : noize}
            disabled={active || protocol === "masque-h2"}
            onChange={(e) => setNoize(e.target.value)}
          >
            <option value="off">Off — no noise</option>
            <option value="light">Light — low noise</option>
            <option value="medium">Medium — default</option>
            <option value="high">High — stronger</option>
            <option value="max">Max — highest noise</option>
            <option value="custom">Custom — manual values</option>
          </select>
        </div>

        {/* Scan Progress Bar & Live Telemetry */}
        {(scanState.active || scanState.scanned > 0) && (
          <div className="scan-inline-progress">
            <div className="scan-progress-header">
              <span className="progress-label">PROBE PROGRESS</span>
              <span className="progress-metric tabular-nums">{progressPct}% ({scanState.scanned.toLocaleString()} / {scanState.total.toLocaleString()})</span>
            </div>
            <div
              className="scan-progress-bar-bg"
              role="progressbar"
              aria-label="Scan progress"
              aria-valuemin={0}
              aria-valuemax={scanState.total}
              aria-valuenow={scanState.scanned}
            >
              <div
                className={`scan-progress-bar-fill ${active ? "active-glow" : ""}`}
                style={{ width: `${progressPct}%` }}
              />
            </div>
            <div className="scan-inline-stats">
              <span className="stat-chip-pill workers">{scanState.concurrency} Workers Active</span>
              <span className="stat-chip-pill hits">{scanState.working} Healthy Gateways</span>
              {scanState.bestRtt && <span className="stat-chip-pill best">Best: {scanState.bestRtt}</span>}
            </div>
          </div>
        )}

        {/* Master Scan CTA Button */}
        <div className="scanner-action-bar">
          {!active ? (
            <button
              type="button"
              className="primary-cta connect"
              onClick={startScan}
              disabled={busy}
            >
              <Zap size={18} aria-hidden="true" />
              <span>{busy ? "Engaging Scanner Engine…" : "Start Standalone Edge Scan"}</span>
            </button>
          ) : (
            <button
              type="button"
              className="primary-cta disconnect"
              onClick={stopScan}
            >
              <X size={18} aria-hidden="true" />
              <span>Halt Active Probe</span>
            </button>
          )}
        </div>
      </section>

      {/* ─── Discovered Endpoints Section ─────────────────────────────────── */}
      <section className="discovered-panel">
        <div className="section-heading">
          <div>
            <p>TELEMETRY RESULTS</p>
            <h3>Discovered Gateways ({endpoints.length})</h3>
          </div>
          <Network size={20} aria-hidden="true" />
        </div>

        {endpoints.length === 0 ? (
          <div className="empty-logs">
            <Search size={28} aria-hidden="true" />
            <strong>No edge gateways discovered yet</strong>
            <span>Launch a standalone scan above to locate the fastest Cloudflare IP candidates.</span>
          </div>
        ) : (
          <div className="discovered-list">
            {endpoints.map((item) => {
              const { tierClass, badgeText } = getRttTier(item.rttMs);
              return (
                <div className="discovered-row" key={item.addr}>
                  <div className="discovered-info">
                    <CopyIpButton addr={item.addr} />
                    <code className="tabular-nums">{item.addr}</code>
                    <span className="discovered-proto">{item.protocol.toUpperCase()}</span>
                  </div>

                  <div className="discovered-actions">
                    <span className={`rtt-badge ${tierClass}`} title={badgeText}>
                      <span className="rtt-dot" />
                      <span className="rtt-val tabular-nums">{item.rtt}</span>
                    </span>
                    <button
                      type="button"
                      className="connect-direct-btn"
                      disabled={connectBusy || active}
                      title={active ? "Stop the active scan before connecting" : "Lock this endpoint for tunnel connection"}
                      onClick={() => connectDirect(item)}
                    >
                      Connect Direct
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </section>
    </div>
  );
}
