import { Search, X, Zap, Radio } from "lucide-react";
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
  return (
    <div className="scanner-view">
      <section className="settings-section">
        <div className="section-heading">
          <div>
            <p>STANDALONE ENGINE PROBER</p>
            <h3>Custom IP Scanner</h3>
          </div>
          <Search size={20} aria-hidden="true" />
        </div>

        <div className="setting-row">
          <div>
            <strong>Target Protocol</strong>
            <span>Service engine to probe Cloudflare edge IPs for</span>
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
            <span>Address family pool to enumerate &amp; sample</span>
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
            <span>Concurrency (Probes)</span>
            <NumberField
              label="Scan concurrency"
              min={1}
              max={2000}
              value={concurrency}
              disabled={active}
              onCommit={setConcurrency}
            />
          </label>
          <label>
            <span>Per-Probe Timeout (ms)</span>
            <NumberField
              label="Per-probe timeout in milliseconds"
              min={100}
              max={30000}
              value={timeoutMs}
              disabled={active}
              onCommit={setTimeoutMs}
            />
          </label>
        </div>

        <div className="setting-row">
          <div>
            <strong>Obfuscation</strong>
            <span>{protocol === "masque-h2" ? "Not applicable for H2 (TCP)" : "Noise profile applied to probe handshakes"}</span>
          </div>
          <select
            aria-label="Obfuscation noise profile for probes"
            value={protocol === "masque-h2" ? "off" : noize}
            disabled={active || protocol === "masque-h2"}
            onChange={(e) => setNoize(e.target.value)}
          >
            <option value="off">Off — no noise</option>
            <option value="light">Light — low noise</option>
            <option value="medium">Medium — default</option>
            <option value="high">High — stronger</option>
            <option value="max">Max — highest noise</option>
          </select>
        </div>

        {/* Scan progress bar */}
        {(scanState.active || scanState.scanned > 0) && (
          <div className="scan-inline-progress">
            <div
              className="scan-progress-bar-bg"
              role="progressbar"
              aria-label="Scan progress"
              aria-valuemin={0}
              aria-valuemax={scanState.total}
              aria-valuenow={scanState.scanned}
            >
              <div
                className="scan-progress-bar-fill"
                style={{
                  width: scanState.total > 0
                    ? `${Math.min(100, Math.round((scanState.scanned / scanState.total) * 100))}%`
                    : "0%",
                }}
              />
            </div>
            <div className="scan-inline-stats">
              <span>{scanState.scanned.toLocaleString()} / {scanState.total.toLocaleString()} probed</span>
              <span>{scanState.working} working</span>
              {scanState.bestRtt && <span>best: {scanState.bestRtt}</span>}
              {!scanState.active && <span className="scan-phase-badge">{scanState.phase}</span>}
            </div>
          </div>
        )}

        <div className="scanner-action-bar">
          {!active ? (
            <button
              type="button"
              className="primary-cta connect"
              onClick={startScan}
              disabled={busy}
            >
              <Zap size={18} aria-hidden="true" />
              <span>{busy ? "Starting…" : "Start Standalone Scan"}</span>
            </button>
          ) : (
            <button
              type="button"
              className="primary-cta disconnect"
              onClick={stopScan}
            >
              <X size={18} aria-hidden="true" />
              <span>Stop Scan</span>
            </button>
          )}
        </div>
      </section>

      <section className="discovered-panel">
        <div className="section-heading">
          <div>
            <p>DISCOVERED ENDPOINTS</p>
            <h3>Healthy Gateways ({endpoints.length})</h3>
          </div>
          <Radio size={20} aria-hidden="true" />
        </div>

        {endpoints.length === 0 ? (
          <div className="empty-logs">
            <Search size={26} aria-hidden="true" />
            <strong>No endpoints discovered yet</strong>
            <span>Click "Start Standalone Scan" to probe healthy edge IPs.</span>
          </div>
        ) : (
          <div className="discovered-list">
            {endpoints.map((item) => (
              <div className="discovered-row" key={item.addr}>
                <div className="discovered-info">
                  <code>{item.addr}</code>
                  <span className="discovered-proto">{item.protocol}</span>
                </div>
                <div className="discovered-actions">
                  <span className={`rtt-badge ${item.rttMs <= 50 ? "fast" : item.rttMs <= 120 ? "mid" : "slow"}`}>
                    {item.rtt}
                  </span>
                  <button
                    type="button"
                    className="connect-direct-btn"
                    disabled={connectBusy || active}
                    title={active ? "Stop the scan before connecting" : undefined}
                    onClick={() => connectDirect(item)}
                  >
                    Connect Direct
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </section>
    </div>
  );
}
