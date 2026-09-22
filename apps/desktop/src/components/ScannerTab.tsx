import { Check, Copy, Network, Radio, Search, SlidersHorizontal, X, Zap } from "lucide-react";
import { useEffect, useId, useRef, useState } from "react";
import type { DiscoveredEndpoint, DisplayedScanState, NoizeProfile } from "../types";
import { NOIZE_PROFILES, oneOf } from "../../../../packages/ui/src/enums";
import type { IpFamily, ScanProtocol, ScanProtocolFilter } from "../../../../packages/ui/src/enums";
import {
  nextOptionIndex,
  SCAN_MAX_CONCURRENCY,
  SCAN_MIN_CONCURRENCY,
  SCAN_MAX_TIMEOUT_MS,
  SCAN_MIN_TIMEOUT_MS,
} from "../../../../packages/ui/src";
import { rttLike } from "../hooks/useScanner";
import { NumberField, Segmented } from "./ui";

interface ScannerTabProps {
  protocol: ScanProtocol;
  setProtocol: (v: ScanProtocol) => void;
  ipScan: IpFamily;
  setIpScan: (v: IpFamily) => void;
  concurrency: number;
  setConcurrency: (v: number) => void;
  timeoutMs: number;
  setTimeoutMs: (v: number) => void;
  /** The profile the scan will really send — see `scanNoizeFor`. */
  noize: NoizeProfile;
  setNoize: (v: NoizeProfile) => void;
  endpoints: DiscoveredEndpoint[];
  active: boolean;
  scanState: DisplayedScanState;
  busy: boolean;
  startScan: () => void;
  stopScan: () => void;
  connectDirect: (item: DiscoveredEndpoint) => void;
  connectBusy: boolean;
}

/**
 * The four tier classes, in the order the shell's own thresholds put them.
 *
 * `getRttTier(rttMs)` was called on whatever arrived, and its last arm is a
 * fallback: a missing or zero measurement — the documented answer for a forced
 * peer, which the engine never times — came out of it as "HIGH LATENCY", so a
 * blank row was badged as the worst kind. An absent round-trip is now its own
 * state, with no colour to lean the claim.
 */
export function rttBadge(item: DiscoveredEndpoint): { tierClass: string; badgeText: string; text: string } {
  const measured =
    typeof item.rttMs === "number" && Number.isFinite(item.rttMs) && item.rttMs > 0
      ? item.rttMs
      : null;
  // The engine's own wording first, then the number it measured, then nothing.
  const text = rttLike(item.rtt) ?? (measured === null ? null : rttLike(measured));
  if (text === null) return { tierClass: "", badgeText: "NOT MEASURED", text: "not measured" };
  if (measured === null) return { tierClass: "", badgeText: "UNRANKED", text };
  if (measured < 20) return { tierClass: "rtt-ultra-green", badgeText: "ULTRA FAST", text };
  if (measured <= 60) return { tierClass: "rtt-optimal-cyan", badgeText: "OPTIMAL", text };
  if (measured <= 100) return { tierClass: "rtt-acceptable-amber", badgeText: "NORMAL", text };
  return { tierClass: "rtt-high-coral", badgeText: "HIGH LATENCY", text };
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
          // Fallback
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
  const [protoFilter, setProtoFilter] = useState<ScanProtocolFilter>("all");
  const resultsId = useId();
  const tabRefs = useRef<(HTMLButtonElement | null)[]>([]);

  const progressPct = scanState.total > 0
    ? Math.min(100, Math.round((scanState.scanned / scanState.total) * 100))
    : 0;

  const h3Count = endpoints.filter((e) => e.protocol.toLowerCase().includes("h3")).length;
  const h2Count = endpoints.filter((e) => e.protocol.toLowerCase().includes("h2")).length;
  const wgCount = endpoints.filter((e) => e.protocol.toLowerCase().includes("wireguard")).length;

  const filteredEndpoints = endpoints.filter((e) => {
    if (protoFilter === "all") return true;
    if (protoFilter === "masque-h3") return e.protocol.toLowerCase().includes("h3");
    if (protoFilter === "masque-h2") return e.protocol.toLowerCase().includes("h2");
    if (protoFilter === "wireguard") return e.protocol.toLowerCase().includes("wireguard");
    return true;
  });

  const protoTabs: { id: ScanProtocolFilter; label: string; count: number }[] = [
    { id: "all", label: "All Protocols", count: endpoints.length },
    { id: "masque-h3", label: "MASQUE H3", count: h3Count },
    { id: "masque-h2", label: "MASQUE H2", count: h2Count },
    { id: "wireguard", label: "WireGuard", count: wgCount },
  ];

  // `role="tablist"` is a promise about the keyboard: one stop in the tab order,
  // arrows between the tabs, and a panel each tab names. None of that was wired,
  // so the markup claimed a pattern the component did not implement.
  const onTabKeyDown = (event: React.KeyboardEvent<HTMLDivElement>) => {
    const selected = Math.max(0, protoTabs.findIndex((t) => t.id === protoFilter));
    const next = nextOptionIndex(selected, event.key, protoTabs.length);
    if (next === null) return;
    event.preventDefault();
    const tab = protoTabs[next];
    if (!tab) return;
    setProtoFilter(tab.id);
    tabRefs.current[next]?.focus();
  };

  return (
    <div className="scanner-view">
      {/* ─── Scanner Radar HUD Panel ───────────────────────────────────────── */}
      <section className="settings-section radar-hud-container" aria-label="Edge Radar Prober">
        <div className="section-heading">
          <div>
            <p className="panel-eyebrow">STANDALONE ENGINE PROBER</p>
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

      {/* ─── Probe Parameters Configuration Card ───────────────────────────── */}
      <section className="settings-section tactical-panel" aria-label="Probe Parameters">
        <div className="section-heading">
          <div>
            <p className="panel-eyebrow">PROBE PARAMETERS</p>
            <h3>Engine Handshake Configuration</h3>
          </div>
          <SlidersHorizontal size={20} className="panel-head-icon" aria-hidden="true" />
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
          <div className="param-field-block">
            <label>
              <div className="field-meta">
                <strong>Concurrency (Workers)</strong>
                <span className="field-hint">
                  {SCAN_MIN_CONCURRENCY}&ndash;{SCAN_MAX_CONCURRENCY} active
                </span>
              </div>
              <NumberField
                label="Scan concurrency"
                min={SCAN_MIN_CONCURRENCY}
                max={SCAN_MAX_CONCURRENCY}
                step={10}
                value={concurrency}
                disabled={active}
                onCommit={setConcurrency}
              />
            </label>
          </div>
          <div className="param-field-block">
            <label>
              <div className="field-meta">
                <strong>Timeout (ms)</strong>
                <span className="field-hint">{SCAN_MIN_TIMEOUT_MS}–{SCAN_MAX_TIMEOUT_MS} ms</span>
              </div>
              <NumberField
                label="Per-probe timeout in milliseconds"
                min={SCAN_MIN_TIMEOUT_MS}
                max={SCAN_MAX_TIMEOUT_MS}
                step={100}
                value={timeoutMs}
                disabled={active}
                onCommit={setTimeoutMs}
              />
            </label>
          </div>
        </div>

        <div className="setting-row">
          <div>
            <strong>Handshake Obfuscation</strong>
            <span>{protocol === "masque-h2" ? "UDP noise is not applicable for H2 (TCP)" : "Anti-DPI noise profile injected during probe"}</span>
          </div>
          {/* One source of truth: `noize` is the profile `startScan` sends, so the
              label cannot read "Off" while junk frames are still being injected. */}
          <select
            aria-label="Obfuscation noise profile for probes"
            className="tactical-select"
            value={noize}
            disabled={active || protocol === "masque-h2"}
            onChange={(e) => setNoize(oneOf(e.target.value, NOIZE_PROFILES, noize))}
          >
            <option value="off">Off — no noise</option>
            <option value="light">Light — low noise</option>
            <option value="medium">Medium — default</option>
            <option value="high">High — stronger</option>
            <option value="max">Max — highest noise</option>
            <option value="custom">Custom — manual values</option>
          </select>
        </div>
      </section>

      {/* ─── Discovered Endpoints Section ─────────────────────────────────── */}
      <section className="discovered-panel" aria-label="Discovered Endpoints">
        <div className="section-heading">
          <div>
            <p className="panel-eyebrow">TELEMETRY RESULTS</p>
            <h3>Discovered Gateways ({endpoints.length})</h3>
          </div>
          <Network size={20} aria-hidden="true" />
        </div>

        {endpoints.length > 0 && (
          <div className="discovered-proto-dock" role="tablist" aria-label="Filter by protocol" onKeyDown={onTabKeyDown}>
            {protoTabs.map((tab, index) => (
              <button
                key={tab.id}
                ref={(node) => {
                  tabRefs.current[index] = node;
                }}
                type="button"
                role="tab"
                id={`proto-tab-${tab.id}`}
                aria-selected={protoFilter === tab.id}
                aria-controls={resultsId}
                tabIndex={protoFilter === tab.id ? 0 : -1}
                className={`proto-tab ${protoFilter === tab.id ? "active" : ""}`}
                onClick={() => setProtoFilter(tab.id)}
              >
                <span>{tab.label}</span>
                <span className="chip-count tabular-nums">{tab.count}</span>
              </button>
            ))}
          </div>
        )}

        {endpoints.length === 0 ? (
          <div className="empty-logs">
            <Search size={28} aria-hidden="true" />
            <strong>No edge gateways discovered yet</strong>
            <span>Launch a standalone scan above to locate the fastest Cloudflare IP candidates.</span>
          </div>
        ) : filteredEndpoints.length === 0 ? (
          <div className="empty-logs">
            <Search size={28} aria-hidden="true" />
            <strong>No endpoints found for {protoFilter.toUpperCase()}</strong>
            <span>Switch to "All Protocols" or launch another scan targeting this protocol.</span>
          </div>
        ) : (
          <div
            className="discovered-list"
            id={resultsId}
            role="tabpanel"
            aria-labelledby={`proto-tab-${protoFilter}`}
          >
            {filteredEndpoints.map((item) => {
              const { tierClass, badgeText, text } = rttBadge(item);
              return (
                <div className="discovered-row" key={`${item.addr}|${item.protocol}`}>
                  <div className="discovered-info">
                    <CopyIpButton addr={item.addr} />
                    <code className="tabular-nums">{item.addr}</code>
                    <span className="discovered-proto">{item.protocol.toUpperCase()}</span>
                  </div>

                  <div className="discovered-actions">
                    <span className={`rtt-badge ${tierClass}`} title={badgeText}>
                      <span className="rtt-dot" />
                      <span className="tabular-nums">{text}</span>
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

