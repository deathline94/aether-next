import { Check, Copy, Network, Radio, Search, SlidersHorizontal, X, Zap } from "lucide-react";
import { memo, useEffect, useId, useMemo, useRef, useState } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import type { DiscoveredEndpoint, DisplayedScanState, NoizeProfile } from "../types";
import { NOIZE_PROFILES, SCAN_PROTOCOL_OPTIONS, oneOf } from "@aether/ui/enums";
import type { IpFamily, ScanProtocol, ScanProtocolFilter } from "@aether/ui/enums";
import {
  nextOptionIndex,
  SCAN_MIN_CONCURRENCY,
  SCAN_MAX_TIMEOUT_MS,
  isEndpointForProtocol,
  rttBadge,
  scanConcurrencyCeiling,
  scanTimeoutFloor,
} from "@aether/ui";
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
  /** Whether a tunnel session is live: a scan start disconnects it, so the CTA
      becomes a two-step confirm instead of dropping the VPN on one click. */
  running: boolean;
  startScan: () => void;
  stopScan: () => void;
  connectDirect: (item: DiscoveredEndpoint) => void;
  connectBusy: boolean;
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

/** Row height before it is measured: 12+12 padding, one line of content, 2 px of
 *  border, plus the gap the list used to express with `gap`. */
const ESTIMATED_ENDPOINT_PX = 56;
const ENDPOINT_GAP_PX = 10;

function ScannerTabImpl({
  protocol, setProtocol,
  ipScan, setIpScan,
  concurrency, setConcurrency,
  timeoutMs, setTimeoutMs,
  noize, setNoize,
  endpoints, active, scanState, busy,
  running,
  startScan, stopScan,
  connectDirect, connectBusy,
}: ScannerTabProps) {
  const [protoFilter, setProtoFilter] = useState<ScanProtocolFilter>("all");
  // First click arms the confirmation, second commits. The scan start silently
  // `disconnect`s a live tunnel, which used to drop the VPN on a single press
  // with no surface beyond one log line.
  const [confirmTunnelDrop, setConfirmTunnelDrop] = useState(false);
  useEffect(() => {
    if (active || !running) setConfirmTunnelDrop(false);
  }, [active, running]);
  const resultsId = useId();
  const tabRefs = useRef<(HTMLButtonElement | null)[]>([]);
  const listRef = useRef<HTMLDivElement | null>(null);

  const progressPct = scanState.total > 0
    ? Math.min(100, Math.round((scanState.scanned / scanState.total) * 100))
    : 0;

  // One pass over the run's rows per change instead of four: the counts, the
  // filter and the list rendering each walked the array separately, so a 2 000
  // endpoint result re-derived the same buckets on every keystroke in the panel.
  const { h3Count, h2Count, wgCount } = useMemo(() => {
    let h3 = 0;
    let h2 = 0;
    let wg = 0;
    for (const e of endpoints) {
      // The shared predicate — the same one the filter and the scan start use —
      // so counting, filtering and preservation can never disagree.
      if (isEndpointForProtocol(e.protocol, "masque-h3")) h3 += 1;
      if (isEndpointForProtocol(e.protocol, "masque-h2")) h2 += 1;
      if (isEndpointForProtocol(e.protocol, "wireguard")) wg += 1;
    }
    return { h3Count: h3, h2Count: h2, wgCount: wg };
  }, [endpoints]);

  const filteredEndpoints = useMemo(() => {
    if (protoFilter === "all") return endpoints;
    // The same predicates as the counts above: a row counted under "WireGuard"
    // has to appear when that tab is selected, or the tab lies in one direction
    // or the other. The engine labels the same transport `wg` and `wireguard`.
    const matches = (p: string) =>
      protoFilter === "masque-h3"
        ? p.includes("h3")
        : protoFilter === "masque-h2"
          ? p.includes("h2")
          : p.includes("wireguard") || p.includes("wg");
    return endpoints.filter((e) => matches(e.protocol.toLowerCase()));
  }, [endpoints, protoFilter]);

  const endpointRows = useVirtualizer({
    count: filteredEndpoints.length,
    getScrollElement: () => listRef.current,
    estimateSize: () => ESTIMATED_ENDPOINT_PX,
    overscan: 8,
    // `.discovered-list` pads the scroll container vertically (14px top);
    // without scrollMargin every item's measured offset is off by that much.
    scrollMargin: 14,
  });

  const protoTabs: { id: ScanProtocolFilter; label: string; count: number }[] = useMemo(
    () => [
      { id: "all", label: "All Protocols", count: endpoints.length },
      { id: "masque-h3", label: "MASQUE H3", count: h3Count },
      { id: "masque-h2", label: "MASQUE H2", count: h2Count },
      { id: "wireguard", label: "WireGuard", count: wgCount },
    ],
    [endpoints.length, h3Count, h2Count, wgCount],
  );

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
              // The pool size is unknown until the engine's first progress frame
              // reports it; 0 as the maximum is invalid progressbar semantics
              // (now must be <= max), so omit both bounds until there is one.
              aria-valuemax={scanState.total > 0 ? scanState.total : undefined}
              aria-valuenow={scanState.scanned > 0 ? scanState.scanned : undefined}
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
            <>
              {running && confirmTunnelDrop && (
                <div className="error-banner" role="alert">
                  <div className="error-banner-content">
                    <span>Starting a scan disconnects the active tunnel.</span>
                  </div>
                  <button
                    type="button"
                    className="banner-action"
                    onClick={() => setConfirmTunnelDrop(false)}
                  >
                    Cancel
                  </button>
                </div>
              )}
              <button
                type="button"
                className="primary-cta connect"
                onClick={() => (running && !confirmTunnelDrop ? setConfirmTunnelDrop(true) : startScan())}
                disabled={busy}
              >
                <Zap size={18} aria-hidden="true" />
                <span>
                  {busy
                    ? "Engaging Scanner Engine…"
                    : running && !confirmTunnelDrop
                      ? "Scan (disconnects the VPN) — confirm first"
                      : running
                        ? "Confirm: Disconnect VPN & Scan"
                        : "Start Standalone Edge Scan"}
                </span>
              </button>
            </>
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
      <section className="settings-section" aria-label="Probe Parameters">
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
            options={SCAN_PROTOCOL_OPTIONS}
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

        <div className="setting-row">
          <div className="param-field-block">
            <label htmlFor="field-concurrency-workers">
              <div className="field-meta">
                <strong>Concurrency (Workers)</strong>
                <span className="field-hint">
                  {SCAN_MIN_CONCURRENCY}&ndash;{scanConcurrencyCeiling(protocol)} lanes
                </span>
              </div>
            </label>
            <NumberField
              id="field-concurrency-workers"
              label="Concurrency (workers)"
              min={SCAN_MIN_CONCURRENCY}
              max={scanConcurrencyCeiling(protocol)}
              step={10}
              value={concurrency}
              disabled={active}
              onCommit={setConcurrency}
            />
          </div>
          <div className="param-field-block">
            <label htmlFor="field-timeout-ms">
              <div className="field-meta">
                <strong>Timeout (ms)</strong>
                <span className="field-hint">{scanTimeoutFloor(protocol)}–{SCAN_MAX_TIMEOUT_MS} ms</span>
              </div>
            </label>
            <NumberField
              id="field-timeout-ms"
              label="Timeout (ms)"
              min={scanTimeoutFloor(protocol)}
              max={SCAN_MAX_TIMEOUT_MS}
              step={100}
              value={timeoutMs}
              disabled={active}
              onCommit={setTimeoutMs}
            />
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
          <div
            className="empty-logs"
            // The chips beside this still say they control it: `aria-controls`
            // named `resultsId`, and an empty result dropped the only element that
            // carried that id, so every tab pointed at nothing exactly when the
            // filter had something to report.
            id={resultsId}
            role="tabpanel"
            aria-labelledby={`proto-tab-${protoFilter}`}
            tabIndex={0}
          >
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
            ref={listRef}
            // A hundred rows in a fixed-height panel cannot be reached without this:
            // the list was mouse-only, so PageUp and the arrows scrolled the page
            // behind it instead of the endpoints the tab just promised.
            tabIndex={0}
          >
            {/* The whole result of a deep scan used to be in the DOM at once: a
                thorough run streams hundreds of rows, and each one is a button, a
                copy control and a badge. Only the visible window is mounted now,
                positioned inside a spacer of the full height so the scrollbar still
                describes the whole list. */}
            <div
              style={{ height: endpointRows.getTotalSize(), position: "relative", width: "100%" }}
            >
              {endpointRows.getVirtualItems().map((row) => {
                const item = filteredEndpoints[row.index];
                if (!item) return null;
                const { tierClass, badgeText, text } = rttBadge(item);
                return (
                  <div
                    key={`${item.addr}|${item.protocol}`}
                    data-index={row.index}
                    ref={endpointRows.measureElement}
                    style={{
                      position: "absolute",
                      top: 0,
                      left: 0,
                      width: "100%",
                      transform: `translateY(${row.start}px)`,
                      // The 10 px gap between rows lives inside the measured box, so
                      // the stride the list is laid out on is the stride the rows
                      // actually occupy.
                      paddingBottom: ENDPOINT_GAP_PX,
                    }}
                  >
                    <div className="discovered-row">
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
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </section>
    </div>
  );
}

// Memoized at the boundary: the log and scan buffers live in App, so every
// appended line re-rendered all four tabs even when nothing they read changed.
export const ScannerTab = memo(ScannerTabImpl);
