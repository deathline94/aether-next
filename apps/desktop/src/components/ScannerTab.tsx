import { Network, Radio, Search, SlidersHorizontal, X, Zap } from "lucide-react";
import { memo, useEffect, useId, useMemo, useRef, useState } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import type { DiscoveredEndpoint, DisplayedScanState, NoizeProfile } from "../types";
import { CopyButton, NumberField, Segmented } from "./ui";
import {
  isEndpointForProtocol,
  nextOptionIndex,
  rttBadge,
  SCAN_MAX_TIMEOUT_MS,
  SCAN_MIN_CONCURRENCY,
  scanConcurrencyCeiling,
  scanTimeoutFloor,
} from "@aether/ui";
import { IP_FAMILY_OPTIONS, NOIZE_PROFILES, oneOf, SCAN_PROTOCOL_OPTIONS } from "@aether/ui/enums";
import type { ScanProtocolFilter } from "@aether/ui/enums";

type ProtoFilter = ScanProtocolFilter;
const ESTIMATED_ENDPOINT_PX = 58;
const ENDPOINT_GAP_PX = 8;

interface ScannerTabProps {
  protocol: "masque-h3" | "masque-h2" | "wireguard";
  setProtocol: (v: "masque-h3" | "masque-h2" | "wireguard") => void;
  ipScan: "v4" | "v6" | "both";
  setIpScan: (v: "v4" | "v6" | "both") => void;
  concurrency: number;
  setConcurrency: (v: number) => void;
  timeoutMs: number;
  setTimeoutMs: (v: number) => void;
  noize: NoizeProfile;
  setNoize: (v: NoizeProfile) => void;
  endpoints: DiscoveredEndpoint[];
  active: boolean;
  scanState: DisplayedScanState;
  busy: boolean;
  running: boolean;
  startScan: () => void;
  stopScan: () => void;
  connectDirect: (item: DiscoveredEndpoint) => void;
  connectBusy: boolean;
}

function ScannerTabImpl({
  protocol,
  setProtocol,
  ipScan,
  setIpScan,
  concurrency,
  setConcurrency,
  timeoutMs,
  setTimeoutMs,
  noize,
  setNoize,
  endpoints,
  active,
  scanState,
  busy,
  running,
  startScan,
  stopScan,
  connectDirect,
  connectBusy,
}: ScannerTabProps) {
  const [protoFilter, setProtoFilter] = useState<ProtoFilter>("all");
  const [confirmTunnelDrop, setConfirmTunnelDrop] = useState(false);
  useEffect(() => {
    if (active || !running) setConfirmTunnelDrop(false);
  }, [active, running]);
  const listRef = useRef<HTMLDivElement | null>(null);

  const filteredEndpoints = useMemo(() => {
    if (protoFilter === "all") return endpoints;
    return endpoints.filter((e) => isEndpointForProtocol(e.protocol, protoFilter));
  }, [endpoints, protoFilter]);

  const h3Count = useMemo(
    () => endpoints.filter((e) => isEndpointForProtocol(e.protocol, "masque-h3")).length,
    [endpoints],
  );
  const h2Count = useMemo(
    () => endpoints.filter((e) => isEndpointForProtocol(e.protocol, "masque-h2")).length,
    [endpoints],
  );
  const wgCount = useMemo(
    () => endpoints.filter((e) => isEndpointForProtocol(e.protocol, "wireguard")).length,
    [endpoints],
  );

  const protoTabs: { id: ProtoFilter; label: string; count: number }[] = [
    { id: "all", label: "All Protocols", count: endpoints.length },
    { id: "masque-h3", label: "MASQUE H3", count: h3Count },
    { id: "masque-h2", label: "MASQUE H2", count: h2Count },
    { id: "wireguard", label: "WireGuard", count: wgCount },
  ];

  const resultsId = useId();
  const endpointRows = useVirtualizer({
    count: filteredEndpoints.length,
    getScrollElement: () => listRef.current,
    estimateSize: () => ESTIMATED_ENDPOINT_PX,
    overscan: 8,
  });
  const tabRefs = useRef<(HTMLButtonElement | null)[]>([]);

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

  const progressPct =
    scanState.total > 0 ? Math.min(100, Math.round((scanState.scanned / scanState.total) * 100)) : 0;

  return (
    <div className="scanner-view">
      <section className="nordic-card" aria-label="Edge Scanner">
        <div className="section-heading">
          <div>
            <p className="panel-eyebrow">EDGE DISCOVERY</p>
            <h2 className="nordic-card-title">Cloudflare Edge Scanner</h2>
          </div>
          <span className={`tactical-chip ${active ? "emerald" : ""}`}>
            <Radio size={13} className={active ? "spin-icon" : ""} aria-hidden="true" />
            <span>{scanState.phase}</span>
          </span>
        </div>

        <p className="section-subcopy">
          {active
            ? `Probing Cloudflare ${ipScan.toUpperCase()} ranges across ${scanState.concurrency} workers.`
            : "Test Cloudflare edge ranges directly on your network to locate low-latency endpoints."}
        </p>

        {(scanState.active || scanState.scanned > 0) && (
          <div className="scan-inline-progress">
            <div className="scan-progress-header">
              <span>Progress</span>
              <span className="tabular-nums">
                {progressPct}% ({scanState.scanned.toLocaleString()} / {scanState.total.toLocaleString()})
              </span>
            </div>
            <div
              className="scan-progress-bar-bg"
              role="progressbar"
              aria-label="Scan progress"
              aria-valuemin={0}
              aria-valuemax={scanState.total}
              aria-valuenow={scanState.scanned}
            >
              <div className="scan-progress-bar-fill" style={{ width: `${progressPct}%` }} />
            </div>
            <div className="scan-inline-stats">
              <span className="tactical-chip">{scanState.concurrency} Workers</span>
              <span className="tactical-chip emerald">{scanState.working} Working</span>
              {scanState.bestRtt && <span className="tactical-chip cyan">Best: {scanState.bestRtt}</span>}
            </div>
          </div>
        )}

        <div className="scanner-action-bar">
          {!active ? (
            <>
              {running && confirmTunnelDrop && (
                <div className="error-banner" role="alert">
                  <div className="error-banner-content">
                    <span>Starting a scan disconnects the active tunnel.</span>
                  </div>
                  <button type="button" className="banner-action" onClick={() => setConfirmTunnelDrop(false)}>
                    Cancel
                  </button>
                </div>
              )}
              <button
                type="button"
                className="primary-cta"
                onClick={() => (running && !confirmTunnelDrop ? setConfirmTunnelDrop(true) : startScan())}
                disabled={busy}
              >
                <Zap size={16} aria-hidden="true" />
                <span>
                  {busy
                    ? "Starting Scanner…"
                    : running && !confirmTunnelDrop
                      ? "Scan (disconnects tunnel) — confirm first"
                      : running
                        ? "Confirm: Disconnect VPN & Scan"
                        : "Start Standalone Edge Scan"}
                </span>
              </button>
            </>
          ) : (
            <button type="button" className="primary-cta disconnect" onClick={stopScan}>
              <X size={16} aria-hidden="true" />
              <span>Stop Scan</span>
            </button>
          )}
        </div>
      </section>

      <section className="nordic-card" aria-label="Probe Parameters">
        <div className="section-heading">
          <div>
            <p className="panel-eyebrow">PARAMETERS</p>
            <h2 className="nordic-card-title">Scan Configuration</h2>
          </div>
          <SlidersHorizontal size={18} className="panel-head-icon" aria-hidden="true" />
        </div>

        <div className="setting-row">
          <div>
            <strong>Target Protocol</strong>
            <span>Protocol used to verify each candidate IP</span>
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
            <span>Address family pool to probe</span>
          </div>
          <Segmented
            label="IP family"
            value={ipScan}
            options={IP_FAMILY_OPTIONS}
            onChange={setIpScan}
            disabled={active}
          />
        </div>

        <div className="setting-row input-row">
          <div className="param-field-block">
            <label htmlFor="field-concurrency-workers">
              <strong>Concurrency (Workers)</strong>
              <span className="field-hint">
                {SCAN_MIN_CONCURRENCY}–{scanConcurrencyCeiling(protocol)} lanes
              </span>
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
              <strong>Timeout (ms)</strong>
              <span className="field-hint">
                {scanTimeoutFloor(protocol)}–{SCAN_MAX_TIMEOUT_MS} ms
              </span>
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
            <span>
              {protocol === "masque-h2"
                ? "UDP noise is not applicable for H2 (TCP)"
                : "Pre-handshake anti-DPI profile during probes"}
            </span>
          </div>
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

      <section className="nordic-card" aria-label="Discovered Endpoints">
        <div className="section-heading">
          <div>
            <p className="panel-eyebrow">RESULTS</p>
            <h2 className="nordic-card-title">Discovered Gateways ({endpoints.length})</h2>
          </div>
          <Network size={18} className="panel-head-icon" aria-hidden="true" />
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
            <Search size={24} aria-hidden="true" />
            <strong>No endpoints scanned yet</strong>
            <span>Run a scan above to discover reachable low-latency Cloudflare servers.</span>
          </div>
        ) : filteredEndpoints.length === 0 ? (
          <div
            className="empty-logs"
            id={resultsId}
            role="tabpanel"
            aria-labelledby={`proto-tab-${protoFilter}`}
            tabIndex={0}
          >
            <Search size={24} aria-hidden="true" />
            <strong>No endpoints found for {protoFilter.toUpperCase()}</strong>
            <span>Switch to All Protocols or run a scan for this protocol.</span>
          </div>
        ) : (
          <div
            className="discovered-list"
            id={resultsId}
            role="tabpanel"
            aria-labelledby={`proto-tab-${protoFilter}`}
            ref={listRef}
            tabIndex={0}
          >
            <div style={{ height: endpointRows.getTotalSize(), position: "relative", width: "100%" }}>
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
                      paddingBottom: ENDPOINT_GAP_PX,
                    }}
                  >
                    <div className="discovered-row">
                      <div className="discovered-info">
                        <CopyButton value={item.addr} label={`Copy ${item.addr}`} />
                        <code className="font-mono tabular-nums">{item.addr}</code>
                        <span className="tactical-chip">{item.protocol.toUpperCase()}</span>
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
                          title={active ? "Stop the active scan before connecting" : "Connect directly to this endpoint"}
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

export const ScannerTab = memo(ScannerTabImpl);
