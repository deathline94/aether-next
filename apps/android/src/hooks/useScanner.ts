import { useCallback, useEffect, useRef, useState } from "react";
import { invoke, listen } from "../bridge";
import { initialScanState } from "../types";
import type { DiscoveredEndpoint, ScanEvent, ScanState } from "../types";

function isProtocolMatch(endpointProtocol: string, scanProtocol: string): boolean {
  const norm = (endpointProtocol || "").toLowerCase();
  if (scanProtocol === "masque-h3") return norm.includes("h3");
  if (scanProtocol === "masque-h2") return norm.includes("h2");
  if (scanProtocol === "wireguard") return norm.includes("wireguard") || norm.includes("wg");
  return false;
}

/**
 * Owns standalone-scanner state. Progress/hits arrive as structured
 * `scan://event` messages forwarded by the native bridge — no log-string
 * parsing. `running` lets us disconnect an active tunnel before scanning.
 */
export function useScanner(
  appendLog: (entry: { level: "info" | "warn" | "error"; message: string }) => void,
  running: boolean,
  clearLogs?: () => void,
) {
  const [protocol, setProtocol] = useState<"masque-h3" | "masque-h2" | "wireguard">("masque-h3");
  const [ipScan, setIpScan] = useState<"v4" | "v6" | "both">("v4");
  const [concurrency, setConcurrency] = useState(250);
  const [timeoutMs, setTimeoutMs] = useState(6000);
  const [noize, setNoize] = useState("off");
  const [endpoints, setEndpoints] = useState<DiscoveredEndpoint[]>([]);
  const [scanState, setScanState] = useState<ScanState>(initialScanState);
  const [busy, setBusy] = useState(false);
  const unlistenRef = useRef<(() => void) | null>(null);
  // Single source of truth — buttons and progress UI must never disagree.
  const active = scanState.active;

  useEffect(() => {
    let disposed = false;
    listen<ScanEvent>("scan://event", (event) => {
      if (disposed) return;
      const ev = event.payload;
      switch (ev.type) {
        case "scan_start":
          setScanState({
            active: true,
            mode: ev.mode,
            total: ev.total,
            concurrency: ev.concurrency,
            scanned: 0,
            working: 0,
            bestRtt: null,
            phase: "Probing Pool",
          });
          break;
        case "scan_progress":
          setScanState((prev) => ({ ...prev, scanned: ev.scanned, total: ev.total, working: ev.working }));
          break;
        case "scan_hit":
          setScanState((prev) => ({ ...prev, working: prev.working + 1, bestRtt: ev.rtt || prev.bestRtt }));
          setEndpoints((prev) => {
            if (prev.some((e) => e.addr === ev.addr)) return prev;
            return [...prev, { addr: ev.addr, rtt: ev.rtt, rttMs: ev.rttMs, protocol: ev.protocol }].sort(
              (a, b) => a.rttMs - b.rttMs,
            );
          });
          break;
        case "scan_done":
          setScanState((prev) => ({ ...prev, active: false, phase: "Verified" }));
          if (ev.addr) appendLog({ level: "info", message: `Scan complete — best: ${ev.addr} (${ev.rtt})` });
          break;
        case "scan_failed":
          setScanState((prev) => ({ ...prev, active: false, phase: "Failed" }));
          appendLog({ level: "error", message: `Scan failed: ${ev.message}` });
          break;
      }
    }).then((unlisten) => {
      if (disposed) {
        unlisten();
        return;
      }
      unlistenRef.current = unlisten;
    });
    return () => {
      disposed = true;
      unlistenRef.current?.();
    };
  }, [appendLog]);

  const startScan = useCallback(async () => {
    if (busy || active) return;
    clearLogs?.();
    setBusy(true);
    setEndpoints((prev) => prev.filter((e) => !isProtocolMatch(e.protocol, protocol)));
    setScanState({ ...initialScanState, active: true, phase: "Starting" });
    appendLog({
      level: "info",
      message: `Starting standalone scan: ${protocol.toUpperCase()} (concurrency=${concurrency}, timeout=${timeoutMs}ms)`,
    });
    try {
      if (running) {
        await invoke("disconnect");
      }
      const effectiveTimeout = protocol === "masque-h3" ? Math.max(6000, timeoutMs) : Math.max(3000, timeoutMs);
      await invoke("scan", { protocol, ipVersion: ipScan, concurrency, timeoutMs: effectiveTimeout, noize });
    } catch (error) {
      appendLog({ level: "error", message: `Scan error: ${String(error)}` });
      setScanState((prev) => ({ ...prev, active: false, phase: "Error" }));
    } finally {
      setBusy(false);
    }
  }, [busy, active, protocol, ipScan, concurrency, timeoutMs, noize, running, appendLog]);

  const stopScan = useCallback(async () => {
    // Ask the engine first; report "Stopped" regardless so the UI never sticks.
    try {
      await invoke("stop_scan");
      appendLog({ level: "info", message: "Scan stopped." });
    } catch (error) {
      appendLog({ level: "warn", message: `Stop scan: ${String(error)}` });
    } finally {
      setScanState((prev) => ({ ...prev, active: false, phase: "Stopped" }));
    }
  }, [appendLog]);

  return {
    protocol, setProtocol,
    ipScan, setIpScan,
    concurrency, setConcurrency,
    timeoutMs, setTimeoutMs,
    noize, setNoize,
    endpoints, active, scanState, busy,
    startScan, stopScan,
  };
}
