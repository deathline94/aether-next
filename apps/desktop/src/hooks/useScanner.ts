import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { useCallback, useEffect, useRef, useState } from "react";
import { initialScanState } from "../types";
import type { DiscoveredEndpoint, ScanEvent, ScanState } from "../types";

export function useScanner(
  appendLog: (entry: { level: "info" | "warn" | "error"; message: string }) => void,
  running: boolean,
) {
  const [protocol, setProtocol] = useState<"masque-h3" | "masque-h2" | "wireguard">("masque-h3");
  const [ipScan, setIpScan] = useState<"v4" | "v6" | "both">("v4");
  const [concurrency, setConcurrency] = useState(250);
  const [timeoutMs, setTimeoutMs] = useState(1000);
  const [endpoints, setEndpoints] = useState<DiscoveredEndpoint[]>([]);
  const [active, setActive] = useState(false);
  const [scanState, setScanState] = useState<ScanState>(initialScanState);
  const [busy, setBusy] = useState(false);
  const unlistenRef = useRef<(() => void) | null>(null);

  // Listen for structured scan events from the Tauri backend
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
          setScanState((prev) => ({
            ...prev,
            scanned: ev.scanned,
            total: ev.total,
            working: ev.working,
          }));
          break;
        case "scan_hit":
          setScanState((prev) => ({
            ...prev,
            working: prev.working + 1,
            bestRtt: ev.rtt || prev.bestRtt,
          }));
          setEndpoints((prev) => {
            if (prev.some((e) => e.addr === ev.addr)) return prev;
            return [...prev, { addr: ev.addr, rtt: ev.rtt, rttMs: ev.rttMs, protocol: ev.protocol }].sort(
              (a, b) => a.rttMs - b.rttMs,
            );
          });
          break;
        case "scan_done":
          setScanState((prev) => ({ ...prev, active: false, phase: "Verified" }));
          setActive(false);
          appendLog({ level: "info", message: `Scan complete — best: ${ev.addr} (${ev.rtt})` });
          break;
        case "scan_failed":
          setScanState((prev) => ({ ...prev, active: false, phase: "Failed" }));
          setActive(false);
          appendLog({ level: "error", message: `Scan failed: ${ev.message}` });
          break;
      }
    }).then((unlisten) => {
      if (disposed) { unlisten(); return; }
      unlistenRef.current = unlisten;
    });
    return () => { disposed = true; unlistenRef.current?.(); };
  }, [appendLog]);

  const startScan = useCallback(async () => {
    if (busy || active) return;
    setBusy(true);
    setActive(true);
    setEndpoints([]);
    setScanState({ ...initialScanState, active: true, phase: "Starting" });
    appendLog({
      level: "info",
      message: `Starting standalone scan: ${protocol.toUpperCase()} (concurrency=${concurrency}, timeout=${timeoutMs}ms)`,
    });
    try {
      if (running) {
        await invoke("disconnect");
        await new Promise((r) => setTimeout(r, 400));
      }
      await invoke("scan", { protocol, ipVersion: ipScan, concurrency, timeoutMs });
    } catch (error) {
      appendLog({ level: "error", message: `Scan error: ${String(error)}` });
      setActive(false);
      setScanState((prev) => ({ ...prev, active: false, phase: "Error" }));
    } finally {
      setBusy(false);
    }
  }, [busy, active, protocol, ipScan, concurrency, timeoutMs, running, appendLog]);

  const stopScan = useCallback(async () => {
    setActive(false);
    try {
      await invoke("stop_scan");
    } catch { /* already stopped */ }
    setScanState((prev) => ({ ...prev, active: false, phase: "Stopped" }));
    appendLog({ level: "info", message: "Scan stopped." });
  }, [appendLog]);

  return {
    protocol, setProtocol,
    ipScan, setIpScan,
    concurrency, setConcurrency,
    timeoutMs, setTimeoutMs,
    endpoints, active, scanState, busy,
    startScan, stopScan,
  };
}
