import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { useCallback, useEffect, useRef, useState } from "react";
import { initialScanState } from "../types";
import type { DiscoveredEndpoint, LogInput, ScanEvent, ScanState } from "../types";
import { errorMessage } from "../ipcError";
import { hitAddressKey } from "./useLogs";

/**
 * A round-trip that can be shown: the engine's own text, or a measured number
 * formatted. Anything empty or absent is `null`, so a caller keeps the previous
 * value or says nothing rather than storing `""` and printing it.
 */
function rttLike(value: string | number | null | undefined): string | null {
  if (typeof value === "number") return Number.isFinite(value) ? `${value} ms` : null;
  const text = typeof value === "string" ? value.trim() : "";
  return text.length > 0 ? text : null;
}

/**
 * The completion line, without the brackets that used to be empty.
 *
 * The engine's terminal event carries `rtt: ""` whenever it settled on a forced
 * peer instead of a probe it timed, and `best: 1.1.1.1:443 ()` was the result —
 * punctuation standing in for a number nobody measured. `bestRttMs` is the honest
 * channel (absent, never a 0, when nothing was probed), so the order of preference
 * is the engine's own text, then the measured number, then say nothing.
 */
export function scanCompletionMessage(addr: string, rtt: string, bestRttMs?: number | null): string {
  if (!addr) return "Scan complete — no working endpoints found.";
  const measured = rttLike(rtt) ?? rttLike(bestRttMs);
  return measured ? `Scan complete — best: ${addr} (${measured})` : `Scan complete — best: ${addr}`;
}

export function useScanner(
  appendLog: (entry: LogInput) => void,
  running: boolean,
  clearLogs?: () => void,
) {
  const [protocol, setProtocol] = useState<"masque-h3" | "masque-h2" | "wireguard">("masque-h3");
  const [ipScan, setIpScan] = useState<"v4" | "v6" | "both">("v4");
  const [concurrency, setConcurrency] = useState(250);
  // 6s: at or above the engine's expensive-mode (H3/BoringSSL) per-probe floor so
  // the UI default never silently under-budgets QUIC handshake probes.
  const [timeoutMs, setTimeoutMs] = useState(6000);
  const [noize, setNoize] = useState("off");
  const [endpoints, setEndpoints] = useState<DiscoveredEndpoint[]>([]);
  const [scanState, setScanState] = useState<ScanState>(initialScanState);
  const [busy, setBusy] = useState(false);
  const unlistenRef = useRef<(() => void) | null>(null);
  // Single source of truth — buttons and progress UI must never disagree.
  const active = scanState.active;

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
          // The log's Hits filter reads this key rather than recognising the hit
          // from prose, so the scanner's count and the Activity tab's agree by
          // construction and survive an engine that rewords its own lines.
          appendLog({
            level: "info",
            message: `Working endpoint ${ev.addr}${ev.protocol ? ` (${ev.protocol})` : ""}`,
            hitKey: hitAddressKey(ev.addr),
          });
          setEndpoints((prev) => {
            // One IP:port can answer on h2 and on h3; keyed on the address alone the
            // second protocol's hit was discarded as a duplicate of the first.
            if (prev.some((e) => e.addr === ev.addr && e.protocol === ev.protocol)) return prev;
            return [...prev, { addr: ev.addr, rtt: ev.rtt, rttMs: ev.rttMs, protocol: ev.protocol }].sort(
              (a, b) => a.rttMs - b.rttMs,
            );
          });
          break;
        case "scan_done": {
          // The engine's terminal event names the endpoint it settled on; how many
          // answered is what the run's own counter says (`scan_progress` keeps it
          // current), not a field on this event — the `working?` here was always
          // undefined, so the "0 found" verdict rested on `addr` alone.
          setScanState((prev) => ({
            ...prev,
            active: false,
            phase: prev.working > 0 || Boolean(ev.addr) ? "Verified" : "Completed (0 found)",
            bestRtt: (rttLike(ev.rtt) ?? rttLike(ev.bestRttMs)) ?? prev.bestRtt,
          }));
          appendLog({
            level: "info",
            message: scanCompletionMessage(ev.addr, ev.rtt, ev.bestRttMs),
          });
          break;
        }
        case "scan_failed":
          setScanState((prev) => ({ ...prev, active: false, phase: "Failed" }));
          appendLog({ level: "error", message: `Scan failed: ${ev.message}` });
          break;
      }
    }).then((unlisten) => {
      if (disposed) { unlisten(); return; }
      unlistenRef.current = unlisten;
    }).catch((err) => {
      appendLog({ level: "error", message: `Scan event listener failed to start: ${errorMessage(err)}` });
    });
    return () => { disposed = true; unlistenRef.current?.(); };
  }, [appendLog]);

  const startScan = useCallback(async () => {
    if (busy || active) return;
    clearLogs?.();
    setBusy(true);
    // The counters and `bestRtt` restart with the run, so the list has to as well:
    // keeping earlier protocols' rows meant a table of nine under "3 working".
    setEndpoints([]);
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
      appendLog({ level: "error", message: `Scan error: ${errorMessage(error)}` });
      setScanState((prev) => ({ ...prev, active: false, phase: "Error" }));
    } finally {
      setBusy(false);
    }
  }, [busy, active, protocol, ipScan, concurrency, timeoutMs, noize, running, appendLog, clearLogs]);

  const stopScan = useCallback(async () => {
    // Ask the engine first — only report "Stopped" once it actually is.
    try {
      await invoke("stop_scan");
      setScanState((prev) => ({ ...prev, active: false, phase: "Stopped" }));
      appendLog({ level: "info", message: "Scan stopped." });
    } catch (error) {
      // Engine may have already finished; don't leave the UI stuck either way.
      setScanState((prev) => ({ ...prev, active: false, phase: "Stopped" }));
      appendLog({ level: "warn", message: `Stop scan: ${errorMessage(error)}` });
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
