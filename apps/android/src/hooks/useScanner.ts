import { useCallback, useEffect, useRef, useState } from "react";
import { invoke, listen } from "../bridge";
import { initialScanState, effectiveScanTimeout, clampConcurrency } from "../types";
import { errorMessage } from "../ipcError";
import { scanVerdict } from "../../../../packages/ui/src";
import { hitAddressKey } from "../../../../packages/ui/src/logs";
import type { DiscoveredEndpoint, LogInput, ScanEvent, ScanState } from "../types";

/**
 * Owns standalone-scanner state. Progress/hits arrive as structured
 * `scan://event` messages forwarded by the native bridge - no log-string
 * parsing. `running` lets us disconnect an active tunnel before scanning.
 */
export function useScanner(
  appendLog: (entry: LogInput) => void,
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
  // The run this window started. Events from any other run are dropped rather
  // than merged, so a late terminal event from a cancelled scan cannot end the
  // one that is actually running.
  const runIdRef = useRef<string>("");
  /**
   * The run's rows, as a ref as well as state: the `bestRtt` the progress card shows
   * has to be derived from the whole list at the moment a hit lands, and reading
   * `endpoints` from inside the listener's closure would read the list as of the
   * render that installed it.
   */
  const endpointsRef = useRef<DiscoveredEndpoint[]>([]);
  // Single source of truth — buttons and progress UI must never disagree.
  const active = scanState.active;

  useEffect(() => {
    let disposed = false;
    listen<ScanEvent>("scan://event", (event) => {
      if (disposed) return;
      const ev = event.payload;
      if (ev.runId && ev.runId !== runIdRef.current) return;
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
          // The engine's own tally. Nothing else writes `working`: the per-hit
          // `prev.working + 1` this replaces used to race the progress frame — the
          // list grew by a hit, the next frame overwrote the count with a number that
          // is only right as of fifty probes ago — so the "N healthy" chip oscillated
          // downwards while the scan was still finding endpoints.
          setScanState((prev) => ({ ...prev, scanned: ev.scanned, total: ev.total, working: ev.working }));
          break;
        case "scan_hit": {
          // The log reads this key rather than recognising the hit from prose, so
          // the scanner's count and the Activity tab agree by construction and
          // survive an engine that rewords its own lines. This case used to log
          // nothing at all, so "Hits" on the phone showed only whatever prose the
          // engine happened to emit rather than the endpoints that answered.
          appendLog({
            level: "info",
            message: `Working endpoint ${ev.addr}${ev.protocol ? ` (${ev.protocol})` : ""}`,
            hitKey: hitAddressKey(ev.addr),
          });
          const current = endpointsRef.current;
          // Keyed on addr + protocol: one address answers the h2 and the h3 handshake
          // and keying on the address alone threw the second one away.
          if (!current.some((e) => e.addr === ev.addr && e.protocol === ev.protocol)) {
            const next = [...current, { addr: ev.addr, rtt: ev.rtt, rttMs: ev.rttMs, protocol: ev.protocol }].sort(
              (a, b) => a.rttMs - b.rttMs,
            );
            endpointsRef.current = next;
            setEndpoints(next);
            // `bestRtt` is derived from the run's own rows, fastest first — not from
            // `ev.rtt || prev.bestRtt`, which kept the first hit's text alive for the
            // rest of the run and showed `0ms` for an honest zero.
            setScanState((prev) => ({ ...prev, bestRtt: next[0]?.rtt ?? prev.bestRtt }));
          }
          break;
        }
        case "scan_done":
          // A run that found nothing is not a verified route. `scanVerdict` is the
          // shared rule; this fork used to write "Verified" unconditionally.
          setScanState((prev) => ({
            ...prev,
            active: false,
            phase: scanVerdict(endpointsRef.current.length, ev.addr, prev.working),
          }));
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
    }).catch((err) => {
      // Without this the rejection was unhandled and the panel kept offering a
      // scan whose events could never arrive: a failed `listen` is silent, so a
      // run would sit on "Starting" forever with nothing to report.
      appendLog({ level: "error", message: `Scan event listener failed to start: ${errorMessage(err)}` });
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
    // The counters and `bestRtt` restart with the run, so the list has to as well:
    // keeping earlier protocols' rows meant a table of nine under "3 working".
    setEndpoints([]);
    endpointsRef.current = [];
    setScanState({ ...initialScanState, active: true, phase: "Starting" });
    // Both values are resolved *before* anything is announced, so the log line
    // describes the run the engine will perform rather than the numbers the fields
    // happened to hold: `concurrency` used to be printed and sent raw while the
    // shell clamped it, which is how "concurrency=1500" could end up as 500 lanes.
    const workers = clampConcurrency(concurrency, protocol);
    // Same clamp the shell applies (`ScanLimits.clampTimeout`), so what the field
    // shows and what the engine runs are one number.
    const effectiveTimeout = effectiveScanTimeout(protocol, timeoutMs);
    appendLog({
      level: "info",
      message: `Starting standalone scan: ${protocol.toUpperCase()} (concurrency=${workers}, timeout=${effectiveTimeout}ms)`,
    });
    try {
      if (running) {
        await invoke("disconnect");
      }
      const runId = crypto.randomUUID();
      runIdRef.current = runId;
      await invoke("scan", { runId, protocol, ipVersion: ipScan, concurrency: workers, timeoutMs: effectiveTimeout, noize });
    } catch (error) {
      appendLog({ level: "error", message: `Scan error: ${errorMessage(error)}` });
      setScanState((prev) => ({ ...prev, active: false, phase: "Error" }));
    } finally {
      setBusy(false);
    }
  }, [busy, active, protocol, ipScan, concurrency, timeoutMs, noize, running, appendLog, clearLogs]);

  const stopScan = useCallback(async () => {
    // Ask the engine first; report "Stopped" regardless so the UI never sticks.
    try {
      await invoke("stop_scan");
      appendLog({ level: "info", message: "Scan stopped." });
    } catch (error) {
      appendLog({ level: "warn", message: `Stop scan: ${errorMessage(error)}` });
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
