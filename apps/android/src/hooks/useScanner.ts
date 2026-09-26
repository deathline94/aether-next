import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { invoke, listen } from "../bridge";
import { initialScanState } from "../types";
import { parseScanEvent } from "../scanEventPayload";
import { errorMessage } from "../ipcError";
// One home for the ladder and for the rule that reads it: this pair of front-ends
// used to keep their own clamps, and this one had none on its send path at all.
import {
  clampConcurrency,
  effectiveScanTimeout,
  isEndpointForProtocol,
  SCAN_MAX_DISCOVERED,
  SCAN_PHASES,
  scanVerdict,
  SCAN_DEFAULT_CONCURRENCY,
} from "@aether/ui";
import { hitAddressKey } from "@aether/ui/logs";
import type { IpFamily, ScanProtocol } from "@aether/ui/enums";
import type { DiscoveredEndpoint, LogInput, ScanState } from "../types";

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
  const [protocol, setProtocol] = useState<ScanProtocol>("masque-h3");
  const [ipScan, setIpScan] = useState<IpFamily>("v4");
  // What the user asked for, which is not necessarily what this protocol can run.
  // The field used to open at 250 — a cheap H2/WireGuard width — on a scan that
  // opens on H3 and stops at 16, so the control advertised lanes the engine would
  // never put on the wire, and the first `scan_start` frame contradicted the number
  // still printed in the box.
  const [requestedConcurrency, setRequestedConcurrency] = useState(SCAN_DEFAULT_CONCURRENCY);
  // One resolution, shown and sent: the panel gets *this* as `concurrency`, the log
  // line prints it and the request carries it, so no path can name a lane count the
  // others do not run. Re-clamping an already clamped number is a no-op, which is
  // what makes the three safe to read from the same value.
  const effectiveConcurrency = useMemo(
    () => clampConcurrency(requestedConcurrency, protocol),
    [requestedConcurrency, protocol],
  );
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
  /**
   * One log line per distinct unreadable frame, not one per frame: the shell re-emits
   * on every tick of a run, and a console full of the same complaint hides the scan.
   * The same rule `useRuntime` applies to a rejected `session://state`.
   */
  const rejectedEvents = useRef(new Set<string>());
  // Single source of truth — buttons and progress UI must never disagree.
  const active = scanState.active;

  useEffect(() => {
    let disposed = false;
    // `unknown`, not `ScanEvent`: the cast was the whole lie of this subscription — it
    // asserted a shape nobody checked and let a frame with a string `rttMs` into the
    // sort that orders the hit list, and the progress card, by that number.
    listen<unknown>("scan://event", (event) => {
      if (disposed) return;
      const parsed = parseScanEvent(event.payload);
      if (!parsed.ok) {
        // The recoverable path, the one `parseRuntimeState` already takes: say it once
        // per distinct shape and keep showing the last event that could be read. A
        // malformed frame is not evidence that the run ended, so state is untouched.
        if (!rejectedEvents.current.has(parsed.reason)) {
          rejectedEvents.current.add(parsed.reason);
          appendLog({
            level: "error",
            message: `Ignored a scan event the interface cannot read (${parsed.reason}); showing the last one it could.`,
          });
        }
        return;
      }
      const ev = parsed.event;
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
            phase: SCAN_PHASES.probing,
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
            // Same bound as the desktop twin: full buffer + slower-than-stored
            // hit is dropped, not appended.
            const worst = current[current.length - 1];
            if (current.length >= SCAN_MAX_DISCOVERED && worst && ev.rttMs >= worst.rttMs) {
              break;
            }
            const next = [...current, { addr: ev.addr, rtt: ev.rtt, rttMs: ev.rttMs, protocol: ev.protocol }].sort(
              (a, b) => a.rttMs - b.rttMs,
            ).slice(0, SCAN_MAX_DISCOVERED);
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
          setScanState((prev) => ({ ...prev, active: false, phase: SCAN_PHASES.failed }));
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
    // Preserve results from other protocols; only reset rows belonging to the active protocol.
    const preserved = endpointsRef.current.filter((e) => !isEndpointForProtocol(e.protocol, protocol));
    endpointsRef.current = preserved;
    setEndpoints(preserved);
    setScanState({ ...initialScanState, active: true, phase: SCAN_PHASES.starting });
    // Both values are resolved *before* anything is announced, so the log line
    // describes the run the engine will perform rather than the numbers the fields
    // happened to hold: `concurrency` used to be printed and sent raw while the
    // shell clamped it, which is how "concurrency=1500" could end up as 500 lanes.
    // They are the resolved values the fields above show, not a second clamp that
    // could disagree with the first.
    const workers = effectiveConcurrency;
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
      setScanState((prev) => ({ ...prev, active: false, phase: SCAN_PHASES.error }));
    } finally {
      setBusy(false);
    }
  }, [busy, active, protocol, ipScan, effectiveConcurrency, timeoutMs, noize, running, appendLog, clearLogs]);

  const stopScan = useCallback(async () => {
    // Ask the engine first; report "Stopped" regardless so the UI never sticks.
    try {
      await invoke("stop_scan");
      appendLog({ level: "info", message: "Scan stopped." });
    } catch (error) {
      appendLog({ level: "warn", message: `Stop scan: ${errorMessage(error)}` });
    } finally {
      setScanState((prev) => ({ ...prev, active: false, phase: SCAN_PHASES.stopped }));
    }
  }, [appendLog]);

  return {
    protocol, setProtocol,
    ipScan, setIpScan,
    // The lanes this protocol runs, which is the number the field shows; the setter
    // still takes what the user asks for, so a wider transport can carry it.
    concurrency: effectiveConcurrency, setConcurrency: setRequestedConcurrency,
    timeoutMs, setTimeoutMs,
    noize, setNoize,
    endpoints, active, scanState, busy,
    startScan, stopScan,
  };
}
