import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { initialScanState } from "../types";
import type {
  DiscoveredEndpoint,
  DisplayedScanState,
  LogInput,
  NoizeProfile,
  ScanEvent,
  ScanState,
} from "../types";
import { errorMessage } from "../ipcError";
import { hitAddressKey } from "./useLogs";
import { SCAN_MAX_CONCURRENCY, SCAN_MIN_CONCURRENCY } from "../../../../packages/ui/src";
import { NOIZE_PROFILES, oneOf } from "../../../../packages/ui/src/enums";
import type { ScanProtocol } from "../../../../packages/ui/src/enums";

/**
 * The noise profile a scan will actually run, which is the one the panel may show.
 *
 * `masque-h2` probes are TCP handshakes: UDP junk frames have nowhere to go, and
 * the select used to read "Off — no noise" while `startScan` forwarded the stored
 * profile regardless. One value, computed here, feeds both the `scan` invoke and
 * the control that displays it, so the label and the wire cannot disagree. The
 * user's own choice survives a transport that cannot carry it.
 */
export function scanNoizeFor(protocol: ScanProtocol, noize: NoizeProfile): NoizeProfile {
  if (protocol === "masque-h2") return "off";
  // A profile the shell does not know is not a profile: send nothing rather than
  // an invented name that fails the scan for a reason nobody can see.
  return oneOf(noize, NOIZE_PROFILES, "off");
}

/** Workers the engine will run, which is the only range worth offering. */
export function clampConcurrency(value: number): number {
  if (!Number.isFinite(value)) return SCAN_MIN_CONCURRENCY;
  return Math.min(SCAN_MAX_CONCURRENCY, Math.max(SCAN_MIN_CONCURRENCY, Math.round(value)));
}

/**
 * A round-trip that can be shown: the engine's own text, or a measured number
 * formatted. Anything empty or absent is `null`, so a caller keeps the previous
 * value or says nothing rather than storing `""` and printing it.
 */
export function rttLike(value: string | number | null | undefined): string | null {
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

/**
 * The round-trip of the fastest row, or `null` when nothing answered.
 *
 * "Best" is a property of the list on screen, not of the last event to arrive. It
 * used to be accumulated in state as `ev.rtt || prev.bestRtt`, which is "the most
 * recent hit's RTT": a 240 ms answer landing after a 12 ms one rewrote the chip to
 * "Best: 240 ms" directly above a table whose first row read 12 ms. Deriving it
 * means the chip cannot disagree with the rows, and a new run that clears the list
 * clears the claim with it.
 */
export function bestRttOf(endpoints: readonly DiscoveredEndpoint[]): string | null {
  let fastest: DiscoveredEndpoint | null = null;
  for (const e of endpoints) {
    if (typeof e.rttMs !== "number" || !Number.isFinite(e.rttMs)) continue;
    if (fastest === null || e.rttMs < fastest.rttMs) fastest = e;
  }
  if (!fastest) return null;
  // The engine's own text wins when it carried one; a measured number is the
  // fallback, and an empty string is neither.
  return rttLike(fastest.rtt) ?? `${fastest.rttMs} ms`;
}

/**
 * The verdict line at the end of a run.
 *
 * `working` arrives on `scan_progress`, which the engine only republishes every
 * fifty probes, so the final batch of hits can be missing from it. A run whose
 * list is non-empty found something whatever the lagging counter says, and an empty
 * list with no address is the honest "0 found" — the Android fork's unconditional
 * `phase: "Verified"` read an empty scan as a verified one (T199).
 */
export function scanVerdict(hitCount: number, addr: string, working: number): string {
  return hitCount > 0 || working > 0 || Boolean(addr) ? "Verified" : "Completed (0 found)";
}

export function useScanner(
  appendLog: (entry: LogInput) => void,
  running: boolean,
  clearLogs?: () => void,
) {
  const [protocol, setProtocol] = useState<ScanProtocol>("masque-h3");
  const [ipScan, setIpScan] = useState<"v4" | "v6" | "both">("v4");
  const [concurrency, setConcurrency] = useState(250);
  // 6s: at or above the engine's expensive-mode (H3/BoringSSL) per-probe floor so
  // the UI default never silently under-budgets QUIC handshake probes.
  const [timeoutMs, setTimeoutMs] = useState(6000);
  const [noize, setNoize] = useState<NoizeProfile>("off");
  const effectiveNoize = useMemo(() => scanNoizeFor(protocol, noize), [protocol, noize]);
  const [endpoints, setEndpoints] = useState<DiscoveredEndpoint[]>([]);
  const [scanState, setScanState] = useState<ScanState>(initialScanState);
  const [busy, setBusy] = useState(false);
  const unlistenRef = useRef<(() => void) | null>(null);
  // Mirror of `endpoints` the event handler reads. The listener is registered once
  // for the component's life, so a closure over `endpoints` would see the empty
  // array forever; a ref gives the handler the list as it actually stands, which is
  // what the dedupe and the end-of-run verdict need.
  const endpointsRef = useRef<DiscoveredEndpoint[]>([]);
  // The run this window started. Events from any other run are dropped rather
  // than merged, so a late terminal event from a cancelled scan cannot end the
  // one that is actually running.
  const runIdRef = useRef<string>("");
  // Single source of truth — buttons and progress UI must never disagree.
  const active = scanState.active;
  // `bestRtt` on the stored state is never read: the chip is the minimum of the
  // rows below it, so it is computed here and nowhere else.
  const displayedScanState = useMemo<DisplayedScanState>(
    () => ({ ...scanState, bestRtt: bestRttOf(endpoints) }),
    [scanState, endpoints],
  );

  // Listen for structured scan events from the Tauri backend
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
            phase: "Probing Pool",
          });
          break;
        case "scan_progress":
          // The engine's own tally. Nothing else writes `working`: the per-hit
          // `prev.working + 1` below used to race this one — the list grew by a hit,
          // the next progress frame overwrote the count with a number that is right
          // as of fifty probes ago — so the "N Healthy Gateways" chip oscillated
          // downwards while a scan was still finding endpoints.
          setScanState((prev) => ({
            ...prev,
            scanned: ev.scanned,
            total: ev.total,
            working: ev.working,
          }));
          break;
        case "scan_hit": {
          // The log's Hits filter reads this key rather than recognising the hit
          // from prose, so the scanner's count and the Activity tab's agree by
          // construction and survive an engine that rewords its own lines.
          appendLog({
            level: "info",
            message: `Working endpoint ${ev.addr}${ev.protocol ? ` (${ev.protocol})` : ""}`,
            hitKey: hitAddressKey(ev.addr),
          });
          // Keyed on addr + protocol: one address can answer the h2 handshake and
          // the h3 one, and keying on the address alone threw the second protocol's
          // hit away as a duplicate of the first — the row kept the protocol and the
          // RTT of whichever transport happened to answer first.
          const current = endpointsRef.current;
          if (current.some((e) => e.addr === ev.addr && e.protocol === ev.protocol)) break;
          const next = [...current, { addr: ev.addr, rtt: ev.rtt, rttMs: ev.rttMs, protocol: ev.protocol }]
            .sort((a, b) => a.rttMs - b.rttMs);
          endpointsRef.current = next;
          setEndpoints(next);
          break;
        }
        case "scan_done": {
          // The engine's terminal event names the endpoint it settled on; how many
          // answered is the run's own list plus the counter `scan_progress` keeps
          // current — not a field on this event, where `working?` was always
          // undefined, so the "0 found" verdict rested on `addr` alone.
          setScanState((prev) => ({
            ...prev,
            active: false,
            phase: scanVerdict(endpointsRef.current.length, ev.addr, prev.working),
            // bestRtt is derived from `endpoints` (see `bestRttOf`), so nothing is
            // written here: a run that displayed rows shows the fastest of them and
            // a run that measured nothing shows no "Best" chip at all.
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
    // Mint the run id before anything is cleared or awaited. This used to happen
    // after `await invoke("disconnect")`, so the outgoing run's terminal event —
    // still stamped with the id the guard was matching — arrived onto the list
    // that had just been cleared for the new run and wrote `active: false` and
    // `phase: "Verified"` onto a scan that had not begun yet.
    const runId = crypto.randomUUID();
    runIdRef.current = runId;
    clearLogs?.();
    setBusy(true);
    // The counters and `bestRtt` restart with the run, so the list has to as well:
    // keeping earlier protocols' rows meant a table of nine under "3 working", and
    // a heading that described the previous scan rather than this one.
    endpointsRef.current = [];
    setEndpoints([]);
    setScanState({ ...initialScanState, active: true, phase: "Starting" });
    // The two values are clamped before they are both announced and sent, so the
    // log line describes the run the engine will actually perform.
    const workers = clampConcurrency(concurrency);
    const timeout = protocol === "masque-h3" ? Math.max(6000, timeoutMs) : Math.max(3000, timeoutMs);
    const noiseProfile = scanNoizeFor(protocol, noize);
    appendLog({
      level: "info",
      message: `Starting standalone scan: ${protocol.toUpperCase()} (concurrency=${workers}, timeout=${timeout}ms, noise=${noiseProfile})`,
    });
    try {
      if (running) {
        await invoke("disconnect");
      }
      await invoke("scan", {
        runId,
        protocol,
        ipVersion: ipScan,
        concurrency: workers,
        timeoutMs: timeout,
        noize: noiseProfile,
      });
    } catch (error) {
      appendLog({ level: "error", message: `Scan error: ${errorMessage(error)}` });
      setScanState((prev) => ({ ...prev, active: false, phase: "Error" }));
    } finally {
      setBusy(false);
    }
  }, [busy, active, protocol, ipScan, concurrency, timeoutMs, noize, running, appendLog, clearLogs]);

  const stopScan = useCallback(async () => {
    // Retire the run id with the run: without this, a stopped scan's stragglers
    // still match and are merged into whichever scan starts next.
    runIdRef.current = "";
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
    noize: effectiveNoize, setNoize,
    endpoints, active, scanState: displayedScanState, busy,
    startScan, stopScan,
  };
}
