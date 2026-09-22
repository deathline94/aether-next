export type View = "home" | "scanner" | "settings" | "logs";
export type Status = "disconnected" | "connecting" | "connected" | "error";
export type LogFilter = "milestones" | "hits" | "errors" | "raw";

export interface DiscoveredEndpoint {
  addr: string;
  rtt: string;
  rttMs: number;
  protocol: string;
}

export interface ScanState {
  active: boolean;
  mode: string;
  scanned: number;
  total: number;
  concurrency: number;
  working: number;
  bestRtt: string | null;
  phase: string;
}

export const initialScanState: ScanState = {
  active: false,
  mode: "balanced",
  scanned: 0,
  total: 0,
  concurrency: 0,
  working: 0,
  bestRtt: null,
  phase: "Idle",
};

export type Settings = {
  protocol: "masque" | "wireguard" | "gool";
  transport: "h2" | "h3";
  scanMode: "turbo" | "balanced" | "thorough" | "stealth";
  ipVersion: "v4" | "v6" | "both";
  noize: string;
  noizeJc: number;
  noizeJmin: number;
  noizeJmax: number;
  noizeIntervalMs: number;
  routingMode: "system-proxy" | "proxy-only" | "tun";
  socksPort: number;
  httpPort: number;
  startMinimized: boolean;
  launchAtLogin: boolean;
  enginePath: string;
  /** Forced peer endpoint (set by Scanner "Connect Direct"). */
  peer: string;
  /** H3 anti-DPI: split the QUIC Initial ClientHello across two datagrams. */
  quicInitialFrag: boolean;
  /** H3 anti-DPI: bytes of ClientHello in the first Initial (16–512). */
  quicInitialFragSize: number;
  endpointPreset?: "warp" | "gool";
};

export type RuntimeState = {
  status: Status;
  detail: string;
  pid: number | null;
  endpoint: string | null;
};

/** The statuses the UI has copy, colours and a beacon for. */
const STATUSES: readonly Status[] = ["disconnected", "connecting", "connected", "error"];

export function isStatus(value: unknown): value is Status {
  return typeof value === "string" && (STATUSES as readonly string[]).includes(value);
}

/**
 * The `session://state` payload guard.
 *
 * The listener used to do `setRuntime(event.payload)` on whatever arrived. One
 * shell build emitting a fifth status, or a truncated payload, was then read
 * through `heroCopy[status]` — an index that misses returns `undefined`, the next
 * property access throws, and a state *update* took the whole window down.
 * Returning `null` means "this is not a state", so the caller keeps the last one
 * it understood instead of rendering a shape it cannot.
 */
export function parseRuntimeState(payload: unknown): RuntimeState | null {
  if (typeof payload !== "object" || payload === null) return null;
  const raw = payload as Partial<Record<keyof RuntimeState, unknown>>;
  if (!isStatus(raw.status)) return null;
  return {
    status: raw.status,
    detail: typeof raw.detail === "string" ? raw.detail : "",
    pid: typeof raw.pid === "number" && Number.isFinite(raw.pid) ? raw.pid : null,
    endpoint: typeof raw.endpoint === "string" ? raw.endpoint : null,
  };
}

export type LogEntry = {
  id: number;
  level: "info" | "warn" | "error";
  message: string;
  /** Epoch milliseconds — formatted at render time so exports keep the date. */
  ts: number;
  /**
   * Set when this line *is* a hit rather than a line that mentions one: the
   * address+protocol the structured event named, verbatim. `useLogs` dedupes on
   * it, so a hit is counted per endpoint and not per prose line and nothing has
   * to guess at the wording. Lines the engine wrote as text carry no key of their
   * own and fall back to the narrow prose rule in `hitKeyOf`.
   */
  hitKey?: string;
};

/**
 * What a caller hands to `appendLog`: an entry without the store's own id and
 * timestamp. `hitKey` is optional — pass it when the line *is* a fact about one
 * endpoint (a structured scan event) instead of leaving the log to recognise it
 * from prose. See `useLogs.hitKeyOf`.
 */
export type LogInput = Pick<LogEntry, "level" | "message"> & { hitKey?: string };

export function formatLogTime(ts: number): string {
  return new Date(ts).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

export const defaults: Settings = {
  protocol: "masque",
  transport: "h2",
  scanMode: "balanced",
  ipVersion: "v4",
  noize: "off",
  noizeJc: 5,
  noizeJmin: 50,
  noizeJmax: 128,
  noizeIntervalMs: 0,
  routingMode: "system-proxy",
  socksPort: 1819,
  httpPort: 1820,
  startMinimized: false,
  launchAtLogin: false,
  enginePath: "",
  peer: "",
  quicInitialFrag: false,
  quicInitialFragSize: 96,
};

export const initialRuntime: RuntimeState = {
  status: "disconnected",
  detail: "Ready",
  pid: null,
  endpoint: null,
};

/**
 * Structured scan event emitted by the engine in scan-only mode, as the shell
 * re-keys it onto `scan://event` (camelCase on every arm).
 *
 * `scan_done` used to list a `working` count nothing sent: the engine's terminal
 * event names the endpoint it settled on and that count rides `scan_progress`, so
 * reading it here meant the "0 found" verdict depended on a field that was always
 * missing. `scan_failed` is sent — the shell emits it when the process ends
 * without saying so (see `scan_terminal_event`), which is why the UI keeps an arm
 * for it.
 */
/**
 * Which scan run produced an event. The shell stamps every `scan://event`
 * with it: a stop/start pair can leave the previous run's terminal event in
 * flight, and without the id a stale "found nothing" lands on a live scan and
 * deactivates it.
 */
export type ScanRunScope = { runId?: string };

export type ScanEvent =
  | ({ type: "scan_start"; mode: string; total: number; concurrency: number } & ScanRunScope)
  | ({ type: "scan_progress"; scanned: number; total: number; working: number } & ScanRunScope)
  | ({ type: "scan_hit"; addr: string; rtt: string; rttMs: number; protocol: string } & ScanRunScope)
  | (
      {
        type: "scan_done";
        addr: string;
        rtt: string;
        protocol: string;
        /**
         * Measured RTT of the endpoint the scan settled on. `null`/absent means
         * the engine measured nothing — a forced peer, for instance — and "not
         * measured" is rendered as exactly that, never as `()` or as 0 ms.
         */
        bestRttMs?: number | null;
      } & ScanRunScope
    )
  | ({ type: "scan_failed"; message: string } & ScanRunScope);
