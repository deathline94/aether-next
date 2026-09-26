/**
 * The shared surface lives in `packages/ui` so the desktop and Android shells
 * cannot drift into offering different legal values for the same setting — or,
 * worse, different guards for the same frame. It is reached by relative path:
 * an npm workspace alias would install nothing here (the apps pin their own
 * dependencies) and would hide which file the value actually comes from.
 */
import {
  IP_FAMILIES,
  NOIZE_PROFILES,
  ROUTING_MODES,
  SCAN_MODES,
  TRANSPORTS,
  TUNNEL_PROTOCOLS,
  oneOf,
} from "@aether/ui/enums";
import type {
  IpFamily,
  NoizeProfile,
  RoutingMode,
  ScanMode,
  TunnelProtocol,
  Transport,
} from "@aether/ui/enums";
import { parseRuntimeCore } from "@aether/ui";
import type { RuntimeStatus } from "@aether/ui";
import type { LogLevel } from "@aether/ui/enums";

export type { IpFamily, NoizeProfile, RoutingMode, ScanMode, TunnelProtocol, Transport };

export type View = "home" | "scanner" | "settings" | "logs";
/** The statuses the UI has copy, colours and a beacon for — one list, in `@aether/ui`. */
export type Status = RuntimeStatus;
export type LogFilter = "milestones" | "hits" | "errors" | "raw";

export interface DiscoveredEndpoint {
  addr: string;
  rtt: string;
  rttMs: number;
  protocol: string;
}

/**
 * What the engine reports about a running scan.
 *
 * `bestRtt` is deliberately absent: it is a property of the endpoint rows on
 * screen, computed by the scanner hook (`bestRttOf`) and overlaid here as
 * `DisplayedScanState`. Storing it as well as deriving it is how the "Best" chip
 * ended up naming a slower endpoint than the first row beneath it.
 */
export interface ScanState {
  active: boolean;
  mode: string;
  scanned: number;
  total: number;
  concurrency: number;
  working: number;
  phase: string;
}

export type DisplayedScanState = ScanState & { bestRtt: string | null };

export const initialScanState: ScanState = {
  active: false,
  mode: "balanced",
  scanned: 0,
  total: 0,
  concurrency: 0,
  working: 0,
  phase: "Idle",
};

/**
 * The settings the shell persists. Every field is required: an optional field is
 * a field some panel has to remember to guard, and `settings.ipVersion...` had no
 * guard. A payload that is missing one is corrected by `parseSettings` instead.
 */
export type Settings = {
  protocol: TunnelProtocol;
  transport: Transport;
  scanMode: ScanMode;
  ipVersion: IpFamily;
  noize: NoizeProfile;
  noizeJc: number;
  noizeJmin: number;
  noizeJmax: number;
  noizeIntervalMs: number;
  routingMode: RoutingMode;
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
};

export type RuntimeState = {
  status: Status;
  detail: string;
  pid: number | null;
  endpoint: string | null;
  /**
   * The round-trip of the probe that proved this session's endpoint, in ms, as
   * the shell's `RuntimeState::handshake_rtt_ms`. `null` until something has been
   * measured. This is the only latency the UI has: the tile used to regex-scrape a
   * number out of `test_connection` prose — which contained no `ms` at all, and on
   * a failed test could scrape a timeout value and print it as latency.
   */
  handshakeRttMs: number | null;
};

/**
 * The `session://state` payload guard.
 *
 * The shape check is the shared one — see `parseRuntimeCore`; this adds the
 * desktop-only measured round-trip.
 */
export function parseRuntimeState(payload: unknown): RuntimeState | null {
  const core = parseRuntimeCore(payload);
  if (!core) return null;
  const raw = payload as Partial<Record<keyof RuntimeState, unknown>>;
  return {
    ...core,
    // A round-trip is a count of milliseconds or nothing; a stringly or negative
    // one is not a measurement, and "not measured" must not render as `0 ms`.
    handshakeRttMs:
      typeof raw.handshakeRttMs === "number" && Number.isFinite(raw.handshakeRttMs) && raw.handshakeRttMs >= 0
        ? raw.handshakeRttMs
        : null,
  };
}

export type LogEntry = {
  id: number;
  level: LogLevel;
  message: string;
  /**
   * Epoch milliseconds, kept machine-readable for the buffer export. The console
   * row prints `time` instead: formatting here on every render multiplied a
   * `toLocaleTimeString` call by the visible rows on every appended line.
   */
  ts: number;
  /** `ts` already rendered as HH:MM:SS, computed once when the line was appended. */
  time: string;
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
  // `hour12: false`: the console is a fixed-width column of timestamps, and an
  // AM/PM string of a different length per locale is what the tabular column and
  // the log export have to cope with.
  return new Date(ts).toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  });
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

/**
 * `get_settings` / the post-write value, merged over `defaults` field by field.
 *
 * The desktop hook used to do `setSettings(loadedSettings)`: a shell build that
 * dropped a field, or renamed its enum arm, handed the panels `undefined` or a
 * value no option list contains, and the next `settings.ipVersion.toUpperCase()`
 * threw on the Settings/Connection render. Android already merged over defaults,
 * which is why the same dropped field only ever white-screened one of the two
 * front ends (`packages/ui/src/index.ts` names this). Merging is not enough on its
 * own either — `{ protocol: "masque" }` is a valid object and a broken setting —
 * so each field is validated against the same lists the option controls offer, and
 * every correction is reported back so the log says which field came up short
 * rather than the form silently persisting the default over the user's value.
 */
export function parseSettings(raw: unknown): { settings: Settings; corrected: string[] } {
  const src: Record<string, unknown> =
    typeof raw === "object" && raw !== null && !Array.isArray(raw)
      ? (raw as Record<string, unknown>)
      : {};
  const corrected: string[] = [];
  const note = (field: string) => {
    if (!corrected.includes(field)) corrected.push(field);
  };

  const enumeration = <T extends string>(
    field: keyof Settings,
    allowed: readonly T[],
    fallback: T,
  ): T => {
    const value = oneOf(src[field], allowed, fallback);
    if (value !== src[field]) note(field);
    return value;
  };
  const finiteNumber = (field: keyof Settings, fallback: number): number => {
    const value = src[field];
    if (typeof value === "number" && Number.isFinite(value)) return value;
    note(field);
    return fallback;
  };
  /** The interval the Rust validator enforces on save (settings.rs). A port
      outside it used to hydrate as-is, and then made every subsequent edit a
      silent save-skip: the dock read "Synchronizing…" forever with nothing to
      click, because the invalid value only existed on disk. Corrected values
      land in the same report as every other hydration fix. */
  const portNumber = (field: keyof Settings, fallback: number): number => {
    const value = src[field];
    if (
      typeof value === "number" &&
      Number.isInteger(value) &&
      value >= 1024 &&
      value <= 65535
    ) {
      return value;
    }
    note(field);
    return fallback;
  };
  const boolean = (field: keyof Settings, fallback: boolean): boolean => {
    const value = src[field];
    if (typeof value === "boolean") return value;
    note(field);
    return fallback;
  };
  const text = (field: keyof Settings, fallback: string): string => {
    const value = src[field];
    if (typeof value === "string") return value;
    note(field);
    return fallback;
  };

  return {
    settings: {
      protocol: enumeration("protocol", TUNNEL_PROTOCOLS, defaults.protocol),
      transport: enumeration("transport", TRANSPORTS, defaults.transport),
      scanMode: enumeration("scanMode", SCAN_MODES, defaults.scanMode),
      ipVersion: enumeration("ipVersion", IP_FAMILIES, defaults.ipVersion),
      noize: enumeration("noize", NOIZE_PROFILES, defaults.noize),
      noizeJc: finiteNumber("noizeJc", defaults.noizeJc),
      noizeJmin: finiteNumber("noizeJmin", defaults.noizeJmin),
      noizeJmax: finiteNumber("noizeJmax", defaults.noizeJmax),
      noizeIntervalMs: finiteNumber("noizeIntervalMs", defaults.noizeIntervalMs),
      routingMode: enumeration("routingMode", ROUTING_MODES, defaults.routingMode),
      socksPort: portNumber("socksPort", defaults.socksPort),
      httpPort: portNumber("httpPort", defaults.httpPort),
      startMinimized: boolean("startMinimized", defaults.startMinimized),
      launchAtLogin: boolean("launchAtLogin", defaults.launchAtLogin),
      enginePath: text("enginePath", defaults.enginePath),
      peer: text("peer", defaults.peer),
      quicInitialFrag: boolean("quicInitialFrag", defaults.quicInitialFrag),
      quicInitialFragSize: finiteNumber("quicInitialFragSize", defaults.quicInitialFragSize),
    },
    corrected,
  };
}

export const initialRuntime: RuntimeState = {
  status: "disconnected",
  detail: "Ready",
  pid: null,
  endpoint: null,
  handshakeRttMs: null,
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
