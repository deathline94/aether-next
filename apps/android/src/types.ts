import { parseRuntimeCore } from "../../../packages/ui/src";
import {
  SCAN_MAX_CONCURRENCY,
  SCAN_MAX_TIMEOUT_MS,
  SCAN_MASQUE_MIN_TIMEOUT_MS,
  SCAN_MIN_CONCURRENCY,
  SCAN_MIN_TIMEOUT_MS,
} from "../../../packages/ui/src";
import type { RuntimeStatus } from "../../../packages/ui/src";
import type { LogLevel } from "../../../packages/ui/src/enums";
import { SPEED_PROFILES, speedProfileHint } from "../../../packages/ui/src/enums";

export type View = "home" | "scanner" | "settings" | "logs";
/** The four statuses the shell has copy, colours and a beacon for — one list, in `packages/ui`. */
export type Status = RuntimeStatus;
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
  /**
   * Honoured by `BootReceiver`: after a reboot it posts the "tap to start"
   * notification. Android will not let a boot receiver start a VPN itself, so
   * the Settings row says "notification", not "auto-connect".
   */
  launchAtLogin: boolean;
  /** Forced peer endpoint (set by Scanner "Connect Direct"); empty = auto-scan. */
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
};

/**
 * The `session://state` frame guard. `parseRuntimeCore` is shared with desktop
 * precisely because the listener used to write whatever arrived straight into
 * state: on the phone an unknown `status` then missed `heroCopy[...]` and threw
 * during a background event, which blanks the WebView with no way back short of
 * a restart.
 */
export function parseRuntimeState(payload: unknown): RuntimeState | null {
  return parseRuntimeCore(payload);
}

export type LogEntry = {
  id: number;
  level: LogLevel;
  message: string;
  /**
   * Epoch milliseconds, kept machine-readable for the buffer export and for
   * `dateTime`. The row prints `time` instead: formatting here on every render
   * multiplied a `toLocaleTimeString` call by the visible rows on every appended
   * line, which is the scan-time freeze on the slower surface.
   */
  ts: number;
  /** `ts` already rendered as HH:MM:SS, computed once when the line was appended. */
  time: string;
  /**
   * Set when this line *is* a hit rather than a line that mentions one: the
   * address the structured event named, verbatim. `appendToStore` dedupes on it,
   * so a hit is counted per endpoint and nothing has to guess at the engine's
   * wording. See `packages/ui/src/logs.ts`.
   */
  hitKey?: string;
};

/**
 * What a caller hands to `appendLog`: an entry without the store's own id and
 * timestamp. `hitKey` is optional - pass it when the line is a fact about one
 * endpoint (a structured scan event) rather than leaving the log to recognise it
 * from prose.
 */
export type LogInput = Pick<LogEntry, "level" | "message"> & { hitKey?: string };

export function formatLogTime(ts: number): string {
  // `hour12: false`, matching the desktop console: the rows sit on a 64 px time
  // track, and an en-US "02:15:33 PM" is ~69 px of an 11-char monospace string —
  // so every afternoon the column wrapped or clipped and the log stopped lining
  // up. A 24-hour HH:MM:SS is always the same width.
  return new Date(ts).toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  });
}

// Android default: full-device VPN (VpnService + hev tun2socks).
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
  routingMode: "tun",
  socksPort: 1819,
  httpPort: 1820,
  launchAtLogin: false,
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

/** Structured scan event forwarded by the native bridge (scan://event). */
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

/**
 * The scanner's numeric bounds — the *only* place the UI states them.
 *
 * The Timeout field used to advertise 100–30000 ms while the native bridge coerced
 * the same value to `>= 3000` (`>= 6000` for the MASQUE family, whose handshake does
 * not fit inside 3 s): two clamp implementations, disagreeing, and the number the
 * user typed was never the number the engine ran. These mirror `ScanLimits` in
 * `app/src/main/java/app/aethernext/EngineProfiles.kt`; the input is disabled below
 * the floor instead of silently rewriting what was typed.
 */
export const SCAN_LIMITS = {
  minTimeoutMs: SCAN_MIN_TIMEOUT_MS,
  masqueMinTimeoutMs: SCAN_MASQUE_MIN_TIMEOUT_MS,
  maxTimeoutMs: SCAN_MAX_TIMEOUT_MS,
  minConcurrency: SCAN_MIN_CONCURRENCY,
  maxConcurrency: SCAN_MAX_CONCURRENCY,
} as const;

/**
 * The floor/ceiling predicates live in `packages/ui`, because the rule they
 * encode — which protocol's probes are QUIC handshakes — is the engine's, not
 * this app's. `scanTimeoutFloor` used to be rewritten here (correctly, as it
 * happened) while the desktop's copy said `startsWith("masque")` and therefore
 * gave an H2 scan a 6 s floor the engine never asks for; two spellings of one
 * rule is how they part ways, so this file re-exports instead.
 */
export {
  scanTimeoutFloor,
  effectiveScanTimeout,
  scanConcurrencyCeiling,
  clampConcurrency,
} from "../../../packages/ui/src";

/** One-click speed presets, shared by Connection tab. */
export const speedProfiles: { id: string; label: string; hint: string; patch: Partial<Settings> }[] = SPEED_PROFILES.map((profile) => ({
  id: profile.id,
  label: profile.label,
  hint: speedProfileHint(profile, "full VPN"),
  // `peer: ""` is the Android half of the difference this table used to encode by
  // being written twice: a preset that leaves a pinned carrier in place is not
  // "full device" coverage, so the phone clears it and the desktop, which patches
  // `system-proxy` and never pins a peer for the profile path, does not.
  patch: {
    protocol: profile.protocol,
    transport: profile.transport,
    noize: "off",
    scanMode: "balanced",
    ipVersion: "v4",
    routingMode: "tun",
    peer: "",
  },
}));

export function profileActive(settings: Settings, patch: Partial<Settings>): boolean {
  return (Object.keys(patch) as (keyof Settings)[]).every((k) => settings[k] === patch[k]);
}
