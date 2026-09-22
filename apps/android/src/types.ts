import { parseRuntimeCore } from "../../../packages/ui/src";
import type { RuntimeStatus } from "../../../packages/ui/src";

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
  level: "info" | "warn" | "error";
  message: string;
  /** Epoch milliseconds — formatted at render time so exports keep the date. */
  ts: number;
};

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
  minTimeoutMs: 3000,
  masqueMinTimeoutMs: 6000,
  maxTimeoutMs: 30000,
  minConcurrency: 1,
  maxConcurrency: 2000,
} as const;

/** The floor that applies to a given protocol, mirroring the shell's `clampTimeout`. */
export function scanTimeoutFloor(protocol: string): number {
  const p = protocol.toLowerCase();
  return p.includes("h3") || p === "masque" ? SCAN_LIMITS.masqueMinTimeoutMs : SCAN_LIMITS.minTimeoutMs;
}

/** The value actually sent for `timeoutMs`, after the shell's clamp. */
export function effectiveScanTimeout(protocol: string, timeoutMs: number): number {
  return Math.min(SCAN_LIMITS.maxTimeoutMs, Math.max(scanTimeoutFloor(protocol), timeoutMs));
}

/** One-click speed presets, shared by Connection tab. */
export const speedProfiles: { id: string; label: string; hint: string; patch: Partial<Settings> }[] = [
  { id: "masque-h3", label: "MASQUE H3", hint: "MASQUE h3 · noise off · balanced · full VPN", patch: { protocol: "masque", transport: "h3", noize: "off", scanMode: "balanced", ipVersion: "v4", routingMode: "tun", peer: "" } },
  { id: "masque-h2", label: "MASQUE H2 (Default)", hint: "MASQUE h2 · noise off · balanced · full VPN", patch: { protocol: "masque", transport: "h2", noize: "off", scanMode: "balanced", ipVersion: "v4", routingMode: "tun", peer: "" } },
  { id: "wireguard", label: "WireGuard", hint: "WireGuard · noise off · balanced · full VPN", patch: { protocol: "wireguard", transport: "h2", noize: "off", scanMode: "balanced", ipVersion: "v4", routingMode: "tun", peer: "" } },
  { id: "gool", label: "Gool", hint: "Gool (WARP-in-WARP) · noise off · balanced · full VPN", patch: { protocol: "gool", transport: "h2", noize: "off", scanMode: "balanced", ipVersion: "v4", routingMode: "tun", peer: "" } },
];

export function profileActive(settings: Settings, patch: Partial<Settings>): boolean {
  return (Object.keys(patch) as (keyof Settings)[]).every((k) => settings[k] === patch[k]);
}
