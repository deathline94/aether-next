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

export type LogEntry = {
  id: number;
  level: "info" | "warn" | "error";
  message: string;
  /** Epoch milliseconds — formatted at render time so exports keep the date. */
  ts: number;
};

export function formatLogTime(ts: number): string {
  return new Date(ts).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
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

/** Structured scan event forwarded by the native bridge (scan://event). */
export type ScanEvent =
  | { type: "scan_start"; mode: string; total: number; concurrency: number }
  | { type: "scan_progress"; scanned: number; total: number; working: number }
  | { type: "scan_hit"; addr: string; rtt: string; rttMs: number; protocol: string }
  | { type: "scan_done"; addr: string; rtt: string; protocol: string }
  | { type: "scan_failed"; message: string };

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
