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
  time: string;
};

export const defaults: Settings = {
  protocol: "masque",
  transport: "h2",
  scanMode: "balanced",
  ipVersion: "v4",
  noize: "off",
  noizeJc: 4,
  noizeJmin: 48,
  noizeJmax: 190,
  noizeIntervalMs: 4,
  routingMode: "system-proxy",
  socksPort: 1819,
  httpPort: 1820,
  startMinimized: false,
  launchAtLogin: false,
  enginePath: "",
  peer: "",
};

export const initialRuntime: RuntimeState = {
  status: "disconnected",
  detail: "Ready",
  pid: null,
  endpoint: null,
};

/** Structured scan event emitted by the engine in scan-only mode. */
export type ScanEvent =
  | { type: "scan_start"; mode: string; total: number; concurrency: number }
  | { type: "scan_progress"; scanned: number; total: number; working: number }
  | { type: "scan_hit"; addr: string; rtt: string; rttMs: number; protocol: string }
  | { type: "scan_done"; addr: string; rtt: string; protocol: string }
  | { type: "scan_failed"; message: string };
