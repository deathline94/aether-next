/**
 * Platform bridge — same command surface as the Tauri desktop shell.
 * On Android, calls go through the Kotlin JavascriptInterface.
 * In browser dev, uses localStorage + mock runtime.
 */

export type Settings = {
  protocol: string;
  transport: string;
  scanMode: string;
  ipVersion: string;
  noize: string;
  routingMode: string;
  socksPort: number;
  httpPort: number;
  startMinimized: boolean;
  launchAtLogin: boolean;
  enginePath: string;
};

export type RuntimeState = {
  status: string;
  detail: string;
  pid: number | null;
  endpoint: string | null;
};

type LogPayload = { level: string; message: string };

const defaults: Settings = {
  protocol: "masque",
  transport: "h2",
  scanMode: "balanced",
  ipVersion: "v4",
  noize: "firewall",
  routingMode: "tun",
  socksPort: 1819,
  httpPort: 1820,
  startMinimized: false,
  launchAtLogin: false,
  enginePath: "",
};

declare global {
  interface Window {
    AetherAndroid?: {
      invoke: (cmd: string, argsJson: string) => string;
    };
    __aetherEmit?: (event: string, payloadJson: string) => void;
  }
}

const listeners = new Map<string, Set<(payload: unknown) => void>>();

// Called from Kotlin via evaluateJavascript
window.__aetherEmit = (event: string, payloadJson: string) => {
  try {
    const payload = JSON.parse(payloadJson);
    listeners.get(event)?.forEach((cb) => cb(payload));
  } catch (e) {
    console.warn("emit parse failed", e);
  }
};

function isAndroid(): boolean {
  return typeof window.AetherAndroid?.invoke === "function";
}

let mockRuntime: RuntimeState = {
  status: "disconnected",
  detail: "Ready",
  pid: null,
  endpoint: null,
};

function loadMockSettings(): Settings {
  try {
    const raw = localStorage.getItem("aether.settings");
    if (raw) return { ...defaults, ...JSON.parse(raw) };
  } catch {
    /* ignore */
  }
  return { ...defaults };
}

function saveMockSettings(s: Settings) {
  localStorage.setItem("aether.settings", JSON.stringify(s));
}

export async function invoke<T = unknown>(
  cmd: string,
  args?: Record<string, unknown>,
): Promise<T> {
  if (isAndroid()) {
    const raw = window.AetherAndroid!.invoke(cmd, JSON.stringify(args ?? {}));
    const parsed = JSON.parse(raw) as { ok: boolean; data?: T; error?: string };
    if (!parsed.ok) throw new Error(parsed.error || "native error");
    return parsed.data as T;
  }

  // Browser / Vite mock for UI work
  switch (cmd) {
    case "get_settings":
      return loadMockSettings() as T;
    case "save_settings": {
      const s = (args?.settings as Settings) || loadMockSettings();
      saveMockSettings(s);
      return undefined as T;
    }
    case "get_state":
      return mockRuntime as T;
    case "is_admin":
      return true as T;
    case "connect": {
      mockRuntime = {
        status: "connecting",
        detail: "Scanning reachable routes",
        pid: 4242,
        endpoint: null,
      };
      emitLocal("session://state", mockRuntime);
      emitLocal("session://log", {
        level: "info",
        message: "[mock] Android UI preview — package aether binary for real tunnels",
      });
      setTimeout(() => {
        mockRuntime = {
          status: "connected",
          detail: "Proxy only active",
          pid: 4242,
          endpoint: "162.159.198.1:443",
        };
        emitLocal("session://state", mockRuntime);
        emitLocal("session://log", {
          level: "info",
          message: "AETHER_EVENT {\"type\":\"connected\",\"detail\":\"mock ready\"}",
        });
      }, 1200);
      return undefined as T;
    }
    case "disconnect": {
      mockRuntime = {
        status: "disconnected",
        detail: "Ready",
        pid: null,
        endpoint: null,
      };
      emitLocal("session://state", mockRuntime);
      return undefined as T;
    }
    case "test_connection":
      return "OK via http://127.0.0.1:1820 · ip=mock loc=?" as T;
    case "app_info":
      return {
        name: "Aether Next",
        version: "1.0.4",
        author: "deathline94",
        engine: "deathline94/aether-next",
        platform: "android",
      } as T;
    default:
      throw new Error(`unknown command ${cmd}`);
  }
}

function emitLocal(event: string, payload: unknown) {
  listeners.get(event)?.forEach((cb) => cb(payload));
}

export async function listen<T = unknown>(
  event: string,
  handler: (event: { payload: T }) => void,
): Promise<() => void> {
  let set = listeners.get(event);
  if (!set) {
    set = new Set();
    listeners.set(event, set);
  }
  const wrap = (payload: unknown) => handler({ payload: payload as T });
  set.add(wrap);
  return () => set.delete(wrap);
}

export function platformLabel(): "Android" | "Desktop" | "Web" {
  if (isAndroid()) return "Android";
  return "Web";
}
