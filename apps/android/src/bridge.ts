/**
 * Platform bridge — same command surface as the Tauri desktop shell.
 * On Android, calls go through the Kotlin JavascriptInterface (AetherAndroid).
 * In browser dev, uses localStorage + a mock runtime so the UI is fully testable.
 *
 * All native responses are validated at this boundary: the rest of the app can
 * trust the returned shape instead of sprinkling `as T` casts everywhere.
 */
import { defaults, type Settings, type RuntimeState } from "./types";
import { IpcRejection } from "./ipcError";

type LogPayload = { level: "info" | "warn" | "error"; message: string };

declare global {
  interface Window {
    AetherAndroid?: {
      invoke: (cmd: string, argsJson: string) => string;
    };
    __aetherEmit?: (event: string, payloadJson: string) => void;
  }
}

const listeners = new Map<string, Set<(payload: unknown) => void>>();

// Called from Kotlin via evaluateJavascript. Never let a bad payload throw
// across the JS bridge boundary — that would silently kill event delivery.
window.__aetherEmit = (event: string, payloadJson: string) => {
  try {
    const payload = JSON.parse(payloadJson);
    listeners.get(event)?.forEach((cb) => {
      try {
        cb(payload);
      } catch (e) {
        console.warn(`listener for ${event} threw`, e);
      }
    });
  } catch (e) {
    console.warn("emit parse failed", e);
  }
};

function isAndroid(): boolean {
  return typeof window.AetherAndroid?.invoke === "function";
}

/**
 * Whether the mocked runtime may answer at all.
 *
 * `vite build` — the only way this bundle reaches an APK — bakes `DEV` to `false`, so
 * a release build can never fall through to `mockInvoke`. That mattered because the
 * fallback reported `connected / "VPN active (full device)"` (see `mockInvoke`) with no
 * tunnel behind it: a release WebView that failed to install `AetherAndroid` — an
 * origin-gated page, a stripped `@JavascriptInterface`, a second WebView — showed a
 * green badge and a fake pid instead of an error.
 */
const MOCK_ALLOWED = import.meta.env.DEV;

/** The envelope of a dispatched command that has not settled yet. */
type PendingEnvelope = { pending: string; pollMs?: number };

function isPending(data: unknown): data is PendingEnvelope {
  return isRecord(data) && typeof data.pending === "string" && data.pending.length > 0;
}

type ResultEnvelope = { state: "pending" } | { state: "done"; envelope: unknown };

/**
 * Collect the result of a command the shell dispatched to a worker.
 *
 * The native `invoke` is a synchronous, return-valued call that runs on the WebView's
 * JavaBridge thread — so a handler that blocks (connect: keystore retries plus a
 * process poll; test_connection: a 12 s HTTP call) blocks the page's JS with it. The
 * shell now answers those commands with a token and the result is polled here, which
 * keeps `await invoke(...)`'s contract — resolve on success, throw on rejection —
 * without freezing the renderer.
 */
async function awaitResult<T>(id: string, pollMs: number, budgetMs: number): Promise<T> {
  const deadline = Date.now() + budgetMs;
  for (;;) {
    const raw = window.AetherAndroid?.invoke("get_result", JSON.stringify({ id }));
    if (typeof raw !== "string") {
      throw new Error("bridge disappeared while a command was in flight");
    }
    const res = unwrapEnvelope<ResultEnvelope>(raw);
    if (res.state === "done") return unwrapEnvelope<T>(res.envelope);
    if (Date.now() > deadline) {
      throw new Error(`bridge command ${id} did not settle within ${budgetMs} ms`);
    }
    await new Promise((resolve) => setTimeout(resolve, pollMs));
  }
}

/** How long a dispatched command may take before the UI gives up on it. */
const SETTLE_BUDGET_MS = 90_000;

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null;
}

/** Validate and unwrap the native `{ ok, data?, error? }` envelope. */
function unwrapEnvelope<T>(raw: string | unknown): T {
  let parsed: unknown;
  try {
    parsed = typeof raw === "string" ? JSON.parse(raw) : raw;
  } catch {
    throw new Error("native bridge returned malformed JSON");
  }
  if (!isRecord(parsed) || typeof parsed.ok !== "boolean") {
    throw new Error("native bridge returned an unexpected shape");
  }
  if (!parsed.ok) {
    // Kotlin reports prose today; the shell reports {code, message, field}. Keep
    // the structure when it is there so a caller can branch on the code instead
    // of matching sentences, and fall back to the message when it is not.
    const reported = parsed.error;
    if (isRecord(reported) && typeof reported.message === "string") {
      throw new IpcRejection({
        code: typeof reported.code === "string" ? reported.code : "unknown",
        message: reported.message,
        field: typeof reported.field === "string" ? reported.field : undefined,
      });
    }
    const msg = typeof reported === "string" && reported ? reported : "native error";
    throw new Error(msg);
  }
  // `data` may legitimately be null/undefined for void commands.
  return parsed.data as T;
}

let mockRuntime: RuntimeState = {
  status: "disconnected",
  detail: "Ready",
  pid: null,
  endpoint: null,
};
let mockScanTimer: ReturnType<typeof setInterval> | null = null;

function loadMockSettings(): Settings {
  try {
    const raw = localStorage.getItem("aether.settings");
    if (raw) return { ...defaults, ...(JSON.parse(raw) as Partial<Settings>) };
  } catch {
    /* ignore */
  }
  return { ...defaults };
}

function saveMockSettings(s: Settings) {
  try {
    localStorage.setItem("aether.settings", JSON.stringify(s));
  } catch {
    /* ignore */
  }
}

export async function invoke<T = unknown>(
  cmd: string,
  args?: Record<string, unknown>,
): Promise<T> {
  if (isAndroid()) {
    let raw: string;
    try {
      raw = window.AetherAndroid!.invoke(cmd, JSON.stringify(args ?? {}));
    } catch (e) {
      throw new Error(`bridge call ${cmd} failed: ${String(e)}`);
    }
    const data = unwrapEnvelope<unknown>(raw);
    // A dispatched command answers with a token; the page keeps running while the
    // shell works, and the settled envelope is collected below.
    if (isPending(data)) {
      return awaitResult<T>(data.pending, data.pollMs ?? 120, SETTLE_BUDGET_MS);
    }
    return data as T;
  }
  if (!MOCK_ALLOWED) {
    // Release builds must fail loudly. Falling through to the mock here is how a
    // phone with a broken bridge ends up showing "VPN active" for a VPN that was never
    // started.
    throw new IpcRejection({
      code: "bridge_unavailable",
      message:
        "The native bridge (AetherAndroid) is not available in this WebView, so no command " +
        "can reach the engine. Reload the app; if it persists, the packaged UI was loaded " +
        "outside the Aether activity.",
    });
  }
  return mockInvoke<T>(cmd, args);
}

/** Browser/Vite mock so the whole UI (incl. scanner + logs) works without a device. */
async function mockInvoke<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
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
      mockRuntime = { status: "connecting", detail: "Scanning reachable routes", pid: 4242, endpoint: null };
      emitLocal("session://state", mockRuntime);
      emitLocal("session://log", { level: "info", message: "[mock] Android UI preview — package the engine for real tunnels" });
      window.setTimeout(() => {
        mockRuntime = { status: "connected", detail: "VPN active (full device)", pid: 4242, endpoint: "162.159.198.1:443" };
        emitLocal("session://state", mockRuntime);
        emitLocal("session://log", { level: "info", message: "connected — mock ready" });
      }, 1200);
      return undefined as T;
    }
    case "disconnect": {
      mockRuntime = { status: "disconnected", detail: "Ready", pid: null, endpoint: null };
      emitLocal("session://state", mockRuntime);
      return undefined as T;
    }
    case "scan": {
      startMockScan();
      return undefined as T;
    }
    case "stop_scan": {
      stopMockScan();
      emitLocal("scan://event", { type: "scan_done", addr: "", rtt: "", protocol: "" });
      return undefined as T;
    }
    case "test_connection":
      return {
        detail: "OK via http://127.0.0.1:1820 · ip=mock loc=?",
        latencyMs: 42,
      } as T;
    case "app_info":
      return { name: "Aether Next", version: "1.1.10", author: "deathline94", engine: "deathline94/aether-next", platform: "web" } as T;
    default:
      throw new Error(`unknown command ${cmd}`);
  }
}

function startMockScan() {
  stopMockScan();
  const total = 240;
  let scanned = 0;
  let working = 0;
  emitLocal("scan://event", { type: "scan_start", mode: "balanced", total, concurrency: 200 });
  mockScanTimer = window.setInterval(() => {
    scanned = Math.min(total, scanned + 12);
    if (Math.random() > 0.6) {
      working += 1;
      const rttMs = 20 + Math.round(Math.random() * 140);
      emitLocal("scan://event", {
        type: "scan_hit",
        addr: `162.159.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}:443`,
        rtt: `${rttMs}ms`,
        rttMs,
        protocol: "MASQUE H2",
      });
    }
    emitLocal("scan://event", { type: "scan_progress", scanned, total, working });
    emitLocal("session://log", { level: "info", message: `scanning... ${scanned}/${total} ips, found ${working} working` });
    if (scanned >= total) {
      stopMockScan();
      emitLocal("scan://event", { type: "scan_done", addr: "162.159.198.1:443", rtt: "24ms", protocol: "MASQUE H2" });
    }
  }, 300);
}

function stopMockScan() {
  if (mockScanTimer !== null) {
    window.clearInterval(mockScanTimer);
    mockScanTimer = null;
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
  return () => {
    set!.delete(wrap);
  };
}

export function platformLabel(): "Android" | "Desktop" | "Web" {
  if (isAndroid()) return "Android";
  return "Web";
}

export type { Settings, RuntimeState, LogPayload };
