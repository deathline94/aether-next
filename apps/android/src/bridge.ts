/**
 * Platform bridge — same command surface as the Tauri desktop shell.
 * On Android, calls go through the Kotlin JavascriptInterface (AetherAndroid).
 * In browser dev, uses localStorage + a mock runtime so the UI is fully testable.
 *
 * All native responses are validated at this boundary: the rest of the app can
 * trust the returned shape instead of sprinkling `as T` casts everywhere.
 */
import { defaults, type Settings, type RuntimeState, type ScanEvent } from "./types";
import { clampConcurrency, effectiveScanTimeout } from "./types";
import { parseSettingsPayload } from "./settingsPayload";
import type { SettingsCorruption } from "./settingsPayload";
import { SCAN_PROTOCOLS } from "@aether/ui/enums";
import type { ScanProtocol } from "@aether/ui/enums";
import { IpcRejection } from "./ipcError";
// The mock's `app_info` reports the version this app's own manifest carries, because
// a mock that reports a version the package does not have is how a UI test reads a
// number out of the app and believes it. `Docs/GUIDE.en.md` pairs that version with
// `versionName` in `build.gradle.kts` and the two Cargo/tauri manifests.
import { version as packageVersion } from "../package.json";

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

/** The two keys a real `SettingsStore` keeps: the profile, and what it refused to read. */
const SETTINGS_KEY = "aether.settings";
const QUARANTINE_KEY = "aether.settings.corrupt";

/**
 * The report the state frames carry, as `SettingsHealth` carries it in the shell:
 * published by a read that could not be honoured, cleared by `reset_settings`, and
 * read off every `session://state` / `get_state` payload.
 */
let mockSettingsError: SettingsCorruption | null = null;

/** What a stored profile read as — values to hand the renderer, plus the report. */
type MockStoreRead = { settings: Settings; error: SettingsCorruption | null };

/**
 * Set the report aside and hand back the defaults, exactly as `SettingsStore.load()`
 * does for a CORRUPT read: the bytes are preserved verbatim in their own key, the
 * caller gets `Settings()`, and the diagnosis travels on the state frame.
 */
function refuseMockStore(raw: string, reason: string, field: string | null): MockStoreRead {
  try {
    localStorage.setItem(QUARANTINE_KEY, raw);
  } catch {
    /* the report still stands; a preview that cannot quarantine loses nothing real */
  }
  return {
    settings: { ...defaults },
    error: { state: "corrupt", reason, field, detectedAt: Date.now(), action: "reset" },
  };
}

/**
 * Read the mock store the way the Kotlin reads the real one — MISSING, Healthy,
 * CORRUPT — instead of swallowing the third case.
 *
 * This used to be `JSON.parse` in a `try` and `{ ...defaults }` in the `catch`, so a
 * blob the user could not have written read as a fresh install, the panel reported
 * healthy settings, and the next debounced save overwrote the thing the preview was
 * meant to be able to demonstrate. The same strict parser the runtime applies to
 * `get_settings` decides here, which is what keeps the two halves honest: the shell
 * refuses a value its own UI cannot produce, and the preview now refuses it too.
 */
function readMockStore(): MockStoreRead {
  let raw: string | null = null;
  try {
    raw = localStorage.getItem(SETTINGS_KEY);
  } catch {
    return { settings: { ...defaults }, error: null };
  }
  // MISSING: nothing stored, so there is nothing to preserve and nothing to report.
  if (raw === null) return { settings: { ...defaults }, error: null };
  let stored: unknown;
  try {
    stored = JSON.parse(raw);
  } catch {
    return refuseMockStore(raw, "the stored settings are not readable JSON", null);
  }
  const parsed = parseSettingsPayload(stored);
  if (parsed.ok) return { settings: parsed.settings, error: null };
  return refuseMockStore(raw, parsed.reason, parsed.field);
}

function saveMockSettings(s: Settings) {
  try {
    localStorage.setItem(SETTINGS_KEY, JSON.stringify(s));
  } catch {
    /* ignore */
  }
}

/**
 * The state payload the WebView reads, with the shell's settings report on it.
 *
 * `RuntimeState.toJson()` puts `settingsError` on this frame (`SettingsStore.kt:108`)
 * and on `get_state`; `parseRuntimeCore` narrows both to the four tunnel fields, so
 * the report is read from the raw payload by `settingsReportOf`. The mock has to put
 * the key on there too, or the one screen this can be looked at never shows it.
 */
function mockStatePayload(): RuntimeState & { settingsError: SettingsCorruption | null } {
  return { ...mockRuntime, settingsError: mockSettingsError };
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
    case "get_settings": {
      // `handleGetSettings` is `session.getSettings()` — `store.load()`, which both
      // publishes the report and answers a corrupt read with defaults. Publishing on
      // the read is the whole contract: the settings payload cannot tell the two
      // cases apart, and this is where the report gets refreshed.
      const read = readMockStore();
      mockSettingsError = read.error;
      return read.settings as T;
    }
    case "save_settings": {
      const read = readMockStore();
      mockSettingsError = read.error;
      if (read.error) {
        // `SettingsStore.save` refuses while a corrupt blob is unresolved, and the
        // refusal names the reset because it is the only way through: `connect()`
        // saves too, so an unresolvable profile locks the user out of the tunnel as
        // well as the form. Verbatim from the Kotlin sentence.
        throw new IpcRejection({
          code: "validation",
          field: "settings",
          message:
            "Settings were not saved: the stored settings are corrupt and would be " +
            "overwritten. Choose Reset settings to accept defaults, or restore the " +
            "saved file, then save again.",
        });
      }
      const s = (args?.settings as Settings) || read.settings;
      saveMockSettings(s);
      return undefined as T;
    }
    case "reset_settings": {
      // `SettingsStore.resetCorruptSettings()`: acknowledge the corruption, keep the
      // rejected bytes, and put defaults on disk. The read above is what quarantines
      // the bytes a first frame may not have seen yet.
      readMockStore();
      saveMockSettings({ ...defaults });
      mockSettingsError = null;
      emitLocal("session://state", mockStatePayload());
      return undefined as T;
    }
    case "get_state": {
      mockSettingsError = readMockStore().error;
      return mockStatePayload() as T;
    }
    case "is_admin":
      return true as T;
    case "connect": {
      mockRuntime = { status: "connecting", detail: "Scanning reachable routes", pid: 4242, endpoint: null };
      emitLocal("session://state", mockStatePayload());
      emitLocal("session://log", { level: "info", message: "[mock] Android UI preview — package the engine for real tunnels" });
      const settings = (args?.settings as Partial<Settings> | undefined) ?? {};
      window.setTimeout(() => {
        // What the mock claims about a session is what the real shell claims for the
        // same mode (`SessionController.markConnected`): a device route in `tun`,
        // listeners only otherwise. A preview that always said "VPN active (full
        // device)" taught the UI — and every screenshot taken from it — to assert a
        // route the app had not installed.
        mockRuntime = {
          status: "connected",
          detail:
            settings.routingMode === "tun" || settings.routingMode === undefined
              ? "VPN active (full device)"
              : "Proxy only active",
          pid: 4242,
          endpoint: "162.159.198.1:443",
        };
        emitLocal("session://state", mockStatePayload());
        emitLocal("session://log", { level: "info", message: "connected — mock ready" });
      }, 1200);
      return undefined as T;
    }
    case "disconnect": {
      mockRuntime = { status: "disconnected", detail: "Ready", pid: null, endpoint: null };
      emitLocal("session://state", mockStatePayload());
      return undefined as T;
    }
    case "scan": {
      startMockScan(args ?? {});
      return undefined as T;
    }
    case "stop_scan": {
      stopMockScan();
      emitLocal("scan://event", {
        ...mockScanDone,
        type: "scan_done",
        addr: "",
        rtt: "",
        protocol: "",
        bestRttMs: null,
      } as ScanEvent);
      return undefined as T;
    }
    case "test_connection":
      return {
        detail: "OK via http://127.0.0.1:1820 · ip=mock loc=?",
        latencyMs: 42,
      } as T;
    case "app_info":
      return {
        name: "Aether Next",
        version: packageVersion,
        author: "deathline94",
        engine: "deathline94/aether-next",
        platform: platformLabel().toLowerCase(),
      } as T;
    default:
      throw new Error(`unknown command ${cmd}`);
  }
}

/**
 * The events one mocked scan run emits, derived entirely from the request.
 *
 * This used to be `Math.random()` and a hardcoded 240 targets / 200 workers /
 * "MASQUE H2" no matter what the Scanner panel had asked for: the mock answered a
 * WireGuard request with MASQUE hits, reported more lanes than the engine will run
 * for an H3 scan (`clampConcurrency` says 16), and — because the addresses, RTTs and
 * hit pattern were random — could not be asserted by any test. Every number below
 * comes from `request`, and the hit pattern comes from a hash of it, so the same
 * request replays the same run.
 */
export type MockScanRequest = {
  protocol?: unknown;
  ipVersion?: unknown;
  concurrency?: unknown;
  timeoutMs?: unknown;
  mode?: unknown;
  runId?: unknown;
};

/** The probes a mocked pool holds per address family. */
const MOCK_POOL = { v4: 96, v6: 48, both: 144 } as const;

/** A 32-bit FNV-1a of the request, so the "random" hits are reproducible. */
function requestSeed(request: MockScanRequest): number {
  const key = JSON.stringify([
    request.protocol ?? "",
    request.ipVersion ?? "",
    request.concurrency ?? "",
    request.timeoutMs ?? "",
    request.mode ?? "",
  ]);
  let hash = 0x811c9dc5;
  for (let i = 0; i < key.length; i += 1) {
    hash ^= key.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return hash >>> 0;
}

const HIT_PROTOCOL: Record<ScanProtocol, string> = {
  "masque-h3": "MASQUE H3",
  "masque-h2": "MASQUE H2",
  wireguard: "WireGuard",
};

/** The octets a hit's address carries: the family the request asked to probe. */
function hitAddress(family: string, seed: number, index: number): string {
  const a = (seed >>> 3) % 255;
  const b = (seed >>> 11) % 255;
  const octet = (index * 7 + ((seed >>> 5) % 13)) % 254;
  // `index` counts *hits*, not probes: the hit pattern below fires on one step parity
  // (`step % 2 === seed % 2`), so keying the family off the step left a "both" request
  // emitting a single family — every hit at the same parity, and the dual-stack scan
  // silently an IPv4 one (or an IPv6 one) depending on a hash of nothing the user chose.
  if (family === "v6") return `[2606:4700:${a.toString(16)}::${b.toString(16)}]:443`;
  if (family === "both" && index % 2 === 1) return `[2606:4700:${a.toString(16)}::${octet.toString(16)}]:443`;
  return `162.159.${a}.${octet || 1}:443`;
}

export function mockScanPlan(request: MockScanRequest): ScanEvent[] {
  const protocol: ScanProtocol = (SCAN_PROTOCOLS as readonly unknown[]).includes(request.protocol)
    ? (request.protocol as ScanProtocol)
    : "masque-h3";
  const family = request.ipVersion === "v6" || request.ipVersion === "both" ? request.ipVersion : "v4";
  const total = MOCK_POOL[family as keyof typeof MOCK_POOL];
  // The two numbers the engine itself resolves — the lane ceiling for this protocol
  // and the per-probe floor — so the mock's `scan_start` and `rtt` describe a run the
  // real scanner could have, and a test can pin them.
  const concurrency = clampConcurrency(
    typeof request.concurrency === "number" ? request.concurrency : 250,
    protocol,
  );
  const timeout = effectiveScanTimeout(
    protocol,
    typeof request.timeoutMs === "number" ? request.timeoutMs : 6_000,
  );
  const mode = typeof request.mode === "string" && request.mode ? request.mode : "balanced";
  const runId = typeof request.runId === "string" ? request.runId : undefined;
  const scope = runId ? { runId } : {};
  const hitLabel = HIT_PROTOCOL[protocol];
  const seed = requestSeed(request);
  // One hit every `stride` probes, so a bigger pool means more hits and the run
  // still terminates: `total` is derived, never invented per render.
  const stride = 8 + (seed % 5);
  const rttBase = Math.max(5, Math.round(timeout / 50));

  const events: ScanEvent[] = [
    { ...scope, type: "scan_start", mode, total, concurrency },
  ];
  let scanned = 0;
  let working = 0;
  let best: { addr: string; rtt: string; rttMs: number } | null = null;
  let step = 0;
  while (scanned < total) {
    scanned = Math.min(total, scanned + stride);
    if (step % 2 === seed % 2) {
      working += 1;
      const addr = hitAddress(family, seed, working - 1);
      const rttMs = rttBase + ((seed + step * 13) % (rttBase * 3));
      const rtt = `${rttMs}ms`;
      if (!best || rttMs < best.rttMs) best = { addr, rtt, rttMs };
      events.push({ ...scope, type: "scan_hit", addr, rtt, rttMs, protocol: hitLabel });
    }
    events.push({ ...scope, type: "scan_progress", scanned, total, working });
    step += 1;
  }
  events.push({
    ...scope,
    type: "scan_done",
    addr: best?.addr ?? "",
    rtt: best?.rtt ?? "",
    protocol: best ? hitLabel : "",
    bestRttMs: best?.rttMs ?? null,
  });
  return events;
}

/** The last planned run, so `stop_scan` can finish it with the same `runId`. */
let mockScanDone: ScanEvent = { type: "scan_done", addr: "", rtt: "", protocol: "" };
let mockScanQueue: ScanEvent[] = [];

function startMockScan(request: MockScanRequest) {
  stopMockScan();
  mockScanQueue = mockScanPlan(request);
  mockScanDone = mockScanQueue[mockScanQueue.length - 1] ?? mockScanDone;
  emitNextMockEvent();
  if (mockScanQueue.length > 0) {
    mockScanTimer = window.setInterval(emitNextMockEvent, 120);
  }
}

/** One event per tick — the plan is fixed, so the animation cannot reorder itself. */
function emitNextMockEvent() {
  const next = mockScanQueue.shift();
  if (!next) {
    stopMockScan();
    return;
  }
  emitLocal("scan://event", next);
  if (next.type === "scan_progress") {
    emitLocal("session://log", {
      level: "info",
      message: `[mock] scanning... ${next.scanned}/${next.total} ips, found ${next.working} working`,
    });
  }
  if (mockScanQueue.length === 0) stopMockScan();
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
