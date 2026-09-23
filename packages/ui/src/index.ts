/*
 * @aether/ui — shared surface for both frontends.
 *
 * Desktop (`apps/desktop/src`) and Android (`apps/android/src`) used to be two
 * ~3,000-line forks whose *behaviour* diverged, not only their styling: only
 * Android had the 90s connect watchdog, only Android merged hydrated settings
 * over defaults. A dropped Rust field therefore white-screened the desktop app
 * while the phone kept working. Anything that both shells need belongs here.
 */

export const DESIGN_TOKENS_VERSION = 1;

/**
 * Shared numeric limits that must not be restated in the UI.
 *
 * `SCAN_MAX_CONCURRENCY` replaces the drift where the slider offered `max={2000}`
 * while the shell clamped to 500, so the user could pick 2000 workers and
 * silently get 500 with no explanation. Generated bindings (T019) become the
 * authoritative source for these; this constant is the interim single home.
 *
 * The ladder the frontends have to describe is three deep, which is why all
 * three numbers live here rather than the one that happens to bind the slider:
 * 500 is what a shell will accept, 1000 is the engine's absolute ceiling for a
 * cheap verify (`SCAN_CONCURRENCY_CEILING` in `aether/src/prober.rs`), and 16 is
 * what an H3 scan actually runs because more concurrent BoringSSL handshakes
 * abort the process (`EXPENSIVE_MAX_CONCURRENCY`). The strictest of those is the
 * one the field has to stop at, or the UI is advertising lanes that never exist.
 */
export const SCAN_MAX_CONCURRENCY = 500;
export const SCAN_MIN_CONCURRENCY = 1;

/** Lanes an H3/QUIC scan will really run: the engine's handshake-safety ceiling. */
export const SCAN_MAX_CONCURRENCY_H3 = 16;

/**
 * Whether a scan's probes are QUIC handshakes — the only condition under which
 * `hunt_best` raises the per-probe floor to 6 s and narrows the run to 16 lanes
 * (`VerifyCost::Expensive`, `aether/src/prober.rs`).
 *
 * `masque-h2` is deliberately *not* in here: its probes are TCP+TLS handshakes
 * the engine classifies as cheap, so the desktop was raising their floor for a
 * reason the engine does not have — and offering a slower scan than the phone
 * offers for the same protocol (`EngineProfiles.kt:99` and the Android web layer
 * both already excluded it, `startsWith("masque")` did not). One predicate now
 * decides expense for the floor, the lane ceiling, and both frontends.
 */
export function isExpensiveVerifyProtocol(protocol: string): boolean {
  const p = (protocol ?? "").toLowerCase();
  return p.includes("h3") || p === "masque";
}

/** The ceiling that applies to a given scan protocol. */
export function scanConcurrencyCeiling(protocol: string): number {
  return isExpensiveVerifyProtocol(protocol) ? SCAN_MAX_CONCURRENCY_H3 : SCAN_MAX_CONCURRENCY;
}

/**
 * Workers the engine will actually run for this protocol.
 *
 * Both front-ends used to keep their own clamp (the desktop's was protocol-blind,
 * the Android hook sent the raw number), which is the same rule written twice and
 * disagreed about the one thing that matters: the number printed in the "starting
 * scan" log is the number the engine will not honour for an H3 run.
 */
export function clampConcurrency(value: number, protocol = ""): number {
  if (!Number.isFinite(value)) return SCAN_MIN_CONCURRENCY;
  return Math.min(
    scanConcurrencyCeiling(protocol),
    Math.max(SCAN_MIN_CONCURRENCY, Math.round(value)),
  );
}

/**
 * Per-probe timeout bounds, in milliseconds.
 *
 * The floor is not a UI preference: a probe under 3 s cannot finish a handshake,
 * and a QUIC handshake cannot finish in 3 s, so the native layer and the shell
 * both raise whatever arrives. The Android scanner offered 100-30000 while the
 * bridge coerced to >=3000 (>=6000 for MASQUE-over-QUIC): a user typing 500 got
 * 3000 with no feedback and no explanation of the difference. One home for the
 * three numbers, referenced by `ScanLimits` on the Kotlin side and by both
 * front-ends, and one predicate deciding which protocol gets which floor.
 */
export const SCAN_MIN_TIMEOUT_MS = 3_000;
export const SCAN_MASQUE_MIN_TIMEOUT_MS = 6_000;
export const SCAN_MAX_TIMEOUT_MS = 30_000;

/** The floor that applies to a given scan protocol. */
export function scanTimeoutFloor(protocol: string): number {
  return isExpensiveVerifyProtocol(protocol)
    ? SCAN_MASQUE_MIN_TIMEOUT_MS
    : SCAN_MIN_TIMEOUT_MS;
}

/** Raise a requested timeout into the range the engine will actually honour. */
export function effectiveScanTimeout(protocol: string, timeoutMs: number): number {
  return Math.min(SCAN_MAX_TIMEOUT_MS, Math.max(scanTimeoutFloor(protocol), timeoutMs));
}

/**
 * Whether the obfuscation profile can have any effect on this combination.
 *
 * MASQUE over HTTP/2 is a plain TCP CONNECT tunnel: there is no QUIC Initial to
 * fragment and no handshake for the junk frames to hide, so the engine ignores
 * `AETHER_NOIZE` on that path. Both front-ends show a noise control and a status
 * tile for it, and each used to decide independently whether to display the
 * stored value — which is how the scanner could read "off" while sending a live
 * profile, and the specification tile could read "NOISE: AGGRESSIVE" for a
 * setting that provably does nothing. One predicate, both places.
 */
export function noiseIsInert(protocol: string, transport: string): boolean {
  return protocol === "masque" && transport === "h2";
}

/**
 * The verdict line at the end of a scan run.
 *
 * `working` arrives on `scan_progress`, which the engine only republishes every
 * fifty probes, so the final batch of hits can be missing from it. A run whose
 * list is non-empty found something whatever the lagging counter says, and an
 * empty list with no address is the honest "0 found". This rule was forked:
 * desktop guarded it, Android set `phase: "Verified"` on every `scan_done`, so a
 * scan that found nothing on the phone reported a verified route (T199).
 */
export function scanVerdict(hitCount: number, addr: string, working: number): string {
  return hitCount > 0 || working > 0 || Boolean(addr) ? "Verified" : "Completed (0 found)";
}

/** The statuses the interface has copy, colours and a beacon for. */
export const RUNTIME_STATUSES = ["disconnected", "connecting", "connected", "error"] as const;
export type RuntimeStatus = (typeof RUNTIME_STATUSES)[number];

export function isRuntimeStatus(value: unknown): value is RuntimeStatus {
  return typeof value === "string" && (RUNTIME_STATUSES as readonly string[]).includes(value);
}

/** The part of a `session://state` frame both shells render. */
export type RuntimeCore = {
  status: RuntimeStatus;
  detail: string;
  pid: number | null;
  endpoint: string | null;
};

/**
 * The `session://state` payload guard, up to each shell's extra fields.
 *
 * Both listeners used to do `setRuntime(event.payload)` on whatever arrived. One
 * build emitting a fifth status, or a truncated frame, was then read through
 * `heroCopy[status]` — a miss returns `undefined`, the next property access
 * throws, and a background *event* took the window down. `null` means "this is
 * not a state", so the caller keeps the last one it understood. Android had no
 * guard at all, so the same frame that only degraded desktop white-screened the
 * phone (T186).
 */
export function parseRuntimeCore(payload: unknown): RuntimeCore | null {
  if (typeof payload !== "object" || payload === null) return null;
  const raw = payload as Partial<Record<keyof RuntimeCore, unknown>>;
  if (!isRuntimeStatus(raw.status)) return null;
  return {
    status: raw.status,
    detail: typeof raw.detail === "string" ? raw.detail : "",
    pid: typeof raw.pid === "number" && Number.isFinite(raw.pid) ? raw.pid : null,
    endpoint: typeof raw.endpoint === "string" ? raw.endpoint : null,
  };
}

/**
 * The one word each status is allowed to be called in the interface.
 *
 * The desktop sidebar spelled it out of a nested ternary while both topbars
 * printed the raw Rust enum (`disconnected`, `connected`), so one screen showed
 * "Standby" beside "disconnected" — two vocabularies for the same fact, one of
 * them an implementation identifier.
 */
export const RUNTIME_STATUS_TAGS: Record<RuntimeStatus, string> = {
  disconnected: "STANDBY",
  connecting: "HANDSHAKE",
  connected: "ACTIVE",
  error: "ALERT",
};

/** Why a frame was refused, phrased for the log and deduped per shape. */
export function describeRejectedState(payload: unknown): string {
  if (typeof payload !== "object" || payload === null) return `non-object payload (${typeof payload})`;
  const raw = (payload as Record<string, unknown>).status;
  if (raw === undefined) return "no status field";
  if (typeof raw !== "string") return `status is ${typeof raw}`;
  return `status "${raw}"`;
}

/**
 * Where the arrow keys take you in a one-of-N control, or `null` when the key is
 * none of theirs.
 *
 * `role="radio"`/`role="tab"` are not decoration: the pattern behind them is a
 * single stop in the tab order that the arrows walk. Desktop's filter dock had
 * the handler and Android had none — every segmented group on the phone (carrier
 * protocol, transport, IP family) was a column of tab stops whose selected member
 * could not be told from the rest by keyboard or assistive tech. One rule, both
 * surfaces.
 */
export function nextOptionIndex(current: number, key: string, length: number): number | null {
  if (length <= 0) return null;
  const at = (index: number) => ((index % length) + length) % length;
  switch (key) {
    case "ArrowRight":
    case "ArrowDown":
      return at(current + 1);
    case "ArrowLeft":
    case "ArrowUp":
      return at(current - 1);
    case "Home":
      return at(0);
    case "End":
      return at(length - 1);
    default:
      return null;
  }
}

/**
 * Has anything the error boundary is keyed on actually changed?
 *
 * Both apps mount one boundary per tab, and this comparison - not React's error
 * plumbing - decides whether a crashed view comes back when the user switches
 * tabs and returns, or when a settings reload lands. It lives here because the
 * boundary's *render* cannot be unit-tested at all: under React 19 + jsdom a
 * child that throws during render is rethrown out of `act()` and the tree
 * unmounts, so the fallback is not observable (spec 015, T186). The logic that
 * can be observed is this function, so that is the part with one owner.
 */
export function resetKeysChanged(
  previous: readonly unknown[] | undefined,
  next: readonly unknown[] | undefined,
): boolean {
  if (previous === undefined || next === undefined) {
    return previous !== next;
  }
  if (previous === next) return false;
  if (previous.length !== next.length) return true;
  return previous.some((value, index) => !Object.is(value, next[index]));
}
