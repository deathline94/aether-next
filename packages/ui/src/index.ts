/*
 * @aether/ui — shared surface for both frontends.
 *
 * Desktop (`apps/desktop/src`) and Android (`apps/android/src`) used to be two
 * ~3,000-line forks whose *behaviour* diverged, not only their styling: only
 * Android had the 90s connect watchdog, only Android merged hydrated settings
 * over defaults. A dropped Rust field therefore white-screened the desktop app
 * while the phone kept working. Anything that both shells need belongs here.
 */

import type { ScanProtocol } from "./enums";

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
 * The lanes the scanner opens with, which is the most the protocol it opens *on*
 * can run.
 *
 * Both front-ends start on `masque-h3` and started the lane field at 250 — the
 * width of a cheap H2/WireGuard scan, against the 16 above. The control then
 * advertised 250 lanes while the engine clamped the run to 16, and the panel only
 * learned the real number from the first `scan_start` frame: the field lied during
 * the whole opening of a scan, which is exactly when it is read. Derived from the
 * H3 ceiling instead of restating it, so the default cannot drift from the ladder.
 */
export const SCAN_DEFAULT_CONCURRENCY = SCAN_MAX_CONCURRENCY_H3;

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
 *
 * It is a *display* rule as well as a send rule, and both hooks resolve their lane
 * field through it: the number a protocol cannot run must not sit in the input, in
 * the hint or in the request, and it is idempotent, so re-resolving what the field
 * already shows is a no-op. The raw request survives underneath — switching to a
 * transport that can carry it puts the user's own number back, as `scanNoizeFor`
 * does for the noise profile.
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
  return (protocol === "masque" || protocol === "mim") && transport === "h2";
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

/**
 * A round-trip that can be shown: the engine's own text, or a measured number
 * formatted. Anything empty or absent is `null`, so a caller keeps the previous
 * value or says nothing rather than storing `""` and printing it.
 */
export function rttLike(value: string | number | null | undefined): string | null {
  if (typeof value === "number") return Number.isFinite(value) ? `${value} ms` : null;
  const text = typeof value === "string" ? value.trim() : "";
  return text.length > 0 ? text : null;
}

/** The shape of a discovered row this badge reads; both apps' `DiscoveredEndpoint`. */
export interface RttBadgeSource {
  rtt: string;
  rttMs?: number;
}

/**
 * The four tier classes, in the order the shell's own thresholds rank them.
 *
 * `getRttTier(rttMs)` was called on whatever arrived, and its last arm is a
 * fallback: a missing or zero measurement — the documented answer for a forced
 * peer, which the engine never times — came out of it as "HIGH LATENCY", so a
 * blank row was badged as the worst kind. An absent round-trip is its own
 * state, with no colour to lean the claim. One implementation for both
 * surfaces: the phone's copy was still the pre-fix version.
 */
export function rttBadge(item: RttBadgeSource): { tierClass: string; badgeText: string; text: string } {
  const measured =
    typeof item.rttMs === "number" && Number.isFinite(item.rttMs) && item.rttMs > 0
      ? item.rttMs
      : null;
  // The engine's own wording first, then the number it measured, then nothing.
  const text = rttLike(item.rtt) ?? (measured === null ? null : rttLike(measured));
  if (text === null) return { tierClass: "", badgeText: "NOT MEASURED", text: "not measured" };
  if (measured === null) return { tierClass: "", badgeText: "UNRANKED", text };
  if (measured < 20) return { tierClass: "rtt-ultra-green", badgeText: "ULTRA FAST", text };
  if (measured <= 60) return { tierClass: "rtt-optimal-cyan", badgeText: "OPTIMAL", text };
  if (measured <= 100) return { tierClass: "rtt-acceptable-amber", badgeText: "NORMAL", text };
  return { tierClass: "rtt-high-coral", badgeText: "HIGH LATENCY", text };
}

/**
 * Whether a speed-preset's patch is fully reflected in the settings — the
 * "ACTIVE" tag on a preset card. One implementation for both surfaces: the
 * desktop copy and Android's had drifted in the patch they compare (the phone
 * also clears the pinned peer, desktop does not), but the *comparison* is the
 * same every-key-matches rule, and a future third surface should not get to
 * invent a third answer.
 */
export function profileActive(
  settings: Record<string, unknown>,
  patch: Record<string, unknown>,
): boolean {
  return Object.keys(patch).every((k) => settings[k] === patch[k]);
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

/**
 * Whether an endpoint's protocol string matches a given scan protocol.
 *
 * Hits from the engine are labelled "MASQUE H3", "MASQUE H2", or "WireGuard".
 * When starting a new scan on a protocol, previously discovered endpoints
 * for other protocols are preserved, and only the current protocol's rows are reset.
 */
export function isEndpointForProtocol(endpointProtocol: string, protocol: ScanProtocol): boolean {
  const p = (endpointProtocol ?? "").toLowerCase();
  if (protocol === "masque-h3") return p.includes("h3");
  if (protocol === "masque-h2") return p.includes("h2");
  if (protocol === "wireguard") return p.includes("wireguard") || p.includes("wg");
  return false;
}

