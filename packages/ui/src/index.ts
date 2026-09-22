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
 */
export const SCAN_MAX_CONCURRENCY = 500;
export const SCAN_MIN_CONCURRENCY = 1;

/**
 * Per-probe timeout bounds, in milliseconds.
 *
 * The floor is not a UI preference: a probe under 3 s cannot finish a
 * handshake, and MASQUE cannot finish one in 3 s, so the native layer and the
 * shell both raise whatever arrives. The Android scanner offered 100-30000 while
 * the bridge coerced to >=3000 (>=6000 for MASQUE): a user typing 500 got 3000
 * with no feedback and no explanation of the difference. One home for the three
 * numbers, referenced by `ScanLimits` on the Kotlin side and by both front-ends.
 */
export const SCAN_MIN_TIMEOUT_MS = 3_000;
export const SCAN_MASQUE_MIN_TIMEOUT_MS = 6_000;
export const SCAN_MAX_TIMEOUT_MS = 30_000;

/** The floor that applies to a given scan protocol. */
export function scanTimeoutFloor(protocol: string): number {
  return protocol.startsWith("masque") ? SCAN_MASQUE_MIN_TIMEOUT_MS : SCAN_MIN_TIMEOUT_MS;
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
