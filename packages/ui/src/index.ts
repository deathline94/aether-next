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

/** Re-export point for shared components as they move in (T197). */
export {};
