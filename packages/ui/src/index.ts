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

/** Re-export point for shared components as they move in (T197). */
export {};
