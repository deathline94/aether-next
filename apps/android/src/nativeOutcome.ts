/**
 * The one reply the shell produces by measurement rather than by reading a file.
 *
 * `SessionController.testConnection` (`SessionController.kt:477`, payload built at
 * 513-517) answers
 * `test_connection` with `{ detail: "OK via … - ip=… loc=…", latencyMs: <elapsed>,
 * ip, loc }` — a `JSONObject` built at the end of a proxied HTTP exchange, on a path
 * that also throws (`proxy test failed: HTTP <code>`) and is caught by the bridge into
 * an envelope rejection. `get_state` and `get_settings` both got strict parsers in
 * this app (`types.ts`, `settingsPayload.ts`) because an `as T` on an unwrapped
 * envelope is not a check; this payload was the last one still written straight into
 * React state, where `result.detail` is rendered as a sentence and `latencyMs` as a
 * measurement.
 *
 * What "refused" means here is the recoverable answer, not a crash: a check whose
 * answer cannot be read is reported as a failed check, with no measurement attached.
 * That is what the caller's `catch` already does for a rejection, so the two failure
 * modes — the shell said no, and the shell said something unreadable — reach the user
 * the same way instead of one of them painting `undefined` into the tile.
 */
export type NativeOutcome = {
  detail: string;
  latencyMs: number | null;
};

/** The measured latency, or `null` for a check that measured nothing. Never guessed. */
export function parseTestOutcome(payload: unknown): NativeOutcome | null {
  if (typeof payload !== "object" || payload === null || Array.isArray(payload)) return null;
  const raw = payload as Record<string, unknown>;
  if (typeof raw.detail !== "string" || raw.detail.length === 0) return null;
  if (raw.latencyMs === undefined || raw.latencyMs === null) return { detail: raw.detail, latencyMs: null };
  if (typeof raw.latencyMs !== "number" || !Number.isFinite(raw.latencyMs) || raw.latencyMs < 0) return null;
  return { detail: raw.detail, latencyMs: Math.round(raw.latencyMs) };
}
