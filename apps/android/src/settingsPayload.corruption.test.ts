// @vitest-environment jsdom
import { describe, expect, it } from "vitest";

/*
 * The parser for the native corruption report, pinned to the Kotlin that produces it.
 *
 * `RuntimeState.toJson()` (`SettingsStore.kt:103-109`) puts `settingsError` on every
 * `session://state` frame and on `get_state`, and `corruptionPayload()`
 * (`SettingsStore.kt:372-379`) builds the value as
 * `{ state:"corrupt", reason:<sentence>, field:<name|null>, detectedAt:<epoch ms>,
 *    action:"reset" }`. `parseRuntimeCore` in `packages/ui` keeps only the four fields
 * both shells render, so on the phone this key used to be dropped on the floor by the
 * frame guard — the user's settings were corrupt, the store refused every write, and
 * the interface said "All parameters synchronized".
 *
 * Reading it is this module's job because the rule is Android's own: the desktop's
 * `get_state` carries no such field, and `packages/ui` may not learn a per-shell key.
 */
import { parseSettingsError, type SettingsReport } from "./settingsPayload";
import { settingsReportOf } from "./types";

/** Exactly what `corruptionPayload()` writes, including `field: null`. */
const NATIVE = {
  state: "corrupt",
  reason: "protocol is \"openvpn\", which no surface of this app can produce",
  field: "protocol",
  detectedAt: 1761234567890,
  action: "reset",
};

describe("parseSettingsError — the native settingsError contract", () => {
  it("reads the payload the Kotlin publishes as the corruption it reports", () => {
    expect(parseSettingsError(NATIVE)).toEqual({
      verdict: "corrupt",
      corruption: NATIVE,
    } satisfies SettingsReport);
  });

  it("reads a blob-level failure, where no field is to blame, with field null", () => {
    // `SettingsStore.parseStored` passes `field = null` when `JSONObject` itself
    // refused the text; `corruptionPayload` writes `JSONObject.NULL` for it.
    expect(parseSettingsError({ ...NATIVE, field: null })).toEqual({
      verdict: "corrupt",
      corruption: { ...NATIVE, field: null },
    });
  });

  it("reads an absent or null settingsError as 'nothing to report'", () => {
    // The healthy branch of `RuntimeState.toJson` is `JSONObject.NULL`, and an older
    // shell omits the key entirely. Neither may look like a failure.
    for (const absent of [undefined, null]) {
      expect(parseSettingsError(absent)).toEqual({ verdict: "healthy" });
    }
  });

  it("reads a report it cannot honour as unreadable, never as healthy", () => {
    // Each of these is a settings report that arrived and could not be used. The
    // alternative — read it as "nothing to report" — is the silent drop ITEM 10 is
    // about, and a `state` this build has never seen is exactly the frame whose one
    // affordance (`action: "reset"`) a user may still need.
    const malformed: unknown[] = [
      {},
      { state: "corrupt" },
      { ...NATIVE, reason: 5 },
      { ...NATIVE, reason: "" },
      { ...NATIVE, detectedAt: "1761234567890" },
      { ...NATIVE, field: 42 },
      { ...NATIVE, action: "delete" },
      { state: "healthy", reason: "nope", field: null, detectedAt: 1, action: "reset" },
      "corrupt",
      [NATIVE],
      true,
    ];
    for (const value of malformed) {
      const report = parseSettingsError(value);
      expect(report.verdict, JSON.stringify(value)).toBe("unreadable");
      if (report.verdict === "unreadable") expect(report.reason.length).toBeGreaterThan(0);
    }
  });

  it("reads the report off a whole get_state frame that parseRuntimeState has already narrowed", () => {
    // The end-to-end claim: `parseRuntimeState` returns the four shared fields and
    // nothing else, so the report has to be taken off the same payload at the frame
    // boundary rather than off the parsed state.
    const frame = {
      status: "disconnected",
      detail: "Ready",
      pid: null,
      endpoint: null,
      settingsError: NATIVE,
    };
    expect(settingsReportOf(frame)).toEqual({ verdict: "corrupt", corruption: NATIVE });
  });

  it("treats a payload that is not an object as nothing to report", () => {
    for (const frame of [undefined, null, "state", 7]) {
      expect(settingsReportOf(frame)).toEqual({ verdict: "healthy" });
    }
  });
});
