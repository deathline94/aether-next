/**
 * The Android payload guard: what the Kotlin shell hands the renderer for
 * `get_settings`, checked before any of it reaches React state.
 *
 * This is a separate module rather than another clause of `types.ts` because the
 * rule is Android's own: the desktop's `get_settings` is a Tauri `Settings`
 * serialised by `apps/desktop/src-tauri`, this one is a `JSONObject` built by
 * `SettingsStore.kt`, and the two shells disagree on which fields exist. The
 * frontends are otherwise kept deliberately in step by the `frontend-fork-parity`
 * gate, which measures how much of the code in `apps/android/src/*.ts` is the same
 * code in `apps/desktop/src/*.ts`; a file with no twin on the other side is the one
 * place a per-shell rule can live without dragging that ratchet down.
 *
 * Why the guard exists at all: `bridge.ts` unwraps the native
 * `{ ok, data, error }` envelope and returns `data as T`, and the runtime hook used
 * to do `{ ...defaults, ...payload }` with whatever came back. `as T` is not a
 * check. A payload whose `protocol` was `"masque-h3"` (a *scanner* value, not a
 * `Settings` one) or whose `transport` was `42` became state, and the panels
 * dereference those fields while rendering — `CARRIER_CHIP[settings.protocol]` on a
 * missing arm is a `TypeError` inside a render, which on this surface is the blank
 * WebView with no banner. Worse, the merged object was written back to disk by the
 * next debounced save, so a bad read silently overwrote the user's profile.
 *
 * Two rules, deliberately different, because they are two different facts:
 *
 * - a field that is **absent** is an older shell. The default for it is used and
 *   the field is named in `corrected`, which is what the merge over `defaults` was
 *   actually for, and the hook logs it.
 * - a field that is **present and unreadable** — wrong type, a value no option list
 *   contains, a number outside the range the shell's own `validateSettings` refuses
 *   — is corrupt data. The whole payload is refused, because substituting a default
 *   for a value the user can see is the silent overwrite this guard exists to stop,
 *   and because half a profile is not a profile.
 */
import {
  IP_FAMILIES,
  NOIZE_PROFILES,
  ROUTING_MODES,
  SCAN_MODES,
  TRANSPORTS,
  TUNNEL_PROTOCOLS,
} from "@aether/ui/enums";
import type { NoizeProfile } from "@aether/ui/enums";
import { defaults, type Settings } from "./types";

/**
 * The bounds the shell enforces on a saved profile.
 *
 * `SessionController.validateSettings` is what actually refuses a write, and the
 * Settings inputs advertise the same numbers; the loader used to advertise nothing
 * and merge whatever arrived. A number outside its range is not a value the form can
 * display or re-send, so it is a reason to refuse the payload — not a reason to
 * rewrite the user's setting behind their back.
 */
export const SETTINGS_BOUNDS = {
  portMin: 1024,
  portMax: 65535,
  noizeJcMax: 64,
  noizeSizeMax: 2048,
  noizeIntervalMsMax: 5000,
  fragSizeMin: 16,
  fragSizeMax: 512,
} as const;

/**
 * The noise spellings a profile saved by an older build can still carry.
 *
 * `NoizeProfiles.appValues` in the Kotlin shell names these as "the legacy aliases
 * it still reads back from a saved profile", and it translates them rather than
 * refusing them — so the loader accepts them too, on the way to the canonical value,
 * and reports every translation instead of quietly picking one. `SettingsTab` used to
 * keep its own private copy of this table for the select's value; it now calls
 * `normalizeNoize`.
 */
export const NOIZE_ALIASES: Record<string, NoizeProfile> = {
  on: "light",
  random: "light",
  m1: "light",
  balanced: "medium",
  firewall: "medium",
  gfw: "high",
  aggressive: "max",
  heavy: "max",
  m2: "max",
};

/** The canonical profile a stored value means, or `null` when nothing does. */
export function normalizeNoize(raw: string): NoizeProfile | null {
  const value = raw.trim().toLowerCase();
  return (NOIZE_PROFILES as readonly string[]).includes(value)
    ? (value as NoizeProfile)
    : (NOIZE_ALIASES[value] ?? null);
}

/** A read profile, with the fields that had to be filled in named; or the refusal. */
export type SettingsParse =
  | { ok: true; settings: Settings; corrected: string[] }
  | { ok: false; field: string; reason: string };

export function parseSettingsPayload(payload: unknown): SettingsParse {
  if (typeof payload !== "object" || payload === null || Array.isArray(payload)) {
    return { ok: false, field: "settings", reason: "expected an object of settings" };
  }
  const src = payload as Record<string, unknown>;
  const corrected: string[] = [];
  // The first field that cannot be read. The helpers below still return a value so
  // the caller's types hold, but a refusal wins: nothing unreadable is kept. Held in
  // an object because a `let` these closures assign is narrowed to `null` by the
  // compiler at the check site.
  const refusal: { current: { field: string; reason: string } | null } = { current: null };
  const refuse = (field: string, detail: string) => {
    if (!refusal.current) refusal.current = { field, reason: `${field} ${detail}` };
  };

  const enumeration = <T extends string>(
    field: keyof Settings,
    allowed: readonly T[],
    fallback: T,
  ): T => {
    const value = src[field];
    if (value === undefined) {
      corrected.push(String(field));
      return fallback;
    }
    if (typeof value === "string" && (allowed as readonly string[]).includes(value)) {
      return value as T;
    }
    refuse(String(field), `is ${JSON.stringify(value)}, not one of ${allowed.join(" | ")}`);
    return fallback;
  };
  const ranged = (field: keyof Settings, fallback: number, min: number, max: number): number => {
    const value = src[field];
    if (value === undefined) {
      corrected.push(String(field));
      return fallback;
    }
    if (typeof value === "number" && Number.isFinite(value) && value >= min && value <= max) {
      return value;
    }
    refuse(String(field), `is ${JSON.stringify(value)}, outside ${min}-${max}`);
    return fallback;
  };
  const flag = (field: keyof Settings, fallback: boolean): boolean => {
    const value = src[field];
    if (value === undefined) {
      corrected.push(String(field));
      return fallback;
    }
    if (typeof value === "boolean") return value;
    refuse(String(field), `is ${typeof value}, expected true or false`);
    return fallback;
  };
  const text = (field: keyof Settings, fallback: string): string => {
    const value = src[field];
    if (value === undefined) {
      corrected.push(String(field));
      return fallback;
    }
    if (typeof value === "string") return value;
    refuse(String(field), `is ${typeof value}, expected text`);
    return fallback;
  };
  const noise = (): NoizeProfile => {
    const value = src.noize;
    if (value === undefined) {
      corrected.push("noize");
      return defaults.noize as NoizeProfile;
    }
    if (typeof value === "string") {
      const canonical = normalizeNoize(value);
      if (canonical) {
        if (canonical !== value) corrected.push("noize");
        return canonical;
      }
      refuse("noize", `is ${JSON.stringify(value)}, which the engine has no name for`);
      return defaults.noize as NoizeProfile;
    }
    refuse("noize", `is ${typeof value}, expected text`);
    return defaults.noize as NoizeProfile;
  };

  const protocol = enumeration("protocol", TUNNEL_PROTOCOLS, defaults.protocol);
  const transport = enumeration("transport", TRANSPORTS, defaults.transport);
  const scanMode = enumeration("scanMode", SCAN_MODES, defaults.scanMode);
  const ipVersion = enumeration("ipVersion", IP_FAMILIES, defaults.ipVersion);
  const routingMode = enumeration("routingMode", ROUTING_MODES, defaults.routingMode);
  const noize = noise();
  const noizeJc = ranged("noizeJc", defaults.noizeJc, 0, SETTINGS_BOUNDS.noizeJcMax);
  const noizeJmin = ranged("noizeJmin", defaults.noizeJmin, 0, SETTINGS_BOUNDS.noizeSizeMax);
  const noizeJmax = ranged("noizeJmax", defaults.noizeJmax, 0, SETTINGS_BOUNDS.noizeSizeMax);
  const noizeIntervalMs = ranged(
    "noizeIntervalMs",
    defaults.noizeIntervalMs,
    0,
    SETTINGS_BOUNDS.noizeIntervalMsMax,
  );
  const socksPort = ranged(
    "socksPort",
    defaults.socksPort,
    SETTINGS_BOUNDS.portMin,
    SETTINGS_BOUNDS.portMax,
  );
  const httpPort = ranged(
    "httpPort",
    defaults.httpPort,
    SETTINGS_BOUNDS.portMin,
    SETTINGS_BOUNDS.portMax,
  );
  const quicInitialFragSize = ranged(
    "quicInitialFragSize",
    defaults.quicInitialFragSize,
    SETTINGS_BOUNDS.fragSizeMin,
    SETTINGS_BOUNDS.fragSizeMax,
  );
  const launchAtLogin = flag("launchAtLogin", defaults.launchAtLogin);
  const quicInitialFrag = flag("quicInitialFrag", defaults.quicInitialFrag);
  const peer = text("peer", defaults.peer);

  if (refusal.current) {
    return { ok: false, field: refusal.current.field, reason: refusal.current.reason };
  }
  return {
    ok: true,
    corrected,
    settings: {
      protocol,
      transport,
      scanMode,
      ipVersion,
      noize,
      noizeJc,
      noizeJmin,
      noizeJmax,
      noizeIntervalMs,
      routingMode,
      socksPort,
      httpPort,
      launchAtLogin,
      peer,
      quicInitialFrag,
      quicInitialFragSize,
    },
  };
}

/**
 * The corruption report the shell rides on `session://state` / `get_state`.
 *
 * `SettingsStore.load()` now reads three ways — MISSING, Healthy, CORRUPT — and for
 * CORRUPT it hands back `Settings()` (plain defaults), keeps the unreadable bytes in
 * `corrupt_json`, and publishes the diagnosis as `settingsError` on the *state*
 * payload (`SettingsStore.kt:108`, built by `corruptionPayload()` at
 * `SettingsStore.kt:372-379`) rather than on the settings payload, because
 * `Settings.toJson()` is the persisted key set and a load diagnosis is not a setting.
 *
 * That split is the whole problem: the profile on screen parses perfectly — because it
 * is the defaults, not the user's — while the fact that says so is two payloads away,
 * on a frame that `parseRuntimeCore` narrows to the four fields both shells render.
 * The report was dropped there, the app reported "settings loaded", and every write
 * the shell then refused (`SettingsStore.save`) looked like a UI bug.
 *
 * So it is read here, in the module that already owns "what the Kotlin shell hands
 * the renderer", and refused as *unreadable* rather than ignored when it arrives in a
 * shape this build cannot honour: a settings report that cannot be read is still a
 * settings report, and the way out (`action: "reset"`) is the one thing the user may
 * not be left without.
 */
export type SettingsCorruption = {
  state: "corrupt";
  reason: string;
  field: string | null;
  detectedAt: number;
  action: "reset";
};

/** The three verdicts a `settingsError` value can carry into the interface. */
export type SettingsReport =
  | { verdict: "healthy" }
  | { verdict: "corrupt"; corruption: SettingsCorruption }
  | { verdict: "unreadable"; reason: string };

/** The `settingsError` of one frame, as a verdict. Never `undefined`, never thrown. */
export function parseSettingsError(raw: unknown): SettingsReport {
  // `JSONObject.NULL` arrives as `null`, and a shell older than this field omits it.
  if (raw === undefined || raw === null) return { verdict: "healthy" };
  if (typeof raw !== "object" || Array.isArray(raw)) {
    return { verdict: "unreadable", reason: `expected an object, found ${Array.isArray(raw) ? "a list" : typeof raw}` };
  }
  const o = raw as Record<string, unknown>;
  const unreadable = (detail: string): SettingsReport => ({
    verdict: "unreadable",
    reason: `cannot read ${JSON.stringify(detail)}`,
  });
  if (o.state !== "corrupt") return unreadable(`state ${JSON.stringify(o.state)}`);
  if (typeof o.reason !== "string" || o.reason.length === 0) return unreadable("reason");
  if (o.field !== null && typeof o.field !== "string") return unreadable("field");
  if (typeof o.detectedAt !== "number" || !Number.isFinite(o.detectedAt)) return unreadable("detectedAt");
  // `action` is the affordance, not decoration: a report whose remedy is not the one
  // this surface offers would promise a button that does not exist.
  if (o.action !== "reset") return unreadable(`action ${JSON.stringify(o.action)}`);
  return {
    verdict: "corrupt",
    corruption: {
      state: "corrupt",
      reason: o.reason,
      field: typeof o.field === "string" ? o.field : null,
      detectedAt: o.detectedAt,
      action: "reset",
    },
  };
}

/**
 * What the user is told, in the sentence they have to be able to act on.
 *
 * Three facts, in this order: the saved profile was not read, it was **not**
 * overwritten, and the only move that clears it is the reset the banner names. The
 * middle one is the point of ITEM 10 — a user who is told "settings failed to load"
 * and offered a reset is being invited to destroy the thing the shell went to
 * considerable lengths to preserve. `null` is the healthy case, and the only other
 * answer is a report this build cannot read, which says so rather than guessing.
 */
export function describeSettingsReport(report: SettingsReport): string | null {
  if (report.verdict === "healthy") return null;
  if (report.verdict === "unreadable") {
    return (
      `The shell reported a problem with the settings stored on this device that this ` +
      `build cannot read (${report.reason}). Nothing was overwritten, and nothing can be ` +
      `saved until it is resolved. Choose Reset settings to accept the built-in defaults; ` +
      `the unreadable profile stays on the device.`
    );
  }
  const { corruption } = report;
  const where = corruption.field ? ` (${corruption.field})` : "";
  // `detectedAt` is the shell's own stamp (`SettingsStore.load` publishes it at the
  // moment it refused the read), so the sentence says when the file went unreadable —
  // the fact a user needs to decide which backup to restore it from.
  const when = new Date(corruption.detectedAt).toLocaleString();
  return (
    `Your saved settings could not be read at ${when}: ${corruption.reason}${where}. They were ` +
    `kept on the device, not overwritten, and this screen is showing the built-in defaults — so ` +
    `no edit here can be saved, and connecting is refused too. Choose Reset settings to accept ` +
    `the defaults; the profile that could not be read stays on the device to be restored.`
  );
}
