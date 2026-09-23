// @vitest-environment jsdom
import { beforeEach, describe, expect, it, vi } from "vitest";

/*
 * The dev/preview mock has to behave like the device for a corrupt profile, or the
 * one screen the fix can be looked at is the one screen that never shows it.
 *
 * `SettingsStore` answers a corrupt read with `Settings()` (defaults), publishes the
 * diagnosis on the state frame, and refuses `save()` until `resetCorruptSettings()`
 * succeeds — while keeping the rejected bytes in `corrupt_json` (`SettingsStore.kt:301`).
 * The mock used to swallow the unreadable blob in a `catch {}` and hand back defaults
 * as if the read had succeeded, so on the preview surface a corrupt profile looked,
 * and saved, exactly like a healthy one.
 */
import { invoke } from "./bridge";
import { defaults } from "./types";
import { IpcRejection } from "./ipcError";
import { parseSettingsPayload } from "./settingsPayload";

const STORED = "aether.settings";
const QUARANTINED = "aether.settings.corrupt";

/*
 * Node 25 ships a `globalThis.localStorage` stub with no methods on it, and vitest's
 * jsdom environment leaves an existing global alone, so the bridge's storage calls
 * land on that. This is the same shape the browser gives: a string store, with the
 * two keys `SettingsStore` keeps — the profile and the quarantined bytes.
 */
const backing = new Map<string, string>();
vi.stubGlobal("localStorage", {
  getItem: (key: string) => (backing.has(key) ? backing.get(key)! : null),
  setItem: (key: string, value: string) => void backing.set(key, String(value)),
  removeItem: (key: string) => void backing.delete(key),
  clear: () => backing.clear(),
});

type StateFrame = {
  status: string;
  detail: string;
  settingsError: {
    state: string;
    reason: string;
    field: string | null;
    detectedAt: number;
    action: string;
  } | null;
};

async function frame(): Promise<StateFrame> {
  return invoke<StateFrame>("get_state");
}

beforeEach(() => {
  backing.clear();
});

describe("the mock shell refuses to destroy a corrupt profile", () => {
  it("reports an unreadable stored blob on the state frame, and still answers get_settings", async () => {
    localStorage.setItem(STORED, '{"protocol":"masque"');

    const state = await frame();
    expect(state.settingsError).toMatchObject({ state: "corrupt", action: "reset" });
    expect(typeof state.settingsError?.detectedAt).toBe("number");

    // The read still yields a usable profile — defaults, not the user's — because a
    // corrupt blob must not white-screen the app that is trying to tell about it.
    expect(await invoke("get_settings")).toEqual(expect.objectContaining({ protocol: defaults.protocol }));
  });

  it("refuses save_settings with the shell's own rejection while the report stands", async () => {
    localStorage.setItem(STORED, '{"protocol":"openvpn"}');

    expect(parseSettingsPayload({ protocol: "openvpn" }).ok).toBe(false);
    const error = await invoke("save_settings", { settings: { ...defaults } }).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(IpcRejection);
    expect((error as IpcRejection).ipc.code).toBe("validation");
    expect((error as IpcRejection).ipc.field).toBe("settings");
    expect((error as IpcRejection).message).toContain("Settings were not saved");
    // Refused means refused: the unreadable bytes are untouched, not quietly replaced.
    expect(localStorage.getItem(STORED)).toBe('{"protocol":"openvpn"}');
  });

  it("keeps the rejected bytes after the reset that replaces them", async () => {
    localStorage.setItem(STORED, "not json at all");

    await invoke("reset_settings");

    expect((await frame()).settingsError).toBeNull();
    expect(localStorage.getItem(STORED)).toBeTruthy();
    expect(JSON.parse(localStorage.getItem(STORED)!)).toEqual(expect.objectContaining({ protocol: defaults.protocol }));
    // `corrupt_json` survives `resetCorruptSettings()`: the user can still restore it.
    expect(localStorage.getItem(QUARANTINED)).toBe("not json at all");
    // And the write lock is off, so a save now works.
    await expect(invoke("save_settings", { settings: { ...defaults, httpPort: 8099 } })).resolves.toBeUndefined();
    expect(await invoke("get_settings")).toEqual(
      expect.objectContaining({ protocol: defaults.protocol, httpPort: 8099 }),
    );
  });

  it("leaves a healthy store with nothing to report and every write allowed", async () => {
    const healthy = { ...defaults, protocol: "wireguard" as const };
    localStorage.setItem(STORED, JSON.stringify(healthy));

    expect((await frame()).settingsError).toBeNull();
    await expect(invoke("save_settings", { settings: { ...defaults } })).resolves.toBeUndefined();
    expect(await invoke("get_settings")).toEqual(expect.objectContaining({ protocol: defaults.protocol }));
    expect(localStorage.getItem(QUARANTINED)).toBeNull();
  });
});
