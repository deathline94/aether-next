/**
 * The health of the *stored* profile, as the shell reports it.
 *
 * Its own module rather than more lines in `useRuntime`, for the reason that module's
 * header gives: `hooks/useRuntime.ts` is a deliberate fork of the desktop's, held by
 * the `frontend-fork-parity` ratchet, and this rule has no desktop counterpart at all
 * — the desktop's settings live in a Tauri store that either parses or does not, and
 * its `get_state` carries no `settingsError`. A per-shell rule belongs in a file the
 * other app does not have.
 *
 * What it owns, and only this:
 *
 * - the report, taken off every `session://state` / `get_state` frame the runtime
 *   reads (`settingsReportOf`, because `parseRuntimeCore` drops the key);
 * - whether that report forbids claiming the settings are loaded — `blocksHydration`,
 *   which the loader consults before it says "Settings loaded from disk";
 * - the one action that clears it. `SettingsStore.save` refuses every write while a
 *   corrupt blob is unresolved, including the one `connect()` makes, so a user with no
 *   reset is locked out of both saving and tunnelling, with an error that names
 *   neither. `resetCorruptSettings()` is the documented way through, and it keeps the
 *   rejected bytes.
 *
 * It deliberately does not own the settings values or the save lifecycle: those are
 * `useRuntime`'s, and conflating them is how "the profile on screen parsed" came to
 * mean "the profile on screen is the user's".
 */
import { useCallback, useRef, useState } from "react";
import { invoke } from "../bridge";
import { describeSettingsReport, type SettingsCorruption, type SettingsReport } from "../settingsPayload";
import { settingsReportOf } from "../types";
import { ipcError } from "../ipcError";
import type { IpcError } from "../ipcError";

type Log = (entry: { level: "info" | "warn" | "error"; message: string }) => void;

/** What the loader has to undo when a frame says the stored profile is not usable. */
export type RevokeHydration = () => void;

export function useSettingsHealth(appendLog: Log, revokeHydration: RevokeHydration) {
  const [report, setReport] = useState<SettingsReport>({ verdict: "healthy" });
  // A ref beside the state, because the loaders that have to consult it run in
  // closures captured before the re-render: `settingsLoaded` is decided in a `finally`
  // whose report would otherwise be the one from first render.
  const reportRef = useRef<SettingsReport>(report);
  const [resetBusy, setResetBusy] = useState(false);
  const [resetError, setResetError] = useState<IpcError | null>(null);
  // One line per distinct corruption, not one per frame: the shell re-publishes the
  // state on every engine event, and the same diagnosis would fill the console.
  const logged = useRef(new Set<string>());
  // The guard is a ref, not the rendered flag: two presses in one tick must not
  // dispatch two resets, and a `state` read here would let both through.
  const busyRef = useRef(false);

  /** The report this frame carries, applied. Runs for events and for `get_state`. */
  const applyFrame = useCallback(
    (payload: unknown) => {
      const next = settingsReportOf(payload);
      reportRef.current = next;
      setReport(next);
      if (next.verdict === "healthy") return;
      // A frame can arrive after hydration said the profile was loaded — the shell
      // re-reads its store on several paths — and "loaded" is a claim about *this*
      // profile, so it has to come back off. The loader owns what that means; this
      // module only says the report no longer supports it.
      revokeHydration();
      const notice = describeSettingsReport(next) ?? "";
      const key = next.verdict === "corrupt" ? `corrupt:${next.corruption.detectedAt}` : `unreadable:${next.reason}`;
      if (!logged.current.has(key)) {
        logged.current.add(key);
        appendLog({ level: "error", message: `Stored settings could not be loaded. ${notice}` });
      }
    },
    [appendLog, revokeHydration],
  );

  /** Whether the profile on screen may be called the user's, or reported as loaded. */
  const blocksHydration = useCallback(() => reportRef.current.verdict !== "healthy", []);

  /**
   * Accept the defaults and clear the write lock.
   *
   * True only when the shell confirmed it, because the caller's next move — re-read
   * the profile and unlock the form — is wrong on a refusal: the report still stands,
   * the values on screen are still not the user's, and a reset that "succeeded"
   * locally would hand back an editable form whose every save is still refused.
   */
  const resetCorruptReport = useCallback(async (): Promise<boolean> => {
    if (busyRef.current) return false;
    busyRef.current = true;
    setResetBusy(true);
    try {
      await invoke("reset_settings");
      reportRef.current = { verdict: "healthy" };
      setReport(reportRef.current);
      logged.current.clear();
      setResetError(null);
      appendLog({
        level: "info",
        message: "Settings reset: the defaults are saved, and the profile that could not be read is kept on the device.",
      });
      return true;
    } catch (error) {
      const err = ipcError(error);
      setResetError(err);
      appendLog({ level: "error", message: `Reset settings failed: ${err.message}` });
      return false;
    } finally {
      busyRef.current = false;
      setResetBusy(false);
    }
  }, [appendLog]);

  const corruption: SettingsCorruption | null =
    report.verdict === "corrupt" ? report.corruption : null;

  return {
    /** A corrupt or unreadable stored profile: the form may not claim otherwise. */
    settingsCorrupt: report.verdict !== "healthy",
    settingsCorruption: corruption,
    /** The sentence for the banner: the diagnosis, and the reset that clears it. */
    settingsCorruptionNotice: describeSettingsReport(report),
    resetSettingsBusy: resetBusy,
    resetSettingsError: resetError,
    applyFrame,
    blocksHydration,
    resetCorruptReport,
  };
}
