import { useCallback, useEffect, useRef, useState } from "react";
import { invoke, listen } from "../bridge";
import { defaults, initialRuntime, parseRuntimeState } from "../types";
import { parseSettingsPayload } from "../settingsPayload";
import { parseTestOutcome } from "../nativeOutcome";
import { useSettingsHealth } from "./useSettingsHealth";
import type { SaveState } from "../saveState";
import type { RuntimeState, Settings } from "../types";
import { errorMessage, ipcError } from "../ipcError";
import type { IpcError } from "../ipcError";
import { describeRejectedState } from "@aether/ui";

/**
 * What a connectivity check actually knows.
 *
 * `latencyMs` is null unless the native layer measured a round trip. The UI used
 * to scrape a number out of the result sentence with `(\d+)\s*ms`, which never
 * matched the success text (the tile read "not measured" forever) and did match
 * the timeout inside a failure (printing a failure's 12000 ms as a latency). An
 * absent measurement is now displayed as absent rather than guessed.
 */
export type TestOutcome = {
  detail: string;
  latencyMs: number | null;
};

const FALLBACK_VERSION = "0.0.0";
const SAVE_DEBOUNCE_MS = 400;
/** If the engine stays "connecting" past this, surface a timeout instead of hanging forever. */
const CONNECT_WATCHDOG_MS = 90_000;

export function useRuntime(
  appendLog: (entry: { level: "info" | "warn" | "error"; message: string }) => void,
) {
  const [settings, setSettings] = useState<Settings>(defaults);
  // Settings must not be editable until hydrated from disk — otherwise a patch
  // during that window persists `defaults` over the user's real config.
  const [settingsLoaded, setSettingsLoaded] = useState(false);
  const [settingsLoadError, setSettingsLoadError] = useState(false);
  const [runtime, setRuntime] = useState<RuntimeState>(initialRuntime);
  const [busy, setBusy] = useState(false);
  const busyRef = useRef(false);
  const [testBusy, setTestBusy] = useState(false);
  const [saveState, setSaveState] = useState<SaveState>("idle");
  const [saveError, setSaveError] = useState<IpcError | null>(null);
  const [admin, setAdmin] = useState(false);
  const [testResult, setTestResult] = useState<TestOutcome | null>(null);
  const [appVersion, setAppVersion] = useState<string | null>(null);

  // The stored profile's own health, reported on the state frame rather than on the
  // settings payload: `SettingsStore.load()` hands back defaults for a blob it cannot
  // read, so a settings payload alone cannot tell "nothing stored" from "the user's
  // profile is unreadable and is being preserved". See `useSettingsHealth`.
  const profileIsNotTheUsers = useCallback(() => {
    setSettingsLoaded(false);
    setSettingsLoadError(true);
  }, []);
  const {
    settingsCorrupt, settingsCorruption, settingsCorruptionNotice,
    resetSettingsBusy, resetSettingsError,
    applyFrame, blocksHydration, resetCorruptReport,
  } = useSettingsHealth(appendLog, profileIsNotTheUsers);

  // One log line per distinct refused shape, not one per frame: a shell that
  // emits a bad status every second must not fill the console with it.
  const rejectedStates = useRef(new Set<string>());

  const savedTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const saveDebounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const pendingSaveRef = useRef<Settings | null>(null);
  const settingsRef = useRef(settings);
  const watchdogRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  /// Monotonic save token: only the newest dispatch may report the dock, so a
  /// slow write of an older payload cannot land the state of a newer one.
  const saveSeqRef = useRef(0);

  const connected = runtime.status === "connected";
  const running = runtime.status === "connecting" || connected;
  const settingsLocked = running || !settingsLoaded;

  /**
   * Put a `get_settings` reply into state, or say why it could not go in.
   *
   * One path for hydration and for "Retry", because a second copy of the read is
   * how a weaker validator gets to exist: both call the same parser the events use,
   * a payload that is merely *incomplete* falls back to the documented default with
   * the field named in the log, and a payload that carries a value this build cannot
   * represent is refused whole — never merged over the profile already on screen,
   * and never rewritten to disk by the next edit as if the user had chosen it.
   */
  const applyLoadedSettings = useCallback(
    (loaded: Settings | null) => {
      const parsed = loaded === null ? null : parseSettingsPayload(loaded);
      if (parsed?.ok) {
        const { settings: merged, corrected } = parsed;
        settingsRef.current = merged;
        setSettings(merged);
        // A readable payload is not yet a readable *profile*: while the shell reports
        // the stored blob corrupt, what was just applied are its defaults, and the
        // hydration failure has to stay on screen with it.
        setSettingsLoadError(blocksHydration());
        // A profile that has just been read *is* the one on disk: nothing is
        // pending, and the dock must say so rather than "Synchronizing…".
        setSaveState("idle");
        if (corrected.length > 0) {
          appendLog({
            level: "warn",
            message: `Settings from disk were incomplete or out of range (${corrected.join(", ")}); the defaults are in use for those until you change them.`,
          });
        }
        return;
      }
      setSettingsLoadError(true);
      appendLog({
        level: "error",
        message: parsed
          ? `Refused the settings the shell sent (${parsed.reason}). Keeping the profile already on screen.`
          : "Could not read the settings from disk.",
      });
    },
    [appendLog, blocksHydration],
  );

  /**
   * A `get_state` reply that cannot be read is reported, not displayed.
   *
   * Leaving the previous status standing would show something as the engine's
   * state when the only fact is that the answer did not parse, so the hero goes to
   * the one state that admits it knows nothing and offers the way out (dismiss, or
   * the next frame the shell sends).
   */
  const reportUnknownEngineState = useCallback(
    (reason: string) => {
      const detail = `Engine status unreadable (${reason}); no tunnel state is shown.`;
      setRuntime({ status: "error", detail, pid: null, endpoint: null });
      appendLog({ level: "error", message: detail });
    },
    [appendLog],
  );

  // Initialize: load settings, state, admin/version + subscribe to engine events.
  useEffect(() => {
    let disposed = false;
    const receivedRuntimeEvent = { current: false };
    const cleanup: Array<() => void> = [];

    async function initialize() {
      try {
        const unlistenState = await listen<unknown>("session://state", (event) => {
          receivedRuntimeEvent.current = true;
          // The settings report rides on the same frame, and is read before the
          // frame is narrowed to the four fields the tunnel has copy for.
          applyFrame(event.payload);
          const next = parseRuntimeState(event.payload);
          if (next) {
            setRuntime(next);
            return;
          }
          // Not a state: keep showing the last one that was understood, and say why
          // once. Writing the frame through is how an unknown `status` reached
          // `heroCopy[status]`, threw inside a background event and blanked the
          // WebView.
          const key = describeRejectedState(event.payload);
          if (!rejectedStates.current.has(key)) {
            rejectedStates.current.add(key);
            appendLog({
              level: "error",
              message: `Ignored a session state the interface cannot render (${key}); showing the previous one.`,
            });
          }
        });
        if (disposed) { unlistenState(); return; }
        cleanup.push(unlistenState);

        const unlistenLog = await listen<{ level: "info" | "warn" | "error"; message: string }>(
          "session://log",
          (event) => appendLog(event.payload),
        );
        if (disposed) { unlistenLog(); return; }
        cleanup.push(unlistenLog);

        // The shell coalesces engine chatter (`RUST_LOG=info` during a scan is
        // hundreds of lines a second) into one post per interval instead of one
        // `evaluateJavascript` per line. Both shapes are accepted so a dev server
        // talking to an older shell, or a newer shell talking to a cached page, still
        // streams — a log line that cannot be rendered must never be the reason the
        // runtime status stops updating.
        const unlistenLogs = await listen<{
          entries?: { level: "info" | "warn" | "error"; message: string }[];
        }>("session://logs", (event) => {
          const entries = Array.isArray(event.payload?.entries) ? event.payload.entries : [];
          for (const entry of entries) {
            if (entry && typeof entry.message === "string") appendLog(entry);
          }
        });
        if (disposed) { unlistenLogs(); return; }
        cleanup.push(unlistenLogs);
      } catch (error) {
        appendLog({ level: "warn", message: errorMessage(error) });
      }

      try {
        const [loadedSettings, state, isAdmin, info] = await Promise.all([
          invoke<Settings>("get_settings").catch((e) => { appendLog({ level: "warn", message: `Load settings failed: ${String(e)}` }); return null; }),
          invoke<RuntimeState>("get_state").catch(() => null),
          invoke<boolean>("is_admin").catch(() => false),
          invoke<{ version?: string }>("app_info").catch(() => null),
        ]);
        if (disposed) return;
        // The frame first, because it is what says whether the settings about to be
        // applied are the user's: `get_settings` answers a corrupt blob with valid
        // defaults, and only `settingsError` distinguishes that from a healthy read.
        if (state !== null) applyFrame(state);
        applyLoadedSettings(loadedSettings);
        // The other half of the same rule: `get_state` is a native payload like the
        // event, so it goes through the event's parser rather than being written
        // straight into state, where a status this build has no copy for used to
        // reach `heroCopy[status]` and throw. A frame that cannot be read is
        // reported as the missing answer it is — the engine's state is unknown, and
        // "Ready" would be a claim nothing observed.
        const parsed = state ? parseRuntimeState(state) : null;
        if (state && !parsed) {
          reportUnknownEngineState(describeRejectedState(state));
        } else if (parsed && !receivedRuntimeEvent.current) {
          setRuntime(parsed);
        }
        setAdmin(Boolean(isAdmin));
        setAppVersion(info?.version ? String(info.version) : FALLBACK_VERSION);
      } finally {
        // Hydration completed, but "loaded" is a claim about the *user's* profile: a
        // corrupt or unreadable stored blob leaves the form showing defaults, and a
        // form that says so is locked until the reset below clears it.
        if (!disposed) setSettingsLoaded(!blocksHydration());
      }
    }
    void initialize();
    return () => { disposed = true; cleanup.forEach((fn) => fn()); };
  }, [appendLog, applyFrame, applyLoadedSettings, blocksHydration, reportUnknownEngineState]);

  // Cleanup timers on unmount.
  useEffect(() => () => {
    if (savedTimerRef.current) clearTimeout(savedTimerRef.current);
    if (saveDebounceRef.current) clearTimeout(saveDebounceRef.current);
    if (watchdogRef.current) clearTimeout(watchdogRef.current);
  }, []);

  // Connection watchdog: never let the UI sit on "connecting" forever.
  useEffect(() => {
    if (watchdogRef.current) { clearTimeout(watchdogRef.current); watchdogRef.current = null; }
    if (runtime.status !== "connecting") return;
    watchdogRef.current = setTimeout(() => {
      setRuntime((prev) =>
        prev.status === "connecting"
          ? { status: "error", detail: "Connection timed out — no reachable route found. Try another protocol or network.", pid: null, endpoint: null }
          : prev,
      );
      void invoke("disconnect").catch(() => {});
      appendLog({ level: "error", message: "Connection timed out after 90s; engine stopped." });
    }, CONNECT_WATCHDOG_MS);
    return () => {
      if (watchdogRef.current) { clearTimeout(watchdogRef.current); watchdogRef.current = null; }
    };
  }, [runtime.status, appendLog]);

  /**
   * Stop the current session without letting a partial teardown block the next
   * one. `disconnect` reports `disconnect_incomplete` when the engine had to be
   * killed or the system proxy could not be restored; reconnecting is the remedy
   * in both cases, so the wording must reach the log without failing the caller
   * that is trying to reconnect.
   */
  const safeDisconnect = useCallback(async () => {
    try {
      await invoke("disconnect");
    } catch (error) {
      const detail = errorMessage(error);
      appendLog({ level: "error", message: `Disconnect reported a problem: ${detail}` });
    }
  }, [appendLog]);

  const persistSettings = useCallback((next: Settings) => {
    // Debounced: NumberField commits and toggles arrive in bursts; don't hit
    // storage per event.
    pendingSaveRef.current = next;
    if (saveDebounceRef.current) clearTimeout(saveDebounceRef.current);
    saveDebounceRef.current = setTimeout(async () => {
      const toSave = pendingSaveRef.current;
      if (!toSave) return;
      const mine = ++saveSeqRef.current;
      setSaveState("saving");
      try {
        await invoke("save_settings", { settings: toSave });
        if (mine !== saveSeqRef.current) return; // superseded by a newer edit
        setSaveError(null);
        setSaveState("saved");
        if (savedTimerRef.current) clearTimeout(savedTimerRef.current);
        savedTimerRef.current = setTimeout(() => setSaveState("idle"), 1200);
      } catch (error) {
        if (mine !== saveSeqRef.current) return;
        const err = ipcError(error);
        setSaveError(err);
        // Still pending: the value on screen is not the value on disk, and a
        // refusal is not a synchronisation. `saveError` is what the dock reads as
        // the rejection; the lifecycle stays `dirty`.
        setSaveState("dirty");
        appendLog({ level: "error", message: `Save settings failed: ${err.message}` });
      }
    }, SAVE_DEBOUNCE_MS);
  }, [appendLog]);

  const patchSettings = useCallback((patch: Partial<Settings>) => {
    if (settingsLocked) return;
    // A validation error describes the value being replaced, not the new one.
    setSaveError(null);
    setSettings((prev) => ({ ...prev, ...patch }));
  }, [settingsLocked]);

  // Persist as an effect of settings changing — keeps the state updater pure.
  useEffect(() => {
    const prev = settingsRef.current;
    settingsRef.current = settings;
    if (!settingsLoaded || prev === settings) return;
    // An edit is pending the moment it lands on screen, and only the write below
    // may call it "saving": the dock used to read every state that was not a
    // just-flashed success as a synchronisation in progress.
    setSaveState("dirty");
    persistSettings(settings);
  }, [settings, settingsLoaded, persistSettings]);

  const toggleConnection = useCallback(async () => {
    if (busyRef.current || busy) return;
    // Settings hydration is a load, not a formality: the shell's connect
    // persists the settings it receives (SessionController.connect stores them),
    // so a tap before hydration lands would overwrite the user's saved profile
    // with factory defaults — the exact reason the settings rows are locked on
    // `settingsLocked`. Disconnecting stays available even when the load failed;
    // only the connect arm is gated.
    if (!running && !settingsLoaded) return;
    busyRef.current = true;
    setBusy(true);
    setTestResult(null);
    try {
      if (running) {
        await safeDisconnect();
      } else {
        // Primary "Connect" always does a fresh scan — clear any pinned peer so
        // a previously-dead Connect-Direct endpoint can't block the main flow.
        const fresh: Settings = { ...settings, peer: "" };
        if (settings.peer) setSettings(fresh);
        setRuntime({ status: "connecting", detail: "Starting engine", pid: null, endpoint: null });
        await invoke("connect", { settings: fresh });
      }
    } catch (error) {
      const detail = errorMessage(error);
      setRuntime({ status: "error", detail, pid: null, endpoint: null });
      appendLog({ level: "error", message: detail });
    } finally {
      busyRef.current = false;
      setBusy(false);
    }
  }, [busy, running, settings, settingsLoaded, appendLog, safeDisconnect]);

  const connectToPeer = useCallback(async (peer: string, protocol: Settings["protocol"], transport: Settings["transport"]) => {
    if (busyRef.current || busy) return;
    // Same hydration gate as toggleConnection: this connect would persist its
    // settings, and doing that from a defaults snapshot loses the saved profile.
    if (!settingsLoaded) return;
    busyRef.current = true;
    setBusy(true);
    setTestResult(null);
    try {
      try {
        await invoke("stop_scan");
      } catch (_) {}
      if (running) {
        await safeDisconnect();
        await new Promise((r) => setTimeout(r, 400));
      }
      // Pin the chosen endpoint so the engine skips scanning and dials it directly.
      const nextSettings: Settings = { ...settings, protocol, transport, peer };
      setSettings(nextSettings);
      setRuntime({ status: "connecting", detail: `Connecting to ${peer}`, pid: null, endpoint: peer });
      await invoke("connect", { settings: nextSettings });
    } catch (error) {
      const detail = `Direct connect error: ${errorMessage(error)}`;
      setRuntime({ status: "error", detail, pid: null, endpoint: null });
      appendLog({ level: "error", message: detail });
    } finally {
      busyRef.current = false;
      setBusy(false);
    }
  }, [busy, running, settings, settingsLoaded, appendLog, safeDisconnect]);

  const runTest = useCallback(async () => {
    setTestBusy(true);
    setTestResult(null);
    try {
      const outcome = parseTestOutcome(await invoke("test_connection", { settings }));
      if (!outcome) throw new Error("The connectivity check answered with something this build cannot read");
      setTestResult(outcome);
      appendLog({ level: "info", message: outcome.detail });
    } catch (error) {
      const msg = errorMessage(error);
      // A failure has no latency. Reporting the error text as if it were a
      // measurement is what made the old regex able to print a timeout as RTT.
      setTestResult({ detail: msg, latencyMs: null });
      appendLog({ level: "error", message: msg });
    } finally {
      setTestBusy(false);
    }
  }, [settings, appendLog]);

  const dismissError = useCallback(async () => {
    try { await invoke("disconnect"); } catch { /* already stopped */ }
    setRuntime(initialRuntime);
  }, []);

  const retrySettings = useCallback(async () => {
    try {
      const loaded = await invoke<Settings>("get_settings");
      // The same guard and the same reporting as hydration.
      applyLoadedSettings(loaded ?? null);
      // A corrupt read answers with defaults, so "loaded from disk" would be true of
      // the shell's answer and false of the user's profile. Only a frame with nothing
      // to report may say it; the reset below is what changes that.
      if (loaded && !blocksHydration()) {
        setSettingsLoaded(true);
        appendLog({ level: "info", message: "Settings loaded from disk." });
      }
    } catch (error) {
      setSettingsLoadError(true);
      appendLog({ level: "error", message: `Retry load settings failed: ${errorMessage(error)}` });
    }
  }, [appendLog, applyLoadedSettings, blocksHydration]);

  /**
   * The one action that resolves a corrupt stored profile.
   *
   * `SettingsStore.save` refuses every write while one is unresolved — including the
   * one `connect()` performs — so this is not a convenience: without it the user can
   * neither save nor tunnel, on a device whose settings screen says everything is
   * synchronized. On the shell's confirmation the profile is re-read, which is what
   * takes the form out of "reading from disk" and onto the defaults now on disk.
   */
  const resetSettings = useCallback(async () => {
    if (await resetCorruptReport()) await retrySettings();
  }, [resetCorruptReport, retrySettings]);

  return {
    // `saved` is the lifecycle, not a boolean: `App.tsx` forwards this key straight
    // to the Settings dock, and a dock that can only say "synchronizing" or
    // "synchronized" cannot say "nothing pending". `saveState` is the same value
    // under the name a caller that can pass a second prop should use.
    settings, runtime, busy, testBusy, saved: saveState, saveState, saveError,
    admin, testResult,
    appVersion: appVersion ?? "…",
    // The stored profile's health and its remedy, as the shell reported them (ITEM 10).
    settingsCorrupt, settingsCorruption, settingsCorruptionNotice,
    resetSettings, resetSettingsBusy, resetSettingsError,
    connected, running, settingsLocked, settingsLoaded, settingsLoadError, retrySettings,
    patchSettings, toggleConnection, connectToPeer, runTest, dismissError,
  };
}
