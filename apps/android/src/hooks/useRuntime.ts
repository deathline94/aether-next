import { useCallback, useEffect, useRef, useState } from "react";
import { invoke, listen } from "../bridge";
import { defaults, initialRuntime, parseRuntimeState } from "../types";
import type { RuntimeState, Settings } from "../types";
import { errorMessage, ipcError } from "../ipcError";
import type { IpcError } from "../ipcError";
import { describeRejectedState } from "../../../../packages/ui/src";

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
  const [testBusy, setTestBusy] = useState(false);
  const [saved, setSaved] = useState(false);
  const [saveError, setSaveError] = useState<IpcError | null>(null);
  const [admin, setAdmin] = useState(false);
  const [testResult, setTestResult] = useState<TestOutcome | null>(null);
  const [appVersion, setAppVersion] = useState<string | null>(null);

  // One log line per distinct refused shape, not one per frame: a shell that
  // emits a bad status every second must not fill the console with it.
  const rejectedStates = useRef(new Set<string>());

  const savedTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const saveDebounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const pendingSaveRef = useRef<Settings | null>(null);
  const settingsRef = useRef(settings);
  const watchdogRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const connected = runtime.status === "connected";
  const running = runtime.status === "connecting" || connected;
  const settingsLocked = running || !settingsLoaded;

  // Initialize: load settings, state, admin/version + subscribe to engine events.
  useEffect(() => {
    let disposed = false;
    const receivedRuntimeEvent = { current: false };
    const cleanup: Array<() => void> = [];

    async function initialize() {
      try {
        const unlistenState = await listen<unknown>("session://state", (event) => {
          receivedRuntimeEvent.current = true;
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
        if (loadedSettings) {
          settingsRef.current = { ...defaults, ...loadedSettings };
          setSettings(settingsRef.current);
          setSettingsLoadError(false);
        } else {
          setSettingsLoadError(true);
        }
        if (state && !receivedRuntimeEvent.current) setRuntime(state);
        setAdmin(Boolean(isAdmin));
        setAppVersion(info?.version ? String(info.version) : FALLBACK_VERSION);
      } finally {
        if (!disposed) {
          setSettingsLoaded(true);
        }
      }
    }
    void initialize();
    return () => { disposed = true; cleanup.forEach((fn) => fn()); };
  }, [appendLog]);

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
      try {
        await invoke("save_settings", { settings: toSave });
        setSaveError(null);
        setSaved(true);
        if (savedTimerRef.current) clearTimeout(savedTimerRef.current);
        savedTimerRef.current = setTimeout(() => setSaved(false), 1200);
      } catch (error) {
        const err = ipcError(error);
        setSaveError(err);
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
    persistSettings(settings);
  }, [settings, settingsLoaded, persistSettings]);

  const toggleConnection = useCallback(async () => {
    if (busy) return;
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
      setBusy(false);
    }
  }, [busy, running, settings, appendLog, safeDisconnect]);

  const connectToPeer = useCallback(async (peer: string, protocol: Settings["protocol"], transport: Settings["transport"]) => {
    if (busy) return;
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
      setBusy(false);
    }
  }, [busy, running, settings, appendLog, safeDisconnect]);

  const runTest = useCallback(async () => {
    setTestBusy(true);
    setTestResult(null);
    try {
      const result = await invoke<TestOutcome>("test_connection", { settings });
      setTestResult(result);
      appendLog({ level: "info", message: result.detail });
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
      if (loaded) {
        settingsRef.current = { ...defaults, ...loaded };
        setSettings(settingsRef.current);
        setSettingsLoadError(false);
        setSettingsLoaded(true);
        appendLog({ level: "info", message: "Settings loaded from disk." });
      }
    } catch (error) {
      setSettingsLoadError(true);
      appendLog({ level: "error", message: `Retry load settings failed: ${errorMessage(error)}` });
    }
  }, [appendLog]);

  return {
    settings, runtime, busy, testBusy, saved, saveError, admin, testResult,
    appVersion: appVersion ?? "…",
    connected, running, settingsLocked, settingsLoaded, settingsLoadError, retrySettings,
    patchSettings, toggleConnection, connectToPeer, runTest, dismissError,
  };
}
