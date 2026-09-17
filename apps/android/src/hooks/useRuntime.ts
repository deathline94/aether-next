import { useCallback, useEffect, useRef, useState } from "react";
import { invoke, listen } from "../bridge";
import { defaults, initialRuntime } from "../types";
import type { RuntimeState, Settings } from "../types";

const FALLBACK_VERSION = "0.0.0";
const SAVE_DEBOUNCE_MS = 400;
/** If the engine stays "connecting" past this, surface a timeout instead of hanging forever. */
const CONNECT_WATCHDOG_MS = 90_000;

export function useRuntime(
  appendLog: (entry: { level: "info" | "warn" | "error"; message: string }) => void,
  clearLogs?: () => void,
) {
  const [settings, setSettings] = useState<Settings>(defaults);
  // Settings must not be editable until hydrated from disk — otherwise a patch
  // during that window persists `defaults` over the user's real config.
  const [settingsLoaded, setSettingsLoaded] = useState(false);
  const [runtime, setRuntime] = useState<RuntimeState>(initialRuntime);
  const [busy, setBusy] = useState(false);
  const [testBusy, setTestBusy] = useState(false);
  const [saved, setSaved] = useState(false);
  const [admin, setAdmin] = useState(false);
  const [testResult, setTestResult] = useState<string | null>(null);
  const [appVersion, setAppVersion] = useState<string | null>(null);

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
        const unlistenState = await listen<RuntimeState>("session://state", (event) => {
          receivedRuntimeEvent.current = true;
          setRuntime(event.payload);
        });
        if (disposed) { unlistenState(); return; }
        cleanup.push(unlistenState);

        const unlistenLog = await listen<{ level: "info" | "warn" | "error"; message: string }>(
          "session://log",
          (event) => appendLog(event.payload),
        );
        if (disposed) { unlistenLog(); return; }
        cleanup.push(unlistenLog);
      } catch (error) {
        appendLog({ level: "warn", message: String(error) });
      }

      // Each fetch fails independently — one backend hiccup must not strand
      // settings on defaults or leave admin/version unknown.
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
        setSettingsLoaded(true);
      }
      if (state && !receivedRuntimeEvent.current) setRuntime(state);
      setAdmin(Boolean(isAdmin));
      setAppVersion(info?.version ? String(info.version) : FALLBACK_VERSION);
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
        setSaved(true);
        if (savedTimerRef.current) clearTimeout(savedTimerRef.current);
        savedTimerRef.current = setTimeout(() => setSaved(false), 1200);
      } catch (error) {
        appendLog({ level: "error", message: `Save settings failed: ${String(error)}` });
      }
    }, SAVE_DEBOUNCE_MS);
  }, [appendLog]);

  const patchSettings = useCallback((patch: Partial<Settings>) => {
    if (settingsLocked) return;
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
    clearLogs?.();
    setBusy(true);
    setTestResult(null);
    try {
      if (running) {
        await invoke("disconnect");
      } else {
        // Primary "Connect" always does a fresh scan — clear any pinned peer so
        // a previously-dead Connect-Direct endpoint can't block the main flow.
        const fresh: Settings = { ...settings, peer: "" };
        if (settings.peer) setSettings(fresh);
        setRuntime({ status: "connecting", detail: "Starting engine", pid: null, endpoint: null });
        await invoke("connect", { settings: fresh });
      }
    } catch (error) {
      const detail = String(error);
      setRuntime({ status: "error", detail, pid: null, endpoint: null });
      appendLog({ level: "error", message: detail });
    } finally {
      setBusy(false);
    }
  }, [busy, running, settings, appendLog, clearLogs]);

  const connectToPeer = useCallback(async (peer: string, protocol: Settings["protocol"], transport: Settings["transport"]) => {
    if (busy) return;
    clearLogs?.();
    setBusy(true);
    setTestResult(null);
    try {
      if (running) {
        await invoke("disconnect");
        await new Promise((r) => setTimeout(r, 400));
      }
      // Pin the chosen endpoint so the engine skips scanning and dials it directly.
      const nextSettings: Settings = { ...settings, protocol, transport, peer };
      setSettings(nextSettings);
      setRuntime({ status: "connecting", detail: `Connecting to ${peer}`, pid: null, endpoint: peer });
      await invoke("connect", { settings: nextSettings });
    } catch (error) {
      const detail = `Direct connect error: ${String(error)}`;
      setRuntime({ status: "error", detail, pid: null, endpoint: null });
      appendLog({ level: "error", message: detail });
    } finally {
      setBusy(false);
    }
  }, [busy, running, settings, appendLog, clearLogs]);

  const runTest = useCallback(async () => {
    clearLogs?.();
    setTestBusy(true);
    setTestResult(null);
    try {
      const result = await invoke<string>("test_connection", { settings });
      setTestResult(result);
      appendLog({ level: "info", message: result });
    } catch (error) {
      const msg = String(error);
      setTestResult(msg);
      appendLog({ level: "error", message: msg });
    } finally {
      setTestBusy(false);
    }
  }, [settings, appendLog, clearLogs]);

  const dismissError = useCallback(async () => {
    try { await invoke("disconnect"); } catch { /* already stopped */ }
    setRuntime(initialRuntime);
  }, []);

  return {
    settings, runtime, busy, testBusy, saved, admin, testResult,
    appVersion: appVersion ?? "…",
    connected, running, settingsLocked, settingsLoaded,
    patchSettings, toggleConnection, connectToPeer, runTest, dismissError,
  };
}
