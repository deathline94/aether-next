import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { useCallback, useEffect, useRef, useState } from "react";
import { defaults, initialRuntime } from "../types";
import type { RuntimeState, Settings } from "../types";

const FALLBACK_VERSION = "0.0.0";
const SAVE_DEBOUNCE_MS = 400;

export function useRuntime(
  appendLog: (entry: { level: "info" | "warn" | "error"; message: string }) => void,
  clearLogs?: () => void,
) {
  const [settings, setSettings] = useState<Settings>(defaults);
  // Settings must not be editable until hydrated from disk — otherwise a
  // patch during that window persists `defaults` over the user's config.
  const [settingsLoaded, setSettingsLoaded] = useState(false);
  const [runtime, setRuntime] = useState<RuntimeState>(initialRuntime);
  const [busy, setBusy] = useState(false);
  const [testBusy, setTestBusy] = useState(false);
  const [saved, setSaved] = useState(false);
  const [admin, setAdmin] = useState(false);
  const [testResult, setTestResult] = useState<string | null>(null);
  const [appVersion, setAppVersion] = useState<string | null>(null);
  const [updateAvailable, setUpdateAvailable] = useState<{ version: string; url: string } | null>(null);
  const [updateDismissed, setUpdateDismissed] = useState(false);

  const savedTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const saveDebounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const pendingSaveRef = useRef<Settings | null>(null);
  // Mirrors the last settings object seen by the persist effect so hydration
  // does not trigger a redundant write-back to disk.
  const settingsRef = useRef(settings);

  const connected = runtime.status === "connected";
  const running = runtime.status === "connecting" || connected;
  const settingsLocked = running || !settingsLoaded;

  // Initialize: load settings, state, admin status, version + listen for events
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

      try {
        const [loadedSettings, state, isAdmin, info] = await Promise.all([
          invoke<Settings>("get_settings").catch((e) => { appendLog({ level: "warn", message: `Load settings failed: ${String(e)}` }); return null; }),
          invoke<RuntimeState>("get_state").catch(() => null),
          invoke<boolean>("is_admin").catch(() => false),
          invoke<{ version?: string }>("app_info").catch(() => null),
        ]);
        if (disposed) return;
        if (loadedSettings) {
          settingsRef.current = loadedSettings;
          setSettings(loadedSettings);
        }
        if (state && !receivedRuntimeEvent.current) setRuntime(state);
        setAdmin(isAdmin);
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

  // Cleanup timers on unmount
  useEffect(() => () => {
    if (savedTimerRef.current) clearTimeout(savedTimerRef.current);
    if (saveDebounceRef.current) clearTimeout(saveDebounceRef.current);
  }, []);

  // Check for updates once the real version is known (semver-aware).
  useEffect(() => {
    if (!appVersion || appVersion === FALLBACK_VERSION) return;
    fetch("https://api.github.com/repos/deathline94/aether-next/releases/latest")
      .then((res) => res.json())
      .then((data) => {
        if (data?.tag_name) {
          const latest = String(data.tag_name).replace(/^v/, "");
          if (semverGt(latest, appVersion)) {
            setUpdateAvailable({
              version: data.tag_name,
              url: data.html_url || "https://github.com/deathline94/aether-next/releases/latest",
            });
          }
        }
      })
      .catch(() => {});
  }, [appVersion]);

  const persistSettings = useCallback((next: Settings) => {
    // Debounced: NumberField commits and toggles can arrive in bursts;
    // don't hit the disk per event.
    pendingSaveRef.current = next;
    if (saveDebounceRef.current) clearTimeout(saveDebounceRef.current);
    saveDebounceRef.current = setTimeout(async () => {
      const toSave = pendingSaveRef.current;
      if (!toSave) return;
      // Skip auto-saving intermediate typing states that violate port invariants
      if (
        toSave.socksPort === toSave.httpPort ||
        toSave.socksPort < 1024 || toSave.socksPort > 65535 ||
        toSave.httpPort < 1024 || toSave.httpPort > 65535
      ) {
        return;
      }
      try {
        await invoke("save_settings", { settings: toSave });
        setSaved(true);
        if (savedTimerRef.current) clearTimeout(savedTimerRef.current);
        savedTimerRef.current = setTimeout(() => setSaved(false), 1200);
      } catch (error) {
        appendLog({ level: "error", message: String(error) });
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
        setRuntime({ status: "connecting", detail: "Starting engine", pid: null, endpoint: null });
        await invoke("connect", { settings });
      }
    } catch (error) {
      const detail = String(error);
      setRuntime({ status: "error", detail, pid: null, endpoint: null });
      appendLog({ level: "error", message: detail });
    } finally {
      setBusy(false);
    }
  }, [busy, running, settings, appendLog, clearLogs]);

  const connectToPeer = useCallback(async (peer: string, protocol: string, transport: string) => {
    if (busy) return;
    clearLogs?.();
    setBusy(true);
    try {
      if (running) {
        await invoke("disconnect");
        await new Promise((r) => setTimeout(r, 400));
      }
      const nextSettings: Settings = { ...settings, protocol: protocol as Settings["protocol"], transport: transport as Settings["transport"], peer };
      // Keep UI state in sync with what the engine actually runs — otherwise
      // the Connection tab reports the previous protocol.
      setSettings(nextSettings);
      setRuntime({ status: "connecting", detail: `Connecting to ${peer}`, pid: null, endpoint: null });
      await invoke("connect", { settings: nextSettings });
    } catch (error) {
      const detail = String(error);
      setRuntime({ status: "error", detail, pid: null, endpoint: null });
      appendLog({ level: "error", message: `Direct connect error: ${detail}` });
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

  const dismissUpdate = useCallback(() => setUpdateDismissed(true), []);

  return {
    settings, setSettings, runtime, setRuntime, busy, setBusy, testBusy,
    saved, admin, testResult, appVersion: appVersion ?? "…", updateAvailable: updateDismissed ? null : updateAvailable,
    connected, running, settingsLocked, settingsLoaded,
    patchSettings, toggleConnection, connectToPeer, runTest, dismissError, dismissUpdate,
  };
}

/** Semver-aware greater-than comparison; tolerates pre-release suffixes. */
function semverGt(a: string, b: string): boolean {
  const parse = (v: string) =>
    v.split("-")[0].split(".").map((p) => Number.parseInt(p, 10) || 0);
  const pa = parse(a);
  const pb = parse(b);
  for (let i = 0; i < 3; i++) {
    const na = pa[i] || 0;
    const nb = pb[i] || 0;
    if (na > nb) return true;
    if (na < nb) return false;
  }
  return false;
}
