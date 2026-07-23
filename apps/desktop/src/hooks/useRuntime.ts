import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { useCallback, useEffect, useState } from "react";
import { defaults, initialRuntime } from "../types";
import type { RuntimeState, Settings } from "../types";

export function useRuntime(appendLog: (entry: { level: "info" | "warn" | "error"; message: string }) => void) {
  const [settings, setSettings] = useState<Settings>(defaults);
  const [runtime, setRuntime] = useState<RuntimeState>(initialRuntime);
  const [busy, setBusy] = useState(false);
  const [saved, setSaved] = useState(false);
  const [admin, setAdmin] = useState(false);
  const [testResult, setTestResult] = useState<string | null>(null);
  const [appVersion, setAppVersion] = useState("1.0.29");
  const [updateAvailable, setUpdateAvailable] = useState<{ version: string; url: string } | null>(null);

  const connected = runtime.status === "connected";
  const running = runtime.status === "connecting" || connected;
  const settingsLocked = running;

  // Initialize: load settings, state, admin status, version + listen for events
  useEffect(() => {
    let disposed = false;
    let receivedRuntimeEvent = { current: false };
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

        const [loadedSettings, state, isAdmin, info] = await Promise.all([
          invoke<Settings>("get_settings"),
          invoke<RuntimeState>("get_state"),
          invoke<boolean>("is_admin").catch(() => false),
          invoke<{ version?: string }>("app_info").catch(() => ({ version: "1.0.29" })),
        ]);
        if (disposed) return;
        setSettings(loadedSettings);
        if (!receivedRuntimeEvent.current) setRuntime(state);
        setAdmin(isAdmin);
        if (info?.version) setAppVersion(String(info.version));
      } catch (error) {
        appendLog({ level: "warn", message: String(error) });
      }
    }
    void initialize();
    return () => { disposed = true; cleanup.forEach((fn) => fn()); };
  }, [appendLog]);

  // Check for updates (semver-aware)
  useEffect(() => {
    fetch("https://api.github.com/repos/deathline94/aether-next/releases/latest")
      .then((res) => res.json())
      .then((data) => {
        if (data?.tag_name) {
          const latest = data.tag_name.replace(/^v/, "");
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

  const persistSettings = useCallback(async (next: Settings) => {
    try {
      await invoke("save_settings", { settings: next });
      setSaved(true);
      setTimeout(() => setSaved(false), 1200);
    } catch (error) {
      appendLog({ level: "error", message: String(error) });
    }
  }, [appendLog]);

  const patchSettings = useCallback((patch: Partial<Settings>) => {
    if (settingsLocked) return;
    setSettings((prev) => {
      const next = { ...prev, ...patch };
      void persistSettings(next);
      return next;
    });
  }, [settingsLocked, persistSettings]);

  const toggleConnection = useCallback(async () => {
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
  }, [running, settings, appendLog]);

  const connectToPeer = useCallback(async (peer: string, protocol: string, transport: string) => {
    setBusy(true);
    try {
      if (running) {
        await invoke("disconnect");
        await new Promise((r) => setTimeout(r, 400));
      }
      const nextSettings: Settings = { ...settings, protocol: protocol as Settings["protocol"], transport: transport as Settings["transport"], peer };
      setRuntime({ status: "connecting", detail: `Connecting to ${peer}`, pid: null, endpoint: null });
      await invoke("connect", { settings: nextSettings });
    } catch (error) {
      appendLog({ level: "error", message: `Direct connect error: ${String(error)}` });
    } finally {
      setBusy(false);
    }
  }, [running, settings, appendLog]);

  const runTest = useCallback(async () => {
    setBusy(true);
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
      setBusy(false);
    }
  }, [settings, appendLog]);

  const dismissError = useCallback(async () => {
    try { await invoke("disconnect"); } catch { /* already stopped */ }
    setRuntime(initialRuntime);
  }, []);

  return {
    settings, setSettings, runtime, setRuntime, busy, setBusy,
    saved, admin, testResult, appVersion, updateAvailable,
    connected, running, settingsLocked,
    patchSettings, toggleConnection, connectToPeer, runTest, dismissError,
  };
}

/** Semver-aware greater-than comparison. */
function semverGt(a: string, b: string): boolean {
  const pa = a.split(".").map(Number);
  const pb = b.split(".").map(Number);
  for (let i = 0; i < 3; i++) {
    const na = pa[i] || 0;
    const nb = pb[i] || 0;
    if (na > nb) return true;
    if (na < nb) return false;
  }
  return false;
}
