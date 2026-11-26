import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { useCallback, useEffect, useRef, useState } from "react";
import { defaults, initialRuntime, parseRuntimeState, parseSettings } from "../types";
import type { RuntimeState, Settings } from "../types";
import {
  applyProtocolScopedPatch,
  clearProtocolProfiles,
  describeRejectedState,
  parseSessionStats,
  RELEASES_PAGE,
  releasePageUrl,
  syncProtocolProfile,
  useInlineUpdater,
  type InstallOutcome,
  type SessionStats,
} from "@aether/ui";
import { setupDesktopPreview } from "../previewBridge";
import { errorMessage, ipcError } from "../ipcError";
import type { IpcError } from "../ipcError";

const FALLBACK_VERSION = "0.0.0";
const SAVE_DEBOUNCE_MS = 400;
/**
 * How long the UI will sit in `connecting` before it calls the attempt failed.
 *
 * Android had this and desktop did not, so on the machine where most people
 * start a tunnel, a connect that never reaches readiness - an endpoint that
 * accepts UDP and answers nothing, a hung handshake - left the beacon on
 * "connecting", the settings panel locked, and no error ever surfaced. 90 s is
 * the same budget both shells use, and it is above the engine's own per-probe
 * ceiling so a slow but live route is not aborted.
 */
const CONNECT_WATCHDOG_MS = 90_000;
export { RELEASES_PAGE, releasePageUrl };

/** A state the UI asserts for itself, with nothing measured. */
function uiState(status: RuntimeState["status"], detail: string): RuntimeState {
  return { status, detail, pid: null, endpoint: null, handshakeRttMs: null };
}

/** The port invariant the Rust `save_settings` validator enforces. Shared by the
 * debounced skip and the unmount flush so neither path puts a profile the shell
 * will refuse onto the disk. */
export function portsSaveable(s: Pick<Settings, "socksPort" | "httpPort">): boolean {
  const ok = (p: number) => Number.isInteger(p) && p >= 1024 && p <= 65535;
  return s.socksPort !== s.httpPort && ok(s.socksPort) && ok(s.httpPort);
}

/**
 * Engine-side diagnostics for the activity export: which binary ran, what the
 * process settled on, and whether packets are being dropped. A failure comes
 * back as text rather than an exception, so a diagnostics problem can never
 * swallow the log the user was trying to send.
 */
export async function engineDiagnostics(): Promise<string> {
  try {
    const report = await invoke<Record<string, unknown>>("diagnostics");
    return JSON.stringify(report, null, 2);
  } catch (error) {
    return `unavailable: ${ipcError(error).message}`;
  }
}

export function useRuntime(
  appendLog: (entry: { level: "info" | "warn" | "error"; message: string }) => void,
) {
  const [settings, setSettings] = useState<Settings>(defaults);
  // Settings must not be editable until hydrated from disk — otherwise a
  // patch during that window persists `defaults` over the user's config.
  const [settingsLoaded, setSettingsLoaded] = useState(false);
  const [settingsLoadError, setSettingsLoadError] = useState(false);
  const [runtime, setRuntime] = useState<RuntimeState>(initialRuntime);
  const [stats, setStats] = useState<SessionStats | null>(null);
  const [busy, setBusy] = useState(false);
  const busyRef = useRef(false);
  const [testBusy, setTestBusy] = useState(false);
  const [saved, setSaved] = useState(false);
  // True while a change of ours has not been accepted by the shell: the debounce
  // window, the in-flight write, and a refusal. `!saved` was the whole idle test,
  // which made the Settings dock pulse "Auto-Saving / Synchronizing changes…" from
  // first paint with nothing pending — the form cannot show a save it is not doing.
  const [dirty, setDirty] = useState(false);
  // The last save the shell refused. Without this the form's only signal is a
  // log line, and the status text stays on "Synchronizing changes…" forever.
  const [saveError, setSaveError] = useState<IpcError | null>(null);
  const [admin, setAdmin] = useState(false);
  const [testResult, setTestResult] = useState<string | null>(null);
  const [appVersion, setAppVersion] = useState<string | null>(null);

  const savedTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const saveDebounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const watchdogRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const pendingSaveRef = useRef<Settings | null>(null);
  /// Monotonic save token: only the newest dispatch may report success, so a
  /// slow write of an older payload cannot flip "Synchronized" for a newer one.
  const saveSeqRef = useRef(0);
  // Mirrors the last settings object seen by the persist effect so hydration
  // does not trigger a redundant write-back to disk.
  const settingsRef = useRef(settings);
  // Malformed session frames are logged once per distinct shape, not once per
  // event: a shell stuck in a bad emit loop must not fill the log buffer.
  const rejectedStatuses = useRef(new Set<string>());

  const connected = runtime.status === "connected";
  const running = runtime.status === "connecting" || connected;
  const settingsLocked = running || !settingsLoaded;

  // A failed hydration leaves defaults on screen that no write may commit. Say
  // why once when the user tries anyway; the disabled controls cover the mouse.
  const loadFailureWarnedRef = useRef(false);
  const refuseOnFailedLoad = useCallback(() => {
    if (!settingsLoadError || loadFailureWarnedRef.current) return;
    loadFailureWarnedRef.current = true;
    appendLog({
      level: "warn",
      message: "Settings could not be loaded from disk; defaults are read-only until Retry in Settings succeeds.",
    });
  }, [appendLog, settingsLoadError]);

  // Initialize: load settings, state, admin status, version + listen for events
  useEffect(() => {
    let disposed = false;
    const receivedRuntimeEvent = { current: false };
    const cleanup: Array<() => void> = [];

    async function initialize() {
      const isTauri =
        typeof window !== "undefined" &&
        Boolean((window as { __TAURI_INTERNALS__?: unknown }).__TAURI_INTERNALS__);

      if (!isTauri && import.meta.env.MODE !== "test") {
        const stopPreview = setupDesktopPreview(
          FALLBACK_VERSION,
          (merged) => {
            settingsRef.current = merged;
            setSettings(merged);
            setSettingsLoadError(false);
          },
          (nextState) => setRuntime(nextState),
          (nextStats) => setStats(nextStats),
          (ver) => {
            setAppVersion(ver);
            setSettingsLoaded(true);
          },
        );
        cleanup.push(stopPreview);
        return;
      }

      try {
        const unlistenState = await listen<unknown>("session://state", (event) => {
          receivedRuntimeEvent.current = true;
          const next = parseRuntimeState(event.payload);
          if (next) {
            setRuntime(next);
            if (next.status !== "connected") setStats(null);
            return;
          }
          // A frame the guard refuses is not a state: keep rendering the last one
          // that was, and say so once per distinct shape. Writing the payload
          // through was how one unknown `status` threw inside `heroCopy[status]`
          // and white-screened the window from a background event.
          const seen = rejectedStatuses.current;
          const key = describeRejectedState(event.payload);
          if (!seen.has(key)) {
            seen.add(key);
            appendLog({
              level: "error",
              message: `Ignored a session state the interface cannot render (${key}); showing the previous one.`,
            });
          }
        });
        if (disposed) { unlistenState(); return; }
        cleanup.push(unlistenState);

        const unlistenStats = await listen<unknown>("session://stats", (event) => {
          const parsedStats = parseSessionStats(event.payload);
          if (parsedStats) setStats(parsedStats);
        });
        if (disposed) { unlistenStats(); return; }
        cleanup.push(unlistenStats);

        const unlistenLog = await listen<{ level: "info" | "warn" | "error"; message: string }>(
          "session://log",
          (event) => appendLog(event.payload),
        );
        if (disposed) { unlistenLog(); return; }
        cleanup.push(unlistenLog);
      } catch (error) {
        appendLog({ level: "warn", message: errorMessage(error) });
      }

      let hydrated = false;
      try {
        const [loadedSettings, state, isAdmin, info] = await Promise.all([
          invoke<Settings>("get_settings").catch((e) => { appendLog({ level: "warn", message: `Load settings failed: ${errorMessage(e)}` }); return null; }),
          invoke<RuntimeState>("get_state").catch(() => null),
          invoke<boolean>("is_admin").catch(() => false),
          invoke<{ version?: string }>("app_info").catch(() => null),
        ]);
        if (disposed) return;
        if (loadedSettings) {
          // Merge, never replace: a field this build's shell does not send has to
          // fall back to the default the panels assume, not become `undefined`.
          const { settings: merged, corrected } = parseSettings(loadedSettings);
          syncProtocolProfile(merged);
          settingsRef.current = merged;
          setSettings(merged);
          setSettingsLoadError(false);
          hydrated = true;
          if (corrected.length > 0) {
            appendLog({
              level: "warn",
              message: `Settings from disk were incomplete or out of range (${corrected.join(", ")}); the defaults are in use for those until you change them.`,
            });
          }
        } else {
          setSettingsLoadError(true);
        }
        const parsed = state ? parseRuntimeState(state) : null;
        if (parsed && !receivedRuntimeEvent.current) setRuntime(parsed);
        setAdmin(isAdmin);
        setAppVersion(info?.version ? String(info.version) : FALLBACK_VERSION);
      } finally {
        // Only a successful load unlocks the form. `settingsLoaded` gates the
        // patch, the save and the connect, and after a failure the state holds
        // defaults rather than the user's profile — the banner's Retry is the
        // one way back, as on Android.
        if (!disposed && hydrated) {
          setSettingsLoaded(true);
        }
      }
    }
    void initialize();
    return () => { disposed = true; cleanup.forEach((fn) => fn()); };
  }, [appendLog]);

  // Cleanup timers on unmount. The save debounce is flushed, not merely cleared:
  // an edit made within the debounce window of a window close used to die with
  // the timer, so the last change never reached the disk.
  useEffect(() => () => {
    if (savedTimerRef.current) clearTimeout(savedTimerRef.current);
    if (saveDebounceRef.current) {
      clearTimeout(saveDebounceRef.current);
      saveDebounceRef.current = null;
      const pending = pendingSaveRef.current;
      pendingSaveRef.current = null;
      // Fire-and-forget: the window is going away either way, and a rejection has
      // no surface left to render on.
      if (pending && portsSaveable(pending)) {
        void invoke("save_settings", { settings: pending }).catch(() => {});
      }
    }
    if (watchdogRef.current) clearTimeout(watchdogRef.current);
  }, []);

  // Connection watchdog: never let the UI sit on "connecting" forever.
  useEffect(() => {
    if (watchdogRef.current) {
      clearTimeout(watchdogRef.current);
      watchdogRef.current = null;
    }
    if (runtime.status !== "connecting") return;
    watchdogRef.current = setTimeout(() => {
      setRuntime((prev) =>
        prev.status === "connecting"
          ? uiState("error", "Connection timed out - no reachable route found. Try another protocol or network.")
          : prev,
      );
      // The engine may still be handshaking; leaving it running would mean the
      // next Connect has to fight its own predecessor for the host lock.
      void invoke("disconnect").catch(() => {});
      appendLog({
        level: "error",
        message: `Connection timed out after ${CONNECT_WATCHDOG_MS / 1000}s; engine stopped.`,
      });
    }, CONNECT_WATCHDOG_MS);
    return () => {
      if (watchdogRef.current) {
        clearTimeout(watchdogRef.current);
        watchdogRef.current = null;
      }
    };
  }, [runtime.status, appendLog]);

  const checkUpdateCmd = useCallback(
    (args: { httpPort: number; useLocalProxy: boolean }) => invoke<unknown>("check_update", args),
    [],
  );
  const downloadInstallCmd = useCallback(
    (args: {
      assetUrl: string;
      assetName: string;
      sha256: string | null;
      httpPort: number;
      useLocalProxy: boolean;
    }) => invoke<InstallOutcome>("download_and_install_update", args),
    [],
  );

  const updater = useInlineUpdater({
    appVersion,
    fallbackVersion: FALLBACK_VERSION,
    connected,
    routingMode: settings.routingMode,
    httpPort: settings.httpPort,
    checkUpdateCmd,
    downloadInstallCmd,
    listenEvent: listen,
    formatError: errorMessage,
    appendLog,
  });

  /**
   * Stop the current session without letting a partial teardown block the next
   * one. `disconnect` reports `disconnect_incomplete` when the engine had to be
   * killed or the system proxy could not be restored — the remedy in both cases
   * is to reconnect, so the message has to be surfaced without failing the
   * caller that is trying to do exactly that.
   */
  const safeDisconnect = useCallback(async () => {
    try {
      await invoke("disconnect");
    } catch (error) {
      const err = ipcError(error);
      appendLog({ level: "error", message: `Disconnect reported a problem: ${err.message}` });
    }
  }, [appendLog]);

  const persistSettings = useCallback((next: Settings) => {
    // `settingsLoaded` is false exactly when the profile never arrived; the state
    // then holds defaults, and writing those to disk would erase the real one.
    if (!settingsLoaded) {
      refuseOnFailedLoad();
      return;
    }
    // Debounced: NumberField commits and toggles can arrive in bursts;
    // don't hit the disk per event.
    pendingSaveRef.current = next;
    if (saveDebounceRef.current) clearTimeout(saveDebounceRef.current);
    saveDebounceRef.current = setTimeout(async () => {
      // Skip auto-saving intermediate typing states that violate port invariants
      saveDebounceRef.current = null;
      const toSave = pendingSaveRef.current;
      pendingSaveRef.current = null;
      if (!toSave) return;
      if (!portsSaveable(toSave)) return;
      const mine = ++saveSeqRef.current;
      try {
        await invoke("save_settings", { settings: toSave });
        if (mine !== saveSeqRef.current) return; // superseded by a newer save
        setSaveError(null);
        setSaved(true);
        setDirty(false);
        if (savedTimerRef.current) clearTimeout(savedTimerRef.current);
        savedTimerRef.current = setTimeout(() => setSaved(false), 1200);
      } catch (error) {
        if (mine !== saveSeqRef.current) return;
        const err = ipcError(error);
        setSaveError(err);
        // Still pending: the form must not read as idle over a value the disk
        // does not hold.
        setDirty(true);
        appendLog({ level: "error", message: err.message });
      }
    }, SAVE_DEBOUNCE_MS);
  }, [appendLog, settingsLoaded, refuseOnFailedLoad]);

  const patchSettings = useCallback((patch: Partial<Settings>) => {
    if (settingsLocked) return;
    // A validation error describes the value being replaced, not the new one.
    setSaveError(null);
    setSettings((prev) => applyProtocolScopedPatch(prev, patch));
  }, [settingsLocked]);

  // Persist as an effect of settings changing — keeps the state updater pure.
  useEffect(() => {
    const prev = settingsRef.current;
    settingsRef.current = settings;
    if (!settingsLoaded || prev === settings) return;
    setDirty(true);
    persistSettings(settings);
  }, [settings, settingsLoaded, persistSettings]);

  const toggleConnection = useCallback(async () => {
    if (busyRef.current || busy) return;
    // Only the connect arm waits for hydration: connect persists the settings it
    // receives, so a tap before the load lands would push a defaults snapshot at
    // the shell. Disconnecting a live tunnel must stay possible even when the
    // load failed.
    if (!running && !settingsLoaded) {
      refuseOnFailedLoad();
      return;
    }
    busyRef.current = true;
    setBusy(true);
    setTestResult(null);
    try {
      if (running) {
        await safeDisconnect();
      } else {
        setRuntime(uiState("connecting", "Starting engine"));
        await invoke("connect", { settings });
      }
    } catch (error) {
      const detail = errorMessage(error);
      setRuntime(uiState("error", detail));
      appendLog({ level: "error", message: detail });
    } finally {
      busyRef.current = false;
      setBusy(false);
    }
  }, [busy, running, settings, settingsLoaded, appendLog, safeDisconnect, refuseOnFailedLoad]);

  const connectToPeer = useCallback(async (peer: string, protocol: string, transport: string) => {
    if (busyRef.current || busy) return;
    // Same hydration gate as toggleConnection: this connect persists its
    // settings, and doing it from a defaults snapshot loses the saved profile.
    if (!settingsLoaded) {
      refuseOnFailedLoad();
      return;
    }
    if (saveDebounceRef.current) {
      clearTimeout(saveDebounceRef.current);
      saveDebounceRef.current = null;
      pendingSaveRef.current = null;
    }
    busyRef.current = true;
    setBusy(true);
    const previous = settings;
    try {
      if (running) {
        await safeDisconnect();
        await new Promise((r) => setTimeout(r, 400));
      }
      const nextSettings: Settings = applyProtocolScopedPatch(settings, {
        protocol: protocol as Settings["protocol"],
        transport: transport as Settings["transport"],
        peer,
      });
      // Keep UI state in sync with what the engine actually runs — otherwise
      // the Connection tab reports the previous protocol.
      setSettings(nextSettings);
      setRuntime(uiState("connecting", `Connecting to ${peer}`));
      await invoke("connect", { settings: nextSettings });
    } catch (error) {
      const detail = errorMessage(error);
      // Roll the optimistic commit back: this path wrote protocol/transport/
      // peer through the settings effect as well as to the engine, so a failed
      // attempt used to leave the user's carrier protocol permanently rewritten
      // by a tunnel that never came up.
      setSettings(previous);
      setRuntime(uiState("error", detail));
      appendLog({ level: "error", message: `Direct connect error: ${detail}` });
    } finally {
      busyRef.current = false;
      setBusy(false);
    }
  }, [busy, running, settings, settingsLoaded, appendLog, safeDisconnect, refuseOnFailedLoad]);

  const runTest = useCallback(async () => {
    setTestBusy(true);
    setTestResult(null);
    try {
      const result = await invoke<string>("test_connection", { settings });
      setTestResult(result);
      appendLog({ level: "info", message: result });
    } catch (error) {
      const msg = errorMessage(error);
      setTestResult(msg);
      appendLog({ level: "error", message: msg });
    } finally {
      setTestBusy(false);
    }
  }, [settings, appendLog]);

  const dismissError = useCallback(async () => {
    try { await invoke("disconnect"); } catch { /* already stopped */ }
    setStats(null);
    setRuntime(initialRuntime);
  }, []);

  const retrySettings = useCallback(async () => {
    try {
      const loaded = await invoke<Settings>("get_settings");
      if (loaded) {
        // The same merge as hydration: "Retry" must not be a second, weaker path.
        const { settings: merged, corrected } = parseSettings(loaded);
        syncProtocolProfile(merged);
        settingsRef.current = merged;
        setSettings(merged);
        setSettingsLoadError(false);
        setSettingsLoaded(true);
        loadFailureWarnedRef.current = false;
        if (corrected.length > 0) {
          appendLog({
            level: "warn",
            message: `Settings from disk were incomplete or out of range (${corrected.join(", ")}); the defaults are in use for those.`,
          });
        } else {
          appendLog({ level: "info", message: "Settings loaded from disk." });
        }
      }
    } catch (error) {
      setSettingsLoadError(true);
      appendLog({ level: "error", message: `Retry load settings failed: ${errorMessage(error)}` });
    }
  }, [appendLog]);

  const resetSettings = useCallback(async () => {
    if (running) return;
    if (saveDebounceRef.current) {
      clearTimeout(saveDebounceRef.current);
      saveDebounceRef.current = null;
      pendingSaveRef.current = null;
    }
    try {
      const reset = await invoke<Settings>("reset_settings");
      const { settings: merged } = parseSettings(reset);
      clearProtocolProfiles();
      syncProtocolProfile(merged);
      settingsRef.current = merged;
      setSettings(merged);
      setSaveError(null);
      setSettingsLoadError(false);
      setSettingsLoaded(true);
      setDirty(false);
      setSaved(true);
      if (savedTimerRef.current) clearTimeout(savedTimerRef.current);
      savedTimerRef.current = setTimeout(() => setSaved(false), 1200);
      appendLog({ level: "info", message: "Settings reset to factory defaults." });
    } catch (error) {
      const err = ipcError(error);
      setSaveError(err);
      appendLog({ level: "error", message: `Reset settings failed: ${err.message}` });
    }
  }, [running, appendLog]);

  return {
    settings, setSettings, runtime, stats, setRuntime, busy, setBusy, testBusy,
    saved, dirty, saveError, admin, testResult, appVersion: appVersion ?? "…",
    updateAvailable: updater.updateInfo?.available
      ? { version: `v${updater.updateInfo.latestVersion}`, url: updater.updateInfo.releaseUrl }
      : null,
    updateInfo: updater.updateInfo,
    updateProgress: updater.updateProgress,
    updateChecking: updater.updateChecking,
    updateCheckError: updater.updateCheckError,
    checkForUpdates: updater.checkForUpdates,
    installUpdate: updater.installUpdate,
    dismissUpdate: updater.dismissUpdate,
    connected, running, settingsLocked, settingsLoaded, settingsLoadError, retrySettings, resetSettings,
    patchSettings, toggleConnection, connectToPeer, runTest, dismissError,
  };
}
