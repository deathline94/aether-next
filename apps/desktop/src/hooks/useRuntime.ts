import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { useCallback, useEffect, useRef, useState } from "react";
import { defaults, initialRuntime, parseRuntimeState, parseSettings } from "../types";
import type { RuntimeState, Settings } from "../types";
import { describeRejectedState } from "@aether/ui";
import { semverGt } from "../semver";
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
const UPDATE_CHECK_URL = "https://api.github.com/repos/deathline94/aether-next/releases/latest";

/** A state the UI asserts for itself, with nothing measured. */
function uiState(status: RuntimeState["status"], detail: string): RuntimeState {
  return { status, detail, pid: null, endpoint: null, handshakeRttMs: null };
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
  const [updateAvailable, setUpdateAvailable] = useState<{ version: string; url: string } | null>(null);
  const [updateDismissed, setUpdateDismissed] = useState(false);

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

  // Initialize: load settings, state, admin status, version + listen for events
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

        const unlistenLog = await listen<{ level: "info" | "warn" | "error"; message: string }>(
          "session://log",
          (event) => appendLog(event.payload),
        );
        if (disposed) { unlistenLog(); return; }
        cleanup.push(unlistenLog);
      } catch (error) {
        appendLog({ level: "warn", message: errorMessage(error) });
      }

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
          settingsRef.current = merged;
          setSettings(merged);
          setSettingsLoadError(false);
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

  // "A new version exists", nothing more.
  //
  // This is an unauthenticated `api.github.com` fetch with a swallowed error, so
  // the 60-requests-per-hour IP limit means the banner can simply never appear —
  // it is advisory and its absence is not evidence of being up to date.
  //
  // `tauri-plugin-updater` is deliberately not adopted: it needs
  // `createUpdaterArtifacts`, a literal minisign public key compiled in, an
  // endpoint template, an `updater:default` capability and a CI-generated
  // manifest, and with no key custody (the signing key would have to live in the
  // repo or be generated per run) the result would be an auto-updater that is
  // misconfigured by construction — the one component of this app that could
  // install arbitrary code as the user, without a witness anyone reviewed.
  useEffect(() => {
    if (!appVersion || appVersion === FALLBACK_VERSION) return;
    // The app's own content policy states the pre-tunnel window must not reach out
    // to a third party at all — for a circumvention client the request *is* the
    // leak, made before there is any path to hide it behind. This used to fire on
    // mount, on every machine, tunnel or no tunnel. A connected session at least
    // puts it behind the route the user chose.
    if (!connected) return;
    // ...and the answer must not land after the session dropped or the window
    // unmounted, which is what an uncancelled `fetch` does.
    const controller = new AbortController();
    fetch(UPDATE_CHECK_URL, { signal: controller.signal })
      .then((res) => res.json())
      .then((data) => {
        if (controller.signal.aborted) return;
        if (data?.tag_name) {
          const latest = String(data.tag_name).replace(/^v/, "");
          if (semverGt(latest, appVersion)) {
            setUpdateAvailable({
              version: data.tag_name,
              url: typeof data.html_url === "string"
                ? data.html_url
                : "https://github.com/deathline94/aether-next/releases/latest",
            });
          }
        }
      })
      // Advisory: a failure, a rate limit or an abort means no banner, nothing else.
      .catch(() => {});
    return () => controller.abort();
  }, [appVersion, connected]);

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
    setDirty(true);
    persistSettings(settings);
  }, [settings, settingsLoaded, persistSettings]);

  const toggleConnection = useCallback(async () => {
    if (busyRef.current || busy) return;
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
  }, [busy, running, settings, appendLog, safeDisconnect]);

  const connectToPeer = useCallback(async (peer: string, protocol: string, transport: string) => {
    if (busyRef.current || busy) return;
    busyRef.current = true;
    setBusy(true);
    const previous = settings;
    try {
      if (running) {
        await safeDisconnect();
        await new Promise((r) => setTimeout(r, 400));
      }
      const nextSettings: Settings = { ...settings, protocol: protocol as Settings["protocol"], transport: transport as Settings["transport"], peer };
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
  }, [busy, running, settings, appendLog, safeDisconnect]);

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
    setRuntime(initialRuntime);
  }, []);

  const dismissUpdate = useCallback(() => setUpdateDismissed(true), []);

  const retrySettings = useCallback(async () => {
    try {
      const loaded = await invoke<Settings>("get_settings");
      if (loaded) {
        // The same merge as hydration: "Retry" must not be a second, weaker path.
        const { settings: merged, corrected } = parseSettings(loaded);
        settingsRef.current = merged;
        setSettings(merged);
        setSettingsLoadError(false);
        setSettingsLoaded(true);
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

  return {
    settings, setSettings, runtime, setRuntime, busy, setBusy, testBusy,
    saved, dirty, saveError, admin, testResult, appVersion: appVersion ?? "…", updateAvailable: updateDismissed ? null : updateAvailable,
    connected, running, settingsLocked, settingsLoaded, settingsLoadError, retrySettings,
    patchSettings, toggleConnection, connectToPeer, runTest, dismissError, dismissUpdate,
  };
}
