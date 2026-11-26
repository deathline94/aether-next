import { useCallback, useEffect, useRef, useState } from "react";
import {
  parseUpdateInfo,
  parseUpdateProgress,
  type InstallOutcome,
  type UpdateInfo,
  type UpdateProgress,
} from "../update";

export interface InlineUpdaterDeps {
  appVersion: string | null;
  fallbackVersion: string;
  connected: boolean;
  routingMode: string;
  httpPort: number;
  checkUpdateCmd: (args: { httpPort: number; useLocalProxy: boolean }) => Promise<unknown>;
  downloadInstallCmd: (args: {
    assetUrl: string;
    assetName: string;
    sha256: string | null;
    httpPort: number;
    useLocalProxy: boolean;
  }) => Promise<InstallOutcome>;
  listenEvent: <T>(event: string, handler: (event: { payload: T }) => void) => Promise<() => void>;
  formatError: (err: unknown) => string;
  appendLog: (entry: { level: "info" | "warn" | "error"; message: string }) => void;
}

export interface InlineUpdaterState {
  updateInfo: UpdateInfo | null;
  updateProgress: UpdateProgress | null;
  updateChecking: boolean;
  updateDismissed: boolean;
  updateCheckError: string | null;
  checkForUpdates: () => Promise<void>;
  installUpdate: () => Promise<void>;
  dismissUpdate: () => void;
}

/**
 * Shared auto-check and in-app download/install hook for Desktop and Android.
 *
 * Routes GitHub API and asset fetches through the local HTTP proxy when
 * connected in non-TUN modes so update checks never bypass an active proxy
 * session, and falls back to direct access otherwise (including TUN mode).
 */
export function useInlineUpdater({
  appVersion,
  fallbackVersion,
  connected,
  routingMode,
  httpPort,
  checkUpdateCmd,
  downloadInstallCmd,
  listenEvent,
  formatError,
  appendLog,
}: InlineUpdaterDeps): InlineUpdaterState {
  const [updateInfo, setUpdateInfo] = useState<UpdateInfo | null>(null);
  const [updateProgress, setUpdateProgress] = useState<UpdateProgress | null>(null);
  const [updateChecking, setUpdateChecking] = useState(false);
  const [updateDismissed, setUpdateDismissed] = useState(false);
  const [updateCheckError, setUpdateCheckError] = useState<string | null>(null);

  const autoCheckedRef = useRef(false);
  const checkingRef = useRef(false);
  const installingRef = useRef(false);

  useEffect(() => {
    let disposed = false;
    let unlisten: (() => void) | null = null;
    void listenEvent<unknown>("update-progress", (event) => {
      if (disposed) return;
      const parsed = parseUpdateProgress(event.payload);
      if (parsed) setUpdateProgress(parsed);
    })
      .then((fn) => {
        if (disposed) fn();
        else unlisten = fn;
      })
      .catch(() => {});
    return () => {
      disposed = true;
      unlisten?.();
    };
  }, [listenEvent]);

  const runCheck = useCallback(
    async (silent: boolean) => {
      if (checkingRef.current) return;
      checkingRef.current = true;
      setUpdateChecking(true);
      if (!silent) setUpdateCheckError(null);
      try {
        const useLocalProxy = connected && routingMode !== "tun";
        const raw = await checkUpdateCmd({
          httpPort,
          useLocalProxy,
        });
        const parsed = parseUpdateInfo(raw);
        if (!parsed) {
          throw new Error("Update check returned an unexpected payload.");
        }
        setUpdateInfo(parsed);
        setUpdateCheckError(null);
        if (parsed.available) {
          setUpdateDismissed(false);
          appendLog({
            level: "info",
            message: `Update available: v${parsed.latestVersion} (${parsed.assetName})`,
          });
        } else if (!silent) {
          appendLog({
            level: "info",
            message: `Aether Next v${parsed.currentVersion} is up to date.`,
          });
        }
      } catch (err) {
        const msg = formatError(err);
        if (!silent) {
          setUpdateCheckError(msg);
          appendLog({ level: "warn", message: `Update check failed: ${msg}` });
        }
      } finally {
        checkingRef.current = false;
        setUpdateChecking(false);
      }
    },
    [appendLog, checkUpdateCmd, connected, formatError, httpPort, routingMode],
  );

  // Auto-check once per app session when a tunnel connects (all routing modes:
  // proxy-only / system-proxy route through the local HTTP listener; TUN routes through TUN).
  useEffect(() => {
    if (!appVersion || appVersion === fallbackVersion) return;
    if (!connected || autoCheckedRef.current) return;
    autoCheckedRef.current = true;
    void runCheck(true);
  }, [appVersion, connected, fallbackVersion, runCheck]);

  const checkForUpdates = useCallback(() => runCheck(false), [runCheck]);

  const installUpdate = useCallback(async () => {
    if (installingRef.current || !updateInfo || !updateInfo.available || !updateInfo.assetUrl) return;
    installingRef.current = true;
    setUpdateProgress({
      stage: "downloading",
      downloadedBytes: 0,
      totalBytes: updateInfo.assetSize,
      percent: 0,
      message: "Starting update download...",
    });
    try {
      const useLocalProxy = connected && routingMode !== "tun";
      const outcome = await downloadInstallCmd({
        assetUrl: updateInfo.assetUrl,
        assetName: updateInfo.assetName,
        sha256: updateInfo.sha256,
        httpPort,
        useLocalProxy,
      });
      if (outcome?.status === "permission_required") {
        setUpdateProgress({
          stage: "permission_required",
          downloadedBytes: 100,
          totalBytes: 100,
          percent: 100,
          message: "Allow 'Install unknown apps', then tap Install update.",
        });
      } else {
        setUpdateProgress({
          stage: "installing",
          downloadedBytes: 100,
          totalBytes: 100,
          percent: 100,
          message: "Installer launched.",
        });
      }
    } catch (err) {
      const msg = formatError(err);
      setUpdateProgress({
        stage: "error",
        downloadedBytes: 0,
        totalBytes: 0,
        percent: 0,
        message: msg,
      });
      appendLog({ level: "error", message: `Update install failed: ${msg}` });
    } finally {
      installingRef.current = false;
    }
  }, [appendLog, connected, downloadInstallCmd, formatError, httpPort, routingMode, updateInfo]);

  const dismissUpdate = useCallback(() => setUpdateDismissed(true), []);

  return {
    updateInfo: updateDismissed ? null : updateInfo,
    updateProgress,
    updateChecking,
    updateDismissed,
    updateCheckError,
    checkForUpdates,
    installUpdate,
    dismissUpdate,
  };
}
