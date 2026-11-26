import { releasePageUrl, type UpdateInfo, type UpdateProgress } from "../update";

function ArrowUpRightIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M7 17 17 7" />
      <path d="M7 7h10v10" />
    </svg>
  );
}

function DownloadIcon() {
  return (
    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
      <polyline points="7 10 12 15 17 10" />
      <line x1="12" x2="12" y1="15" y2="3" />
    </svg>
  );
}

function RefreshIcon() {
  return (
    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M3 12a9 9 0 0 1 15-6.7L21 8" />
      <path d="M21 3v5h-5" />
      <path d="M21 12a9 9 0 0 1-15 6.7L3 16" />
      <path d="M8 16H3v5" />
    </svg>
  );
}

function CloseIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M18 6 6 18" />
      <path d="m6 6 12 12" />
    </svg>
  );
}

export interface InlineUpdateBannerProps {
  updateInfo: UpdateInfo | null;
  updateProgress?: UpdateProgress | null;
  onInstall?: () => void | Promise<void>;
  onOpenRelease?: (url: string) => void;
  onDismiss?: () => void;
}

export function InlineUpdateBanner({
  updateInfo,
  updateProgress = null,
  onInstall,
  onOpenRelease,
  onDismiss,
}: InlineUpdateBannerProps) {
  if (!updateInfo || !updateInfo.available) return null;

  const busy =
    updateProgress?.stage === "downloading" ||
    updateProgress?.stage === "verifying";
  const isError = updateProgress?.stage === "error";
  const needsPermission = updateProgress?.stage === "permission_required";
  const isInstalling = updateProgress?.stage === "installing";

  const actionLabel = busy
    ? updateProgress?.stage === "verifying"
      ? "Verifying…"
      : `${updateProgress?.percent ?? 0}%`
    : needsPermission
      ? "Install update"
      : isError
        ? "Retry"
        : isInstalling
          ? "Launched"
          : "Download & install";

  return (
    <div className="update-banner" role="status">
      <div className="update-banner-main">
        <div className="error-banner-content">
          <ArrowUpRightIcon />
          <div className="update-banner-meta">
            <span>
              <strong>v{updateInfo.latestVersion}</strong> is available
            </span>
            {updateProgress && updateProgress.stage !== "idle" && updateProgress.message && (
              <span className="update-banner-sub">{updateProgress.message}</span>
            )}
          </div>
        </div>
        {busy && (
          <div
            className="update-progress-track"
            role="progressbar"
            aria-valuenow={updateProgress?.percent ?? 0}
            aria-valuemin={0}
            aria-valuemax={100}
            aria-label="Update download progress"
          >
            <div
              className="update-progress-fill"
              style={{ width: `${updateProgress?.percent ?? 0}%` }}
            />
          </div>
        )}
      </div>

      <div className="banner-actions">
        {onInstall && (
          <button
            type="button"
            className="banner-action"
            disabled={busy}
            onClick={() => void onInstall()}
          >
            <DownloadIcon />
            <span>{actionLabel}</span>
          </button>
        )}
        {onOpenRelease && (
          <button
            type="button"
            className="banner-action"
            onClick={() => onOpenRelease(releasePageUrl(updateInfo.releaseUrl))}
          >
            View release
          </button>
        )}
        {onDismiss && (
          <button
            type="button"
            className="error-banner-dismiss"
            onClick={onDismiss}
            aria-label="Dismiss update"
          >
            <CloseIcon />
          </button>
        )}
      </div>
    </div>
  );
}

export interface UpdateSettingsRowProps {
  appVersion: string;
  updateInfo: UpdateInfo | null;
  updateProgress?: UpdateProgress | null;
  updateChecking: boolean;
  updateCheckError?: string | null;
  onCheck: () => void | Promise<void>;
  onInstall?: () => void | Promise<void>;
}

export function UpdateSettingsRow({
  appVersion,
  updateInfo,
  updateProgress = null,
  updateChecking,
  updateCheckError = null,
  onCheck,
  onInstall,
}: UpdateSettingsRowProps) {
  const busy =
    updateProgress?.stage === "downloading" ||
    updateProgress?.stage === "verifying";

  const statusLine = updateCheckError
    ? `Check failed: ${updateCheckError}`
    : updateProgress && updateProgress.stage !== "idle" && updateProgress.message
      ? updateProgress.message
      : updateInfo?.available
        ? `v${updateInfo.latestVersion} ready (${updateInfo.assetName})`
        : updateInfo
          ? `Up to date (v${updateInfo.currentVersion})`
          : `Installed v${appVersion} — checks GitHub Releases`;

  return (
    <div className="setting-row">
      <div>
        <strong>App Updates</strong>
        <span>{statusLine}</span>
      </div>
      <div className="update-row-actions">
        {updateInfo?.available && onInstall && (
          <button
            type="button"
            className="banner-action"
            disabled={busy}
            onClick={() => void onInstall()}
          >
            <DownloadIcon />
            <span>
              {busy
                ? `${updateProgress?.percent ?? 0}%`
                : updateProgress?.stage === "permission_required"
                  ? "Install update"
                  : "Download & install"}
            </span>
          </button>
        )}
        <button
          type="button"
          className="banner-action"
          disabled={updateChecking || busy}
          onClick={() => void onCheck()}
        >
          <RefreshIcon />
          <span>{updateChecking ? "Checking…" : "Check updates"}</span>
        </button>
      </div>
    </div>
  );
}
