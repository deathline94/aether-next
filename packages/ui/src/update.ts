/**
 * Shared inline auto-update contract for Desktop and Android.
 *
 * Keeping the payload types, URL sanitizer, and progress parsers in `packages/ui`
 * ensures both surfaces present identical update state transitions and keeps the
 * frontend fork ratchet from drifting when update UX evolves.
 */

export const RELEASES_PAGE = "https://github.com/deathline94/aether-next/releases";

export type UpdateStage =
  | "idle"
  | "checking"
  | "downloading"
  | "verifying"
  | "installing"
  | "permission_required"
  | "up_to_date"
  | "error";

export interface UpdateInfo {
  available: boolean;
  currentVersion: string;
  latestVersion: string;
  releaseUrl: string;
  assetName: string;
  assetUrl: string;
  assetSize: number;
  sha256: string | null;
  notes: string;
}

export interface UpdateProgress {
  stage: UpdateStage;
  downloadedBytes: number;
  totalBytes: number;
  percent: number;
  message: string;
}

export interface InstallOutcome {
  status: string;
  path: string;
}

const VALID_STAGES = new Set<UpdateStage>([
  "idle",
  "checking",
  "downloading",
  "verifying",
  "installing",
  "permission_required",
  "up_to_date",
  "error",
]);

export function releasePageUrl(candidate: unknown): string {
  if (typeof candidate !== "string") return RELEASES_PAGE;
  try {
    const parsed = new URL(candidate);
    if (
      parsed.protocol === "https:" &&
      parsed.hostname === "github.com" &&
      parsed.pathname.startsWith("/deathline94/aether-next/releases")
    ) {
      return parsed.toString();
    }
  } catch {
    /* ignore */
  }
  return RELEASES_PAGE;
}

export function parseUpdateInfo(raw: unknown): UpdateInfo | null {
  if (typeof raw !== "object" || raw === null) return null;
  const r = raw as Record<string, unknown>;
  if (
    typeof r.available !== "boolean" ||
    typeof r.currentVersion !== "string" ||
    typeof r.latestVersion !== "string" ||
    typeof r.assetName !== "string" ||
    typeof r.assetUrl !== "string"
  ) {
    return null;
  }
  const size = typeof r.assetSize === "number" && Number.isFinite(r.assetSize) && r.assetSize >= 0
    ? r.assetSize
    : 0;
  return {
    available: r.available,
    currentVersion: r.currentVersion,
    latestVersion: r.latestVersion,
    releaseUrl: releasePageUrl(r.releaseUrl),
    assetName: r.assetName,
    assetUrl: r.assetUrl,
    assetSize: size,
    sha256: typeof r.sha256 === "string" && r.sha256.length === 64 ? r.sha256 : null,
    notes: typeof r.notes === "string" ? r.notes : "",
  };
}

export function parseUpdateProgress(raw: unknown): UpdateProgress | null {
  if (typeof raw !== "object" || raw === null) return null;
  const r = raw as Record<string, unknown>;
  const stage = typeof r.stage === "string" && VALID_STAGES.has(r.stage as UpdateStage)
    ? (r.stage as UpdateStage)
    : null;
  if (!stage) return null;
  const downloadedBytes =
    typeof r.downloadedBytes === "number" && Number.isFinite(r.downloadedBytes) && r.downloadedBytes >= 0
      ? r.downloadedBytes
      : 0;
  const totalBytes =
    typeof r.totalBytes === "number" && Number.isFinite(r.totalBytes) && r.totalBytes >= 0
      ? r.totalBytes
      : 0;
  const percent =
    typeof r.percent === "number" && Number.isFinite(r.percent)
      ? Math.max(0, Math.min(100, Math.round(r.percent)))
      : totalBytes > 0
        ? Math.max(0, Math.min(100, Math.round((downloadedBytes / totalBytes) * 100)))
        : 0;
  return {
    stage,
    downloadedBytes,
    totalBytes,
    percent,
    message: typeof r.message === "string" ? r.message : "",
  };
}
