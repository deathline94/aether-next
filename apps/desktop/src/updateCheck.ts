import { semverGt } from "./semver";

const UPDATE_CHECK_URL = "https://api.github.com/repos/deathline94/aether-next/releases/latest";
export const RELEASES_PAGE = "https://github.com/deathline94/aether-next/releases";

export function releasePageUrl(candidate: unknown): string {
  if (typeof candidate !== "string") return RELEASES_PAGE;
  try {
    const parsed = new URL(candidate);
    if (
      parsed.protocol === "https:" &&
      parsed.hostname === "github.com" &&
      parsed.pathname.startsWith("/deathline94/aether-next/releases/")
    ) {
      return parsed.toString();
    }
  } catch {
    /* ignore */
  }
  return RELEASES_PAGE;
}

export function startUpdateCheck(
  appVersion: string,
  onFound: (update: { version: string; url: string }) => void,
): () => void {
  const controller = new AbortController();
  fetch(UPDATE_CHECK_URL, { signal: controller.signal })
    .then((res) => {
      if (typeof res?.ok === "boolean" && !res.ok) throw new Error(`HTTP ${res.status}`);
      return res.json();
    })
    .then((data: unknown) => {
      if (controller.signal.aborted) return;
      const payload = data as { tag_name?: unknown; html_url?: unknown } | null;
      const tag = typeof payload?.tag_name === "string" ? payload.tag_name : null;
      if (!payload || !tag) return;
      const latest = tag.replace(/^v/, "");
      if (semverGt(latest, appVersion)) {
        onFound({ version: tag, url: releasePageUrl(payload.html_url) });
      }
    })
    .catch(() => {});
  return () => controller.abort();
}
