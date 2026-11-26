import { parseRuntimeState, parseSettings, defaults, type RuntimeState, type Settings } from "./types";
import { parseSessionStats, type SessionStats } from "@aether/ui";

export function setupDesktopPreview(
  fallbackVersion: string,
  applySettings: (s: Settings) => void,
  applyRuntime: (r: RuntimeState) => void,
  applyStats: (s: SessionStats | null) => void,
  markReady: (version: string) => void,
): () => void {
  const handler = (event: Event) => {
    const detail = (
      event as CustomEvent<{
        state?: unknown;
        stats?: unknown;
        settings?: Partial<Settings>;
      }>
    ).detail;
    if (!detail) return;
    if (detail.settings) {
      const { settings: merged } = parseSettings({ ...defaults, ...detail.settings });
      applySettings(merged);
    }
    if (detail.state !== undefined) {
      const parsedState = parseRuntimeState(detail.state);
      if (parsedState) {
        applyRuntime(parsedState);
        if (parsedState.status !== "connected") applyStats(null);
      }
    }
    if (detail.stats !== undefined) {
      if (detail.stats === null) applyStats(null);
      else {
        const parsedStats = parseSessionStats(detail.stats);
        if (parsedStats) applyStats(parsedStats);
      }
    }
  };
  window.addEventListener("aether-preview", handler);
  const { settings: initial } = parseSettings(defaults);
  applySettings(initial);
  markReady(fallbackVersion);
  return () => window.removeEventListener("aether-preview", handler);
}
