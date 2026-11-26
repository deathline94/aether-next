import { useCallback, useEffect, useState } from "react";

export type ThemeMode = "light" | "dark";

const THEME_STORAGE_KEY = "aether-theme";
const LIGHT_CHROME = "#ebf1f5";
const DARK_CHROME = "#101720";

function readStoredTheme(): ThemeMode {
  try {
    if (typeof window !== "undefined" && window.localStorage.getItem(THEME_STORAGE_KEY) === "dark") {
      return "dark";
    }
  } catch {
    // Storage may be unavailable under hardened webview policies.
  }
  return "light";
}

function applyTheme(theme: ThemeMode): void {
  if (typeof document === "undefined") return;
  document.documentElement.dataset.theme = theme;
  const meta = document.querySelector('meta[name="theme-color"]');
  if (meta) {
    meta.setAttribute("content", theme === "dark" ? DARK_CHROME : LIGHT_CHROME);
  }
}

export function useTheme() {
  const [theme, setThemeState] = useState<ThemeMode>(readStoredTheme);

  useEffect(() => {
    applyTheme(theme);
    try {
      window.localStorage.setItem(THEME_STORAGE_KEY, theme);
    } catch {
      // Ignore persistence failures when storage is restricted.
    }
  }, [theme]);

  const setTheme = useCallback((next: ThemeMode) => {
    setThemeState(next);
  }, []);

  const toggleTheme = useCallback(() => {
    setThemeState((prev) => (prev === "dark" ? "light" : "dark"));
  }, []);

  return {
    theme,
    isDark: theme === "dark",
    setTheme,
    toggleTheme,
  };
}
