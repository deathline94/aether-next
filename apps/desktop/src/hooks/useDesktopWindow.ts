import { getCurrentWindow } from "@tauri-apps/api/window";
import { useCallback, useEffect, useState } from "react";

const isTauriEnv = () =>
  typeof window !== "undefined" &&
  Boolean((window as { __TAURI_INTERNALS__?: unknown }).__TAURI_INTERNALS__);

export function useDesktopWindow() {
  const [maximized, setMaximized] = useState(false);

  useEffect(() => {
    if (!isTauriEnv()) return;
    let active = true;
    const win = getCurrentWindow();
    void win.isMaximized().then((m) => {
      if (active) setMaximized(m);
    }).catch(() => {});
    let unlisten: (() => void) | undefined;
    void win.onResized(() => {
      void win.isMaximized().then((m) => {
        if (active) setMaximized(m);
      }).catch(() => {});
    }).then((fn) => {
      if (active) unlisten = fn;
      else fn();
    }).catch(() => {});
    return () => {
      active = false;
      unlisten?.();
    };
  }, []);

  const minimize = useCallback(() => {
    if (!isTauriEnv()) return;
    void getCurrentWindow().minimize().catch(() => {});
  }, []);

  const toggleMaximize = useCallback(() => {
    if (!isTauriEnv()) return;
    const win = getCurrentWindow();
    void win.toggleMaximize().then(() => win.isMaximized()).then(setMaximized).catch(() => {});
  }, []);

  const close = useCallback(() => {
    if (!isTauriEnv()) return;
    void getCurrentWindow().close().catch(() => {});
  }, []);

  return { maximized, minimize, toggleMaximize, close };
}
