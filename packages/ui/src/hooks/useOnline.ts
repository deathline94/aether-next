import { useEffect, useState } from "react";

/** Tracks browser/WebView online status so the UI can warn when the network is down. */
export function useOnline(): boolean {
  const [online, setOnline] = useState(() =>
    typeof navigator !== "undefined" && "onLine" in navigator ? navigator.onLine : true,
  );

  useEffect(() => {
    const up = () => setOnline(true);
    const down = () => setOnline(false);
    window.addEventListener("online", up);
    window.addEventListener("offline", down);
    return () => {
      window.removeEventListener("online", up);
      window.removeEventListener("offline", down);
    };
  }, []);

  return online;
}
