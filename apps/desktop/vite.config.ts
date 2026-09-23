// `test` is a vitest key, and vite's own `defineConfig` does not know it: importing
// the config helper from `vitest/config` is what types the block below without
// reaching for a triple-slash reference.
import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

// A config is loaded as ESM, so there is no __dirname, and @types/node is not
// installed. Turn import.meta.url into a native path for both the Windows
// file:///C:/... and the POSIX file:///... spelling.
const uiPath = (rel: string) => {
  const href = new URL(rel, import.meta.url).href;
  const windowsDrive = /^file:\/\/\/([A-Za-z]:)/.test(href);
  return decodeURIComponent(href.slice(windowsDrive ? "file:///".length : "file://".length));
};
const uiSrc = uiPath("../../packages/ui/src");

// @ts-expect-error process is a nodejs global
const host = process.env.TAURI_DEV_HOST;

// https://vite.dev/config/
export default defineConfig(async () => ({
  plugins: [react()],

  // Vite does not read tsconfig paths; without this the bundler cannot see
  // @aether/ui and only the type-check would pass.
  resolve: {
    alias: { "@aether/ui": uiSrc },
    // A component that lives in packages/ui still renders JSX, so the runtime
    // has to be reachable from there too: no root node_modules exists, and the
    // shared package deliberately has none of its own.
    react: uiPath("./node_modules/react"),
    "react/jsx-runtime": uiPath("./node_modules/react/jsx-runtime"),
    "react/jsx-dev-runtime": uiPath("./node_modules/react/jsx-dev-runtime"),
  },

  // `packages/ui` installs nothing of its own — there is no root node_modules and
  // the package deliberately has none — so it has no runner, and its tests would
  // never be discovered. They run from each app's vitest instead: both suites
  // execute the same shared-table test, which is the only way that file can mean
  // what it asserts (one definition, read by both surfaces). The app's own tests
  // stay under `src/`, exactly as they were found before.
  test: {
    include: [
      "src/**/*.{test,spec}.{ts,tsx}",
      "../../packages/ui/src/**/*.{test,spec}.{ts,tsx}",
    ],
  },

  // Vite options tailored for Tauri development and only applied in `tauri dev` or `tauri build`
  //
  // 1. prevent Vite from obscuring rust errors
  clearScreen: false,
  // 2. tauri expects a fixed port, fail if that port is not available
  server: {
    port: 1420,
    strictPort: true,
    host: host || false,
    hmr: host
      ? {
          protocol: "ws",
          host,
          port: 1421,
        }
      : undefined,
    watch: {
      // 3. tell Vite to ignore watching `src-tauri`
      ignored: ["**/src-tauri/**"],
    },
  },
}));
