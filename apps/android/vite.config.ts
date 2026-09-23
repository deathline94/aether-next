import { defineConfig } from "vite";
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

export default defineConfig({
  plugins: [react()],

  // Vite does not read tsconfig paths; without this the bundler cannot see
  // @aether/ui and only the type-check would pass.
  resolve: {
    alias: { "@aether/ui": uiSrc },
  },
  base: "./",
  build: {
    outDir: "dist",
    emptyOutDir: true,
  },
  server: {
    port: 1421,
    strictPort: true,
  },
});
