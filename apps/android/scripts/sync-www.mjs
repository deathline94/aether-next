import { cpSync, rmSync, mkdirSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const dist = join(root, "dist");
const www = join(root, "android", "app", "src", "main", "assets", "www");

if (!existsSync(dist)) {
  console.error("dist/ missing — run npm run build first");
  process.exit(1);
}

rmSync(www, { recursive: true, force: true });
mkdirSync(www, { recursive: true });
cpSync(dist, www, { recursive: true });
console.log(`synced ${dist} → ${www}`);
