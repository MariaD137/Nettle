import fs from "fs";
import path from "path";

const SKIP_DIRS = new Set(["node_modules", ".git", "dist", "build", ".next"]);

export function walk(dir: string, exts: string[], out: string[] = []): string[] {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (SKIP_DIRS.has(entry.name)) continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      walk(full, exts, out);
    } else if (exts.some((ext) => entry.name.toLowerCase().endsWith(ext))) {
      out.push(full);
    }
  }
  return out;
}
