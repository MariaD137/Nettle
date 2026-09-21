import fs from "fs";
import path from "path";

const SKIP_DIRS = new Set(["node_modules", ".git", "dist", "build", ".next"]);

export function walk(dir: string, exts: string[], out: string[] = [], maxDepth = 100, currentDepth = 1): string[] {
  if (currentDepth > maxDepth) {
    throw new Error(`Directory depth exceeds limit (max ${maxDepth})`);
  }

  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (SKIP_DIRS.has(entry.name)) continue;
    const full = path.join(dir, entry.name);

    // Symlinks are skipped, never followed.
    //
    // Not following them is the security property that matters: following one
    // turns the scanner into an arbitrary-file-read oracle, reporting whatever
    // the link targets back to whoever supplied it.
    //
    // Skipping rather than throwing, because this walks git clones too
    // (/api/scans/repo), and symlinks are ordinary in real repositories —
    // monorepo package links, vendored docs, dotfiles. Throwing meant one
    // benign symlink failed the entire scan with a 422. Uploaded archives are
    // still rejected outright at extraction time (see safeExtraction.ts);
    // this is the second layer, and for a clone it is the only one.
    if (entry.isSymbolicLink()) continue;

    if (entry.isDirectory()) {
      walk(full, exts, out, maxDepth, currentDepth + 1);
    } else if (exts.some((ext) => entry.name.toLowerCase().endsWith(ext))) {
      out.push(full);
    }
  }
  return out;
}
