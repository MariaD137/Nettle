import fs from "fs";
import path from "path";

const SKIP_DIRS = new Set(["node_modules", ".git", "dist", "build", ".next"]);

// Patterns starting with "." match as a filename suffix (the original,
// extension-based behavior). Patterns without a leading "." match as a
// case-insensitive substring anywhere in the filename — needed for files
// like "Dockerfile", "web.Dockerfile", or "Dockerfile.prod" that don't
// share a common suffix.
function matchesAny(name: string, patterns: string[]): boolean {
  const lower = name.toLowerCase();
  return patterns.some((p) => (p.startsWith(".") ? lower.endsWith(p) : lower.includes(p)));
}

export function walk(dir: string, exts: string[], out: string[] = [], maxDepth = 100, currentDepth = 1): string[] {
  if (currentDepth > maxDepth) {
    throw new Error(`Directory depth exceeds limit (max ${maxDepth})`);
  }

  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (SKIP_DIRS.has(entry.name)) continue;
    const full = path.join(dir, entry.name);

    // Defense in depth: reject symlinks if any exist (should be caught at extraction)
    if (entry.isSymbolicLink()) {
      throw new Error(`Symlink detected during traversal: ${full}`);
    }

    if (entry.isDirectory()) {
      walk(full, exts, out, maxDepth, currentDepth + 1);
    } else if (matchesAny(entry.name, exts)) {
      out.push(full);
    }
  }
  return out;
}
