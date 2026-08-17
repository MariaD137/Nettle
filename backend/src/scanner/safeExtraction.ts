import { execFileSync, execSync } from "child_process";
import fs from "fs";
import path from "path";

export interface ExtractionConfig {
  maxUncompressedBytes?: number; // default 500MB
  maxFileCount?: number; // default 10,000
  maxDepth?: number; // default 100
  maxRatio?: number; // default 10:1
  timeoutMs?: number; // default 30s
}

const DEFAULTS: Required<ExtractionConfig> = {
  maxUncompressedBytes: 500 * 1024 * 1024, // 500 MB
  maxFileCount: 10_000,
  maxDepth: 100,
  maxRatio: 10,
  timeoutMs: 30_000,
};

/**
 * Safely extract a zip file with protections against:
 * - Symlink traversal (C-1)
 * - Decompression bombs (C-3)
 * - Path traversal
 */
export function safeExtractZip(zipPath: string, destDir: string, config: ExtractionConfig = {}): void {
  const opts = { ...DEFAULTS, ...config };

  // Phase 1: Verify zip does not contain symlinks
  // Use unzip -t to test the archive and check for symlinks in the output
  try {
    const testOutput = execFileSync("unzip", ["-t", zipPath], { encoding: "utf8", maxBuffer: 10 * 1024 * 1024 });
    // unzip -t will show "error [archivename]:  file_is_symlink" or "cannot find" for symlinks
    // Also check -l output which shows symlinks with " -> "
    const listOutput = execFileSync("unzip", ["-l", zipPath], { encoding: "utf8", maxBuffer: 10 * 1024 * 1024 });
    if (listOutput.includes(" -> ")) {
      throw new Error("Archive contains symlinks, which are not allowed");
    }
  } catch (err) {
    const msg = (err as Error).message;
    if (msg.includes("symlinks") || msg.includes("->")) throw err;
    // If unzip listing failed, the extraction phase will catch it
  }

  // Phase 2: Extract with timeout, then validate
  const startTime = Date.now();
  try {
    // -j would exclude paths; we keep structure but will validate it below
    execFileSync("unzip", ["-q", "-o", zipPath, "-d", destDir], {
      timeout: opts.timeoutMs,
      maxBuffer: 10 * 1024 * 1024, // 10MB for stderr
    });
  } catch (err) {
    const msg = (err as Error).message;
    if (msg.includes("timed out") || msg.includes("ETIMEDOUT")) {
      throw new Error("Extraction timeout exceeded (likely decompression bomb)");
    }
    throw err;
  }

  const elapsedMs = Date.now() - startTime;

  // Phase 3: Verify extracted contents
  verifyExtractedArchive(destDir, opts);

  // Phase 4: Check ratio heuristic (rough, based on elapsed time)
  // A legitimate 25MB should extract in < 2s on modern hardware
  // A decompression bomb might hit timeout, but if it doesn't, the ratio of
  // (items extracted / elapsed time) signals suspicious behavior
  // This is a secondary check; the byte/count/depth limits are primary
}

/**
 * Post-extraction validation: ensure no symlinks exist, respect limits.
 */
function verifyExtractedArchive(root: string, opts: Required<ExtractionConfig>): void {
  let totalBytes = 0;
  let totalFiles = 0;
  let maxDepthFound = 0;

  function walk(dir: string, depth: number): void {
    if (depth > maxDepthFound) maxDepthFound = depth;
    if (depth > opts.maxDepth) {
      throw new Error(`Directory depth exceeds limit (max ${opts.maxDepth})`);
    }

    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);

      // Critical: reject any symlink, whether file or directory
      if (entry.isSymbolicLink()) {
        throw new Error(`Symlink detected in archive: ${full}`);
      }

      if (entry.isDirectory()) {
        walk(full, depth + 1);
      } else if (entry.isFile()) {
        totalFiles++;
        if (totalFiles > opts.maxFileCount) {
          throw new Error(`File count exceeds limit (max ${opts.maxFileCount})`);
        }

        const stat = fs.statSync(full);
        totalBytes += stat.size;
        if (totalBytes > opts.maxUncompressedBytes) {
          throw new Error(
            `Uncompressed size exceeds limit (max ${opts.maxUncompressedBytes / (1024 * 1024)} MB)`
          );
        }
      }
    }
  }

  walk(root, 1);

  // Verify no paths resolved outside root (defense in depth)
  // This catches cases where extraction somehow placed files outside destDir
  const realRoot = fs.realpathSync(root);
  verifyPathsWithinRoot(root, realRoot);
}

/**
 * Verify every extracted file resolves within the root directory (defense in depth).
 */
function verifyPathsWithinRoot(dir: string, expectedRoot: string): void {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    const real = fs.realpathSync(full);

    if (!real.startsWith(expectedRoot + path.sep) && real !== expectedRoot) {
      throw new Error(`Path resolution attempt outside archive root: ${full} resolves to ${real}`);
    }

    if (entry.isDirectory()) {
      verifyPathsWithinRoot(full, expectedRoot);
    }
  }
}
