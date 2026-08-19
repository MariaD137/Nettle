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

  // Phase 2: Check declared size/count/depth/ratio from the central
  // directory BEFORE extracting anything. `unzip -l` reads only the zip's
  // central directory (at the end of the file) — it does not decompress
  // any file content, so this is fast and safe to run even against a
  // maliciously huge archive. This is what actually stops a decompression
  // bomb: rejecting it here means the bomb's content is never written to
  // disk at all. The post-extraction walk below stays in place as
  // defense-in-depth for the case of a zip whose central directory
  // under-reports its real size.
  const stats = getArchiveStats(zipPath, opts);
  if (stats.totalBytes > opts.maxUncompressedBytes) {
    throw new Error(`Uncompressed size exceeds limit (max ${opts.maxUncompressedBytes / (1024 * 1024)} MB)`);
  }
  if (stats.fileCount > opts.maxFileCount) {
    throw new Error(`File count exceeds limit (max ${opts.maxFileCount})`);
  }
  if (stats.maxDepth > opts.maxDepth) {
    throw new Error(`Directory depth exceeds limit (max ${opts.maxDepth})`);
  }
  const compressedSize = fs.statSync(zipPath).size;
  if (compressedSize > 0 && stats.totalBytes / compressedSize > opts.maxRatio) {
    throw new Error(`Compression ratio exceeds limit (max ${opts.maxRatio}:1) — likely a decompression bomb`);
  }

  // Phase 3: Extract with a wall-clock timeout as a further backstop
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

  // Phase 4: Verify extracted contents actually match what was declared
  // (defense-in-depth against a central directory that lied)
  verifyExtractedArchive(destDir, opts);
}

/**
 * Reads the zip's central directory listing (`unzip -l`) to get the total
 * uncompressed size, file count, and max path depth without extracting
 * anything.
 */
function getArchiveStats(
  zipPath: string,
  opts: Required<ExtractionConfig>
): { totalBytes: number; fileCount: number; maxDepth: number } {
  const listOutput = execFileSync("unzip", ["-l", zipPath], { encoding: "utf8", maxBuffer: 10 * 1024 * 1024 });
  const lines = listOutput.split("\n");

  // Info-ZIP's -l output brackets the data rows between two dashed
  // separator lines (one after the "Length Date Time Name" header, one
  // before the "<total> <n> files" footer). Parsing between them, rather
  // than matching a specific date format, keeps this working across
  // Info-ZIP versions/locales that format the date column differently.
  const separatorIndices: number[] = [];
  lines.forEach((line, i) => {
    if (/^-+\s+-+/.test(line.trim())) separatorIndices.push(i);
  });
  if (separatorIndices.length < 2) {
    throw new Error("Could not read archive listing");
  }
  const dataLines = lines.slice(separatorIndices[0] + 1, separatorIndices[1]);

  let totalBytes = 0;
  let fileCount = 0;
  let maxDepth = 0;

  for (const line of dataLines) {
    const match = line.match(/^\s*(\d+)\s+\S+\s+\S+\s+(.+)$/);
    if (!match) continue;
    const length = Number(match[1]);
    const name = match[2].trim();

    const depth = name.split("/").filter(Boolean).length;
    if (depth > maxDepth) maxDepth = depth;

    // Directory entries (trailing "/") have no content of their own —
    // matches how the post-extraction walk below counts files vs dirs.
    if (!name.endsWith("/")) {
      fileCount++;
      totalBytes += length;
    }
  }

  return { totalBytes, fileCount, maxDepth };
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
