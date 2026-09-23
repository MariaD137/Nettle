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
 * Pre-extraction inspection of the archive's central directory.
 *
 * The previous implementation searched `unzip -l` output for " -> ", which
 * never appears: `unzip -l` prints only length/date/name and says nothing
 * about entry type. The check could not fire, so the post-extraction lstat
 * walk was the only thing standing between an uploaded symlink and the host
 * filesystem, and a file legitimately named "a -> b.js" would have tripped it
 * spuriously.
 *
 * `unzip -Z` (zipinfo) does report the stored Unix mode, where a symlink is
 * an `l` in the first column, and `unzip -Z1` lists one entry name per line
 * (so names containing spaces stay intact). Between them the archive can be
 * rejected before extraction on:
 *   - symlinks (an exfiltration primitive: the scanner would read and report
 *     whatever the link points at),
 *   - absolute paths and `..` segments (writes outside the workspace).
 *
 * This runs in addition to, not instead of, the post-extraction verification:
 * either alone is a single point of failure.
 */
function inspectArchiveEntries(zipPath: string, opts: Required<ExtractionConfig>): void {
  let names: string[];
  let longListing: string;
  try {
    names = execFileSync("unzip", ["-Z1", zipPath], {
      encoding: "utf8",
      maxBuffer: 10 * 1024 * 1024,
    })
      .split("\n")
      .map((line) => line.trim())
      .filter(Boolean);
    longListing = execFileSync("unzip", ["-Z", zipPath], {
      encoding: "utf8",
      maxBuffer: 10 * 1024 * 1024,
    });
  } catch {
    // An unreadable or corrupt archive is not something to guess about; let
    // the extraction step below produce the real error.
    return;
  }

  // A symlink entry's mode begins with "l". Entry lines always start with the
  // 10-character mode string, so this cannot collide with a file name.
  if (/^l[rwxsStT-]{9}\s/m.test(longListing)) {
    throw new Error("Archive contains symlinks, which are not allowed");
  }

  if (names.length > opts.maxFileCount) {
    throw new Error(`File count exceeds limit (max ${opts.maxFileCount})`);
  }

  for (const name of names) {
    if (name.startsWith("/") || /^[A-Za-z]:[\\/]/.test(name)) {
      throw new Error(`Archive contains an absolute path, which is not allowed: ${name}`);
    }
    if (name.split(/[\\/]/).includes("..")) {
      throw new Error(`Archive contains a path traversal entry, which is not allowed: ${name}`);
    }
  }

  // Decompression-bomb check, before a single byte is written to disk: sum
  // every entry's uncompressed size straight from the archive's own
  // directory listing (no extraction needed to know this) and compare both
  // the raw total and its ratio against the compressed file on disk. The
  // post-extraction byte count in verifyExtractedArchive is real defense in
  // depth (it catches an extractor lying about its own listing), but on its
  // own it runs only after `unzip` has already written a bomb's full
  // expansion to disk — which is the resource exhaustion this exists to
  // prevent in the first place.
  const totalUncompressed = sumUncompressedBytes(zipPath);
  if (totalUncompressed > opts.maxUncompressedBytes) {
    throw new Error(`Uncompressed size exceeds limit (max ${opts.maxUncompressedBytes / (1024 * 1024)} MB)`);
  }
  const compressedBytes = fs.statSync(zipPath).size;
  if (compressedBytes > 0 && totalUncompressed / compressedBytes > opts.maxRatio) {
    throw new Error(`Compression ratio exceeds limit (max ${opts.maxRatio}:1) — likely a decompression bomb`);
  }
}

/**
 * Sums every entry's uncompressed length from `unzip -l`'s own listing.
 * Parsed from the numeric data rows between the two `---------` separator
 * lines rather than trusting the summary row's wording, which varies by
 * unzip version/locale ("1 file" vs "1 files", etc.) — the per-row lengths
 * are stable across versions.
 */
function sumUncompressedBytes(zipPath: string): number {
  let listing: string;
  try {
    listing = execFileSync("unzip", ["-l", zipPath], { encoding: "utf8", maxBuffer: 10 * 1024 * 1024 });
  } catch {
    return 0; // let the extraction step below produce the real error
  }

  let total = 0;
  let dashCount = 0;
  for (const rawLine of listing.split("\n")) {
    const line = rawLine.trim();
    if (/^-{9,}/.test(line)) {
      dashCount++;
      continue;
    }
    if (dashCount === 1) {
      const match = line.match(/^(\d+)\s/);
      if (match) total += parseInt(match[1], 10);
    }
  }
  return total;
}

/**
 * Safely extract a zip file with protections against:
 * - Symlink traversal (C-1)
 * - Decompression bombs (C-3)
 * - Path traversal
 */
export function safeExtractZip(zipPath: string, destDir: string, config: ExtractionConfig = {}): void {
  const opts = { ...DEFAULTS, ...config };

  // Phase 1: reject dangerous entries before a single byte is written to disk.
  inspectArchiveEntries(zipPath, opts);

  // Phase 2: Extract with timeout, then validate
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

  // Phase 3: Verify extracted contents. The uncompressed-size/ratio bomb
  // checks already ran pre-extraction (see inspectArchiveEntries); this pass
  // is the defense-in-depth re-check against what was actually written to
  // disk, plus symlink/depth/path verification that can only be done
  // post-extraction.
  verifyExtractedArchive(destDir, opts);
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
