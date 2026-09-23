import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "fs";
import path from "path";
import os from "os";
import { execFileSync } from "child_process";
import { safeExtractZip } from "../src/scanner/safeExtraction";

/**
 * Security tests for symlink traversal (C-1) and decompression bombs (C-3).
 */

test("C-1: symlink in archive is detected and rejected", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "symlink-test-"));
  try {
    // Create a file and a symlink to it
    const testFile = path.join(tmpDir, "secret.txt");
    fs.writeFileSync(testFile, "sensitive data");

    const symlinkFile = path.join(tmpDir, "link.txt");
    try {
      fs.symlinkSync(testFile, symlinkFile);
    } catch {
      // If symlink creation fails (permissions), skip this test
      return;
    }

    // Zip with symlink support (-y flag preserves symlinks)
    const zipPath = path.join(tmpDir, "payload.zip");
    execFileSync("zip", ["-q", "-y", zipPath, symlinkFile], { cwd: tmpDir });

    // Attempt extraction — should fail either at detection or verification
    const extractDir = fs.mkdtempSync(path.join(os.tmpdir(), "extract-"));
    try {
      assert.throws(
        () => safeExtractZip(zipPath, extractDir),
        /symlink/i,
        "Expected symlink to be detected and rejected"
      );
    } finally {
      fs.rmSync(extractDir, { recursive: true, force: true });
    }
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("C-1: symlink to /etc/passwd blocked", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "symlink-passwd-test-"));
  try {
    // Create symlink to a sensitive file
    const linkPath = path.join(tmpDir, "db.json");
    try {
      fs.symlinkSync("/etc/passwd", linkPath);
    } catch {
      // Skip if can't create symlink (permission issue)
      return;
    }

    // Zip it
    const zipPath = path.join(tmpDir, "payload.zip");
    execFileSync("zip", ["-q", "-y", zipPath, linkPath], { cwd: tmpDir });

    // Attempt extraction — should fail
    const extractDir = fs.mkdtempSync(path.join(os.tmpdir(), "extract-"));
    try {
      assert.throws(
        () => safeExtractZip(zipPath, extractDir),
        /symlink/i,
        "symlink to /etc/passwd must be rejected"
      );
    } finally {
      fs.rmSync(extractDir, { recursive: true, force: true });
    }
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("C-3: extraction timeout on decompression bomb", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "decomp-test-"));
  try {
    // Create a highly compressible file (all zeros)
    const largeFile = path.join(tmpDir, "zeros.bin");
    fs.writeFileSync(largeFile, Buffer.alloc(100 * 1024 * 1024)); // 100 MB of zeros
    fs.chmodSync(largeFile, 0o644);

    // Zip with maximum compression
    const zipPath = path.join(tmpDir, "bomb.zip");
    execFileSync("zip", ["-q", "-9", zipPath, largeFile], { cwd: tmpDir });

    // Verify the zip is small (compresses well) but uncompresses to 100MB
    const zipSize = fs.statSync(zipPath).size;
    console.log(`  Decompression bomb test: ${zipSize / 1024} KB zip → 100 MB uncompressed`);

    const extractDir = fs.mkdtempSync(path.join(os.tmpdir(), "extract-"));
    try {
      // The pre-extraction ratio check (see the next test) now catches this
      // exact bomb before extraction even starts — so to isolate and still
      // verify the timeout path specifically, maxRatio is set permissive
      // enough here that this bomb passes that earlier check and actually
      // reaches extraction, where the 100ms timeout is what stops it.
      assert.throws(
        () =>
          safeExtractZip(zipPath, extractDir, {
            timeoutMs: 100,
            maxUncompressedBytes: 500 * 1024 * 1024,
            maxRatio: 1_000_000,
          }),
        /timeout/i,
        "Extraction timeout should be enforced"
      );
    } finally {
      fs.rmSync(extractDir, { recursive: true, force: true });
    }
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("C-3: compression-ratio bomb rejected pre-extraction, no disk write needed", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "ratio-test-"));
  try {
    const largeFile = path.join(tmpDir, "zeros.bin");
    fs.writeFileSync(largeFile, Buffer.alloc(100 * 1024 * 1024)); // 100 MB of zeros
    fs.chmodSync(largeFile, 0o644);

    const zipPath = path.join(tmpDir, "bomb.zip");
    execFileSync("zip", ["-q", "-9", zipPath, largeFile], { cwd: tmpDir });

    const extractDir = fs.mkdtempSync(path.join(os.tmpdir(), "extract-"));
    try {
      // Default maxRatio (10:1) and a generous timeout: this must be
      // rejected by the ratio check itself, not by timing out — proving the
      // check actually fires rather than merely existing as dead code.
      assert.throws(
        () => safeExtractZip(zipPath, extractDir, { timeoutMs: 30_000 }),
        /ratio/i,
        "A highly compressible archive should be rejected on its compression ratio"
      );
      // Nothing should have been written — the ratio check runs before
      // `unzip` is ever invoked.
      assert.deepEqual(fs.readdirSync(extractDir), []);
    } finally {
      fs.rmSync(extractDir, { recursive: true, force: true });
    }
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("C-3: uncompressed size limit enforced", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "size-test-"));
  try {
    // Create a file larger than our max
    const largeFile = path.join(tmpDir, "huge.bin");
    fs.writeFileSync(largeFile, Buffer.alloc(600 * 1024 * 1024)); // 600 MB

    const zipPath = path.join(tmpDir, "large.zip");
    try {
      // This might fail to zip if disk is small, so wrap it
      execFileSync("zip", ["-q", "-0", zipPath, largeFile], { cwd: tmpDir });
    } catch {
      // Skip if can't create the test zip
      return;
    }

    const extractDir = fs.mkdtempSync(path.join(os.tmpdir(), "extract-"));
    try {
      assert.throws(
        () =>
          safeExtractZip(zipPath, extractDir, {
            maxUncompressedBytes: 500 * 1024 * 1024, // 500 MB limit
            timeoutMs: 60_000,
          }),
        /exceeds limit/i,
        "Uncompressed size limit should be enforced"
      );
    } finally {
      fs.rmSync(extractDir, { recursive: true, force: true });
    }
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("C-3: file count limit enforced", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "filecount-test-"));
  try {
    // Create many small files
    const filesDir = path.join(tmpDir, "files");
    fs.mkdirSync(filesDir);

    for (let i = 0; i < 1000; i++) {
      fs.writeFileSync(path.join(filesDir, `file${i}.txt`), "small");
    }

    const zipPath = path.join(tmpDir, "manyfiles.zip");
    execFileSync("zip", ["-q", "-r", zipPath, filesDir], { cwd: tmpDir });

    const extractDir = fs.mkdtempSync(path.join(os.tmpdir(), "extract-"));
    try {
      assert.throws(
        () =>
          safeExtractZip(zipPath, extractDir, {
            maxFileCount: 100, // Only allow 100 files
            timeoutMs: 60_000,
          }),
        /exceeds limit/i,
        "File count limit should be enforced"
      );
    } finally {
      fs.rmSync(extractDir, { recursive: true, force: true });
    }
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("C-3: directory depth limit enforced", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "depth-test-"));
  try {
    // Create deeply nested directory structure
    let deepPath = path.join(tmpDir, "files");
    for (let i = 0; i < 50; i++) {
      deepPath = path.join(deepPath, `level${i}`);
    }
    fs.mkdirSync(deepPath, { recursive: true });

    // Put a file at the bottom
    fs.writeFileSync(path.join(deepPath, "deep.txt"), "very deep");

    const zipPath = path.join(tmpDir, "deep.zip");
    execFileSync("zip", ["-q", "-r", zipPath, path.join(tmpDir, "files")], { cwd: tmpDir });

    const extractDir = fs.mkdtempSync(path.join(os.tmpdir(), "extract-"));
    try {
      assert.throws(
        () =>
          safeExtractZip(zipPath, extractDir, {
            maxDepth: 10, // Only allow depth 10
            timeoutMs: 60_000,
          }),
        /depth exceeds/i,
        "Directory depth limit should be enforced"
      );
    } finally {
      fs.rmSync(extractDir, { recursive: true, force: true });
    }
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("normal archive without symlinks extracts successfully", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "normal-test-"));
  try {
    // Create a normal zip with some files
    const filesDir = path.join(tmpDir, "files");
    fs.mkdirSync(filesDir);

    fs.writeFileSync(path.join(filesDir, "index.js"), "console.log('hello')");
    fs.writeFileSync(path.join(filesDir, "package.json"), '{"name": "test"}');

    const zipPath = path.join(tmpDir, "normal.zip");
    execFileSync("zip", ["-q", "-r", zipPath, "files"], { cwd: tmpDir });

    const extractDir = fs.mkdtempSync(path.join(os.tmpdir(), "extract-"));
    try {
      // Should not throw
      safeExtractZip(zipPath, extractDir);

      // Verify files exist (zip preserves the directory structure)
      const expectedDir = path.join(extractDir, "files");
      assert.ok(fs.existsSync(expectedDir), `Directory ${expectedDir} should exist`);
      assert.ok(fs.existsSync(path.join(expectedDir, "index.js")), "index.js should exist");
      assert.ok(fs.existsSync(path.join(expectedDir, "package.json")), "package.json should exist");
    } finally {
      fs.rmSync(extractDir, { recursive: true, force: true });
    }
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});
