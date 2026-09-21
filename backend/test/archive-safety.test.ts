import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "fs";
import os from "os";
import path from "path";
import { execFileSync } from "child_process";
import { safeExtractZip } from "../src/scanner/safeExtraction";
import { walk } from "../src/scanner/walk";

function workspace(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "nettle-archive-test-"));
}

// Build a zip with arbitrary entry names, including ones the `zip` CLI will
// not produce (absolute paths, `..` segments).
function craftedZip(dir: string, entries: Record<string, string>): string {
  const zipPath = path.join(dir, "crafted.zip");
  const script = [
    "import zipfile, json, sys",
    "entries = json.loads(sys.argv[2])",
    "z = zipfile.ZipFile(sys.argv[1], 'w')",
    "[z.writestr(k, v) for k, v in entries.items()]",
    "z.close()",
  ].join("\n");
  execFileSync("python3", ["-c", script, zipPath, JSON.stringify(entries)]);
  return zipPath;
}

test("a normal archive extracts", () => {
  const dir = workspace();
  const src = path.join(dir, "app");
  fs.mkdirSync(src);
  fs.writeFileSync(path.join(src, "index.js"), "console.log(1)");
  const zipPath = path.join(dir, "ok.zip");
  execFileSync("zip", ["-q", "-r", zipPath, "app"], { cwd: dir });

  const dest = path.join(dir, "out");
  fs.mkdirSync(dest);
  safeExtractZip(zipPath, dest);
  assert.ok(fs.existsSync(path.join(dest, "app", "index.js")));
});

test("a symlink entry is rejected before extraction, not after", () => {
  const dir = workspace();
  const src = path.join(dir, "app");
  fs.mkdirSync(src);
  fs.writeFileSync(path.join(src, "index.js"), "console.log(1)");
  fs.symlinkSync("/etc/passwd", path.join(src, "stolen.js"));
  const zipPath = path.join(dir, "link.zip");
  execFileSync("zip", ["-q", "-y", "-r", zipPath, "app"], { cwd: dir });

  const dest = path.join(dir, "out");
  fs.mkdirSync(dest);
  assert.throws(() => safeExtractZip(zipPath, dest), /symlink/i);
  // Rejected up front: nothing from the archive should have been written.
  assert.equal(fs.readdirSync(dest).length, 0, "no files should be written for a rejected archive");
});

test("a `..` traversal entry is rejected", () => {
  const dir = workspace();
  const zipPath = craftedZip(dir, { "../../escape.txt": "pwned", "ok.txt": "fine" });
  const dest = path.join(dir, "out");
  fs.mkdirSync(dest);
  assert.throws(() => safeExtractZip(zipPath, dest), /path traversal/i);
  assert.ok(!fs.existsSync(path.join(dir, "escape.txt")));
});

test("an absolute-path entry is rejected", () => {
  const dir = workspace();
  const zipPath = craftedZip(dir, { "/tmp/nettle-absolute-escape.txt": "pwned", "ok.txt": "fine" });
  const dest = path.join(dir, "out");
  fs.mkdirSync(dest);
  assert.throws(() => safeExtractZip(zipPath, dest), /absolute path/i);
});

test("a legitimate filename containing ' -> ' is NOT treated as a symlink", () => {
  // The old pre-check searched `unzip -l` output for " -> ", so this file
  // would have been rejected as an attack while real symlinks sailed through.
  const dir = workspace();
  const zipPath = craftedZip(dir, { "app/before -> after.js": "console.log(1)" });
  const dest = path.join(dir, "out");
  fs.mkdirSync(dest);

  safeExtractZip(zipPath, dest);
  assert.ok(fs.existsSync(path.join(dest, "app", "before -> after.js")));
});

test("the file-count limit is enforced from the archive listing", () => {
  const dir = workspace();
  const entries: Record<string, string> = {};
  for (let i = 0; i < 20; i++) entries[`f${i}.txt`] = "x";
  const zipPath = craftedZip(dir, entries);
  const dest = path.join(dir, "out");
  fs.mkdirSync(dest);
  assert.throws(() => safeExtractZip(zipPath, dest, { maxFileCount: 5 }), /exceeds limit/i);
});

// --- walk(): skip symlinks, never follow, never fail the whole scan ---

test("walk skips a symlink instead of failing the scan", () => {
  const dir = workspace();
  fs.writeFileSync(path.join(dir, "real.js"), "console.log(1)");
  fs.symlinkSync("/etc/passwd", path.join(dir, "linked.js"));

  const found = walk(dir, [".js"]);
  assert.ok(
    found.some((f) => f.endsWith("real.js")),
    "real files must still be scanned"
  );
  assert.ok(
    !found.some((f) => f.endsWith("linked.js")),
    "a symlink must never be followed — that is an arbitrary-file-read primitive"
  );
});

test("walk does not follow a symlinked directory out of the tree", () => {
  const dir = workspace();
  const outside = workspace();
  fs.writeFileSync(path.join(outside, "secret.js"), "const k = 'leak'");
  fs.symlinkSync(outside, path.join(dir, "escape"));
  fs.writeFileSync(path.join(dir, "real.js"), "console.log(1)");

  const found = walk(dir, [".js"]);
  assert.equal(found.length, 1);
  assert.ok(found[0].endsWith("real.js"));
});
