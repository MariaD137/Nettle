import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { resolveScanRoot } from "../src/scanner/resolveScanRoot";

function mktemp(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "resolve-scan-root-test-"));
}

test("unwraps a single top-level folder (the common zip -r case)", () => {
  const root = mktemp();
  fs.mkdirSync(path.join(root, "my-app"));
  fs.writeFileSync(path.join(root, "my-app", "package.json"), "{}");

  const resolved = resolveScanRoot(root);
  assert.equal(resolved, path.join(root, "my-app"));
});

test("unwraps multiple nested single-folder levels", () => {
  const root = mktemp();
  const nested = path.join(root, "a", "b", "c");
  fs.mkdirSync(nested, { recursive: true });
  fs.writeFileSync(path.join(nested, "package.json"), "{}");

  const resolved = resolveScanRoot(root);
  assert.equal(resolved, nested);
});

test("does not unwrap when the root already has multiple entries", () => {
  const root = mktemp();
  fs.writeFileSync(path.join(root, "package.json"), "{}");
  fs.mkdirSync(path.join(root, "src"));

  const resolved = resolveScanRoot(root);
  assert.equal(resolved, root);
});

test("does not unwrap a directory containing only a file (nothing to unwrap into)", () => {
  const root = mktemp();
  fs.writeFileSync(path.join(root, "package.json"), "{}");

  const resolved = resolveScanRoot(root);
  assert.equal(resolved, root);
});
