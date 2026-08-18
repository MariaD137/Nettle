import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "fs";
import path from "path";
import os from "os";
import { scanOSVVulnerabilities } from "../src/scanner/osvVulnerabilities";

/**
 * Exercises the real scanner against the real bundled OSV database (no
 * mocking) — "hono" has a known MODERATE vulnerability fixed at 4.6.5 in
 * that database as of when this test was written. If the bundled database
 * is regenerated and no longer carries this specific advisory, this test
 * will need a different package/version pair; that's an accepted tradeoff
 * for testing against real data instead of a synthetic double.
 */
function makeProject(files: Record<string, string>): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "nettle-osv-paths-"));
  for (const [name, contents] of Object.entries(files)) {
    fs.writeFileSync(path.join(dir, name), contents);
  }
  return dir;
}

test("a vulnerable direct dependency gets no dependencyPaths when there's no lockfile", () => {
  const dir = makeProject({
    "package.json": JSON.stringify({ name: "app", dependencies: { hono: "^4.0.0" } }),
  });
  try {
    const { findings } = scanOSVVulnerabilities(dir);
    const finding = findings.find((f) => f.title.startsWith("Vulnerable dependency: hono"));
    assert.ok(finding, "expected a finding for the vulnerable hono range");
    assert.equal(finding!.dependencyPaths, undefined);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("a vulnerable transitive dependency gets its real resolved path from the lockfile", () => {
  const dir = makeProject({
    "package.json": JSON.stringify({ name: "app", dependencies: { hono: "^4.0.0" } }),
    "package-lock.json": JSON.stringify({
      name: "app",
      lockfileVersion: 3,
      packages: {
        "": { name: "app", dependencies: { "some-framework-wrapper": "^1.0.0" } },
        "node_modules/some-framework-wrapper": { version: "1.0.0", dependencies: { hono: "^4.0.0" } },
        "node_modules/hono": { version: "4.0.0" },
      },
    }),
  });
  try {
    const { findings } = scanOSVVulnerabilities(dir);
    const finding = findings.find((f) => f.title.startsWith("Vulnerable dependency: hono"));
    assert.ok(finding, "expected a finding for the vulnerable hono range");
    assert.deepEqual(finding!.dependencyPaths, [
      ["your project", "some-framework-wrapper@1.0.0", "hono@4.0.0"],
    ]);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("an unparsable lockfile degrades to no dependencyPaths rather than failing the scan", () => {
  const dir = makeProject({
    "package.json": JSON.stringify({ name: "app", dependencies: { hono: "^4.0.0" } }),
    "package-lock.json": "{ not valid json",
  });
  try {
    const { findings } = scanOSVVulnerabilities(dir);
    const finding = findings.find((f) => f.title.startsWith("Vulnerable dependency: hono"));
    assert.ok(finding);
    assert.equal(finding!.dependencyPaths, undefined);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
