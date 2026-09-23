import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "fs";
import os from "os";
import path from "path";
import "../src/scanner/controls";
import { getControl } from "../src/scanner/controls/registry";
import { hydrateCheckResult } from "../src/scanner/controls/hydrate";
import { scanSupplyChainControl } from "../src/scanner/controls/checks/supplyChainControl";
import { compareScans, type ScanForComparison } from "../src/scanner/scanComparison";
import type { ScanReport, CheckResult } from "../src/scanner/types";

/**
 * SUPPLY-001/002: Supply Chain (master spec §16), beyond the
 * lockfile/known-vulnerability coverage DEPS-001/OSV-001 already provide.
 * "Supply Chain" has been a FindingCategory since before this Phase B
 * effort started but had no control using it, confirmed via grep.
 */

function tmpDir(prefix: string): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

function writePkgJson(dir: string, deps: Record<string, string>, devDeps: Record<string, string> = {}): void {
  fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ name: "app", dependencies: deps, devDependencies: devDeps }), "utf8");
}

test("SUPPLY-001/002 are registered", () => {
  assert.ok(getControl("SUPPLY-001"));
  assert.ok(getControl("SUPPLY-002"));
});

test("scanSupplyChainControl: NOT_VERIFIED for both controls when no package.json exists", () => {
  const dir = tmpDir("nettle-supply-nomanifest-");

  const results = scanSupplyChainControl(dir);
  assert.equal(results.length, 2);
  assert.ok(results.every((r) => r.status === "NOT_VERIFIED"));
  assert.ok(results.some((r) => r.controlKey === "SUPPLY-001"));
  assert.ok(results.some((r) => r.controlKey === "SUPPLY-002"));

  fs.rmSync(dir, { recursive: true, force: true });
});

// --- SUPPLY-001: typosquatting ---

test("scanSupplyChainControl: SUPPLY-001 FAILs for a single-edit-distance typo of a well-known package (transposition example)", () => {
  const dir = tmpDir("nettle-supply-typo-");
  writePkgJson(dir, { lodahs: "^4.17.21" });

  const results = scanSupplyChainControl(dir);
  const result = results.find((r) => r.controlKey === "SUPPLY-001");
  assert.ok(result);
  assert.equal(result!.status, "FAIL");
  assert.match(result!.title, /lodahs/);
  assert.match(result!.detail!, /lodash/);

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanSupplyChainControl: SUPPLY-001 FAILs for a single-character-insertion typo", () => {
  const dir = tmpDir("nettle-supply-typo2-");
  writePkgJson(dir, { expresss: "^4.18.0" });

  const results = scanSupplyChainControl(dir);
  assert.equal(results.find((r) => r.controlKey === "SUPPLY-001")?.status, "FAIL");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanSupplyChainControl: SUPPLY-001 does not FAIL for real, legitimate near-variant packages", () => {
  // globby (vs glob), bcryptjs (vs bcrypt), uuidv4 (vs uuid), express-session
  // (vs express), and vuex are all real, extremely popular packages that a
  // looser edit-distance threshold false-positived on during this control's
  // design — verified directly before finalizing the distance-1 threshold.
  const dir = tmpDir("nettle-supply-legit-");
  writePkgJson(dir, {
    globby: "^13.0.0",
    bcryptjs: "^2.4.3",
    uuidv4: "^6.2.13",
    "express-session": "^1.17.3",
    vuex: "^4.1.0",
  });

  const results = scanSupplyChainControl(dir);
  assert.equal(results.find((r) => r.controlKey === "SUPPLY-001")?.status, "PASS");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanSupplyChainControl: SUPPLY-001 PASSes for exact matches to well-known packages", () => {
  const dir = tmpDir("nettle-supply-exact-");
  writePkgJson(dir, { lodash: "^4.17.21", express: "^4.18.0" });

  const results = scanSupplyChainControl(dir);
  assert.equal(results.find((r) => r.controlKey === "SUPPLY-001")?.status, "PASS");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanSupplyChainControl: SUPPLY-001 also checks devDependencies", () => {
  const dir = tmpDir("nettle-supply-devdep-");
  writePkgJson(dir, {}, { chlak: "^5.0.0" });

  const results = scanSupplyChainControl(dir);
  assert.equal(results.find((r) => r.controlKey === "SUPPLY-001")?.status, "FAIL");

  fs.rmSync(dir, { recursive: true, force: true });
});

// --- SUPPLY-002: non-registry dependency reference ---

test("scanSupplyChainControl: SUPPLY-002 FAILs for a git URL dependency", () => {
  const dir = tmpDir("nettle-supply-giturl-");
  writePkgJson(dir, { "internal-pkg": "git+https://github.com/org/internal-pkg.git#main" });

  const results = scanSupplyChainControl(dir);
  const result = results.find((r) => r.controlKey === "SUPPLY-002");
  assert.ok(result);
  assert.equal(result!.status, "FAIL");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanSupplyChainControl: SUPPLY-002 FAILs for a GitHub shorthand dependency", () => {
  const dir = tmpDir("nettle-supply-shorthand-");
  writePkgJson(dir, { "internal-pkg": "myorg/internal-pkg" });

  const results = scanSupplyChainControl(dir);
  assert.equal(results.find((r) => r.controlKey === "SUPPLY-002")?.status, "FAIL");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanSupplyChainControl: SUPPLY-002 FAILs for a tarball URL dependency", () => {
  const dir = tmpDir("nettle-supply-tarball-");
  writePkgJson(dir, { "some-pkg": "https://example.com/some-pkg-1.0.0.tgz" });

  const results = scanSupplyChainControl(dir);
  assert.equal(results.find((r) => r.controlKey === "SUPPLY-002")?.status, "FAIL");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanSupplyChainControl: SUPPLY-002 PASSes for normal semver ranges", () => {
  const dir = tmpDir("nettle-supply-semver-");
  writePkgJson(dir, { lodash: "^4.17.21", express: "~4.18.0", axios: "4.0.0" });

  const results = scanSupplyChainControl(dir);
  assert.equal(results.find((r) => r.controlKey === "SUPPLY-002")?.status, "PASS");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanSupplyChainControl: NOT_VERIFIED when package.json is unparseable", () => {
  const dir = tmpDir("nettle-supply-badjson-");
  fs.writeFileSync(path.join(dir, "package.json"), "{ not valid json", "utf8");

  const results = scanSupplyChainControl(dir);
  assert.equal(results.length, 2);
  assert.ok(results.every((r) => r.status === "NOT_VERIFIED"));

  fs.rmSync(dir, { recursive: true, force: true });
});

// --- hydration ---

test("hydration gives SUPPLY-001 a real fix", () => {
  const hydrated = hydrateCheckResult(
    { checkId: "x", status: "FAIL", category: "Supply Chain", title: 'Dependency name "lodahs" resembles the well-known package "lodash"', severity: "high", confidence: 70, controlKey: "SUPPLY-001" },
    { detectedTechnology: "generic" }
  );
  assert.ok(hydrated.recommendation);
  assert.match(hydrated.recommendation!.quickFix, /double-check/i);
});

test("hydration gives SUPPLY-002 a real fix", () => {
  const hydrated = hydrateCheckResult(
    { checkId: "x", status: "FAIL", category: "Supply Chain", title: "Dependency installed from a git/URL reference", severity: "medium", confidence: 90, controlKey: "SUPPLY-002" },
    { detectedTechnology: "generic" }
  );
  assert.ok(hydrated.recommendation);
  assert.match(hydrated.recommendation!.quickFix, /registry|commit SHA/i);
});

// --- scan comparison: a newly-added Phase B control participates in the diff engine ---

function report(checkResults: CheckResult[]): ScanReport {
  return {
    scannedAt: "2026-01-01T00:00:00.000Z",
    target: "app",
    scannerVersion: "1.3.0",
    score: 80,
    findings: [],
    passed: [],
    checkResults,
    summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0, clear: 0 },
  };
}

function scanAt(id: string, scannedAt: string, checkResults: CheckResult[]): ScanForComparison {
  return { id, scannedAt, status: "COMPLETED", report: report(checkResults) };
}

test("SUPPLY-001 participates fully in scan comparison: open -> fixed -> regressed", () => {
  const dirTypo = tmpDir("nettle-supply-cmp-typo-");
  writePkgJson(dirTypo, { lodahs: "^4.17.21" });
  const dirFixed = tmpDir("nettle-supply-cmp-fixed-");
  writePkgJson(dirFixed, { lodash: "^4.17.21" });

  const typoResults = scanSupplyChainControl(dirTypo);
  const fixedResults = scanSupplyChainControl(dirFixed);

  const s1 = scanAt("s1", "2026-01-01T00:00:00Z", typoResults); // open
  const s2 = scanAt("s2", "2026-01-02T00:00:00Z", fixedResults); // fixed
  const s3 = scanAt("s3", "2026-01-03T00:00:00Z", typoResults); // regressed
  const history = [s1, s2, s3];

  const openToFixed = compareScans(history, "s1", "s2");
  assert.ok(openToFixed.fixed.some((f) => f.finding.controlKey === "SUPPLY-001"));

  const fixedToRegressed = compareScans(history, "s2", "s3");
  assert.ok(fixedToRegressed.regressed.some((f) => f.finding.controlKey === "SUPPLY-001"));
  assert.equal(fixedToRegressed.summary.new, 0, "a regression must not be miscounted as NEW");

  fs.rmSync(dirTypo, { recursive: true, force: true });
  fs.rmSync(dirFixed, { recursive: true, force: true });
});
