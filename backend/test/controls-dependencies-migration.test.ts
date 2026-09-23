import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "fs";
import os from "os";
import path from "path";
import "../src/scanner/controls";
import { getControl } from "../src/scanner/controls/registry";
import { hydrateCheckResult } from "../src/scanner/controls/hydrate";
import { scanDependencyLockfileControl } from "../src/scanner/controls/checks/dependencyLockfileControl";
import { compareScans, type ScanForComparison } from "../src/scanner/scanComparison";
import type { ScanReport, CheckResult } from "../src/scanner/types";

/**
 * Completes the dependencies.ts migration onto the control library
 * (DEPS-001). dependencies.ts itself has been deleted; both checks it made
 * now live in scanDependencyLockfileControl.
 *
 * One check was redesigned, not just ported: the legacy module treated "no
 * package.json found" as its own medium-severity FAIL. A missing manifest
 * isn't evidence the app is insecure -- it means dependency management
 * couldn't be assessed at all, which is what NOT_VERIFIED exists for. Under
 * the old design, a non-Node project (or one whose manifest wasn't in the
 * scanned file set) would be flagged as if it had a real problem.
 */

function tmpDir(prefix: string): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

test("DEPS-001 is registered", () => {
  assert.ok(getControl("DEPS-001"));
});

test("scanDependencyLockfileControl: NOT_VERIFIED when no package.json exists (the legacy check FAILed this)", () => {
  const dir = tmpDir("nettle-deps-nomanifest-");

  const results = scanDependencyLockfileControl(dir);
  assert.equal(results.length, 1);
  assert.equal(results[0].status, "NOT_VERIFIED");
  assert.equal(results[0].controlKey, "DEPS-001");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanDependencyLockfileControl: FAIL when package.json exists with no lockfile", () => {
  const dir = tmpDir("nettle-deps-nolock-");
  fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ name: "app" }), "utf8");

  const results = scanDependencyLockfileControl(dir);
  assert.equal(results.length, 1);
  assert.equal(results[0].status, "FAIL");
  assert.equal(results[0].controlKey, "DEPS-001");
  assert.equal(results[0].severity, "medium");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanDependencyLockfileControl: PASS when package-lock.json is present", () => {
  const dir = tmpDir("nettle-deps-npm-");
  fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ name: "app" }), "utf8");
  fs.writeFileSync(path.join(dir, "package-lock.json"), "{}", "utf8");

  const results = scanDependencyLockfileControl(dir);
  assert.equal(results.length, 1);
  assert.equal(results[0].status, "PASS");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanDependencyLockfileControl: PASS when yarn.lock is present", () => {
  const dir = tmpDir("nettle-deps-yarn-");
  fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ name: "app" }), "utf8");
  fs.writeFileSync(path.join(dir, "yarn.lock"), "", "utf8");

  const results = scanDependencyLockfileControl(dir);
  assert.equal(results[0].status, "PASS");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanDependencyLockfileControl: PASS when pnpm-lock.yaml is present", () => {
  const dir = tmpDir("nettle-deps-pnpm-");
  fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ name: "app" }), "utf8");
  fs.writeFileSync(path.join(dir, "pnpm-lock.yaml"), "", "utf8");

  const results = scanDependencyLockfileControl(dir);
  assert.equal(results[0].status, "PASS");

  fs.rmSync(dir, { recursive: true, force: true });
});

// --- hydration ---

test("hydration gives DEPS-001 a real fix", () => {
  const hydrated = hydrateCheckResult(
    { checkId: "x", status: "FAIL", category: "Dependencies", title: "No dependency lockfile committed", severity: "medium", confidence: 95, controlKey: "DEPS-001" },
    { detectedTechnology: "generic" }
  );
  assert.ok(hydrated.recommendation);
  assert.match(hydrated.recommendation!.quickFix, /lockfile/i);
});

test("NOT_VERIFIED DEPS-001 result carries humanReviewRequired and no fabricated recommendation", () => {
  const hydrated = hydrateCheckResult({
    checkId: "x",
    status: "NOT_VERIFIED",
    category: "Dependencies",
    title: "No package.json found — dependency management could not be assessed",
    confidence: 0,
    controlKey: "DEPS-001",
  });
  assert.equal(hydrated.recommendation, null);
  assert.equal(hydrated.humanReviewRequired, true);
});

// --- scan comparison: a newly-migrated finding participates in the diff engine ---

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

test("DEPS-001 (a newly-migrated control) participates fully in scan comparison: open -> fixed -> regressed", () => {
  const dirNoLock = tmpDir("nettle-deps-cmp-none-");
  fs.writeFileSync(path.join(dirNoLock, "package.json"), JSON.stringify({ name: "app" }), "utf8");
  const dirWithLock = tmpDir("nettle-deps-cmp-lock-");
  fs.writeFileSync(path.join(dirWithLock, "package.json"), JSON.stringify({ name: "app" }), "utf8");
  fs.writeFileSync(path.join(dirWithLock, "package-lock.json"), "{}", "utf8");

  const noLockResults = scanDependencyLockfileControl(dirNoLock);
  const withLockResults = scanDependencyLockfileControl(dirWithLock);

  const s1 = scanAt("s1", "2026-01-01T00:00:00Z", noLockResults); // open
  const s2 = scanAt("s2", "2026-01-02T00:00:00Z", withLockResults); // fixed
  const s3 = scanAt("s3", "2026-01-03T00:00:00Z", noLockResults); // regressed
  const history = [s1, s2, s3];

  const openToFixed = compareScans(history, "s1", "s2");
  assert.equal(openToFixed.summary.fixed, 1);
  assert.ok(openToFixed.fixed.some((f) => f.finding.controlKey === "DEPS-001"));

  const fixedToRegressed = compareScans(history, "s2", "s3");
  assert.equal(fixedToRegressed.summary.regressed, 1);
  assert.ok(fixedToRegressed.regressed.some((f) => f.finding.controlKey === "DEPS-001"));
  assert.equal(fixedToRegressed.summary.new, 0, "a regression must not be miscounted as NEW");

  fs.rmSync(dirNoLock, { recursive: true, force: true });
  fs.rmSync(dirWithLock, { recursive: true, force: true });
});
