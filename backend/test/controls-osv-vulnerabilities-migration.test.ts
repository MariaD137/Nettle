import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "fs";
import os from "os";
import path from "path";
import "../src/scanner/controls";
import { getControl } from "../src/scanner/controls/registry";
import { hydrateCheckResult } from "../src/scanner/controls/hydrate";
import { scanOsvVulnerabilityControl } from "../src/scanner/controls/checks/osvVulnerabilityControl";
import { compareScans, type ScanForComparison } from "../src/scanner/scanComparison";
import type { ScanReport, CheckResult } from "../src/scanner/types";

/**
 * Completes the osvVulnerabilities.ts migration onto the control library
 * (OSV-001). osvVulnerabilities.ts itself has been deleted; its check now
 * lives in scanOsvVulnerabilityControl, with three fixes:
 *
 * 1. No package.json used to return {findings: [], passed: []} silently —
 *    completely invisible in the scan report. Now NOT_VERIFIED, matching
 *    DEPS-001's precedent for the same underlying condition.
 * 2. A missing OSV database used to produce a "low severity" Finding about
 *    the scanned application, when it's actually a fact about the scan
 *    environment. Now NOT_VERIFIED.
 * 3. Opening/querying the database had no try/catch, so a corrupted
 *    database would throw and abort the entire scan — the same defect
 *    class already fixed for SECRET-001 and aiDisclosure.ts.
 *
 * Uses the real bundled OSV database and the same sample-app/clean-app
 * fixtures scanner.test.ts already relies on (sample-app pins a
 * known-vulnerable lodash@4.17.4; clean-app doesn't), rather than
 * fabricating database rows.
 */

const SAMPLE_APP = path.join(__dirname, "fixtures", "sample-app");
const CLEAN_APP = path.join(__dirname, "fixtures", "clean-app");

function tmpDir(prefix: string): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

test("OSV-001 is registered", () => {
  assert.ok(getControl("OSV-001"));
});

test("scanOsvVulnerabilityControl: FAIL for a known-vulnerable dependency (real OSV data, sample-app fixture)", () => {
  const results = scanOsvVulnerabilityControl(SAMPLE_APP);
  const lodashResult = results.find((r) => r.title.includes("lodash@4.17.4"));
  assert.ok(lodashResult, JSON.stringify(results, null, 2));
  assert.equal(lodashResult!.status, "FAIL");
  assert.equal(lodashResult!.controlKey, "OSV-001");
  assert.equal(lodashResult!.file, "package.json");
  assert.ok(lodashResult!.remediation?.includes("npm install lodash@"));
});

test("scanOsvVulnerabilityControl: PASS for a clean dependency set (real OSV data, clean-app fixture)", () => {
  const results = scanOsvVulnerabilityControl(CLEAN_APP);
  assert.equal(results.length, 1);
  assert.equal(results[0].status, "PASS");
  assert.equal(results[0].controlKey, "OSV-001");
});

test("scanOsvVulnerabilityControl: NOT_VERIFIED when no package.json exists (the legacy check was silently invisible here)", () => {
  const dir = tmpDir("nettle-osv-nomanifest-");

  const results = scanOsvVulnerabilityControl(dir);
  assert.equal(results.length, 1);
  assert.equal(results[0].status, "NOT_VERIFIED");
  assert.equal(results[0].controlKey, "OSV-001");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanOsvVulnerabilityControl: NOT_VERIFIED when package.json is unparseable", () => {
  const dir = tmpDir("nettle-osv-badjson-");
  fs.writeFileSync(path.join(dir, "package.json"), "{ not valid json", "utf8");

  const results = scanOsvVulnerabilityControl(dir);
  assert.equal(results.length, 1);
  assert.equal(results[0].status, "NOT_VERIFIED");
  assert.equal(results[0].controlKey, "OSV-001");

  fs.rmSync(dir, { recursive: true, force: true });
});

// --- hydration ---

test("hydration gives OSV-001 a real fix", () => {
  const hydrated = hydrateCheckResult(
    { checkId: "x", status: "FAIL", category: "Dependencies", title: "Vulnerable dependency: lodash@4.17.4", severity: "high", confidence: 85, controlKey: "OSV-001" },
    { detectedTechnology: "generic" }
  );
  assert.ok(hydrated.recommendation);
  assert.match(hydrated.recommendation!.quickFix, /npm install/i);
});

test("NOT_VERIFIED OSV-001 result carries humanReviewRequired and no fabricated recommendation", () => {
  const hydrated = hydrateCheckResult({
    checkId: "x",
    status: "NOT_VERIFIED",
    category: "Dependencies",
    title: "No package.json found — dependency vulnerabilities could not be checked",
    confidence: 0,
    controlKey: "OSV-001",
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

test("OSV-001 (a newly-migrated control) participates fully in scan comparison: open -> fixed -> regressed", () => {
  const vulnerableResults = scanOsvVulnerabilityControl(SAMPLE_APP);
  const cleanResults = scanOsvVulnerabilityControl(CLEAN_APP);

  const s1 = scanAt("s1", "2026-01-01T00:00:00Z", vulnerableResults); // open
  const s2 = scanAt("s2", "2026-01-02T00:00:00Z", cleanResults); // fixed
  const s3 = scanAt("s3", "2026-01-03T00:00:00Z", vulnerableResults); // regressed
  const history = [s1, s2, s3];

  const openToFixed = compareScans(history, "s1", "s2");
  assert.ok(openToFixed.fixed.some((f) => f.finding.controlKey === "OSV-001"));

  const fixedToRegressed = compareScans(history, "s2", "s3");
  assert.ok(fixedToRegressed.regressed.some((f) => f.finding.controlKey === "OSV-001"));
  assert.equal(fixedToRegressed.summary.new, 0, "a regression must not be miscounted as NEW");
});
