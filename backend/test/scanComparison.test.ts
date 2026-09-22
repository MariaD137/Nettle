import { test } from "node:test";
import assert from "node:assert/strict";
import { compareScans, computeFingerprint, ScanComparisonError, type ScanForComparison } from "../src/scanner/scanComparison";
import type { CheckResult, ScanReport } from "../src/scanner/types";

/**
 * Unit tests for the rescan-diff engine, covering every scenario Phase 6 §26
 * requires. These build ScanForComparison objects directly (no real scanner
 * run, no HTTP, no DB) so each scenario is exact and fast; scanComparison-api.test.ts
 * covers the same engine wired through the real API and a real scan.
 */

function cr(overrides: Partial<CheckResult> & Pick<CheckResult, "title" | "category">): CheckResult {
  return {
    checkId: "x",
    status: "FAIL",
    severity: "high",
    confidence: 80,
    detectionMethod: "heuristic",
    file: "src/app.ts",
    ...overrides,
  };
}

function report(overrides: Partial<ScanReport> & { checkResults: CheckResult[] }): ScanReport {
  return {
    scannedAt: "2026-01-01T00:00:00.000Z",
    target: "app",
    scannerVersion: "1.3.0",
    score: 80,
    findings: [],
    passed: [],
    summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0, clear: 0 },
    ...overrides,
  };
}

function scan(id: string, scannedAt: string, checkResults: CheckResult[], extra: Partial<ScanForComparison & { reportOverrides: Partial<ScanReport> }> = {}): ScanForComparison {
  return {
    id,
    scannedAt,
    status: "COMPLETED",
    ...extra,
    report: report({ checkResults, ...(extra.reportOverrides ?? {}) }),
  };
}

const HARDCODED_SECRET = cr({
  title: "Hardcoded credential detected",
  category: "Security",
  controlKey: "SECRET-001",
  file: "src/config.ts",
});

test("computeFingerprint is stable across identical findings and differs for different ones", () => {
  const a = computeFingerprint(HARDCODED_SECRET);
  const b = computeFingerprint({ ...HARDCODED_SECRET, checkId: "different-hash", confidence: 40, evidence: "abc" });
  assert.equal(a, b, "checkId/confidence/evidence must not affect identity");

  const differentFile = computeFingerprint({ ...HARDCODED_SECRET, file: "src/other.ts" });
  assert.notEqual(a, differentFile);
});

test("computeFingerprint normalizes numeric counts so a PASS summary's count doesn't create a new identity", () => {
  const three = cr({ title: "3 route(s) in this file have a recognized authentication check", category: "Authentication", status: "PASS", file: "src/routes.ts" });
  const five = cr({ title: "5 route(s) in this file have a recognized authentication check", category: "Authentication", status: "PASS", file: "src/routes.ts" });
  assert.equal(computeFingerprint(three), computeFingerprint(five));
});

test("basic comparison: baseline finding, absent from current -> FIXED", () => {
  const a = scan("a", "2026-01-01T00:00:00Z", [HARDCODED_SECRET]);
  const b = scan("b", "2026-01-02T00:00:00Z", []);
  const result = compareScans([a, b], "a", "b");
  assert.equal(result.summary.fixed, 1);
  assert.equal(result.fixed[0].status, "FIXED");
  assert.equal(result.fixed[0].fingerprint, computeFingerprint(HARDCODED_SECRET));
  assert.equal(result.summary.stillOpen, 0);
  assert.equal(result.summary.new, 0);
});

test("basic comparison: finding present in both -> STILL_OPEN", () => {
  const a = scan("a", "2026-01-01T00:00:00Z", [HARDCODED_SECRET]);
  const b = scan("b", "2026-01-02T00:00:00Z", [HARDCODED_SECRET]);
  const result = compareScans([a, b], "a", "b");
  assert.equal(result.summary.stillOpen, 1);
  assert.equal(result.stillOpen[0].status, "STILL_OPEN");
  assert.equal(result.summary.fixed, 0);
});

test("basic comparison: finding only in current -> NEW", () => {
  const a = scan("a", "2026-01-01T00:00:00Z", []);
  const b = scan("b", "2026-01-02T00:00:00Z", [HARDCODED_SECRET]);
  const result = compareScans([a, b], "a", "b");
  assert.equal(result.summary.new, 1);
  assert.equal(result.new[0].status, "NEW");
});

test("regression: open -> fixed -> regressed across three scans", () => {
  const s1 = scan("s1", "2026-01-01T00:00:00Z", [HARDCODED_SECRET]);
  const s2 = scan("s2", "2026-01-02T00:00:00Z", []); // fixed
  const s3 = scan("s3", "2026-01-03T00:00:00Z", [HARDCODED_SECRET]); // returned
  const history = [s1, s2, s3];

  const openToFixed = compareScans(history, "s1", "s2");
  assert.equal(openToFixed.summary.fixed, 1);
  assert.equal(openToFixed.fixed[0].status, "FIXED");

  const fixedToRegressed = compareScans(history, "s2", "s3");
  assert.equal(fixedToRegressed.summary.regressed, 1);
  assert.equal(fixedToRegressed.regressed[0].status, "REGRESSED");
  assert.equal(fixedToRegressed.summary.new, 0, "a regression must not also be counted as NEW");

  // A finding present at both ends of a wider comparison, regardless of a
  // dip in between, is still just STILL_OPEN for that specific comparison.
  const openToRegressed = compareScans(history, "s1", "s3");
  assert.equal(openToRegressed.summary.stillOpen, 1);
});

test("changed: same finding, meaningfully different severity -> CHANGED, identity preserved", () => {
  const low = cr({ ...HARDCODED_SECRET, severity: "low" });
  const critical = { ...HARDCODED_SECRET, severity: "critical" as const };
  const a = scan("a", "2026-01-01T00:00:00Z", [low]);
  const b = scan("b", "2026-01-02T00:00:00Z", [critical]);
  const result = compareScans([a, b], "a", "b");
  assert.equal(result.summary.changed, 1);
  assert.equal(result.changed[0].status, "CHANGED");
  assert.match(result.changed[0].reason ?? "", /[Ss]everity/);
  assert.equal(result.changed[0].fingerprint, computeFingerprint(HARDCODED_SECRET));
  assert.equal(result.summary.fixed, 0);
  assert.equal(result.summary.new, 0);
});

test("changed: a trivial confidence wobble is not treated as a meaningful change", () => {
  const a = scan("a", "2026-01-01T00:00:00Z", [{ ...HARDCODED_SECRET, confidence: 80 }]);
  const b = scan("b", "2026-01-02T00:00:00Z", [{ ...HARDCODED_SECRET, confidence: 85 }]);
  const result = compareScans([a, b], "a", "b");
  assert.equal(result.summary.changed, 0);
  assert.equal(result.summary.stillOpen, 1);
});

test("analyzer unavailable: current scan could not read the file -> NOT_VERIFIED, not FIXED", () => {
  const notVerifiedEntry = cr({
    title: "File could not be read for secret analysis",
    category: "Security",
    status: "NOT_VERIFIED",
    controlKey: "SECRET-001",
    file: "src/config.ts",
    confidence: 0,
  });
  const a = scan("a", "2026-01-01T00:00:00Z", [HARDCODED_SECRET]);
  const b = scan("b", "2026-01-02T00:00:00Z", [notVerifiedEntry]);
  const result = compareScans([a, b], "a", "b");
  assert.equal(result.summary.fixed, 0, "must never claim FIXED when the current scan couldn't verify the file");
  assert.equal(result.summary.notVerified, 1);
  assert.match(result.notVerified[0].reason ?? "", /could not reliably analyz/);
});

test("control version mismatch -> NOT_VERIFIED instead of FIXED or REGRESSED", () => {
  const a = scan("a", "2026-01-01T00:00:00Z", [HARDCODED_SECRET], { reportOverrides: { controlVersions: { "SECRET-001": "1.0.0" } } });
  const b = scan("b", "2026-01-02T00:00:00Z", [], { reportOverrides: { controlVersions: { "SECRET-001": "2.0.0" } } });
  const result = compareScans([a, b], "a", "b");
  assert.equal(result.summary.fixed, 0);
  assert.equal(result.summary.notVerified, 1);
  assert.match(result.notVerified[0].reason ?? "", /control's definition changed/);
});

test("control version mismatch also withholds a REGRESSED claim, not just FIXED", () => {
  const v1 = { controlVersions: { "SECRET-001": "1.0.0" } };
  const v2 = { controlVersions: { "SECRET-001": "2.0.0" } };
  const s1 = scan("s1", "2026-01-01T00:00:00Z", [HARDCODED_SECRET], { reportOverrides: v1 });
  const s2 = scan("s2", "2026-01-02T00:00:00Z", [], { reportOverrides: v1 }); // fixed, same control version
  const s3 = scan("s3", "2026-01-03T00:00:00Z", [HARDCODED_SECRET], { reportOverrides: v2 }); // control version changed before it came back
  const history = [s1, s2, s3];

  const result = compareScans(history, "s2", "s3");
  assert.equal(result.summary.regressed, 0, "must not claim a genuine regression across a control-version change");
  assert.equal(result.summary.notVerified, 1);
  assert.match(result.notVerified[0].reason ?? "", /control's definition changed/);
});

test("scans recorded before controlVersions existed (both undefined) compare normally", () => {
  const a = scan("a", "2026-01-01T00:00:00Z", [HARDCODED_SECRET]);
  const b = scan("b", "2026-01-02T00:00:00Z", []);
  const result = compareScans([a, b], "a", "b");
  assert.equal(result.summary.fixed, 1);
});

test("incomplete baseline scan: no false NEW/fixed claims", () => {
  const a = scan("a", "2026-01-01T00:00:00Z", [], { status: "PARTIALLY_COMPLETED" });
  const b = scan("b", "2026-01-02T00:00:00Z", [HARDCODED_SECRET]);
  const result = compareScans([a, b], "a", "b");
  assert.equal(result.summary.new, 0, "an incomplete baseline cannot vouch that this finding is actually new");
  assert.equal(result.summary.notVerified, 1);
});

test("incomplete current scan: no false FIXED claims", () => {
  const a = scan("a", "2026-01-01T00:00:00Z", [HARDCODED_SECRET]);
  const b = scan("b", "2026-01-02T00:00:00Z", [], { status: "FAILED" });
  const result = compareScans([a, b], "a", "b");
  assert.equal(result.summary.fixed, 0, "an incomplete current scan cannot prove the issue is actually gone");
  assert.equal(result.summary.notVerified, 1);
});

test("score delta and metadata are reported without implying the finding-level result", () => {
  const a = scan("a", "2026-01-01T00:00:00Z", [HARDCODED_SECRET], { reportOverrides: { score: 60 } });
  const b = scan("b", "2026-01-02T00:00:00Z", [], { reportOverrides: { score: 90 } });
  const result = compareScans([a, b], "a", "b");
  assert.equal(result.baselineScore, 60);
  assert.equal(result.currentScore, 90);
  assert.equal(result.scoreDelta, 30);
});

test("versionNote surfaces when scanner versions differ between the two scans", () => {
  const a = scan("a", "2026-01-01T00:00:00Z", [], { reportOverrides: { scannerVersion: "1.3.0" } });
  const b = scan("b", "2026-01-02T00:00:00Z", [], { reportOverrides: { scannerVersion: "1.4.0" } });
  const result = compareScans([a, b], "a", "b");
  assert.match(result.versionNote ?? "", /scanner version/);
});

test("versionNote is null when nothing about the scan conditions changed", () => {
  const a = scan("a", "2026-01-01T00:00:00Z", []);
  const b = scan("b", "2026-01-02T00:00:00Z", []);
  const result = compareScans([a, b], "a", "b");
  assert.equal(result.versionNote, null);
});

test("unknown scan id -> ScanComparisonError(SCAN_NOT_FOUND)", () => {
  const a = scan("a", "2026-01-01T00:00:00Z", []);
  const b = scan("b", "2026-01-02T00:00:00Z", []);
  assert.throws(() => compareScans([a, b], "a", "does-not-exist"), (err: unknown) => err instanceof ScanComparisonError && err.code === "SCAN_NOT_FOUND");
});

test("baseline newer than current -> ScanComparisonError(INVALID_ORDER)", () => {
  const a = scan("a", "2026-01-01T00:00:00Z", []);
  const b = scan("b", "2026-01-02T00:00:00Z", []);
  assert.throws(() => compareScans([a, b], "b", "a"), (err: unknown) => err instanceof ScanComparisonError && err.code === "INVALID_ORDER");
});

test("PASS and NOT_VERIFIED results never appear as fixed/new/still-open findings themselves", () => {
  const pass = cr({ title: "No hardcoded secrets found", category: "Security", status: "PASS" });
  const a = scan("a", "2026-01-01T00:00:00Z", [pass]);
  const b = scan("b", "2026-01-02T00:00:00Z", []);
  const result = compareScans([a, b], "a", "b");
  assert.equal(result.summary.fixed, 0);
  assert.equal(result.summary.stillOpen, 0);
  assert.equal(result.summary.notVerified, 0);
});
