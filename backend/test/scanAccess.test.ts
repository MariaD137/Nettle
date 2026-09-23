import { test, before } from "node:test";
import assert from "node:assert/strict";
import path from "path";
import { runScan } from "../src/scanner";
import { applyScanAccess, limitFindings, hasFullScanAccess, PREVIEW_FINDING_LIMIT } from "../src/billing/scanAccess";

const FLAWED_APP = path.join(__dirname, "fixtures", "sample-app");

let report: ReturnType<typeof runScan>;
before(() => {
  report = runScan(FLAWED_APP);
  // The fixture must have more findings than a preview reveals, or the
  // gating assertions below would pass vacuously.
  assert.ok(report.findings.length > PREVIEW_FINDING_LIMIT);
});

test("hasFullScanAccess unlocks only the paid tiers", () => {
  assert.equal(hasFullScanAccess("build"), true);
  assert.equal(hasFullScanAccess("protect"), true);
  assert.equal(hasFullScanAccess("free"), false);
  assert.equal(hasFullScanAccess(null), false);
  assert.equal(hasFullScanAccess(undefined), false);
  assert.equal(hasFullScanAccess("enterprise"), false);
});

test("a paid plan gets every finding, marked as a full report", () => {
  const result = applyScanAccess(report, "build");
  assert.equal(result.findings.length, report.findings.length);
  assert.equal(result.access?.fullReport, true);
  assert.equal(result.access?.tier, "full");
  assert.equal(result.access?.lockedFindings, 0);
});

test("the free plan gets a capped preview that reports the true total", () => {
  const result = applyScanAccess(report, "free");

  assert.equal(result.findings.length, PREVIEW_FINDING_LIMIT);
  assert.equal(result.access?.fullReport, false);
  assert.equal(result.access?.tier, "preview");
  assert.equal(result.access?.totalFindings, report.findings.length);
  assert.equal(result.access?.lockedFindings, report.findings.length - PREVIEW_FINDING_LIMIT);
  assert.ok(result.access?.message);
});

test("a preview reveals the most severe findings first", () => {
  const result = applyScanAccess(report, "free");
  const rank = { critical: 0, high: 1, medium: 2, low: 3, info: 4 } as const;
  const worstWithheld = Math.min(
    ...report.findings
      .filter((f) => !result.findings.includes(f))
      .map((f) => rank[f.severity])
  );
  for (const shown of result.findings) {
    assert.ok(rank[shown.severity] <= worstWithheld);
  }
});

test("a preview withholds detail rather than blanking it", () => {
  const result = applyScanAccess(report, "free");
  // Every finding that does come back is intact — no half-redacted rows.
  for (const f of result.findings) {
    assert.ok(f.title);
    assert.ok(f.detail);
  }
});

test("score, summary and passed checks survive redaction untouched", () => {
  const result = applyScanAccess(report, "free");
  assert.equal(result.score, report.score);
  assert.deepEqual(result.summary, report.summary);
  assert.deepEqual(result.passed, report.passed);
});

test("redaction does not mutate the report it was given", () => {
  const before = report.findings.length;
  applyScanAccess(report, "free");
  assert.equal(report.findings.length, before);
  assert.equal(report.access, undefined);
});

test("limitFindings caps free plans and passes paid plans through", () => {
  assert.equal(limitFindings(report.findings, "protect").length, report.findings.length);
  assert.equal(limitFindings(report.findings, "free").length, PREVIEW_FINDING_LIMIT);
});

test("a free-plan preview does not leak full checkResults detail — the paywall covers both representations", () => {
  assert.ok(report.checkResults && report.checkResults.length > 0, "fixture must produce checkResults to make this assertion meaningful");
  const totalFails = report.checkResults!.filter((r) => r.status === "FAIL").length;
  assert.ok(totalFails > PREVIEW_FINDING_LIMIT, "fixture must have more FAIL checkResults than the preview limit");

  const result = applyScanAccess(report, "free");
  const visibleFails = result.checkResults!.filter((r) => r.status === "FAIL");
  assert.equal(visibleFails.length, PREVIEW_FINDING_LIMIT);

  // PASS/NOT_VERIFIED entries carry no remediation detail, so they aren't
  // paid content — they survive in full, describing the report's shape.
  const nonFailCount = report.checkResults!.filter((r) => r.status !== "FAIL").length;
  const visibleNonFailCount = result.checkResults!.filter((r) => r.status !== "FAIL").length;
  assert.equal(visibleNonFailCount, nonFailCount);
});

test("a paid plan's checkResults are not trimmed", () => {
  const result = applyScanAccess(report, "build");
  assert.equal(result.checkResults!.length, report.checkResults!.length);
});
