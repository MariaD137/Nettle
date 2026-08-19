import { test, before } from "node:test";
import assert from "node:assert/strict";
import path from "path";
import { runScan } from "../src/scanner";
import { applyScanAccess, limitFindings, hasFullScanAccess, PREVIEW_FINDING_LIMIT } from "../src/billing/scanAccess";

const FLAWED_APP = path.join(__dirname, "fixtures", "sample-app");

const TIER1_ACTIVE = { plan: "tier1", subscriptionStatus: "active" };
const TIER2_ACTIVE = { plan: "tier2", subscriptionStatus: "active" };
const TIER1_TRIALING = { plan: "tier1", subscriptionStatus: "trialing" };
const FREE = { plan: "free", subscriptionStatus: "none" };
const TIER1_CANCELED = { plan: "tier1", subscriptionStatus: "canceled" };
const TIER2_PAST_DUE = { plan: "tier2", subscriptionStatus: "past_due" };

let report: ReturnType<typeof runScan>;
before(() => {
  report = runScan(FLAWED_APP);
  // The fixture must have more findings than a preview reveals, or the
  // gating assertions below would pass vacuously.
  assert.ok(report.findings.length > PREVIEW_FINDING_LIMIT);
});

test("hasFullScanAccess unlocks only an active/trialing paid plan", () => {
  assert.equal(hasFullScanAccess(TIER1_ACTIVE), true);
  assert.equal(hasFullScanAccess(TIER2_ACTIVE), true);
  assert.equal(hasFullScanAccess(TIER1_TRIALING), true);
  assert.equal(hasFullScanAccess(FREE), false);
  assert.equal(hasFullScanAccess(null), false);
  assert.equal(hasFullScanAccess(undefined), false);
  assert.equal(hasFullScanAccess({ plan: "enterprise", subscriptionStatus: "active" }), false);
});

// Regression coverage for the entitlement-drift bug: a paid plan string
// alone must never be sufficient once the subscription itself has lapsed —
// canceling or a failed payment must immediately drop full-report access,
// not just dashboard access.
test("a paid plan whose subscription has lapsed does not keep full scan access", () => {
  assert.equal(hasFullScanAccess(TIER1_CANCELED), false);
  assert.equal(hasFullScanAccess(TIER2_PAST_DUE), false);
});

test("a paid plan gets every finding, marked as a full report", () => {
  const result = applyScanAccess(report, TIER1_ACTIVE);
  assert.equal(result.findings.length, report.findings.length);
  assert.equal(result.access?.fullReport, true);
  assert.equal(result.access?.tier, "full");
  assert.equal(result.access?.lockedFindings, 0);
});

test("a canceled subscription gets the preview, not the full report, even though plan still says tier1/tier2", () => {
  const result = applyScanAccess(report, TIER1_CANCELED);
  assert.equal(result.access?.fullReport, false);
  assert.equal(result.access?.tier, "preview");
  assert.equal(result.findings.length, PREVIEW_FINDING_LIMIT);
});

test("the free plan gets a capped preview that reports the true total", () => {
  const result = applyScanAccess(report, FREE);

  assert.equal(result.findings.length, PREVIEW_FINDING_LIMIT);
  assert.equal(result.access?.fullReport, false);
  assert.equal(result.access?.tier, "preview");
  assert.equal(result.access?.totalFindings, report.findings.length);
  assert.equal(result.access?.lockedFindings, report.findings.length - PREVIEW_FINDING_LIMIT);
  assert.ok(result.access?.message);
});

test("a preview reveals the most severe findings first", () => {
  const result = applyScanAccess(report, FREE);
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
  const result = applyScanAccess(report, FREE);
  // Every finding that does come back is intact — no half-redacted rows.
  for (const f of result.findings) {
    assert.ok(f.title);
    assert.ok(f.detail);
  }
});

test("score, summary and passed checks survive redaction untouched", () => {
  const result = applyScanAccess(report, FREE);
  assert.equal(result.score, report.score);
  assert.deepEqual(result.summary, report.summary);
  assert.deepEqual(result.passed, report.passed);
});

test("redaction does not mutate the report it was given", () => {
  const before = report.findings.length;
  applyScanAccess(report, FREE);
  assert.equal(report.findings.length, before);
  assert.equal(report.access, undefined);
});

test("limitFindings caps free/lapsed plans and passes active paid plans through", () => {
  assert.equal(limitFindings(report.findings, TIER2_ACTIVE).length, report.findings.length);
  assert.equal(limitFindings(report.findings, FREE).length, PREVIEW_FINDING_LIMIT);
  assert.equal(limitFindings(report.findings, TIER2_PAST_DUE).length, PREVIEW_FINDING_LIMIT);
});
