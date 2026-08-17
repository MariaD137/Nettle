import { test } from "node:test";
import assert from "node:assert/strict";
import { computeChangeIntelligence } from "../src/scanner/changeIntelligence";
import type { Finding, ScanReport } from "../src/scanner/types";

function finding(overrides: Partial<Finding>): Finding {
  return {
    severity: "medium",
    category: "Security",
    title: "placeholder",
    detail: "placeholder",
    file: "src/example.ts",
    line: null,
    remediation: null,
    ...overrides,
  };
}

function report(findings: Finding[]): ScanReport {
  return {
    scannedAt: new Date().toISOString(),
    target: "example",
    scannerVersion: "test",
    score: 0,
    findings,
    passed: [],
    summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0, clear: 0 },
  };
}

test("reports no sensitive changes when nothing changed between scans", () => {
  const same = [finding({ category: "Code Quality", title: "Unused variable" })];
  const result = computeChangeIntelligence(report(same), report(same));

  assert.deepEqual(result.sensitiveCategoriesChanged, []);
  assert.equal(result.highRiskChange, false);
  assert.match(result.summary, /No new findings/);
});

test("flags a new finding in a sensitive category", () => {
  const older = report([]);
  const newer = report([finding({ category: "Authentication", severity: "high", title: "No detected authentication check" })]);

  const result = computeChangeIntelligence(older, newer);

  assert.deepEqual(result.sensitiveCategoriesChanged, ["Authentication"]);
  assert.equal(result.highRiskChange, true);
  assert.match(result.summary, /Authentication/);
});

test("does not flag a new finding in a non-sensitive category as high risk", () => {
  const older = report([]);
  const newer = report([finding({ category: "Code Quality", severity: "critical", title: "Console log left in" })]);

  const result = computeChangeIntelligence(older, newer);

  assert.deepEqual(result.sensitiveCategoriesChanged, []);
  assert.equal(result.highRiskChange, false);
});

test("does not flag a sensitive-category finding that only dropped in severity as high risk", () => {
  const older = report([]);
  const newer = report([finding({ category: "Database", severity: "low", title: "Missing index on frequently-queried column" })]);

  const result = computeChangeIntelligence(older, newer);

  assert.deepEqual(result.sensitiveCategoriesChanged, ["Database"]);
  assert.equal(result.highRiskChange, false);
});

test("counts fixed findings that disappeared between scans", () => {
  const shared = finding({ category: "Cryptography", title: "Weak hash algorithm (MD5) in use" });
  const older = report([shared]);
  const newer = report([]);

  const result = computeChangeIntelligence(older, newer);
  const cryptoChange = result.categoryChanges.find((c) => c.category === "Cryptography");

  assert.ok(cryptoChange);
  assert.equal(cryptoChange!.fixed, 1);
  assert.equal(cryptoChange!.new, 0);
});

test("counts unchanged findings present in both scans by identical category/title/file", () => {
  const shared = finding({ category: "API Security", title: "Missing rate limiting", file: "src/routes/api.ts" });
  const result = computeChangeIntelligence(report([shared]), report([shared]));
  const apiChange = result.categoryChanges.find((c) => c.category === "API Security");

  assert.ok(apiChange);
  assert.equal(apiChange!.unchanged, 1);
  assert.equal(apiChange!.new, 0);
  assert.equal(apiChange!.fixed, 0);
});

test("treats a finding as new (not unchanged) if the file differs even with the same title", () => {
  const older = report([finding({ category: "Database", title: "SQL query built with string concatenation or interpolation", file: "src/a.ts" })]);
  const newer = report([finding({ category: "Database", title: "SQL query built with string concatenation or interpolation", file: "src/b.ts" })]);

  const result = computeChangeIntelligence(older, newer);
  const dbChange = result.categoryChanges.find((c) => c.category === "Database");

  assert.ok(dbChange);
  assert.equal(dbChange!.new, 1);
  assert.equal(dbChange!.fixed, 1);
});

test("newHighestSeverity reflects the worst severity among new findings in a category, not existing ones", () => {
  const older = report([]);
  const newer = report([
    finding({ category: "Infrastructure", severity: "low", title: "Base image is not pinned to a specific version" }),
    finding({ category: "Infrastructure", severity: "critical", title: "S3 bucket may be publicly accessible", file: "infra/s3.tf" }),
  ]);

  const result = computeChangeIntelligence(older, newer);
  const infraChange = result.categoryChanges.find((c) => c.category === "Infrastructure");

  assert.ok(infraChange);
  assert.equal(infraChange!.newHighestSeverity, "critical");
});
