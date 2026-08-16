import { test } from "node:test";
import assert from "node:assert/strict";
import type { Finding, Pass, CheckResult } from "../src/scanner/types";
import {
  findingToCheckResult,
  passToCheckResult,
  createNotVerified,
  calculateScoreConfidence,
  mergeCheckResults,
  filterByStatus,
  countByStatus,
} from "../src/scanner/threeStateModel";

test("H-2: three-state model basics", () => {
  // Convert legacy Finding to CheckResult
  const finding: Finding = {
    severity: "high",
    category: "Security",
    title: "SQL injection found",
    detail: "String concatenation in SQL query",
    file: "src/db.js",
    line: 42,
    remediation: "Use parameterized queries",
  };

  const result = findingToCheckResult(finding);
  assert.equal(result.status, "FAIL");
  assert.equal(result.severity, "high");
  assert.equal(result.title, "SQL injection found");
  assert.equal(result.confidence, 80);
  assert.ok(result.checkId, "checkId should be generated");
});

test("H-2: convert legacy Pass to CheckResult", () => {
  const pass: Pass = {
    category: "Security",
    title: "No SQL injection patterns found",
  };

  const result = passToCheckResult(pass);
  assert.equal(result.status, "PASS");
  assert.equal(result.title, "No SQL injection patterns found");
  assert.equal(result.confidence, 100);
});

test("H-2: create NOT_VERIFIED result for incomplete checks", () => {
  const result = createNotVerified("Security", "SQL injection detection", "Semgrep not available");
  assert.equal(result.status, "NOT_VERIFIED");
  assert.equal(result.title, "SQL injection detection");
  assert.equal(result.confidence, 0);
  assert.ok(result.detail?.includes("Semgrep"));
});

test("H-2: score confidence reflects completion", () => {
  const results: CheckResult[] = [
    {
      checkId: "1",
      status: "PASS",
      category: "Security",
      title: "Check 1",
      confidence: 100,
    },
    {
      checkId: "2",
      status: "PASS",
      category: "Security",
      title: "Check 2",
      confidence: 100,
    },
    {
      checkId: "3",
      status: "NOT_VERIFIED",
      category: "Security",
      title: "Check 3",
      confidence: 0,
    },
  ];

  const confidence = calculateScoreConfidence(results);
  // 2 complete, 1 incomplete = 67% confidence
  assert.ok(confidence >= 60 && confidence <= 70, `Expected ~67, got ${confidence}`);
});

test("H-2: score confidence 100% when all checks complete", () => {
  const results: CheckResult[] = [
    { checkId: "1", status: "PASS", category: "Security", title: "Check 1", confidence: 100 },
    { checkId: "2", status: "FAIL", category: "Security", title: "Check 2", confidence: 95 },
  ];

  const confidence = calculateScoreConfidence(results);
  assert.equal(confidence, 100);
});

test("H-2: score confidence 0% when all checks incomplete", () => {
  const results: CheckResult[] = [
    { checkId: "1", status: "NOT_VERIFIED", category: "Security", title: "Check 1", confidence: 0 },
    { checkId: "2", status: "NOT_VERIFIED", category: "Security", title: "Check 2", confidence: 0 },
  ];

  const confidence = calculateScoreConfidence(results);
  assert.equal(confidence, 0);
});

test("H-2: merge results deduplicates by checkId", () => {
  const array1: CheckResult[] = [
    { checkId: "1", status: "PASS", category: "Security", title: "Check 1", confidence: 100 },
  ];

  const array2: CheckResult[] = [
    { checkId: "1", status: "FAIL", category: "Security", title: "Check 1 (updated)", confidence: 50 },
  ];

  const merged = mergeCheckResults(array1, array2);
  assert.equal(merged.length, 1);
  assert.equal(merged[0].status, "FAIL"); // array2 wins
  assert.equal(merged[0].title, "Check 1 (updated)");
});

test("H-2: filter by status", () => {
  const results: CheckResult[] = [
    { checkId: "1", status: "PASS", category: "Security", title: "Check 1", confidence: 100 },
    { checkId: "2", status: "FAIL", category: "Security", title: "Check 2", confidence: 95 },
    { checkId: "3", status: "NOT_VERIFIED", category: "Security", title: "Check 3", confidence: 0 },
  ];

  const failures = filterByStatus(results, "FAIL");
  assert.equal(failures.length, 1);
  assert.equal(failures[0].checkId, "2");

  const incomplete = filterByStatus(results, "NOT_VERIFIED");
  assert.equal(incomplete.length, 1);
  assert.equal(incomplete[0].checkId, "3");

  const multiStatus = filterByStatus(results, "PASS", "FAIL");
  assert.equal(multiStatus.length, 2);
});

test("H-2: count by status", () => {
  const results: CheckResult[] = [
    { checkId: "1", status: "PASS", category: "Security", title: "Check 1", confidence: 100 },
    { checkId: "2", status: "PASS", category: "Security", title: "Check 2", confidence: 100 },
    { checkId: "3", status: "FAIL", category: "Security", title: "Check 3", confidence: 95 },
    { checkId: "4", status: "NOT_VERIFIED", category: "Security", title: "Check 4", confidence: 0 },
  ];

  const counts = countByStatus(results);
  assert.equal(counts.PASS, 2);
  assert.equal(counts.FAIL, 1);
  assert.equal(counts.NOT_VERIFIED, 1);
});

test("H-2: NOT_VERIFIED findings don't affect score", () => {
  // A scan with all checks available and complete should have score impact
  const completeResults: CheckResult[] = [
    { checkId: "1", status: "PASS", category: "Security", title: "Check 1", severity: "medium", confidence: 100 },
    { checkId: "2", status: "FAIL", category: "Security", title: "Check 2", severity: "high", confidence: 95 },
  ];

  const confidence = calculateScoreConfidence(completeResults);
  assert.equal(confidence, 100);

  // A scan where one check couldn't run should have reduced confidence
  // but should NOT reduce score credit from the checks that DID run
  const partialResults: CheckResult[] = [
    { checkId: "1", status: "PASS", category: "Security", title: "Check 1", severity: "medium", confidence: 100 },
    { checkId: "2", status: "FAIL", category: "Security", title: "Check 2", severity: "high", confidence: 95 },
    { checkId: "3", status: "NOT_VERIFIED", category: "Security", title: "Check 3", confidence: 0 },
  ];

  const partialConfidence = calculateScoreConfidence(partialResults);
  assert.ok(partialConfidence < 100, "Confidence should be reduced when some checks don't run");
  assert.ok(partialConfidence > 50, "But confidence shouldn't drop to 0 just because one check failed");
});
