import { test } from "node:test";
import assert from "node:assert/strict";
import { calculateScore, calculateConfidence, SCORING_CONFIG } from "../src/scanner/scoringConfig";

test("H-4: Scoring config is versioned", () => {
  assert.ok(SCORING_CONFIG.version, "Should have version");
  assert.ok(SCORING_CONFIG.createdAt, "Should have createdAt timestamp");
  assert.ok(SCORING_CONFIG.penalties, "Should have penalties");
});

test("H-4: Score calculation uses versioned penalties", () => {
  const findings = [{ severity: "critical" }, { severity: "high" }, { severity: "medium" }];
  const score = calculateScore(findings, SCORING_CONFIG);

  // 100 - 20 - 10 - 5 = 65
  assert.equal(score, 65);
});

test("H-4: Score is clamped to 0-100", () => {
  const manyFindings = Array(20).fill({ severity: "critical" });
  const score = calculateScore(manyFindings, SCORING_CONFIG);
  assert.ok(score >= 0 && score <= 100);
  assert.equal(score, 0, "Many critical findings should result in 0 score");
});

test("H-4: NOT_VERIFIED findings do not reduce score", () => {
  // Without NOT_VERIFIED
  const verifiedOnly = [{ severity: "high", status: "FAIL" }];
  const scoreWithVerified = calculateScore(verifiedOnly);

  // With NOT_VERIFIED added
  const mixed = [
    { severity: "high", status: "FAIL" },
    { severity: "critical", status: "NOT_VERIFIED" },
  ];
  const scoreWithNotVerified = calculateScore(mixed);

  // Adding NOT_VERIFIED findings should not reduce the score
  assert.equal(
    scoreWithVerified,
    scoreWithNotVerified,
    "NOT_VERIFIED findings should not affect score"
  );
  assert.equal(scoreWithVerified, 90, "Score should be 100 - 10 = 90");
});

test("H-4: Unknown severity defaults to conservative penalty", () => {
  const findings = [{ severity: "unknown" }];
  const score = calculateScore(findings, SCORING_CONFIG);
  assert.equal(score, 93, "Unknown severity should use default penalty of 7");
});

test("H-4: Confidence reflects completion", () => {
  // All findings verified
  const complete = [
    { status: "FAIL" },
    { status: "PASS" },
    { status: "FAIL" },
  ];
  const completeConfidence = calculateConfidence(complete);
  assert.equal(completeConfidence, 100);

  // Some NOT_VERIFIED
  const partial = [
    { status: "FAIL" },
    { status: "PASS" },
    { status: "NOT_VERIFIED" },
  ];
  const partialConfidence = calculateConfidence(partial);
  assert.equal(partialConfidence, 67); // 2 verified, 1 not verified = 66.67% ≈ 67%

  // All NOT_VERIFIED
  const incomplete = [
    { status: "NOT_VERIFIED" },
    { status: "NOT_VERIFIED" },
  ];
  const incompleteConfidence = calculateConfidence(incomplete);
  assert.equal(incompleteConfidence, 0);
});

test("H-4: Confidence is 100% with no findings", () => {
  const empty: Array<{ status?: string }> = [];
  const confidence = calculateConfidence(empty);
  assert.equal(confidence, 100, "Empty scan should have 100% confidence");
});

test("H-4: Confidence range is 0-100", () => {
  // Create various scenarios and verify confidence is always in range
  const scenarios = [
    [],
    [{ status: "FAIL" }],
    [{ status: "NOT_VERIFIED" }],
    [{ status: "FAIL" }, { status: "FAIL" }, { status: "NOT_VERIFIED" }],
    Array(100).fill({ status: "FAIL" }),
  ];

  for (const scenario of scenarios) {
    const confidence = calculateConfidence(scenario);
    assert.ok(confidence >= 0 && confidence <= 100, `Confidence ${confidence} out of range`);
  }
});

test("H-4: Scoring config penalties sum to expected range", () => {
  // Verify that the penalties are reasonable
  const penalties = Object.values(SCORING_CONFIG.penalties);
  assert.ok(penalties[0] > penalties[1], "critical > high");
  assert.ok(penalties[1] > penalties[2], "high > medium");
  assert.ok(penalties[2] > penalties[3], "medium > low");
  assert.equal(penalties[4], 0, "info should have 0 penalty");
});
