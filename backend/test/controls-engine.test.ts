import { test } from "node:test";
import assert from "node:assert/strict";
import "../src/scanner/controls"; // registers AUTH-001, SECRET-001
import { getControl, listControls, registerControl, __resetRegistryForTests } from "../src/scanner/controls/registry";
import { AUTH_001 } from "../src/scanner/controls/library/auth";
import { SECRET_001 } from "../src/scanner/controls/library/secrets";
import { hydrateCheckResult } from "../src/scanner/controls/hydrate";
import { computeReleaseImpact } from "../src/scanner/controls/releaseGate";
import type { CheckResult } from "../src/scanner/types";

test("control library registers AUTH-001 and SECRET-001", () => {
  assert.ok(getControl("AUTH-001"));
  assert.ok(getControl("SECRET-001"));
  assert.ok(listControls().length >= 2);
});

test("a FAIL result with a controlKey gets hydrated with a full recommendation", () => {
  const result: CheckResult = {
    checkId: "x",
    status: "FAIL",
    category: "Authentication",
    title: "POST /api/pets/:userId has no recognized authentication check",
    severity: "critical",
    confidence: 90,
    controlKey: "AUTH-001",
  };

  const hydrated = hydrateCheckResult(result, { detectedTechnology: "express" });
  assert.ok(hydrated.recommendation);
  assert.equal(hydrated.recommendation!.technologyMatched, "express");
  assert.match(hydrated.recommendation!.quickFix, /verifyJWT/);
  assert.match(hydrated.recommendation!.developerFix, /middleware/i);
  assert.ok(hydrated.recommendation!.verificationMethod.length > 0);
  assert.ok(hydrated.recommendation!.references.length > 0);
  assert.equal(hydrated.humanReviewRequired, false);
  // recommendationConfidence: distinct from CheckResult.confidence (the
  // evidence for the finding) — this is about how well the fix itself was
  // matched to the detected stack. A real technology match is HIGH.
  assert.equal(hydrated.recommendation!.recommendationConfidence, "HIGH");
});

test("hydration falls back to the control's generic fix for an unmatched technology, and recommendationConfidence reflects that a more specific fix exists but wasn't matched", () => {
  const result: CheckResult = {
    checkId: "x",
    status: "FAIL",
    category: "Authentication",
    title: "unprotected route",
    severity: "high",
    confidence: 80,
    controlKey: "AUTH-001",
  };

  const hydrated = hydrateCheckResult(result, { detectedTechnology: "some-unknown-framework" });
  assert.equal(hydrated.recommendation!.technologyMatched, "generic");
  // AUTH-001 has express/django/flask/fastapi-specific fixes that exist but
  // weren't matched here — LOW, not MEDIUM, since a better answer is out
  // there, just not selected.
  assert.equal(hydrated.recommendation!.recommendationConfidence, "LOW");
});

test("recommendationConfidence is MEDIUM when the control only ever offers a generic fix — there's nothing more specific to miss", () => {
  const result: CheckResult = {
    checkId: "x",
    status: "FAIL",
    category: "AI Disclosure",
    title: "No token limits configured for AI API calls",
    severity: "medium",
    confidence: 70,
    controlKey: "AI-002", // aiCostLimits.ts: a single "generic" TechnologyFix, no others
  };

  const hydrated = hydrateCheckResult(result, { detectedTechnology: "express" });
  assert.equal(hydrated.recommendation!.technologyMatched, "generic");
  assert.equal(hydrated.recommendation!.recommendationConfidence, "MEDIUM");
});

test("recommendationConfidence with no detectedTechnology option at all behaves the same as an unmatched one", () => {
  const result: CheckResult = {
    checkId: "x",
    status: "FAIL",
    category: "Authentication",
    title: "unprotected route",
    severity: "high",
    confidence: 80,
    controlKey: "AUTH-001",
  };

  const hydrated = hydrateCheckResult(result); // no options at all
  assert.equal(hydrated.recommendation!.technologyMatched, "generic");
  assert.equal(hydrated.recommendation!.recommendationConfidence, "LOW");
});

test("hydration never fabricates a recommendation for a result with no controlKey", () => {
  const result: CheckResult = {
    checkId: "x",
    status: "FAIL",
    category: "Code Quality",
    title: "something not yet on the control library",
    severity: "low",
  };

  const hydrated = hydrateCheckResult(result);
  assert.equal(hydrated.recommendation, null);
  assert.equal(hydrated.releaseImpact, null);
});

test("NOT_VERIFIED never gets a release impact, and is marked for human review", () => {
  const result: CheckResult = {
    checkId: "x",
    status: "NOT_VERIFIED",
    category: "Authentication",
    title: "framework not recognized",
    controlKey: "AUTH-001",
  };

  const hydrated = hydrateCheckResult(result);
  assert.equal(hydrated.releaseImpact, null);
  assert.equal(hydrated.humanReviewRequired, true);
});

test("PASS never gets a release impact", () => {
  const result: CheckResult = {
    checkId: "x",
    status: "PASS",
    category: "Security",
    title: "no hardcoded secrets",
    controlKey: "SECRET-001",
  };

  const hydrated = hydrateCheckResult(result);
  assert.equal(hydrated.releaseImpact, null);
});

test("release gate: high confidence critical secret leak blocks release", () => {
  const control = getControl("SECRET-001")!;
  assert.equal(computeReleaseImpact(control, "critical", 95), "BLOCK_RELEASE");
});

test("release gate: low-confidence findings are downgraded, never used to block a release", () => {
  const control = getControl("AUTH-001")!;
  // AUTH-001's baseline for "high" is REVIEW_BEFORE_RELEASE; low confidence
  // should downgrade it twice, never invent certainty from a weak signal.
  const highConfidence = computeReleaseImpact(control, "high", 90);
  const lowConfidence = computeReleaseImpact(control, "high", 20);
  assert.equal(highConfidence, "REVIEW_BEFORE_RELEASE");
  assert.equal(lowConfidence, "IMPROVEMENT");
});

test("registering the same controlKey twice throws rather than silently overwriting", () => {
  __resetRegistryForTests();
  const dupe = {
    controlKey: "DUPE-001",
    category: "Security" as const,
    name: "x",
    description: "x",
    question: "x?",
    defaultSeverity: "low" as const,
    passCriteria: "x",
    failCriteria: "x",
    notVerifiedCriteria: "x",
    whyItMatters: "x",
    technologyFixes: [{ technology: "generic", quickFix: "x", developerFix: "x" }],
    verificationMethod: "x",
    releaseImpactBySeverity: {},
    enabled: true,
    version: "1.0.0",
  };
  registerControl(dupe);
  assert.throws(() => registerControl(dupe), /already registered/);

  // Restore the real library so later tests in this process still see it —
  // the module files already ran (registerControl side effect), so calling
  // it again directly on the exported objects is what re-populates the
  // registry the reset just cleared.
  registerControl(AUTH_001);
  registerControl(SECRET_001);
});
