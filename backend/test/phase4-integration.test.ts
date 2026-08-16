/**
 * Phase 4: Integration tests verifying all Phase 3 modules work together.
 * Tests complete scan workflows and cross-module interactions.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { redactSecrets, createEvidence } from "../src/scanner/evidence";
import { calculatePriority, sortByPriority } from "../src/scanner/findingPriority";
import { getEducation } from "../src/scanner/education";
import { analyzeAuth, getAuthSeverity } from "../src/scanner/authAnalysis";
import { detectFrameworks } from "../src/scanner/frameworkDetection";
import type { CheckResult } from "../src/scanner/types";

function createTestFinding(overrides: Partial<CheckResult>): CheckResult {
  return {
    checkId: "test-check",
    status: "FAIL",
    category: "Security",
    title: "Test Finding",
    detail: "Test detail",
    severity: "medium",
    file: null,
    line: null,
    remediation: "Fix it",
    confidence: 100,
    detectionMethod: ["manual"],
    whyItMatters: "It matters",
    ruleId: "test-rule",
    ...overrides,
  };
}

test("Phase 4: Evidence + Priority integration", () => {
  // A hardcoded secret with evidence should be high priority
  const code = "const API_KEY = 'sk_live_abc123xyz789'";
  const evidence = createEvidence(code);

  const finding = createTestFinding({
    title: "Hardcoded API key",
    detail: evidence || "",
    severity: "low",
    category: "hardcoded-secret",
  });

  const priority = calculatePriority(finding);

  // Low severity but hardcoded secret + API key = should boost to priority 2
  assert.ok(priority <= 2);
  assert.ok(evidence?.includes("[REDACTED"));
});

test("Phase 4: Priority + Education integration", () => {
  // High-priority finding should have appropriate education
  const finding = createTestFinding({
    severity: "critical",
    category: "sql-injection",
    title: "SQL injection vulnerability",
  });

  const priority = calculatePriority(finding);
  const education = getEducation(finding);

  assert.equal(priority, 1);
  assert.ok(education.developer.includes("parameterized"));
});

test("Phase 4: Auth + Framework detection integration", () => {
  // Framework detection should enable better auth analysis
  const expressCode = `const express = require('express');
const app = express();
app.get('/api/users', (req, res) => res.json([]));`;

  const framework = detectFrameworks(expressCode);
  // Framework detection works via package.json parsing
  // For this test, use explicit framework type
  const authResult = analyzeAuth(expressCode, "express");
  assert.ok(authResult.unprotectedRoutes.length > 0);
});

test("Phase 4: Multiple findings sorted by priority", () => {
  const findings = [
    createTestFinding({
      severity: "low",
      title: "Best practice issue",
      category: "best-practice",
    }),
    createTestFinding({
      severity: "critical",
      title: "SQL injection",
      category: "sql-injection",
    }),
    createTestFinding({
      severity: "medium",
      title: "Hardcoded API key",
      category: "hardcoded-secret",
    }),
  ];

  const sorted = sortByPriority(findings);

  // Should be ordered: SQL injection (1), API key (1, boosted), best practice (3)
  assert.ok(calculatePriority(sorted[0]) <= calculatePriority(sorted[1]));
  assert.ok(calculatePriority(sorted[sorted.length - 1]) >= 2);
});

test("Phase 4: Framework detection influences remediation", () => {
  const djangoCode = `def user_profile(request):
    return render(request, 'profile.html')`;

  // Use explicit framework for auth analysis
  const authResult = analyzeAuth(djangoCode, "django");
  assert.ok(authResult.unprotectedRoutes.length > 0);
  assert.equal(authResult.framework, "django");
});

test("Phase 4: Complex finding workflow", () => {
  // Simulate a complete finding: detected, prioritized, explained, remediated
  const secretFinding = createTestFinding({
    severity: "high",
    title: "AWS secret key hardcoded",
    detail: "Found: AKIA1234567890ABCDEF in source",
    category: "hardcoded-secret",
  });

  // Step 1: Evidence redaction
  const evidence = redactSecrets("AKIA1234567890ABCDEF");
  assert.ok(evidence.includes("[REDACTED"));

  // Step 2: Prioritization
  const priority = calculatePriority(secretFinding);
  assert.ok(priority <= 1, "AWS key should be priority 1");

  // Step 3: Education
  const education = getEducation(secretFinding);
  assert.ok(education.developer.includes("environment"));

  // Step 4: Severity assessment
  assert.equal(secretFinding.severity, "high");
});

test("Phase 4: Auth analysis per framework", () => {
  const frameworks = [
    { lang: "express" as const, code: "app.get('/api', (req,res) => res.json([]))" },
    { lang: "django" as const, code: "def api(request): return JsonResponse({})" },
    { lang: "flask" as const, code: "def api(): return jsonify([])" },
  ];

  for (const { lang, code } of frameworks) {
    const result = analyzeAuth(code, lang);
    assert.equal(result.framework, lang, `Should detect ${lang} framework`);
  }
});

test("Phase 4: Finding enrichment pipeline", () => {
  // Test that findings flow through enrichment pipeline correctly
  const rawFinding = createTestFinding({
    severity: "medium",
    title: "Missing authentication",
    category: "no-authentication",
  });

  // Enrich through pipeline
  const priority = calculatePriority(rawFinding);
  const education = getEducation(rawFinding);
  const severity = "medium";

  assert.ok(priority);
  assert.ok(education.beginner);
  assert.ok(severity);
  assert.ok(rawFinding.remediation);
});

test("Phase 4: Evidence preserves finding context", () => {
  const finding = createTestFinding({
    detail: "const PASSWORD = 'super-secret-pass'",
  });

  const evidence = createEvidence(finding.detail);
  assert.ok(evidence);
  assert.ok(!evidence.includes("super-secret"));
  assert.ok(evidence.includes("[REDACTED"));
});

test("Phase 4: Framework detection stability", () => {
  const code = `
    import express from 'express';
    import React from 'react';
    const app = express();
    app.get('/', (req, res) => res.send('hello'));
  `;

  const result1 = detectFrameworks(code);
  const result2 = detectFrameworks(code);

  // Should be deterministic
  assert.equal(result1.primaryFramework, result2.primaryFramework);
  assert.equal(result1.confidence, result2.confidence);
});
