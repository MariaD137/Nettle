import { test } from "node:test";
import assert from "node:assert/strict";
import {
  getEducation,
  enrichWithEducation,
  getExplanation,
  formatFindingWithEducation,
} from "../src/scanner/education";
import type { CheckResult } from "../src/scanner/types";

function createFinding(overrides: Partial<CheckResult>): CheckResult {
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

test("M-3: education content exists for hardcoded secrets", () => {
  const finding = createFinding({
    category: "hardcoded-secret",
    title: "Hardcoded API key",
  });
  const education = getEducation(finding);

  assert.ok(education.beginner);
  assert.ok(education.developer);
  assert.ok(education.expert);
  assert.ok(education.beginner.includes("password"));
});

test("M-3: education content exists for SQL injection", () => {
  const finding = createFinding({
    category: "sql-injection",
    title: "SQL injection vulnerability",
  });
  const education = getEducation(finding);

  assert.ok(education.beginner.includes("database"));
  assert.ok(education.developer.includes("parameterized"));
  assert.ok(education.expert.includes("ORM"));
});

test("M-3: education content exists for XSS", () => {
  const finding = createFinding({
    category: "xss",
    title: "Cross-site scripting",
  });
  const education = getEducation(finding);

  assert.ok(education.beginner.includes("escape") || education.beginner.includes("display"));
  assert.ok(education.developer.includes("React") || education.developer.includes("Escape"));
  assert.ok(education.expert.includes("context") || education.expert.includes("matters"));
});

test("M-3: education content exists for CORS misconfiguration", () => {
  const finding = createFinding({
    category: "cors-misconfiguration",
    title: "Wildcard CORS",
  });
  const education = getEducation(finding);

  assert.ok(education.beginner.includes("website") || education.beginner.includes("API"));
  assert.ok(education.developer.includes("Access-Control"));
  assert.ok(education.expert.includes("preflight") || education.expert.includes("origin"));
});

test("M-3: education content exists for vulnerable dependencies", () => {
  const finding = createFinding({
    category: "vulnerable-dependency",
    title: "Vulnerable lodash version",
  });
  const education = getEducation(finding);

  assert.ok(education.beginner.includes("hole") || education.beginner.includes("library"));
  assert.ok(education.developer.includes("npm audit") || education.developer.includes("Update"));
  assert.ok(education.expert.includes("transitive") || education.expert.includes("dependency"));
});

test("M-3: education content exists for missing auth", () => {
  const finding = createFinding({
    category: "no-authentication",
    title: "No authentication check",
  });
  const education = getEducation(finding);

  assert.ok(education.beginner.includes("logged in"));
  assert.ok(education.developer.includes("middleware"));
  assert.ok(education.expert.includes("semantic"));
});

test("M-3: education content exists for missing HTTPS", () => {
  const finding = createFinding({
    category: "missing-https",
    title: "HTTP endpoint detected",
  });
  const education = getEducation(finding);

  assert.ok(education.beginner.includes("encrypted"));
  assert.ok(education.developer.includes("HSTS"));
  assert.ok(education.expert.includes("TLS"));
});

test("M-3: education content exists for privacy policy", () => {
  const finding = createFinding({
    category: "missing-privacy-policy",
    title: "No privacy policy found",
  });
  const education = getEducation(finding);

  assert.ok(education.beginner.includes("data"));
  assert.ok(education.developer.includes("PRIVACY_POLICY"));
  assert.ok(education.expert.includes("GDPR"));
});

test("M-3: beginner explanation is simpler", () => {
  const finding = createFinding({ category: "hardcoded-secret" });
  const education = getEducation(finding);

  // Beginner should be shorter and use simpler language
  assert.ok(education.beginner.length < education.expert.length);
  assert.ok(!education.beginner.includes("exploit"));
});

test("M-3: expert explanation is more technical", () => {
  const finding = createFinding({ category: "hardcoded-secret" });
  const education = getEducation(finding);

  // Expert should include technical terms
  assert.ok(
    education.expert.includes("git") ||
      education.expert.includes("hash") ||
      education.expert.includes("rotate")
  );
});

test("M-3: developer explanation is practical", () => {
  const finding = createFinding({ category: "sql-injection" });
  const education = getEducation(finding);

  // Developer should include code examples or tool names
  assert.ok(
    education.developer.includes("?") || education.developer.includes("parameterized")
  );
});

test("M-3: enrich finding with education", () => {
  const finding = createFinding({ category: "hardcoded-secret" });
  const enriched = enrichWithEducation(finding, "beginner");

  assert.ok(enriched.education);
  assert.ok(enriched.educationLevel === "beginner");
  assert.equal(enriched.checkId, finding.checkId);
});

test("M-3: get explanation at specific level", () => {
  const finding = createFinding({ category: "sql-injection" });

  const beginner = getExplanation(finding, "beginner");
  const developer = getExplanation(finding, "developer");
  const expert = getExplanation(finding, "expert");

  assert.ok(beginner.includes("database"));
  assert.ok(developer.includes("parameterized"));
  assert.ok(expert.includes("ORM"));
});

test("M-3: format finding as markdown", () => {
  const finding = createFinding({
    category: "hardcoded-secret",
    title: "API Key Hardcoded",
    severity: "critical",
    detail: "An API key was found in source code",
    remediation: "Use environment variables",
  });

  const markdown = formatFindingWithEducation(finding, "developer");

  assert.ok(markdown.includes("# API Key Hardcoded"));
  assert.ok(markdown.includes("critical"));
  assert.ok(markdown.includes("developer level"));
  assert.ok(markdown.includes("environment variables"));
});

test("M-3: fallback for unknown category", () => {
  const finding = createFinding({ category: "unknown-category" });
  const education = getEducation(finding);

  // Should still have content
  assert.ok(education.beginner);
  assert.ok(education.developer);
  assert.ok(education.expert);
});

test("M-3: title-based keyword matching", () => {
  const finding = createFinding({
    category: "custom-category",
    title: "SQL injection in user input",
  });
  const education = getEducation(finding);

  // Should match "sql-injection" from title
  assert.ok(education.beginner.includes("database"));
});

test("M-3: command injection education", () => {
  const finding = createFinding({
    category: "command-injection",
    title: "Command injection vulnerability",
  });
  const education = getEducation(finding);

  assert.ok(education.beginner.includes("shell"));
  assert.ok(education.developer.includes("spawn"));
  assert.ok(education.expert.includes("execFile"));
});

test("M-3: CSRF education", () => {
  const finding = createFinding({
    category: "csrf",
    title: "CSRF token missing",
  });
  const education = getEducation(finding);

  assert.ok(education.beginner.includes("unwanted"));
  assert.ok(education.developer.includes("CSRF token"));
  assert.ok(education.expert.includes("SameSite"));
});
