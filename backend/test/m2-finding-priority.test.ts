import { test } from "node:test";
import assert from "node:assert/strict";
import {
  calculatePriority,
  sortByPriority,
  groupByPriority,
  getPriorityLabel,
  enrichWithPriority,
} from "../src/scanner/findingPriority";
import type { CheckResult } from "../src/scanner/types";

function createFinding(overrides: Partial<CheckResult>): CheckResult {
  return {
    checkId: "test-check",
    status: "FAIL",
    category: "Security",
    title: overrides.title || "Test Finding",
    detail: overrides.detail || "Test detail",
    severity: "medium",
    file: null,
    line: null,
    remediation: "Fix it",
    confidence: 100,
    detectionMethod: "manual",
    whyItMatters: "It matters",
    ruleId: "test-rule",
    ...overrides,
  };
}

test("M-2: critical severity gets priority 1", () => {
  const finding = createFinding({ severity: "critical" });
  assert.equal(calculatePriority(finding), 1);
});

test("M-2: high severity gets priority 1", () => {
  const finding = createFinding({ severity: "high" });
  assert.equal(calculatePriority(finding), 1);
});

test("M-2: medium severity gets priority 2", () => {
  const finding = createFinding({ severity: "medium" });
  assert.equal(calculatePriority(finding), 2);
});

test("M-2: low severity gets priority 3", () => {
  const finding = createFinding({ severity: "low" });
  assert.equal(calculatePriority(finding), 3);
});

test("M-2: info severity gets priority 3", () => {
  const finding = createFinding({ severity: "info" });
  assert.equal(calculatePriority(finding), 3);
});

test("M-2: exploitable medium finding gets boosted to priority 1", () => {
  const finding = createFinding({
    severity: "medium",
    title: "Hardcoded API key detected",
    detail: "An API key is hardcoded in the source",
  });
  assert.equal(calculatePriority(finding), 1);
});

test("M-2: exploitable low finding gets boosted to priority 2", () => {
  const finding = createFinding({
    severity: "low",
    title: "Missing authentication check",
    detail: "Route shows no authorization pattern",
  });
  assert.equal(calculatePriority(finding), 2);
});

test("M-2: exploitable critical stays priority 1", () => {
  const finding = createFinding({
    severity: "critical",
    title: "SQL injection vulnerability",
  });
  assert.equal(calculatePriority(finding), 1);
});

test("M-2: sql injection detection triggers exploitability", () => {
  const finding = createFinding({
    severity: "low",
    detail: "User input concatenated into SQL query",
  });
  // Exploitable + low should be priority 2
  assert.equal(calculatePriority(finding), 2);
});

test("M-2: vulnerable dependency is considered exploitable", () => {
  const finding = createFinding({
    severity: "medium",
    title: "Vulnerable dependency: lodash@4.17.4",
    detail: "10 known vulnerabilities in this version",
  });
  assert.equal(calculatePriority(finding), 1);
});

test("M-2: xss is considered exploitable", () => {
  const finding = createFinding({
    severity: "low",
    title: "Cross-site scripting (XSS) vulnerability",
  });
  assert.equal(calculatePriority(finding), 2);
});

test("M-2: best practice finding stays low priority", () => {
  const finding = createFinding({
    severity: "low",
    title: "No cookie policy found",
    detail: "Consider adding a cookie policy if app uses cookies",
  });
  assert.equal(calculatePriority(finding), 3);
});

test("M-2: sort by priority (1 before 2 before 3)", () => {
  const findings = [
    createFinding({ severity: "low", title: "Best practice" }),
    createFinding({ severity: "critical", title: "Critical issue" }),
    createFinding({ severity: "medium", title: "Medium issue" }),
  ];

  const sorted = sortByPriority(findings);
  assert.equal(calculatePriority(sorted[0]), 1);
  assert.equal(calculatePriority(sorted[1]), 2);
  assert.equal(calculatePriority(sorted[2]), 3);
});

test("M-2: sort within same priority by severity (critical before high)", () => {
  const findings = [
    createFinding({ severity: "high", title: "High issue" }),
    createFinding({ severity: "critical", title: "Critical issue" }),
  ];

  const sorted = sortByPriority(findings);
  assert.equal(sorted[0].severity, "critical");
  assert.equal(sorted[1].severity, "high");
});

test("M-2: group findings by priority", () => {
  const findings = [
    createFinding({ severity: "critical" }),
    createFinding({ severity: "high" }),
    createFinding({ severity: "medium" }),
    createFinding({ severity: "low" }),
    createFinding({ severity: "low" }),
  ];

  const groups = groupByPriority(findings);
  assert.equal(groups.get(1)!.length, 2);
  assert.equal(groups.get(2)!.length, 1);
  assert.equal(groups.get(3)!.length, 2);
});

test("M-2: priority labels are human-readable", () => {
  assert.ok(getPriorityLabel(1).includes("Immediately"));
  assert.ok(getPriorityLabel(2).includes("Soon"));
  assert.ok(getPriorityLabel(3).includes("Practices"));
});

test("M-2: enrich findings with priority", () => {
  const findings = [
    createFinding({ severity: "critical" }),
    createFinding({ severity: "low" }),
  ];

  const enriched = enrichWithPriority(findings);
  assert.equal((enriched[0] as any).priority, 1);
  assert.equal((enriched[1] as any).priority, 3);
});

test("M-2: exploitable findings bubble up in sort order", () => {
  const findings = [
    createFinding({
      severity: "low",
      title: "Basic code style issue",
    }),
    createFinding({
      severity: "low",
      title: "Missing authentication check on route",
    }),
  ];

  const sorted = sortByPriority(findings);
  // Exploitable one (authentication) should come first
  assert.ok(sorted[0].title?.includes("authentication"));
});

test("M-2: passwords and secrets are highly exploitable", () => {
  const findings = [
    createFinding({ severity: "info", title: "Hardcoded password in code" }),
  ];
  // Password + info should still become priority 2 (info boosted by exploitability)
  assert.equal(calculatePriority(findings[0]), 2);
});
