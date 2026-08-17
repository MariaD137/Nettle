import { test } from "node:test";
import assert from "node:assert/strict";
import { correlateAttackChains } from "../src/scanner/attackChains";
import type { Finding } from "../src/scanner/types";

function finding(overrides: Partial<Finding>): Finding {
  return {
    severity: "medium",
    category: "Security",
    title: "placeholder",
    detail: "placeholder",
    file: "src/routes/example.ts",
    line: null,
    remediation: null,
    ...overrides,
  };
}

test("links an unauthenticated route to a SQL string-concatenation query in the same file", () => {
  const findings = [
    finding({ category: "Authentication", title: "Route has no authentication check", detail: "" }),
    finding({ category: "Database", title: "SQL query built with string concatenation or interpolation", detail: "" }),
  ];

  const chains = correlateAttackChains(findings);

  assert.equal(chains.length, 1);
  assert.equal(chains[0].severity, "critical");
  assert.match(chains[0].title, /SQL query/);
  assert.equal(chains[0].findings.length, 2);
});

test("does not link findings that live in different files", () => {
  const findings = [
    finding({ category: "Authentication", title: "Route has no authentication check", detail: "", file: "src/routes/a.ts" }),
    finding({ category: "Database", title: "SQL query built with string concatenation or interpolation", detail: "", file: "src/routes/b.ts" }),
  ];

  assert.deepEqual(correlateAttackChains(findings), []);
});

test("does not link an authenticated route's co-located SQL finding", () => {
  const findings = [
    finding({ category: "Database", title: "SQL query built with string concatenation or interpolation", detail: "" }),
  ];

  assert.deepEqual(correlateAttackChains(findings), []);
});

test("links an unauthenticated route to unsafe deserialization in the same file", () => {
  const findings = [
    finding({ category: "Authentication", title: "No detected authentication check", detail: "" }),
    finding({ category: "Security", title: "Potentially unsafe deserialization", detail: "" }),
  ];

  const chains = correlateAttackChains(findings);
  assert.equal(chains.length, 1);
  assert.match(chains[0].title, /deserialization/);
});

test("links an unauthenticated route to a shell/command-execution finding", () => {
  const findings = [
    finding({ category: "Authentication", title: "No detected authentication check", detail: "" }),
    finding({ category: "Security", title: "Potential command injection via exec", detail: "" }),
  ];

  const chains = correlateAttackChains(findings);
  assert.equal(chains.length, 1);
  assert.match(chains[0].title, /shell\/process-execution/);
});

test("links an unauthenticated route to a hardcoded credential in the same file", () => {
  const findings = [
    finding({ category: "Authentication", title: "No detected authentication check", detail: "" }),
    finding({ category: "Security", title: "AWS Access Key ID found in source", detail: "" }),
  ];

  const chains = correlateAttackChains(findings);
  assert.equal(chains.length, 1);
  assert.match(chains[0].title, /hardcoded credential/);
});

test("produces one chain per distinct file when multiple files match the same rule", () => {
  const findings = [
    finding({ category: "Authentication", title: "No detected authentication check", detail: "", file: "src/routes/a.ts" }),
    finding({ category: "Database", title: "SQL query built with string concatenation or interpolation", detail: "", file: "src/routes/a.ts" }),
    finding({ category: "Authentication", title: "No detected authentication check", detail: "", file: "src/routes/b.ts" }),
    finding({ category: "Database", title: "SQL query built with string concatenation or interpolation", detail: "", file: "src/routes/b.ts" }),
  ];

  const chains = correlateAttackChains(findings);
  assert.equal(chains.length, 2);
  const files = chains.map((c) => c.entryPoint);
  assert.ok(files.some((f) => f.includes("a.ts")));
  assert.ok(files.some((f) => f.includes("b.ts")));
});

test("ignores findings with a null file when correlating", () => {
  const findings = [
    finding({ category: "Authentication", title: "No detected authentication check", detail: "", file: null }),
    finding({ category: "Database", title: "SQL query built with string concatenation or interpolation", detail: "", file: null }),
  ];

  assert.deepEqual(correlateAttackChains(findings), []);
});

test("returns no chains for an empty findings list", () => {
  assert.deepEqual(correlateAttackChains([]), []);
});
