import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "fs";
import os from "os";
import path from "path";
import {
  redactSecrets,
  createEvidence,
  extractLineEvidence,
  generateEvidenceForFinding,
  extractCodeContext,
  enrichFindings,
} from "../src/scanner/evidence";
import type { Finding } from "../src/scanner/types";

test("M-1: redact API keys", () => {
  const text = "const API_KEY = 'sk_live_abc123xyz789'";
  const redacted = redactSecrets(text);

  assert.ok(!redacted.includes("sk_live"));
  assert.ok(redacted.includes("[REDACTED"));
});

test("M-1: redact password assignments", () => {
  const text = "password = 'super-secret-pass'";
  const redacted = redactSecrets(text);

  assert.ok(!redacted.includes("super-secret"));
  assert.ok(redacted.includes("[REDACTED"));
});

test("M-1: redact AWS access keys", () => {
  const text = "AKIA1234567890ABCDEF";
  const redacted = redactSecrets(text);

  assert.ok(!redacted.includes("AKIA"));
  assert.ok(redacted.includes("[REDACTED"));
});

test("M-1: redact long hex strings", () => {
  const text = "token: a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6";
  const redacted = redactSecrets(text);

  assert.ok(!redacted.includes("a1b2c3d4e5f6"));
  assert.ok(redacted.includes("[REDACTED"));
});

test("M-1: preserve non-secret text", () => {
  const text = "function validateUser(username, role) { return true; }";
  const redacted = redactSecrets(text);

  assert.ok(redacted.includes("validateUser"));
  assert.ok(redacted.includes("username"));
  assert.ok(!redacted.includes("[REDACTED"));
});

test("M-1: create evidence from code snippet", () => {
  const code = "app.post('/api/users', (req, res) => { db.query('SELECT * FROM users') })";
  const evidence = createEvidence(code);

  assert.ok(evidence);
  assert.ok(evidence.includes("app.post"));
  assert.ok(!evidence.includes("[REDACTED"));
});

test("M-1: create evidence redacts secrets in snippet", () => {
  const code = "const secret = 'sk_live_abc123xyz789def456ghi789'";
  const evidence = createEvidence(code);

  assert.ok(evidence);
  assert.ok(!evidence.includes("sk_live"));
  assert.ok(evidence.includes("[REDACTED"));
});

test("M-1: truncate long evidence", () => {
  const longCode = "function validateUser(username, role) { return true; }".repeat(20);
  const evidence = createEvidence(longCode, 100);

  assert.ok(evidence);
  assert.ok(evidence.length <= 105); // 100 + "…"
  assert.ok(evidence.endsWith("…"));
});

test("M-1: extract line evidence", () => {
  const line = "  const API_KEY = process.env.SECRET_KEY;  ";
  const evidence = extractLineEvidence(line);

  assert.ok(evidence);
  assert.ok(!evidence.includes("SECRET_KEY"));
  assert.ok(evidence.includes("[REDACTED"));
});

test("M-1: generate evidence from context", () => {
  const context = {
    variable: "password",
    value: "super-secret-password",
  };

  const evidence = generateEvidenceForFinding("hardcoded-secret", context);

  assert.ok(evidence);
  assert.ok(evidence.includes("password"));
  assert.ok(!evidence.includes("super-secret"));
  assert.ok(evidence.includes("[REDACTED"));
});

test("M-1: generate evidence prefers variable over value", () => {
  const context = {
    variable: "mySecret",
    value: "very long secret value that should not appear",
  };

  const evidence = generateEvidenceForFinding("secret", context);

  assert.ok(evidence.includes("mySecret"));
  // Value might be included as assignment, but shouldn't be full text
  assert.ok(!evidence.includes("very long secret"));
});

test("M-1: evidence returns undefined for empty context", () => {
  const evidence = generateEvidenceForFinding("test", {});

  assert.equal(evidence, undefined);
});

test("M-1: sensitive evidence pattern detection", () => {
  const patterns = [
    "api_key: abc123",
    "password='secret'",
    "secret_token: xyz",
    "access_token: token123",
    "AWS_SECRET_KEY: key123",
  ];

  for (const pattern of patterns) {
    const redacted = redactSecrets(pattern);
    assert.ok(redacted.includes("[REDACTED"), `Pattern '${pattern}' should be redacted`);
  }
});

function tempFileWithLines(lines: string[]): { root: string; relFile: string } {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "nettle-code-context-"));
  const relFile = "src/app.js";
  fs.mkdirSync(path.join(root, "src"), { recursive: true });
  fs.writeFileSync(path.join(root, relFile), lines.join("\n"));
  return { root, relFile };
}

test("extractCodeContext returns the redacted matched line", () => {
  const { root, relFile } = tempFileWithLines([
    "const app = require('express')();",
    "const API_KEY = 'sk_live_abc123xyz789';",
    "app.listen(3000);",
  ]);

  const context = extractCodeContext(root, relFile, 2);
  assert.ok(context);
  assert.ok(!context!.includes("sk_live"));
  assert.ok(context!.includes("[REDACTED"));
});

test("extractCodeContext handles a Semgrep-style 'file:line' path by stripping the suffix", () => {
  const { root, relFile } = tempFileWithLines(["eval(userInput);"]);
  const context = extractCodeContext(root, `${relFile}:1`, 1);
  assert.ok(context);
  assert.ok(context!.includes("eval"));
});

test("extractCodeContext returns undefined for a line number out of range", () => {
  const { root, relFile } = tempFileWithLines(["only one line"]);
  assert.equal(extractCodeContext(root, relFile, 99), undefined);
});

test("extractCodeContext returns undefined for a file that doesn't exist", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "nettle-code-context-missing-"));
  assert.equal(extractCodeContext(root, "nope.js", 1), undefined);
});

test("extractCodeContext refuses to read outside targetRoot", () => {
  const { root } = tempFileWithLines(["irrelevant"]);
  assert.equal(extractCodeContext(root, "../../etc/passwd", 1), undefined);
});

function baseFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    severity: "high",
    category: "Security",
    title: "Hardcoded API key found in source",
    detail: "...",
    file: "src/app.js",
    line: 2,
    remediation: null,
    ...overrides,
  };
}

test("enrichFindings backfills a stable ruleId when one isn't already set", () => {
  const findings = [baseFinding(), baseFinding({ file: "src/other.js" })];
  enrichFindings(findings);

  assert.ok(findings[0].ruleId);
  // Same category+title, different file → same rule, same ruleId.
  assert.equal(findings[0].ruleId, findings[1].ruleId);
});

test("enrichFindings never overwrites a ruleId a scanner already set (e.g. Semgrep's real check_id)", () => {
  const findings = [baseFinding({ ruleId: "nettle-js-rules.eval-usage" })];
  enrichFindings(findings);
  assert.equal(findings[0].ruleId, "nettle-js-rules.eval-usage");
});

test("enrichFindings fills in codeContext when file+line are on disk under targetRoot", () => {
  const { root, relFile } = tempFileWithLines(["line one", "const SECRET = 'sk_live_abc123xyz789';", "line three"]);
  const findings = [baseFinding({ file: relFile, line: 2 })];
  enrichFindings(findings, root);

  assert.ok(findings[0].codeContext);
  assert.ok(findings[0].codeContext!.includes("[REDACTED"));
});

test("enrichFindings leaves codeContext unset when no targetRoot is given (e.g. a URL scan)", () => {
  const findings = [baseFinding()];
  enrichFindings(findings);
  assert.equal(findings[0].codeContext, undefined);
});

test("enrichFindings leaves codeContext unset when the finding has no line number", () => {
  const { root, relFile } = tempFileWithLines(["only line"]);
  const findings = [baseFinding({ file: relFile, line: null })];
  enrichFindings(findings, root);
  assert.equal(findings[0].codeContext, undefined);
});
