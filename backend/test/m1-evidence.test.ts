import { test } from "node:test";
import assert from "node:assert/strict";
import { redactSecrets, createEvidence, extractLineEvidence, generateEvidenceForFinding } from "../src/scanner/evidence";

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

  // generateEvidenceForFinding returns string | undefined; assert presence
  // before inspecting it so a silent undefined cannot pass as a pass.
  assert.ok(evidence, "expected evidence for a finding with a variable and value");
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
