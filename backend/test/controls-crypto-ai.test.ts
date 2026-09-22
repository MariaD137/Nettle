import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "fs";
import os from "os";
import path from "path";
import "../src/scanner/controls";
import { getControl } from "../src/scanner/controls/registry";
import { hydrateCheckResult } from "../src/scanner/controls/hydrate";
import { scanCryptoControl } from "../src/scanner/controls/checks/cryptoControl";
import { scanAiPromptInjectionControl } from "../src/scanner/controls/checks/aiPromptInjectionControl";

function writeTempFile(dir: string, name: string, content: string): string {
  const file = path.join(dir, name);
  fs.writeFileSync(file, content, "utf8");
  return file;
}

test("CRYPTO-001 and AI-001 are registered", () => {
  assert.ok(getControl("CRYPTO-001"));
  assert.ok(getControl("AI-001"));
});

test("scanCryptoControl: FAIL for MD5 usage", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "nettle-crypto-"));
  const file = writeTempFile(dir, "hash.js", `const crypto = require('crypto');\nconst h = crypto.createHash('md5').update(data).digest('hex');\n`);

  const results = scanCryptoControl([file], dir);
  const fail = results.find((r) => r.title === "MD5 hash usage");
  assert.ok(fail);
  assert.equal(fail!.controlKey, "CRYPTO-001");
  assert.equal(fail!.severity, "high");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanCryptoControl: FAIL for Math.random() used for a token", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "nettle-crypto-"));
  const file = writeTempFile(dir, "token.js", `const t = Math.random() + '-session';\n`);

  const results = scanCryptoControl([file], dir);
  assert.ok(results.some((r) => r.title === "Math.random used for security" && r.controlKey === "CRYPTO-001"));

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanCryptoControl: PASS (no weak crypto) plus bonus PASS for strong hashing and secure random", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "nettle-crypto-"));
  const file = writeTempFile(
    dir,
    "auth.js",
    "const crypto = require('crypto');\nconst bcrypt = require('bcrypt');\nconst id = crypto.randomUUID();\n"
  );

  const results = scanCryptoControl([file], dir);
  assert.ok(results.every((r) => r.status === "PASS"));
  assert.ok(results.some((r) => r.title === "Strong password hashing detected (Argon2id or bcrypt)"));
  assert.ok(results.some((r) => r.title === "Cryptographically secure random generation used"));
  assert.ok(results.some((r) => r.title === "No weak or deprecated cryptographic algorithms detected"));

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanAiPromptInjectionControl: FAIL when user input reaches a prompt with no guard", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "nettle-ai-"));
  const file = writeTempFile(
    dir,
    "chat.js",
    "app.post('/chat', (req, res) => {\n  const combined = req.body.userMessage + systemPrompt;\n  callModel(combined);\n});\n"
  );

  const results = scanAiPromptInjectionControl([file], dir);
  const fail = results.find((r) => r.status === "FAIL");
  assert.ok(fail);
  assert.equal(fail!.controlKey, "AI-001");
  assert.equal(fail!.severity, "high");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanAiPromptInjectionControl: PASS when a guard is present in the same file", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "nettle-ai-"));
  const file = writeTempFile(
    dir,
    "chat.js",
    "function sanitizePrompt(input) { return input.replace(/ignore.*instructions/gi, ''); } // prompt injection guard\n" +
      "app.post('/chat', (req, res) => {\n  const combined = req.body.userMessage + systemPrompt;\n  callModel(sanitizePrompt(combined));\n});\n"
  );

  const results = scanAiPromptInjectionControl([file], dir);
  assert.equal(results.length, 1);
  assert.equal(results[0].status, "PASS");
  assert.equal(results[0].controlKey, "AI-001");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanAiPromptInjectionControl: nothing reported for a file that doesn't put user input in front of a model", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "nettle-ai-"));
  const file = writeTempFile(dir, "util.js", `function add(a, b) { return a + b; }\n`);

  const results = scanAiPromptInjectionControl([file], dir);
  assert.equal(results.length, 0);

  fs.rmSync(dir, { recursive: true, force: true });
});

test("hydration gives CRYPTO-001 a real fix and AI-001 a real fix", () => {
  const crypto = hydrateCheckResult(
    { checkId: "x", status: "FAIL", category: "Cryptography", title: "MD5 hash usage", severity: "high", confidence: 80, controlKey: "CRYPTO-001" }
  );
  assert.ok(crypto.recommendation);
  assert.match(crypto.recommendation!.developerFix, /SHA-256|Argon2id|bcrypt/);

  const ai = hydrateCheckResult(
    { checkId: "x", status: "FAIL", category: "AI Disclosure", title: "User input passed directly to AI prompt without sanitization", severity: "high", confidence: 60, controlKey: "AI-001" }
  );
  assert.ok(ai.recommendation);
  assert.match(ai.recommendation!.developerFix, /system\/user roles/);
  assert.equal(ai.releaseImpact, "FIX_RECOMMENDED"); // high baseline REVIEW_BEFORE_RELEASE, downgraded once at confidence 60 (<75, >=50)
});
