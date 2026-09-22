import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "fs";
import os from "os";
import path from "path";
import "../src/scanner/controls";
import { getControl } from "../src/scanner/controls/registry";
import { hydrateCheckResult } from "../src/scanner/controls/hydrate";
import { scanJwtExpiryControl } from "../src/scanner/controls/checks/jwtExpiryControl";
import { scanCorsControl } from "../src/scanner/controls/checks/corsControl";

function writeTempFile(dir: string, name: string, content: string): string {
  const file = path.join(dir, name);
  fs.writeFileSync(file, content, "utf8");
  return file;
}

test("AUTH-003 and API-002 are registered", () => {
  assert.ok(getControl("AUTH-003"));
  assert.ok(getControl("API-002"));
});

test("scanJwtExpiryControl: FAIL when JWTs are signed without an expiration", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "nettle-jwtexp-"));
  const file = writeTempFile(dir, "auth.js", `const jwt = require('jsonwebtoken');\njwt.sign(payload, secret);\n`);

  const results = scanJwtExpiryControl([file], dir);
  assert.equal(results.length, 1);
  assert.equal(results[0].status, "FAIL");
  assert.equal(results[0].controlKey, "AUTH-003");
  assert.equal(results[0].severity, "high");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanJwtExpiryControl: PASS when an expiration is configured", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "nettle-jwtexp-"));
  const file = writeTempFile(dir, "auth.js", `const jwt = require('jsonwebtoken');\njwt.sign(payload, secret, { expiresIn: '15m' });\n`);

  const results = scanJwtExpiryControl([file], dir);
  assert.equal(results.length, 1);
  assert.equal(results[0].status, "PASS");
  assert.equal(results[0].controlKey, "AUTH-003");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanJwtExpiryControl: no unearned PASS/FAIL when the app doesn't use JWTs at all", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "nettle-jwtexp-"));
  const file = writeTempFile(dir, "util.js", `function add(a, b) { return a + b; }\n`);

  const results = scanJwtExpiryControl([file], dir);
  assert.equal(results.length, 0);

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanCorsControl: FAIL for a wildcard origin", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "nettle-cors-"));
  const file = writeTempFile(dir, "server.js", `const cors = require('cors');\napp.use(cors({ origin: '*' }));\n`);

  const results = scanCorsControl([file], dir);
  assert.equal(results.length, 1);
  assert.equal(results[0].status, "FAIL");
  assert.equal(results[0].controlKey, "API-002");
  assert.equal(results[0].severity, "high");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanCorsControl: PASS for a specific origin", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "nettle-cors-"));
  const file = writeTempFile(dir, "server.js", `const cors = require('cors');\napp.use(cors({ origin: 'https://example.com' }));\n`);

  const results = scanCorsControl([file], dir);
  assert.equal(results.length, 1);
  assert.equal(results[0].status, "PASS");
  assert.equal(results[0].controlKey, "API-002");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanCorsControl: no unearned finding when CORS isn't configured at all", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "nettle-cors-"));
  const file = writeTempFile(dir, "server.js", `app.get('/', (req, res) => res.send('hi'));\n`);

  const results = scanCorsControl([file], dir);
  assert.equal(results.length, 0);

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanCorsControl: NOT_VERIFIED when CORS isn't found but a file was unreadable", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "nettle-cors-"));
  const file = writeTempFile(dir, "server.js", `app.get('/', (req, res) => res.send('hi'));\n`);
  const unreadable = path.join(dir, "missing.js");

  const results = scanCorsControl([file, unreadable], dir);
  assert.equal(results.length, 1);
  assert.equal(results[0].status, "NOT_VERIFIED");
  assert.equal(results[0].controlKey, "API-002");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("hydration gives AUTH-003 a real fix", () => {
  const hydrated = hydrateCheckResult(
    { checkId: "x", status: "FAIL", category: "Session Management", title: "JWT tokens issued without expiration", severity: "high", confidence: 80, controlKey: "AUTH-003" },
    { detectedTechnology: "express" }
  );
  assert.ok(hydrated.recommendation);
  assert.match(hydrated.recommendation!.quickFix, /expiresIn/);
  assert.equal(hydrated.releaseImpact, "REVIEW_BEFORE_RELEASE");
});

test("hydration gives API-002 a real fix", () => {
  const hydrated = hydrateCheckResult(
    { checkId: "x", status: "FAIL", category: "API Security", title: "CORS allows all origins (wildcard)", severity: "high", confidence: 85, controlKey: "API-002" },
    { detectedTechnology: "express" }
  );
  assert.ok(hydrated.recommendation);
  assert.match(hydrated.recommendation!.quickFix, /origin/);
  assert.equal(hydrated.releaseImpact, "REVIEW_BEFORE_RELEASE");
});
