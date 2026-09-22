import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "fs";
import os from "os";
import path from "path";
import "../src/scanner/controls";
import { getControl } from "../src/scanner/controls/registry";
import { hydrateCheckResult } from "../src/scanner/controls/hydrate";
import { scanApiRateLimitControl } from "../src/scanner/controls/checks/rateLimitControl";
import { scanSqlInjectionControl } from "../src/scanner/controls/checks/sqlInjectionControl";

function writeTempFile(dir: string, name: string, content: string): string {
  const file = path.join(dir, name);
  fs.writeFileSync(file, content, "utf8");
  return file;
}

test("API-001 and DB-001 are registered", () => {
  assert.ok(getControl("API-001"));
  assert.ok(getControl("DB-001"));
});

test("scanApiRateLimitControl: FAIL when routes exist with no rate-limit pattern", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "nettle-api-"));
  const file = writeTempFile(dir, "server.js", `app.get('/api/data', (req, res) => res.json({}));\n`);

  const results = scanApiRateLimitControl([file], dir);
  assert.equal(results.length, 1);
  assert.equal(results[0].status, "FAIL");
  assert.equal(results[0].controlKey, "API-001");
  assert.equal(results[0].severity, "high");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanApiRateLimitControl: PASS when a rate-limit pattern is present", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "nettle-api-"));
  const file = writeTempFile(
    dir,
    "server.js",
    `const rateLimit = require('express-rate-limit');\napp.use(rateLimit({ max: 100 }));\napp.get('/api/data', (req, res) => res.json({}));\n`
  );

  const results = scanApiRateLimitControl([file], dir);
  assert.equal(results.length, 1);
  assert.equal(results[0].status, "PASS");
  assert.equal(results[0].controlKey, "API-001");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanApiRateLimitControl: nothing to report when there are no routes at all", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "nettle-api-"));
  const file = writeTempFile(dir, "util.js", `function add(a, b) { return a + b; }\n`);

  const results = scanApiRateLimitControl([file], dir);
  assert.equal(results.length, 0);

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanSqlInjectionControl: FAIL for a template-literal SQL injection", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "nettle-db-"));
  const file = writeTempFile(
    dir,
    "db.js",
    "const sequelize = require('sequelize');\nfunction getUser(id) { return db.query(`SELECT * FROM users WHERE id = ${id}`); }\n"
  );

  const results = scanSqlInjectionControl([file], dir);
  const fail = results.find((r) => r.status === "FAIL");
  assert.ok(fail);
  assert.equal(fail!.controlKey, "DB-001");
  assert.equal(fail!.severity, "critical");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanSqlInjectionControl: PASS for a parameterized query, with DB usage detected", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "nettle-db-"));
  const file = writeTempFile(
    dir,
    "db.js",
    "const sqlite = require('sqlite3');\nfunction getUser(id) { return db.prepare('SELECT * FROM users WHERE id = ?').get(id); }\n"
  );

  const results = scanSqlInjectionControl([file], dir);
  assert.equal(results.length, 1);
  assert.equal(results[0].status, "PASS");
  assert.equal(results[0].controlKey, "DB-001");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanSqlInjectionControl: no PASS claimed when the app doesn't appear to use a database at all", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "nettle-db-"));
  const file = writeTempFile(dir, "util.js", `function add(a, b) { return a + b; }\n`);

  const results = scanSqlInjectionControl([file], dir);
  assert.equal(results.length, 0); // no FAIL, and no unearned "safe" PASS either

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanSqlInjectionControl: NOT_VERIFIED for an unreadable file", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "nettle-db-"));
  const missing = path.join(dir, "does-not-exist.js");

  const results = scanSqlInjectionControl([missing], dir);
  assert.equal(results.length, 1);
  assert.equal(results[0].status, "NOT_VERIFIED");
  assert.equal(results[0].controlKey, "DB-001");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("hydration gives API-001 a real, technology-specific fix", () => {
  const hydrated = hydrateCheckResult(
    { checkId: "x", status: "FAIL", category: "API Security", title: "No rate limiting detected", severity: "high", confidence: 80, controlKey: "API-001" },
    { detectedTechnology: "fastapi" }
  );
  assert.ok(hydrated.recommendation);
  assert.equal(hydrated.recommendation!.technologyMatched, "fastapi");
  assert.match(hydrated.recommendation!.quickFix, /slowapi/);
});

test("hydration gives DB-001 a real, technology-specific fix", () => {
  const hydrated = hydrateCheckResult(
    { checkId: "x", status: "FAIL", category: "Database", title: "SQL query built with string concatenation", severity: "critical", confidence: 90, controlKey: "DB-001" },
    { detectedTechnology: "postgres" }
  );
  assert.ok(hydrated.recommendation);
  assert.equal(hydrated.recommendation!.technologyMatched, "postgres");
  assert.match(hydrated.recommendation!.quickFix, /\$1/);
  assert.equal(hydrated.releaseImpact, "BLOCK_RELEASE");
});
