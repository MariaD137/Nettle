import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "fs";
import os from "os";
import path from "path";
import "../src/scanner/controls";
import { scanAuthControl } from "../src/scanner/controls/checks/authControl";
import { scanSecretsControl } from "../src/scanner/secrets";

function writeTempFile(dir: string, name: string, content: string): string {
  const file = path.join(dir, name);
  fs.writeFileSync(file, content, "utf8");
  return file;
}

test("scanAuthControl: FAIL for an unprotected Express route, references AUTH-001", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "nettle-auth-"));
  const file = writeTempFile(
    dir,
    "server.js",
    `const express = require('express');\nconst app = express();\napp.get('/api/users/:id', (req, res) => { res.json({}); });\n`
  );

  const results = scanAuthControl([file], dir);
  const fail = results.find((r) => r.status === "FAIL");
  assert.ok(fail, "expected a FAIL result");
  assert.equal(fail!.controlKey, "AUTH-001");
  assert.equal(fail!.severity, "medium"); // GET without auth: medium per getAuthSeverity
  assert.ok(fail!.remediation && fail!.remediation.includes("verifyJWT"));

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanAuthControl: PASS for a protected route", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "nettle-auth-"));
  const file = writeTempFile(
    dir,
    "server.js",
    `const express = require('express');\nconst app = express();\napp.post('/api/admin', verifyJWT, (req, res) => { res.json({}); });\n`
  );

  const results = scanAuthControl([file], dir);
  assert.ok(results.some((r) => r.status === "PASS" && r.controlKey === "AUTH-001"));
  assert.ok(!results.some((r) => r.status === "FAIL"));

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanAuthControl: NOT_VERIFIED, never a guessed PASS or FAIL, when the framework can't be identified", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "nettle-auth-"));
  // Route-shaped (app.get(...) syntax) but with no require('express')/import
  // line or any other framework's signature pattern present, so
  // detectFramework() returns "unknown" while a route is still extracted
  // (the "unknown" strategy reuses the Express extractor — see
  // authAnalysis.ts's ROUTE_EXTRACTORS comment for why).
  const file = writeTempFile(
    dir,
    "server.js",
    `app.get('/api/mystery', (req, res) => { res.json({}); });\n`
  );

  const results = scanAuthControl([file], dir);
  assert.equal(results.length, 1);
  assert.equal(results[0].status, "NOT_VERIFIED");
  assert.equal(results[0].controlKey, "AUTH-001");
  assert.ok(!results.some((r) => r.status === "PASS" || r.status === "FAIL"));

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanSecretsControl: FAIL with SECRET-001 for a hardcoded AWS key", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "nettle-secrets-"));
  const file = writeTempFile(dir, "config.js", `const KEY = "AKIAIOSFODNN7EXAMPLE";\n`);

  const results = scanSecretsControl([file], dir);
  const fail = results.find((r) => r.status === "FAIL");
  assert.ok(fail);
  assert.equal(fail!.controlKey, "SECRET-001");
  assert.equal(fail!.severity, "critical");
  assert.equal(fail!.line, 1);

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanSecretsControl: PASS when nothing matches", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "nettle-secrets-"));
  const file = writeTempFile(dir, "config.js", `const greeting = "hello world";\n`);

  const results = scanSecretsControl([file], dir);
  assert.equal(results.length, 1);
  assert.equal(results[0].status, "PASS");
  assert.equal(results[0].controlKey, "SECRET-001");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanSecretsControl: NOT_VERIFIED for an unreadable file, and the scan doesn't crash", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "nettle-secrets-"));
  const missingFile = path.join(dir, "does-not-exist.js");

  const results = scanSecretsControl([missingFile], dir);
  assert.equal(results.length, 1);
  assert.equal(results[0].status, "NOT_VERIFIED");
  assert.equal(results[0].controlKey, "SECRET-001");

  fs.rmSync(dir, { recursive: true, force: true });
});
