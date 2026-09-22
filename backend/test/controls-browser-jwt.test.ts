import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "fs";
import os from "os";
import path from "path";
import "../src/scanner/controls";
import { getControl } from "../src/scanner/controls/registry";
import { hydrateCheckResult } from "../src/scanner/controls/hydrate";
import { scanSecurityHeadersControl } from "../src/scanner/controls/checks/securityHeadersControl";
import { scanJwtAlgorithmControl } from "../src/scanner/controls/checks/jwtAlgorithmControl";

function writeTempFile(dir: string, name: string, content: string): string {
  const file = path.join(dir, name);
  fs.writeFileSync(file, content, "utf8");
  return file;
}

test("BROWSER-001 and AUTH-002 are registered", () => {
  assert.ok(getControl("BROWSER-001"));
  assert.ok(getControl("AUTH-002"));
});

test("scanSecurityHeadersControl: FAIL for the missing-middleware check and each missing individual header", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "nettle-headers-"));
  const file = writeTempFile(dir, "server.js", `const express = require('express');\nconst app = express();\napp.get('/', (req, res) => res.send('hi'));\n`);

  const results = scanSecurityHeadersControl([file], dir);
  const middlewareFail = results.find((r) => r.title === "No security headers middleware detected");
  assert.ok(middlewareFail);
  assert.equal(middlewareFail!.controlKey, "BROWSER-001");
  assert.equal(middlewareFail!.severity, "high");

  // Six more FAILs, one per individual header, none of which are present.
  const individualFails = results.filter((r) => r.status === "FAIL" && r.title.startsWith("Missing"));
  assert.equal(individualFails.length, 6);
  assert.ok(individualFails.every((r) => r.controlKey === "BROWSER-001"));

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanSecurityHeadersControl: Helmet detected short-circuits to an all-PASS result", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "nettle-headers-"));
  const file = writeTempFile(dir, "server.js", `const helmet = require('helmet');\napp.use(helmet());\n`);

  const results = scanSecurityHeadersControl([file], dir);
  assert.ok(results.every((r) => r.status === "PASS"));
  assert.equal(results.length, 7); // helmet itself + the 6 individual headers "covered by Helmet"

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanJwtAlgorithmControl: FAIL for algorithm: 'none'", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "nettle-jwt-"));
  const file = writeTempFile(dir, "auth.js", `const jwt = require('jsonwebtoken');\njwt.sign(payload, secret, { algorithm: 'none' });\n`);

  const results = scanJwtAlgorithmControl([file], dir);
  const fail = results.find((r) => r.status === "FAIL");
  assert.ok(fail);
  assert.equal(fail!.controlKey, "AUTH-002");
  assert.equal(fail!.severity, "critical");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanJwtAlgorithmControl: PASS when JWT is used without 'none'", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "nettle-jwt-"));
  const file = writeTempFile(dir, "auth.js", `const jwt = require('jsonwebtoken');\njwt.sign(payload, secret, { algorithm: 'RS256' });\n`);

  const results = scanJwtAlgorithmControl([file], dir);
  assert.equal(results.length, 1);
  assert.equal(results[0].status, "PASS");
  assert.equal(results[0].controlKey, "AUTH-002");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanJwtAlgorithmControl: no unearned PASS when the app doesn't use JWT at all", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "nettle-jwt-"));
  const file = writeTempFile(dir, "util.js", `function add(a, b) { return a + b; }\n`);

  const results = scanJwtAlgorithmControl([file], dir);
  assert.equal(results.length, 0);

  fs.rmSync(dir, { recursive: true, force: true });
});

test("hydration gives BROWSER-001 a real fix", () => {
  const hydrated = hydrateCheckResult(
    { checkId: "x", status: "FAIL", category: "Configuration", title: "No security headers middleware detected", severity: "high", confidence: 75, controlKey: "BROWSER-001" },
    { detectedTechnology: "express" }
  );
  assert.ok(hydrated.recommendation);
  assert.match(hydrated.recommendation!.quickFix, /helmet/);
  assert.equal(hydrated.releaseImpact, "REVIEW_BEFORE_RELEASE");
});

test("hydration gives AUTH-002 a real fix and blocks release regardless of confidence (critical, high-confidence detection)", () => {
  const hydrated = hydrateCheckResult({
    checkId: "x",
    status: "FAIL",
    category: "Session Management",
    title: "JWT algorithm set to 'none'",
    severity: "critical",
    confidence: 95,
    controlKey: "AUTH-002",
  });
  assert.ok(hydrated.recommendation);
  assert.match(hydrated.recommendation!.quickFix, /live authentication bypass/);
  assert.equal(hydrated.releaseImpact, "BLOCK_RELEASE");
});
