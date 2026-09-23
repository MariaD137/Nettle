import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "fs";
import os from "os";
import path from "path";
import "../src/scanner/controls";
import { getControl } from "../src/scanner/controls/registry";
import { hydrateCheckResult } from "../src/scanner/controls/hydrate";
import { scanRefreshTokenControl } from "../src/scanner/controls/checks/refreshTokenControl";
import { scanSessionStoreControl } from "../src/scanner/controls/checks/sessionStoreControl";
import { scanSessionExpirationControl } from "../src/scanner/controls/checks/sessionExpirationControl";
import { scanLogoutInvalidationControl } from "../src/scanner/controls/checks/logoutInvalidationControl";
import { compareScans, type ScanForComparison } from "../src/scanner/scanComparison";
import type { ScanReport, CheckResult } from "../src/scanner/types";

/**
 * Completes the sessionJwt.ts migration onto the control library
 * (AUTH-005..008) -- JWT expiry and the "none" algorithm were already
 * promoted to AUTH-003/AUTH-002 in earlier rounds. sessionJwt.ts itself has
 * been deleted; every meaningful check it made now lives here.
 *
 * One check was deliberately NOT migrated: the legacy "JWT uses asymmetric
 * signing algorithm" PASS-only signal. Recommending asymmetric algorithms
 * as a requirement would be indefensible general guidance — HS256 with a
 * properly random secret is a legitimate, widely-used choice, and the real
 * risk (algorithm: 'none') is already covered by AUTH-002. A control that
 * can never meaningfully FAIL and whose "fix" isn't actually necessary
 * isn't a control worth having.
 */

function writeTempFile(dir: string, name: string, content: string): string {
  const file = path.join(dir, name);
  fs.writeFileSync(file, content, "utf8");
  return file;
}

function tmpDir(prefix: string): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

test("AUTH-005, AUTH-006, AUTH-007, and AUTH-008 are registered", () => {
  for (const key of ["AUTH-005", "AUTH-006", "AUTH-007", "AUTH-008"]) {
    assert.ok(getControl(key), `${key} should be registered`);
  }
});

// --- AUTH-005: refresh token rotation ---

test("scanRefreshTokenControl: FAIL when JWTs are issued with no refresh-token pattern", () => {
  const dir = tmpDir("nettle-refresh-");
  const file = writeTempFile(dir, "auth.js", `const jwt = require('jsonwebtoken');\njwt.sign(payload, secret, { expiresIn: '15m' });\n`);

  const results = scanRefreshTokenControl([file], dir);
  assert.equal(results.length, 1);
  assert.equal(results[0].status, "FAIL");
  assert.equal(results[0].controlKey, "AUTH-005");
  assert.equal(results[0].severity, "medium");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanRefreshTokenControl: PASS when a refresh-token pattern is present", () => {
  const dir = tmpDir("nettle-refresh-");
  const file = writeTempFile(dir, "auth.js", `const jwt = require('jsonwebtoken');\nfunction issueRefreshToken(user) { return jwt.sign({ sub: user.id }, refreshSecret); }\n`);

  const results = scanRefreshTokenControl([file], dir);
  assert.equal(results.length, 1);
  assert.equal(results[0].status, "PASS");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanRefreshTokenControl: no unearned finding when JWTs aren't used at all", () => {
  const dir = tmpDir("nettle-refresh-");
  const file = writeTempFile(dir, "util.js", `function add(a, b) { return a + b; }\n`);

  assert.equal(scanRefreshTokenControl([file], dir).length, 0);

  fs.rmSync(dir, { recursive: true, force: true });
});

// --- AUTH-006: session store ---

test("scanSessionStoreControl: FAIL when express-session has no persistent store configured", () => {
  const dir = tmpDir("nettle-sessstore-");
  const file = writeTempFile(dir, "server.js", `const session = require('express-session');\napp.use(session({ secret: 'x' }));\n`);

  const results = scanSessionStoreControl([file], dir);
  assert.equal(results.length, 1);
  assert.equal(results[0].status, "FAIL");
  assert.equal(results[0].controlKey, "AUTH-006");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanSessionStoreControl: PASS when a persistent store is configured", () => {
  const dir = tmpDir("nettle-sessstore-");
  const file = writeTempFile(dir, "server.js", `const session = require('express-session');\napp.use(session({ store: new RedisStore({ client }) }));\n`);

  const results = scanSessionStoreControl([file], dir);
  assert.equal(results.length, 1);
  assert.equal(results[0].status, "PASS");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanSessionStoreControl: not applicable when express-session isn't used", () => {
  const dir = tmpDir("nettle-sessstore-");
  const file = writeTempFile(dir, "server.js", `app.get('/', (req, res) => res.send('hi'));\n`);

  assert.equal(scanSessionStoreControl([file], dir).length, 0);

  fs.rmSync(dir, { recursive: true, force: true });
});

// --- AUTH-007: session expiration ---

test("scanSessionExpirationControl: FAIL when no maxAge is configured", () => {
  const dir = tmpDir("nettle-sessexp-");
  const file = writeTempFile(dir, "server.js", `const session = require('express-session');\napp.use(session({ secret: 'x' }));\n`);

  const results = scanSessionExpirationControl([file], dir);
  assert.equal(results.length, 1);
  assert.equal(results[0].status, "FAIL");
  assert.equal(results[0].controlKey, "AUTH-007");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanSessionExpirationControl: PASS when maxAge is configured (the legacy check never emitted this)", () => {
  const dir = tmpDir("nettle-sessexp-");
  const file = writeTempFile(dir, "server.js", `const session = require('express-session');\napp.use(session({ cookie: { maxAge: 86400000 } }));\n`);

  const results = scanSessionExpirationControl([file], dir);
  assert.equal(results.length, 1);
  assert.equal(results[0].status, "PASS");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanSessionExpirationControl: not applicable when express-session isn't used", () => {
  const dir = tmpDir("nettle-sessexp-");
  const file = writeTempFile(dir, "server.js", `app.get('/', (req, res) => res.send('hi'));\n`);

  assert.equal(scanSessionExpirationControl([file], dir).length, 0);

  fs.rmSync(dir, { recursive: true, force: true });
});

// --- AUTH-008: logout invalidation ---

test("scanLogoutInvalidationControl: FAIL when sessions are used but nothing invalidates on logout", () => {
  const dir = tmpDir("nettle-logout-");
  const file = writeTempFile(dir, "server.js", `const session = require('express-session');\napp.post('/logout', (req, res) => res.json({ ok: true }));\n`);

  const results = scanLogoutInvalidationControl([file], dir);
  assert.equal(results.length, 1);
  assert.equal(results[0].status, "FAIL");
  assert.equal(results[0].controlKey, "AUTH-008");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanLogoutInvalidationControl: PASS when session destruction is present", () => {
  const dir = tmpDir("nettle-logout-");
  const file = writeTempFile(dir, "server.js", `const session = require('express-session');\napp.post('/logout', (req, res) => { req.session.destroy(() => res.status(204).end()); });\n`);

  const results = scanLogoutInvalidationControl([file], dir);
  assert.equal(results.length, 1);
  assert.equal(results[0].status, "PASS");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanLogoutInvalidationControl: applies for JWT-only apps too, not just sessions", () => {
  const dir = tmpDir("nettle-logout-");
  const file = writeTempFile(dir, "server.js", `const jwt = require('jsonwebtoken');\njwt.sign(payload, secret);\n`);

  const results = scanLogoutInvalidationControl([file], dir);
  assert.equal(results.length, 1);
  assert.equal(results[0].status, "FAIL");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanLogoutInvalidationControl: no unearned finding when neither JWTs nor sessions are used", () => {
  const dir = tmpDir("nettle-logout-");
  const file = writeTempFile(dir, "util.js", `function add(a, b) { return a + b; }\n`);

  assert.equal(scanLogoutInvalidationControl([file], dir).length, 0);

  fs.rmSync(dir, { recursive: true, force: true });
});

// --- hydration ---

test("hydration gives AUTH-006 a real fix", () => {
  const hydrated = hydrateCheckResult(
    { checkId: "x", status: "FAIL", category: "Session Management", title: "Express sessions using default in-memory store", severity: "medium", confidence: 75, controlKey: "AUTH-006" },
    { detectedTechnology: "express" }
  );
  assert.ok(hydrated.recommendation);
  assert.match(hydrated.recommendation!.quickFix, /Redis/);
});

test("hydration gives AUTH-008 a real fix", () => {
  const hydrated = hydrateCheckResult({
    checkId: "x",
    status: "FAIL",
    category: "Session Management",
    title: "No token/session invalidation on logout",
    severity: "medium",
    confidence: 65,
    controlKey: "AUTH-008",
  });
  assert.ok(hydrated.recommendation);
  assert.match(hydrated.recommendation!.quickFix, /destroy|revocation/i);
});

// --- scan comparison: a newly-migrated finding participates in the diff engine ---

function report(checkResults: CheckResult[]): ScanReport {
  return {
    scannedAt: "2026-01-01T00:00:00.000Z",
    target: "app",
    scannerVersion: "1.3.0",
    score: 80,
    findings: [],
    passed: [],
    checkResults,
    summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0, clear: 0 },
  };
}

function scanAt(id: string, scannedAt: string, checkResults: CheckResult[]): ScanForComparison {
  return { id, scannedAt, status: "COMPLETED", report: report(checkResults) };
}

test("AUTH-006 (a newly-migrated control) participates fully in scan comparison: open -> fixed -> regressed", () => {
  const dirNoStore = tmpDir("nettle-sessstore-cmp-none-");
  writeTempFile(dirNoStore, "server.js", `const session = require('express-session');\napp.use(session({ secret: 'x' }));\n`);
  const dirWithStore = tmpDir("nettle-sessstore-cmp-store-");
  writeTempFile(dirWithStore, "server.js", `const session = require('express-session');\napp.use(session({ store: new RedisStore({ client }) }));\n`);

  const noStoreResults = scanSessionStoreControl([path.join(dirNoStore, "server.js")], dirNoStore);
  const withStoreResults = scanSessionStoreControl([path.join(dirWithStore, "server.js")], dirWithStore);

  const s1 = scanAt("s1", "2026-01-01T00:00:00Z", noStoreResults); // open
  const s2 = scanAt("s2", "2026-01-02T00:00:00Z", withStoreResults); // fixed
  const s3 = scanAt("s3", "2026-01-03T00:00:00Z", noStoreResults); // regressed
  const history = [s1, s2, s3];

  const openToFixed = compareScans(history, "s1", "s2");
  assert.equal(openToFixed.summary.fixed, 1);
  assert.ok(openToFixed.fixed.some((f) => f.finding.controlKey === "AUTH-006"));

  const fixedToRegressed = compareScans(history, "s2", "s3");
  assert.equal(fixedToRegressed.summary.regressed, 1);
  assert.ok(fixedToRegressed.regressed.some((f) => f.finding.controlKey === "AUTH-006"));
  assert.equal(fixedToRegressed.summary.new, 0, "a regression must not be miscounted as NEW");

  fs.rmSync(dirNoStore, { recursive: true, force: true });
  fs.rmSync(dirWithStore, { recursive: true, force: true });
});
