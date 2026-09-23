import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "fs";
import os from "os";
import path from "path";
import "../src/scanner/controls";
import { getControl } from "../src/scanner/controls/registry";
import { hydrateCheckResult } from "../src/scanner/controls/hydrate";
import { scanCookieSecurityControl } from "../src/scanner/controls/checks/cookieSecurityControl";
import { scanCsrfControl } from "../src/scanner/controls/checks/csrfControl";
import { scanInputValidationControl } from "../src/scanner/controls/checks/inputValidationControl";
import { scanRequestSizeControl } from "../src/scanner/controls/checks/requestSizeControl";
import { scanFileUploadControl } from "../src/scanner/controls/checks/fileUploadControl";
import { scanDeserializationControl } from "../src/scanner/controls/checks/deserializationControl";
import { compareScans, type ScanForComparison } from "../src/scanner/scanComparison";
import type { ScanReport } from "../src/scanner/types";

/**
 * Completes the apiSecurity.ts migration onto the control library (AUTH-004,
 * API-003..006, INPUT-002) -- the last checks in that module that hadn't
 * already been promoted in earlier rounds (rate limiting -> API-001, CORS ->
 * API-002, path traversal -> INPUT-001, HTTPS/TLS -> NET-001). apiSecurity.ts
 * itself has been deleted; every check it made now lives here.
 */

function writeTempFile(dir: string, name: string, content: string): string {
  const file = path.join(dir, name);
  fs.writeFileSync(file, content, "utf8");
  return file;
}

function tmpDir(prefix: string): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

test("AUTH-004, API-003..006, and INPUT-002 are registered", () => {
  for (const key of ["AUTH-004", "API-003", "API-004", "API-005", "API-006", "INPUT-002"]) {
    assert.ok(getControl(key), `${key} should be registered`);
  }
});

// --- AUTH-004: cookie security ---

test("scanCookieSecurityControl: FAIL for each missing flag when cookies are set without any", () => {
  const dir = tmpDir("nettle-cookie-");
  const file = writeTempFile(dir, "server.js", `res.cookie('session', token);\n`);

  const results = scanCookieSecurityControl([file], dir);
  const fails = results.filter((r) => r.status === "FAIL");
  assert.equal(fails.length, 3);
  assert.ok(fails.every((r) => r.controlKey === "AUTH-004"));
  assert.ok(fails.some((r) => r.title.includes("HttpOnly") && r.severity === "high"));
  assert.ok(fails.some((r) => r.title.includes("Secure") && r.severity === "medium"));
  assert.ok(fails.some((r) => r.title.includes("SameSite") && r.severity === "medium"));

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanCookieSecurityControl: all PASS when every flag is set", () => {
  const dir = tmpDir("nettle-cookie-");
  const file = writeTempFile(dir, "server.js", `res.cookie('session', token, { httpOnly: true, secure: true, sameSite: 'strict' });\n`);

  const results = scanCookieSecurityControl([file], dir);
  assert.equal(results.length, 3);
  assert.ok(results.every((r) => r.status === "PASS" && r.controlKey === "AUTH-004"));

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanCookieSecurityControl: no unearned finding when no cookies are set at all", () => {
  const dir = tmpDir("nettle-cookie-");
  const file = writeTempFile(dir, "server.js", `app.get('/', (req, res) => res.send('hi'));\n`);

  assert.equal(scanCookieSecurityControl([file], dir).length, 0);

  fs.rmSync(dir, { recursive: true, force: true });
});

// --- API-003: CSRF ---

test("scanCsrfControl: FAIL when cookies are used but no CSRF pattern is present", () => {
  const dir = tmpDir("nettle-csrf-");
  const file = writeTempFile(dir, "server.js", `res.cookie('session', token, { httpOnly: true });\n`);

  const results = scanCsrfControl([file], dir);
  assert.equal(results.length, 1);
  assert.equal(results[0].status, "FAIL");
  assert.equal(results[0].controlKey, "API-003");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanCsrfControl: PASS when a CSRF pattern is present alongside cookies", () => {
  const dir = tmpDir("nettle-csrf-");
  const file = writeTempFile(dir, "server.js", `res.cookie('session', token);\napp.use(csrf());\n`);

  const results = scanCsrfControl([file], dir);
  assert.equal(results.length, 1);
  assert.equal(results[0].status, "PASS");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanCsrfControl: not applicable when the app doesn't use cookies at all", () => {
  const dir = tmpDir("nettle-csrf-");
  const file = writeTempFile(dir, "server.js", `app.get('/', (req, res) => res.json({}));\n`);

  assert.equal(scanCsrfControl([file], dir).length, 0);

  fs.rmSync(dir, { recursive: true, force: true });
});

// --- API-004: input validation ---

test("scanInputValidationControl: FAIL when routes accept a body but no validation library is present", () => {
  const dir = tmpDir("nettle-inputval-");
  const file = writeTempFile(dir, "server.js", `app.post('/users', (req, res) => { db.insert(req.body); });\n`);

  const results = scanInputValidationControl([file], dir);
  assert.equal(results.length, 1);
  assert.equal(results[0].status, "FAIL");
  assert.equal(results[0].controlKey, "API-004");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanInputValidationControl: PASS when a validation library is imported", () => {
  const dir = tmpDir("nettle-inputval-");
  const file = writeTempFile(dir, "server.js", `import { z } from 'zod';\napp.post('/users', (req, res) => { schema.parse(req.body); });\n`);

  const results = scanInputValidationControl([file], dir);
  assert.equal(results.length, 1);
  assert.equal(results[0].status, "PASS");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanInputValidationControl: not applicable when no route accepts a body", () => {
  const dir = tmpDir("nettle-inputval-");
  const file = writeTempFile(dir, "server.js", `app.get('/users', (req, res) => res.json([]));\n`);

  assert.equal(scanInputValidationControl([file], dir).length, 0);

  fs.rmSync(dir, { recursive: true, force: true });
});

// --- API-005: request size limit ---

test("scanRequestSizeControl: FAIL when a body parser is used without a limit", () => {
  const dir = tmpDir("nettle-reqsize-");
  const file = writeTempFile(dir, "server.js", `app.use(express.json());\n`);

  const results = scanRequestSizeControl([file], dir);
  assert.equal(results.length, 1);
  assert.equal(results[0].status, "FAIL");
  assert.equal(results[0].controlKey, "API-005");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanRequestSizeControl: PASS when a limit is configured", () => {
  const dir = tmpDir("nettle-reqsize-");
  const file = writeTempFile(dir, "server.js", `app.use(express.json({ limit: '1mb' }));\n`);

  const results = scanRequestSizeControl([file], dir);
  assert.equal(results.length, 1);
  assert.equal(results[0].status, "PASS");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanRequestSizeControl: not applicable when no body parser is used", () => {
  const dir = tmpDir("nettle-reqsize-");
  const file = writeTempFile(dir, "server.js", `app.get('/', (req, res) => res.send('hi'));\n`);

  assert.equal(scanRequestSizeControl([file], dir).length, 0);

  fs.rmSync(dir, { recursive: true, force: true });
});

// --- API-006: file upload ---

test("scanFileUploadControl: FAIL for both size and type when neither is configured", () => {
  const dir = tmpDir("nettle-upload-");
  const file = writeTempFile(dir, "server.js", `const upload = multer({ dest: 'uploads/' });\n`);

  const results = scanFileUploadControl([file], dir);
  const fails = results.filter((r) => r.status === "FAIL");
  assert.equal(fails.length, 2);
  assert.ok(fails.every((r) => r.controlKey === "API-006" && r.severity === "high"));
  assert.ok(fails.some((r) => r.title.includes("size limit")));
  assert.ok(fails.some((r) => r.title.includes("MIME type")));

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanFileUploadControl: both PASS when size limit and type check are configured", () => {
  const dir = tmpDir("nettle-upload-");
  const file = writeTempFile(
    dir,
    "server.js",
    `const upload = multer({ limits: { fileSize: 5000000 }, fileFilter: (req, file, cb) => cb(null, true) });\n`
  );

  const results = scanFileUploadControl([file], dir);
  assert.equal(results.length, 2);
  assert.ok(results.every((r) => r.status === "PASS"));

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanFileUploadControl: not applicable when no upload handling is present", () => {
  const dir = tmpDir("nettle-upload-");
  const file = writeTempFile(dir, "server.js", `app.get('/', (req, res) => res.send('hi'));\n`);

  assert.equal(scanFileUploadControl([file], dir).length, 0);

  fs.rmSync(dir, { recursive: true, force: true });
});

// --- INPUT-002: unsafe deserialization ---

test("scanDeserializationControl: FAIL when request input flows into an unsafe deserializer", () => {
  const dir = tmpDir("nettle-deser-");
  const file = writeTempFile(dir, "server.js", `const data = JSON.parse(req.body.raw);\n`);

  const results = scanDeserializationControl([file], dir);
  const fail = results.find((r) => r.status === "FAIL");
  assert.ok(fail);
  assert.equal(fail!.controlKey, "INPUT-002");
  assert.equal(fail!.severity, "high");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanDeserializationControl: PASS when no unsafe pattern is present", () => {
  const dir = tmpDir("nettle-deser-");
  const file = writeTempFile(dir, "server.js", `const data = JSON.parse(rawConfigString);\n`);

  const results = scanDeserializationControl([file], dir);
  assert.equal(results.length, 1);
  assert.equal(results[0].status, "PASS");

  fs.rmSync(dir, { recursive: true, force: true });
});

// --- hydration ---

test("hydration gives AUTH-004 a real fix", () => {
  const hydrated = hydrateCheckResult(
    { checkId: "x", status: "FAIL", category: "Session Management", title: "Cookies set without HttpOnly flag", severity: "high", confidence: 75, controlKey: "AUTH-004" },
    { detectedTechnology: "express" }
  );
  assert.ok(hydrated.recommendation);
  assert.match(hydrated.recommendation!.quickFix, /flags/);
  assert.equal(hydrated.releaseImpact, "REVIEW_BEFORE_RELEASE");
});

test("hydration gives API-006 a real fix", () => {
  const hydrated = hydrateCheckResult(
    { checkId: "x", status: "FAIL", category: "API Security", title: "File uploads without size limit", severity: "high", confidence: 70, controlKey: "API-006" },
    { detectedTechnology: "express" }
  );
  assert.ok(hydrated.recommendation);
  assert.match(hydrated.recommendation!.quickFix, /fileSize/);
});

test("hydration gives INPUT-002 a real fix and blocks release at critical severity with high confidence", () => {
  const hydrated = hydrateCheckResult({
    checkId: "x",
    status: "FAIL",
    category: "Security",
    title: "Potentially unsafe deserialization",
    severity: "critical",
    confidence: 90,
    controlKey: "INPUT-002",
  });
  assert.ok(hydrated.recommendation);
  assert.equal(hydrated.releaseImpact, "BLOCK_RELEASE");
});

test("hydration downgrades INPUT-002's release impact one step at the detector's real (sub-75) confidence", () => {
  // scanDeserializationControl always emits confidence: 70 -- below the
  // releaseGate's 75 threshold, so even a critical-severity real finding is
  // one step less certain than a hand-picked confidence:90 example. This
  // locks in that the detector's actual confidence, not an idealized one,
  // is what drives the release gate.
  const hydrated = hydrateCheckResult({
    checkId: "x",
    status: "FAIL",
    category: "Security",
    title: "Potentially unsafe deserialization",
    severity: "critical",
    confidence: 70,
    controlKey: "INPUT-002",
  });
  assert.equal(hydrated.releaseImpact, "REVIEW_BEFORE_RELEASE");
});

// --- scan comparison: a newly-migrated finding participates in the diff engine ---

function report(checkResults: ReturnType<typeof scanDeserializationControl>): ScanReport {
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

function scanAt(id: string, scannedAt: string, checkResults: ReturnType<typeof scanDeserializationControl>): ScanForComparison {
  return { id, scannedAt, status: "COMPLETED", report: report(checkResults) };
}

test("INPUT-002 (a newly-migrated control) participates fully in scan comparison: open -> fixed -> regressed", () => {
  const dirVuln = tmpDir("nettle-deser-cmp-vuln-");
  writeTempFile(dirVuln, "server.js", `const data = JSON.parse(req.body.raw);\n`);
  const dirFixed = tmpDir("nettle-deser-cmp-fixed-");
  writeTempFile(dirFixed, "server.js", `const data = JSON.parse(rawConfigString);\n`);

  const vulnResults = scanDeserializationControl([path.join(dirVuln, "server.js")], dirVuln);
  const fixedResults = scanDeserializationControl([path.join(dirFixed, "server.js")], dirFixed);

  const s1 = scanAt("s1", "2026-01-01T00:00:00Z", vulnResults); // open
  const s2 = scanAt("s2", "2026-01-02T00:00:00Z", fixedResults); // fixed
  const s3 = scanAt("s3", "2026-01-03T00:00:00Z", vulnResults); // regressed
  const history = [s1, s2, s3];

  const openToFixed = compareScans(history, "s1", "s2");
  assert.equal(openToFixed.summary.fixed, 1);
  assert.ok(openToFixed.fixed.some((f) => f.finding.controlKey === "INPUT-002"));

  const fixedToRegressed = compareScans(history, "s2", "s3");
  assert.equal(fixedToRegressed.summary.regressed, 1);
  assert.ok(fixedToRegressed.regressed.some((f) => f.finding.controlKey === "INPUT-002"));
  assert.equal(fixedToRegressed.summary.new, 0, "a regression must not be miscounted as NEW");

  fs.rmSync(dirVuln, { recursive: true, force: true });
  fs.rmSync(dirFixed, { recursive: true, force: true });
});
