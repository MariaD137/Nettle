import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "fs";
import os from "os";
import path from "path";
import "../src/scanner/controls";
import { getControl } from "../src/scanner/controls/registry";
import { hydrateCheckResult } from "../src/scanner/controls/hydrate";
import { scanSemgrepControl } from "../src/scanner/controls/checks/semgrepControl";
import { isSemgrepAvailable, initializeScanner } from "../src/scanner/initialization";
import { compareScans, type ScanForComparison } from "../src/scanner/scanComparison";
import type { ScanReport, CheckResult } from "../src/scanner/types";

/**
 * Completes the semgrepScanner.ts migration onto the control library.
 * semgrepScanner.ts is deleted; its subprocess-running logic and all 6 AST
 * rules now live in scanSemgrepControl (controls/checks/semgrepControl.ts),
 * with three changes:
 *
 * 1. Two rules with no existing control anywhere in the library (eval
 *    usage, command injection) got new ones: INPUT-003 and INPUT-004.
 * 2. The other four rules detect a risk an existing regex-based control
 *    already owns, but via a genuinely different code shape than that
 *    control's own regex catches (verified directly: NET-001's regex
 *    doesn't match process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
 *    API-002's doesn't match res.setHeader("Access-Control-Allow-Origin",
 *    "*"); DB-001's SQL patterns don't require a .query() call site the way
 *    the AST rule does, and vice versa; SECRET-001's regex requires a
 *    "jwt_secret ="-shaped assignment, not a jwt.sign(payload, "literal")
 *    call site). Rather than inventing near-duplicate controls, these
 *    attach to the SAME existing controlKey (DB-001, SECRET-001, NET-001,
 *    API-002) as complementary, AST-verified evidence.
 * 3. Per-rule PASS, not all-or-nothing: the legacy
 *    scanWithSemgrepCheckResults only emitted PASS for all 6 checks when
 *    EVERY rule was clean — one rule firing meant the other five got no
 *    result at all for that scan (neither PASS nor FAIL), even though
 *    Semgrep genuinely checked them and found nothing. Each rule now
 *    independently reports PASS or FAIL.
 *
 * These tests require the real `semgrep` binary (pinned 1.65.0, present in
 * this environment) to exercise the PASS/FAIL paths meaningfully; the
 * NOT_VERIFIED path is exercised by giving Semgrep an argument it can't
 * process at all.
 */

function writeTempFile(dir: string, name: string, content: string): string {
  const file = path.join(dir, name);
  fs.writeFileSync(file, content, "utf8");
  return file;
}

function tmpDir(prefix: string): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

// isSemgrepAvailable() reads cached metadata that's only populated once
// initializeScanner() has run — call it up front so the skip conditions
// below (evaluated at test-definition time) see the real availability.
initializeScanner();

test("INPUT-003 and INPUT-004 are registered", () => {
  assert.ok(getControl("INPUT-003"));
  assert.ok(getControl("INPUT-004"));
});

test("scanSemgrepControl: always returns exactly one result per rule when nothing fires (per-rule PASS, not all-or-nothing)", { skip: !isSemgrepAvailable() && "semgrep not available in this environment" }, () => {
  const dir = tmpDir("nettle-semgrep-clean-");
  const file = writeTempFile(dir, "clean.js", `function add(a, b) { return a + b; }\n`);

  const results = scanSemgrepControl([file], dir);
  const byKey = Object.fromEntries(results.map((r) => [r.controlKey, r]));

  for (const key of ["INPUT-003", "INPUT-004", "DB-001", "SECRET-001", "NET-001", "API-002"]) {
    assert.equal(byKey[key]?.status, "PASS", `${key} should PASS on clean source`);
    assert.equal(byKey[key]?.detectionMethod, "ast");
    assert.equal(byKey[key]?.confidence, 100);
  }

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanSemgrepControl: FAIL on INPUT-003 for eval() usage, other rules still independently PASS", { skip: !isSemgrepAvailable() && "semgrep not available in this environment" }, () => {
  const dir = tmpDir("nettle-semgrep-eval-");
  const file = writeTempFile(dir, "run.js", `function run(input) { return eval(input); }\n`);

  const results = scanSemgrepControl([file], dir);
  const byKey = Object.fromEntries(results.map((r) => [r.controlKey, r]));

  assert.equal(byKey["INPUT-003"].status, "FAIL");
  assert.equal(byKey["INPUT-003"].severity, "critical");
  assert.equal(byKey["INPUT-003"].confidence, 95);
  assert.equal(byKey["INPUT-003"].detectionMethod, "ast");

  // A rule firing must not suppress the other five rules' own PASS — this
  // is the exact all-or-nothing bug the legacy module had.
  assert.equal(byKey["INPUT-004"].status, "PASS");
  assert.equal(byKey["DB-001"].status, "PASS");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanSemgrepControl: FAIL on INPUT-004 for a shell command built via interpolation", { skip: !isSemgrepAvailable() && "semgrep not available in this environment" }, () => {
  const dir = tmpDir("nettle-semgrep-cmdinj-");
  const file = writeTempFile(dir, "run.js", `const { exec } = require('child_process');\nfunction run(name) { exec(\`ls \${name}\`, () => {}); }\n`);

  const results = scanSemgrepControl([file], dir);
  const byKey = Object.fromEntries(results.map((r) => [r.controlKey, r]));

  assert.equal(byKey["INPUT-004"].status, "FAIL");
  assert.equal(byKey["INPUT-004"].severity, "critical");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanSemgrepControl: FAIL on SECRET-001 for a hardcoded JWT secret passed directly to jwt.sign() (not caught by SECRET-001's own regex)", { skip: !isSemgrepAvailable() && "semgrep not available in this environment" }, () => {
  const dir = tmpDir("nettle-semgrep-jwt-");
  const file = writeTempFile(dir, "auth.js", `const jwt = require('jsonwebtoken');\njwt.sign({ id: 1 }, "hardcoded-secret-value");\n`);

  const results = scanSemgrepControl([file], dir);
  const secretResult = results.find((r) => r.controlKey === "SECRET-001");
  assert.ok(secretResult);
  assert.equal(secretResult!.status, "FAIL");
  assert.equal(secretResult!.detectionMethod, "ast");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanSemgrepControl: FAIL on NET-001 for NODE_TLS_REJECT_UNAUTHORIZED (not caught by NET-001's own regex)", { skip: !isSemgrepAvailable() && "semgrep not available in this environment" }, () => {
  const dir = tmpDir("nettle-semgrep-tls-");
  const file = writeTempFile(dir, "app.js", `process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";\n`);

  const results = scanSemgrepControl([file], dir);
  const netResult = results.find((r) => r.controlKey === "NET-001");
  assert.ok(netResult);
  assert.equal(netResult!.status, "FAIL");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanSemgrepControl: FAIL on API-002 for res.setHeader Access-Control-Allow-Origin wildcard (not caught by API-002's own regex)", { skip: !isSemgrepAvailable() && "semgrep not available in this environment" }, () => {
  const dir = tmpDir("nettle-semgrep-cors-");
  const file = writeTempFile(dir, "app.js", `res.setHeader("Access-Control-Allow-Origin", "*");\n`);

  const results = scanSemgrepControl([file], dir);
  const apiResult = results.find((r) => r.controlKey === "API-002");
  assert.ok(apiResult);
  assert.equal(apiResult!.status, "FAIL");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanSemgrepControl: two FAILs for the same rule in the same file get distinct checkIds (legacy checkId collision fixed)", { skip: !isSemgrepAvailable() && "semgrep not available in this environment" }, () => {
  const dir = tmpDir("nettle-semgrep-multi-");
  const file = writeTempFile(
    dir,
    "run.js",
    `function a(x) { return eval(x); }\nfunction b(y) { return eval(y); }\n`
  );

  const results = scanSemgrepControl([file], dir);
  const evalFails = results.filter((r) => r.controlKey === "INPUT-003" && r.status === "FAIL");
  assert.equal(evalFails.length, 2, "both eval() call sites should be reported");
  assert.notEqual(evalFails[0].checkId, evalFails[1].checkId, "distinct findings must not collide onto the same checkId");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanSemgrepControl: NOT_VERIFIED for all 6 rules when Semgrep fails to run", () => {
  // Semgrep exits non-zero (and thus runSemgrep throws) for a target path
  // that doesn't exist, exercising the same catch path a missing binary
  // would take.
  // A fake .js path (never actually read — files is only used to gate
  // which rules are applicable, by extension) keeps this test about "did
  // the Semgrep-failure path work", not "was a real JS file present".
  const results = scanSemgrepControl(["/nonexistent/fake.js"], "/nonexistent/nettle-semgrep-target-does-not-exist");
  assert.equal(results.length, 6);
  assert.ok(results.every((r) => r.status === "NOT_VERIFIED"));
  assert.ok(results.every((r) => r.confidence === 0));
  assert.ok(results.every((r) => r.detectionMethod === "unknown"));

  const controlKeys = new Set(results.map((r) => r.controlKey));
  for (const key of ["INPUT-003", "INPUT-004", "DB-001", "SECRET-001", "NET-001", "API-002"]) {
    assert.ok(controlKeys.has(key));
  }
});

// --- hydration ---

test("hydration gives INPUT-003 a real fix", () => {
  const hydrated = hydrateCheckResult(
    { checkId: "x", status: "FAIL", category: "Security", title: "eval() usage detected", severity: "critical", confidence: 95, controlKey: "INPUT-003" },
    { detectedTechnology: "generic" }
  );
  assert.ok(hydrated.recommendation);
  assert.match(hydrated.recommendation!.quickFix, /eval/);
});

test("hydration gives INPUT-004 a real fix", () => {
  const hydrated = hydrateCheckResult(
    { checkId: "x", status: "FAIL", category: "Security", title: "Shell command built via string interpolation passed to exec()", severity: "critical", confidence: 95, controlKey: "INPUT-004" },
    { detectedTechnology: "generic" }
  );
  assert.ok(hydrated.recommendation);
  assert.match(hydrated.recommendation!.quickFix, /execFile|spawn/);
});

test("a Semgrep-backed FAIL against an existing control (SECRET-001) hydrates through that control's own recommendation", () => {
  const hydrated = hydrateCheckResult({
    checkId: "x",
    status: "FAIL",
    category: "Security",
    title: "JWT signed or verified with a hardcoded secret (detected via AST analysis)",
    severity: "critical",
    confidence: 95,
    controlKey: "SECRET-001",
  });
  assert.ok(hydrated.recommendation);
  assert.match(hydrated.recommendation!.quickFix, /remove|rotate/i);
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

test("INPUT-003 (a newly-migrated control) participates fully in scan comparison: open -> fixed -> regressed", { skip: !isSemgrepAvailable() && "semgrep not available in this environment" }, () => {
  const dirEval = tmpDir("nettle-semgrep-cmp-eval-");
  const fileEval = writeTempFile(dirEval, "run.js", `function run(input) { return eval(input); }\n`);
  const dirClean = tmpDir("nettle-semgrep-cmp-clean-");
  const fileClean = writeTempFile(dirClean, "run.js", `function run(input) { return JSON.parse(input); }\n`);

  const evalResults = scanSemgrepControl([fileEval], dirEval);
  const cleanResults = scanSemgrepControl([fileClean], dirClean);

  const s1 = scanAt("s1", "2026-01-01T00:00:00Z", evalResults); // open
  const s2 = scanAt("s2", "2026-01-02T00:00:00Z", cleanResults); // fixed
  const s3 = scanAt("s3", "2026-01-03T00:00:00Z", evalResults); // regressed
  const history = [s1, s2, s3];

  const openToFixed = compareScans(history, "s1", "s2");
  assert.ok(openToFixed.fixed.some((f) => f.finding.controlKey === "INPUT-003"));

  const fixedToRegressed = compareScans(history, "s2", "s3");
  assert.ok(fixedToRegressed.regressed.some((f) => f.finding.controlKey === "INPUT-003"));
  assert.equal(fixedToRegressed.summary.new, 0, "a regression must not be miscounted as NEW");

  fs.rmSync(dirEval, { recursive: true, force: true });
  fs.rmSync(dirClean, { recursive: true, force: true });
});
