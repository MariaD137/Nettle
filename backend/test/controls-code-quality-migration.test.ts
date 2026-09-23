import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "fs";
import os from "os";
import path from "path";
import "../src/scanner/controls";
import { getControl } from "../src/scanner/controls/registry";
import { hydrateCheckResult } from "../src/scanner/controls/hydrate";
import { scanCodeQualityControl } from "../src/scanner/controls/checks/codeQualityControl";
import { compareScans, type ScanForComparison } from "../src/scanner/scanComparison";
import type { ScanReport, CheckResult } from "../src/scanner/types";

/**
 * Completes the codeQuality.ts migration onto the control library
 * (CQ-001..007, SECRET-002). codeQuality.ts itself has been deleted; every
 * check it made now lives in scanCodeQualityControl, with two fixes:
 *
 * 1. Only 3 of 7 CHECKS-array items ever emitted PASS, and two of those
 *    three (stack traces, verbose errors) were joined by an AND — either
 *    one firing suppressed the other's PASS even though it was
 *    independently clean. The other 4 checks never emitted PASS at all.
 *    Every control here now independently reports PASS when clean.
 * 2. fs.readFileSync had no try/catch, so one unreadable file would throw
 *    and abort the entire scan.
 */

function writeTempFile(dir: string, name: string, content: string): string {
  const file = path.join(dir, name);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, content, "utf8");
  return file;
}

function tmpDir(prefix: string): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

const ALL_KEYS = ["CQ-001", "CQ-002", "CQ-003", "CQ-004", "CQ-005", "CQ-006", "CQ-007", "SECRET-002"];

test("CQ-001..007 and SECRET-002 are registered", () => {
  for (const key of ALL_KEYS) {
    assert.ok(getControl(key), `${key} should be registered`);
  }
});

test("scanCodeQualityControl: every control independently PASSes on clean source (the legacy check only ever emitted 3 of 8)", () => {
  const dir = tmpDir("nettle-cq-clean-");
  const file = writeTempFile(dir, "app.js", `function add(a, b) { return a + b; }\n`);

  const results = scanCodeQualityControl([file], dir);
  const byKey = Object.fromEntries(results.map((r) => [r.controlKey, r]));

  for (const key of ALL_KEYS) {
    assert.equal(byKey[key]?.status, "PASS", `${key} should PASS on clean source`);
  }

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanCodeQualityControl: CQ-001 FAILs only at 3+ console calls in one file, not 1-2 (matchAll threshold preserved)", () => {
  const dirFew = tmpDir("nettle-cq-fewlogs-");
  const fewFile = writeTempFile(dirFew, "app.js", `console.log("a");\nconsole.log("b");\n`);
  const fewResults = scanCodeQualityControl([fewFile], dirFew);
  assert.equal(fewResults.find((r) => r.controlKey === "CQ-001")?.status, "PASS");

  const dirMany = tmpDir("nettle-cq-manylogs-");
  const manyFile = writeTempFile(dirMany, "app.js", `console.log("a");\nconsole.log("b");\nconsole.log("c");\n`);
  const manyResults = scanCodeQualityControl([manyFile], dirMany);
  assert.equal(manyResults.find((r) => r.controlKey === "CQ-001")?.status, "FAIL");

  fs.rmSync(dirFew, { recursive: true, force: true });
  fs.rmSync(dirMany, { recursive: true, force: true });
});

test("scanCodeQualityControl: CQ-004 and CQ-005 are independent (one firing doesn't suppress the other's PASS)", () => {
  const dir = tmpDir("nettle-cq-independent-");
  // Only CQ-004 (stack trace) fires; CQ-005 (raw error object) never appears.
  const file = writeTempFile(dir, "app.js", `app.get('/x', (req, res) => { res.json({ error: err.stack }); });\n`);

  const results = scanCodeQualityControl([file], dir);
  const byKey = Object.fromEntries(results.map((r) => [r.controlKey, r]));

  assert.equal(byKey["CQ-004"].status, "FAIL");
  // The legacy joined check would have suppressed CQ-005's PASS here too.
  assert.equal(byKey["CQ-005"].status, "PASS");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanCodeQualityControl: FAIL for each of the remaining checks", () => {
  const cases: Array<[string, string]> = [
    ["CQ-002", `// TODO: fix auth bypass before real launch\n`],
    ["CQ-003", `const config = { debug: true };\n`],
    ["CQ-006", `app.get("/debug/status", handler);\n`],
    ["CQ-007", `// eslint-disable-next-line no-eval\n`],
  ];

  for (const [key, content] of cases) {
    const dir = tmpDir(`nettle-cq-${key}-`);
    const file = writeTempFile(dir, "app.js", content);
    const results = scanCodeQualityControl([file], dir);
    const result = results.find((r) => r.controlKey === key);
    assert.ok(result, `expected a result for ${key}`);
    assert.equal(result!.status, "FAIL", `${key} should FAIL for: ${content}`);
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("scanCodeQualityControl: SECRET-002 FAILs for a committed .env file and skips content checks on it", () => {
  const dir = tmpDir("nettle-cq-env-");
  // Three console.log calls inside the .env file's own content — should NOT
  // also trip CQ-001, matching the legacy "continue" behavior for .env
  // files. A second, ordinary clean file is included so CQ-001 has
  // something to actually assert PASS against.
  const envFile = writeTempFile(dir, ".env", `console.log(1);\nconsole.log(2);\nconsole.log(3);\nSECRET=abc\n`);
  const jsFile = writeTempFile(dir, "app.js", `function add(a, b) { return a + b; }\n`);

  const results = scanCodeQualityControl([envFile, jsFile], dir);
  const byKey = Object.fromEntries(results.map((r) => [r.controlKey, r]));

  assert.equal(byKey["SECRET-002"].status, "FAIL");
  assert.equal(byKey["SECRET-002"].severity, "critical");
  assert.equal(byKey["CQ-001"]?.status, "PASS", ".env content must not also be run through the CQ content checks");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanCodeQualityControl: NOT_VERIFIED when a file is unreadable and its check didn't otherwise fire", () => {
  const dir = tmpDir("nettle-cq-unread-");
  const missing = path.join(dir, "does-not-exist.js");

  const results = scanCodeQualityControl([missing], dir);
  const byKey = Object.fromEntries(results.map((r) => [r.controlKey, r]));

  for (const key of ["CQ-001", "CQ-002", "CQ-003", "CQ-004", "CQ-005", "CQ-006", "CQ-007"]) {
    assert.equal(byKey[key]?.status, "NOT_VERIFIED", `${key} should be NOT_VERIFIED when its only input was unreadable`);
  }

  fs.rmSync(dir, { recursive: true, force: true });
});

// --- hydration ---

test("hydration gives CQ-004 a real fix", () => {
  const hydrated = hydrateCheckResult(
    { checkId: "x", status: "FAIL", category: "Code Quality", title: "Stack traces returned to client", severity: "high", confidence: 90, controlKey: "CQ-004" },
    { detectedTechnology: "generic" }
  );
  assert.ok(hydrated.recommendation);
  assert.match(hydrated.recommendation!.quickFix, /generic error/i);
});

test("hydration gives SECRET-002 a real fix", () => {
  const hydrated = hydrateCheckResult(
    { checkId: "x", status: "FAIL", category: "Security", title: "Environment file committed to source", severity: "critical", confidence: 95, controlKey: "SECRET-002" },
    { detectedTechnology: "generic" }
  );
  assert.ok(hydrated.recommendation);
  assert.match(hydrated.recommendation!.quickFix, /gitignore/i);
  assert.equal(hydrated.releaseImpact, "BLOCK_RELEASE");
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

test("CQ-005 (a newly-migrated, previously-suppressed-PASS control) participates fully in scan comparison: open -> fixed -> regressed", () => {
  const dirVerbose = tmpDir("nettle-cq-cmp-verbose-");
  writeTempFile(dirVerbose, "app.js", `try { foo(); } catch (err) { res.json(err); }\n`);
  const dirClean = tmpDir("nettle-cq-cmp-clean-");
  writeTempFile(dirClean, "app.js", `try { foo(); } catch (err) { res.status(500).json({ error: 'Internal server error' }); }\n`);

  const verboseResults = scanCodeQualityControl([path.join(dirVerbose, "app.js")], dirVerbose);
  const cleanResults = scanCodeQualityControl([path.join(dirClean, "app.js")], dirClean);

  const s1 = scanAt("s1", "2026-01-01T00:00:00Z", verboseResults); // open
  const s2 = scanAt("s2", "2026-01-02T00:00:00Z", cleanResults); // fixed
  const s3 = scanAt("s3", "2026-01-03T00:00:00Z", verboseResults); // regressed
  const history = [s1, s2, s3];

  const openToFixed = compareScans(history, "s1", "s2");
  assert.ok(openToFixed.fixed.some((f) => f.finding.controlKey === "CQ-005"));

  const fixedToRegressed = compareScans(history, "s2", "s3");
  assert.ok(fixedToRegressed.regressed.some((f) => f.finding.controlKey === "CQ-005"));
  assert.equal(fixedToRegressed.summary.new, 0, "a regression must not be miscounted as NEW");

  fs.rmSync(dirVerbose, { recursive: true, force: true });
  fs.rmSync(dirClean, { recursive: true, force: true });
});
