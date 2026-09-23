import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "fs";
import os from "os";
import path from "path";
import "../src/scanner/controls";
import { getControl } from "../src/scanner/controls/registry";
import { hydrateCheckResult } from "../src/scanner/controls/hydrate";
import { scanFrontendSecurityControl } from "../src/scanner/controls/checks/frontendSecurityControl";
import { compareScans, type ScanForComparison } from "../src/scanner/scanComparison";
import type { ScanReport, CheckResult } from "../src/scanner/types";

/**
 * Completes the frontendSecurity.ts migration onto the control library --
 * the final Phase A module. frontendSecurity.ts itself has been deleted;
 * every check it made now lives in scanFrontendSecurityControl, with three
 * fixes:
 *
 * 1. INLINE_EVENT_PATTERNS was declared in the legacy module but never
 *    actually referenced anywhere in scanFrontendSecurity() -- inline
 *    event-handler detection was dead code that never ran. Now wired in as
 *    FE-003.
 * 2. The source-map check could FAIL but never PASS -- it wasn't in the
 *    legacy module's PASS-emission block at all, the same asymmetric-PASS
 *    defect already fixed repeatedly across this migration. Now FE-004,
 *    with an independent PASS.
 * 3. fs.readFileSync had no try/catch, so one unreadable file would throw
 *    and abort the entire scan.
 *
 * The eval/Function/string-timer group attaches to the existing INPUT-003
 * ("no eval() usage") rather than a new control, since it's largely the
 * same underlying risk INPUT-003 already covers via Semgrep AST elsewhere
 * in the pipeline -- this module adds regex-based, frontend-scoped
 * evidence, and covers new Function()/string-timers, which the AST rule
 * doesn't.
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

const NEW_KEYS = ["FE-001", "FE-002", "FE-003", "FE-004"];

test("FE-001..004 are registered", () => {
  for (const key of NEW_KEYS) {
    assert.ok(getControl(key), `${key} should be registered`);
  }
});

// A file with an isFrontend signal (window./document./etc) is needed for
// PASS assertions, matching the legacy module's own hasFrontendCode gate.
const FRONTEND_MARKER = `window.addEventListener('load', () => {});\n`;

test("scanFrontendSecurityControl: every group independently PASSes on clean frontend source", () => {
  const dir = tmpDir("nettle-fe-clean-");
  const file = writeTempFile(dir, "app.js", FRONTEND_MARKER);

  const results = scanFrontendSecurityControl([file], dir);
  const byKey = Object.fromEntries(results.map((r) => [r.controlKey, r]));

  for (const key of [...NEW_KEYS, "INPUT-003"]) {
    assert.equal(byKey[key]?.status, "PASS", `${key} should PASS on clean frontend source`);
  }

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanFrontendSecurityControl: FE-001 FAILs for a token stored in localStorage", () => {
  const dir = tmpDir("nettle-fe-storage-");
  const file = writeTempFile(dir, "auth.js", `${FRONTEND_MARKER}localStorage.setItem('authToken', token);\n`);

  const results = scanFrontendSecurityControl([file], dir);
  const result = results.find((r) => r.controlKey === "FE-001");
  assert.ok(result);
  assert.equal(result!.status, "FAIL");
  assert.equal(result!.severity, "high");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanFrontendSecurityControl: FE-002 FAILs for dangerouslySetInnerHTML", () => {
  const dir = tmpDir("nettle-fe-html-");
  const file = writeTempFile(dir, "Comment.jsx", `${FRONTEND_MARKER}const el = <div dangerouslySetInnerHTML={{ __html: content }} />;\n`);

  const results = scanFrontendSecurityControl([file], dir);
  const result = results.find((r) => r.controlKey === "FE-002");
  assert.ok(result);
  assert.equal(result!.status, "FAIL");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanFrontendSecurityControl: FE-003 FAILs for an inline event handler (the legacy check never ran this pattern at all)", () => {
  const dir = tmpDir("nettle-fe-inline-");
  const file = writeTempFile(dir, "index.html.js", `${FRONTEND_MARKER}const markup = '<button onclick="handleClick()">Go</button>';\n`);

  const results = scanFrontendSecurityControl([file], dir);
  const result = results.find((r) => r.controlKey === "FE-003");
  assert.ok(result, "FE-003 should now fire — this pattern was dead code in the legacy module");
  assert.equal(result!.status, "FAIL");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanFrontendSecurityControl: FE-004 PASSes and FAILs independently (the legacy check could only ever FAIL)", () => {
  const dirClean = tmpDir("nettle-fe-nomap-");
  const cleanFile = writeTempFile(dirClean, "app.js", FRONTEND_MARKER);
  const cleanResults = scanFrontendSecurityControl([cleanFile], dirClean);
  assert.equal(cleanResults.find((r) => r.controlKey === "FE-004")?.status, "PASS");

  const dirMap = tmpDir("nettle-fe-map-");
  const mapFile = writeTempFile(dirMap, "app.js", `${FRONTEND_MARKER}//# sourceMappingURL=app.js.map\n`);
  const mapResults = scanFrontendSecurityControl([mapFile], dirMap);
  assert.equal(mapResults.find((r) => r.controlKey === "FE-004")?.status, "FAIL");

  fs.rmSync(dirClean, { recursive: true, force: true });
  fs.rmSync(dirMap, { recursive: true, force: true });
});

test("scanFrontendSecurityControl: eval()/new Function()/string-timers attach to the existing INPUT-003, not a new control", () => {
  const dir = tmpDir("nettle-fe-eval-");
  const file = writeTempFile(dir, "app.js", `${FRONTEND_MARKER}new Function('return ' + x)();\n`);

  const results = scanFrontendSecurityControl([file], dir);
  const result = results.find((r) => r.status === "FAIL" && r.detail?.includes("eval()"));
  assert.ok(result);
  assert.equal(result!.controlKey, "INPUT-003");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanFrontendSecurityControl: no result at all when nothing looks like frontend code (matches the legacy hasFrontendCode gate)", () => {
  const dir = tmpDir("nettle-fe-notfrontend-");
  const file = writeTempFile(dir, "util.js", `function add(a, b) { return a + b; }\n`);

  assert.equal(scanFrontendSecurityControl([file], dir).length, 0);

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanFrontendSecurityControl: NOT_VERIFIED when a frontend file is unreadable and its check didn't otherwise fire", () => {
  const dir = tmpDir("nettle-fe-unread-");
  const good = writeTempFile(dir, "app.js", FRONTEND_MARKER);
  const missing = path.join(dir, "missing.js");

  const results = scanFrontendSecurityControl([good, missing], dir);
  const byKey = Object.fromEntries(results.map((r) => [r.controlKey, r]));

  for (const key of NEW_KEYS) {
    assert.equal(byKey[key]?.status, "NOT_VERIFIED", `${key} should be NOT_VERIFIED when a file was unreadable`);
  }

  fs.rmSync(dir, { recursive: true, force: true });
});

// --- hydration ---

test("hydration gives FE-001 a real fix", () => {
  const hydrated = hydrateCheckResult(
    { checkId: "x", status: "FAIL", category: "Frontend Security", title: "Sensitive data stored in localStorage/sessionStorage", severity: "high", confidence: 85, controlKey: "FE-001" },
    { detectedTechnology: "generic" }
  );
  assert.ok(hydrated.recommendation);
  assert.match(hydrated.recommendation!.quickFix, /HttpOnly/);
});

test("hydration gives FE-002 a technology-specific React fix", () => {
  const hydrated = hydrateCheckResult(
    { checkId: "x", status: "FAIL", category: "Frontend Security", title: "Unescaped HTML injection", severity: "high", confidence: 85, controlKey: "FE-002" },
    { detectedTechnology: "react" }
  );
  assert.ok(hydrated.recommendation);
  assert.equal(hydrated.recommendation!.technologyMatched, "react");
  assert.match(hydrated.recommendation!.quickFix, /DOMPurify|JSX/);
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

test("FE-003 (a newly-wired, previously-dead-code control) participates fully in scan comparison: open -> fixed -> regressed", () => {
  const dirInline = tmpDir("nettle-fe-cmp-inline-");
  writeTempFile(dirInline, "index.js", `${FRONTEND_MARKER}const markup = '<button onclick="go()">Go</button>';\n`);
  const dirClean = tmpDir("nettle-fe-cmp-clean-");
  writeTempFile(dirClean, "index.js", FRONTEND_MARKER);

  const inlineResults = scanFrontendSecurityControl([path.join(dirInline, "index.js")], dirInline);
  const cleanResults = scanFrontendSecurityControl([path.join(dirClean, "index.js")], dirClean);

  const s1 = scanAt("s1", "2026-01-01T00:00:00Z", inlineResults); // open
  const s2 = scanAt("s2", "2026-01-02T00:00:00Z", cleanResults); // fixed
  const s3 = scanAt("s3", "2026-01-03T00:00:00Z", inlineResults); // regressed
  const history = [s1, s2, s3];

  const openToFixed = compareScans(history, "s1", "s2");
  assert.ok(openToFixed.fixed.some((f) => f.finding.controlKey === "FE-003"));

  const fixedToRegressed = compareScans(history, "s2", "s3");
  assert.ok(fixedToRegressed.regressed.some((f) => f.finding.controlKey === "FE-003"));
  assert.equal(fixedToRegressed.summary.new, 0, "a regression must not be miscounted as NEW");

  fs.rmSync(dirInline, { recursive: true, force: true });
  fs.rmSync(dirClean, { recursive: true, force: true });
});
