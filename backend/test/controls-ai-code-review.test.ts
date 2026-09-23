import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "fs";
import os from "os";
import path from "path";
import "../src/scanner/controls";
import { getControl } from "../src/scanner/controls/registry";
import { hydrateCheckResult } from "../src/scanner/controls/hydrate";
import { scanAiCodeReviewControl } from "../src/scanner/controls/checks/aiCodeReviewControl";
import { compareScans, type ScanForComparison } from "../src/scanner/scanComparison";
import type { ScanReport, CheckResult } from "../src/scanner/types";

/**
 * AICODE-001/002: the fifth Phase B category (AI-generated code review —
 * master spec §25), entirely new. Several items from the spec's own list
 * (hidden debug routes, suspicious TODO/FIXME, unsafe eval, disabled
 * security checks) are already covered by CQ-002/006/007 and INPUT-003
 * from the codeQuality.ts migration, confirmed via grep before writing
 * anything — this round covers only the genuinely uncovered ones:
 * placeholder credentials and hardcoded-ID authorization bypasses.
 *
 * Both gated on their own applicability: AICODE-001 only when a
 * credential-shaped variable is assigned any string literal at all;
 * AICODE-002 only when the file references a user-ID token or one of the
 * suspiciously-named ID constants at all.
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

test("AICODE-001/002 are registered", () => {
  assert.ok(getControl("AICODE-001"));
  assert.ok(getControl("AICODE-002"));
});

test("scanAiCodeReviewControl: no result at all when neither pattern applies", () => {
  const dir = tmpDir("nettle-aicode-none-");
  const file = writeTempFile(dir, "app.js", `function add(a, b) { return a + b; }\n`);

  assert.equal(scanAiCodeReviewControl([file], dir).length, 0);

  fs.rmSync(dir, { recursive: true, force: true });
});

// --- AICODE-001: placeholder credentials ---

test("scanAiCodeReviewControl: AICODE-001 FAILs for a placeholder API key", () => {
  const dir = tmpDir("nettle-aicode-placeholder-");
  const file = writeTempFile(dir, "config.js", `const OPENAI_API_KEY = "your_api_key_here";\n`);

  const results = scanAiCodeReviewControl([file], dir);
  const result = results.find((r) => r.controlKey === "AICODE-001");
  assert.ok(result);
  assert.equal(result!.status, "FAIL");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanAiCodeReviewControl: AICODE-001 FAILs for CHANGE_ME", () => {
  const dir = tmpDir("nettle-aicode-changeme-");
  const file = writeTempFile(dir, "config.js", `const stripeSecret = "CHANGE_ME";\n`);

  const results = scanAiCodeReviewControl([file], dir);
  assert.equal(results.find((r) => r.controlKey === "AICODE-001")?.status, "FAIL");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanAiCodeReviewControl: AICODE-001 PASSes for a non-placeholder-shaped value (SECRET-001's job, not this control's)", () => {
  const dir = tmpDir("nettle-aicode-envvar-");
  const file = writeTempFile(dir, "config.js", `const apiKey = "abcdef1234567890real-looking-value";\n`);

  const results = scanAiCodeReviewControl([file], dir);
  const result = results.find((r) => r.controlKey === "AICODE-001");
  assert.ok(result);
  assert.equal(result!.status, "PASS");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanAiCodeReviewControl: AICODE-001 produces no result when there's no credential-shaped assignment at all", () => {
  const dir = tmpDir("nettle-aicode-nocred-");
  const file = writeTempFile(dir, "app.js", `const port = process.env.PORT || 3000;\n`);

  assert.equal(scanAiCodeReviewControl([file], dir).find((r) => r.controlKey === "AICODE-001"), undefined);

  fs.rmSync(dir, { recursive: true, force: true });
});

// --- AICODE-002: hardcoded ID bypass ---

test("scanAiCodeReviewControl: AICODE-002 FAILs for a hardcoded userId comparison", () => {
  const dir = tmpDir("nettle-aicode-bypass-");
  const file = writeTempFile(dir, "auth.js", `if (userId === 1) { grantAdminAccess(); }\n`);

  const results = scanAiCodeReviewControl([file], dir);
  const result = results.find((r) => r.controlKey === "AICODE-002");
  assert.ok(result);
  assert.equal(result!.status, "FAIL");
  assert.equal(result!.severity, "critical");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanAiCodeReviewControl: AICODE-002 FAILs for a suspiciously-named hardcoded ID constant", () => {
  const dir = tmpDir("nettle-aicode-constant-");
  const file = writeTempFile(dir, "auth.js", `const ADMIN_ID = 12345;\nif (userId === ADMIN_ID) { grant(); }\n`);

  const results = scanAiCodeReviewControl([file], dir);
  assert.equal(results.find((r) => r.controlKey === "AICODE-002")?.status, "FAIL");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanAiCodeReviewControl: AICODE-002 does not FAIL for a compound condition where the digit is unrelated to the userId comparison", () => {
  const dir = tmpDir("nettle-aicode-compound-");
  const file = writeTempFile(dir, "auth.js", `if (userId === currentUser && retries < 3) { doSomething(); }\n`);

  const results = scanAiCodeReviewControl([file], dir);
  assert.equal(results.find((r) => r.controlKey === "AICODE-002")?.status, "PASS");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanAiCodeReviewControl: AICODE-002 PASSes for a legitimate ownership comparison between two variables", () => {
  const dir = tmpDir("nettle-aicode-ownership-");
  const file = writeTempFile(dir, "auth.js", `if (req.user.id === resource.ownerId) { allow(); }\n`);

  const results = scanAiCodeReviewControl([file], dir);
  const result = results.find((r) => r.controlKey === "AICODE-002");
  assert.ok(result);
  assert.equal(result!.status, "PASS");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanAiCodeReviewControl: AICODE-002 produces no result when there's no user-ID token at all", () => {
  const dir = tmpDir("nettle-aicode-nouserid-");
  const file = writeTempFile(dir, "app.js", `function add(a, b) { return a + b; }\n`);

  assert.equal(scanAiCodeReviewControl([file], dir).find((r) => r.controlKey === "AICODE-002"), undefined);

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanAiCodeReviewControl: NOT_VERIFIED when a file is unreadable and no evidence was found elsewhere", () => {
  const dir = tmpDir("nettle-aicode-unread-");
  const good = writeTempFile(dir, "auth.js", `if (req.user.id === resource.ownerId) { allow(); }\n`);
  const missing = path.join(dir, "missing.js");

  const results = scanAiCodeReviewControl([good, missing], dir);
  const result = results.find((r) => r.controlKey === "AICODE-002");
  assert.ok(result);
  assert.equal(result!.status, "NOT_VERIFIED");

  fs.rmSync(dir, { recursive: true, force: true });
});

// --- hydration ---

test("hydration gives AICODE-001 a real fix", () => {
  const hydrated = hydrateCheckResult(
    { checkId: "x", status: "FAIL", category: "Code Quality", title: "Placeholder credential left in source", severity: "medium", confidence: 85, controlKey: "AICODE-001" },
    { detectedTechnology: "generic" }
  );
  assert.ok(hydrated.recommendation);
  assert.match(hydrated.recommendation!.quickFix, /environment/i);
});

test("hydration gives AICODE-002 a real fix, and its confidence downgrades release impact one step", () => {
  const hydrated = hydrateCheckResult(
    { checkId: "x", status: "FAIL", category: "Code Quality", title: "Hardcoded user ID used as an authorization bypass", severity: "critical", confidence: 60, controlKey: "AICODE-002" },
    { detectedTechnology: "generic" }
  );
  assert.ok(hydrated.recommendation);
  assert.match(hydrated.recommendation!.quickFix, /role|permission/i);
  // critical -> BLOCK_RELEASE, downgraded once at confidence < 75
  assert.equal(hydrated.releaseImpact, "REVIEW_BEFORE_RELEASE");
});

// --- scan comparison: a newly-added Phase B control participates in the diff engine ---

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

test("AICODE-002 participates fully in scan comparison: open -> fixed -> regressed", () => {
  const dirBypass = tmpDir("nettle-aicode-cmp-bypass-");
  writeTempFile(dirBypass, "auth.js", `if (userId === 1) { grantAdminAccess(); }\n`);
  const dirFixed = tmpDir("nettle-aicode-cmp-fixed-");
  writeTempFile(dirFixed, "auth.js", `if (user.role === 'admin') { grantAdminAccess(); }\nconst userId2 = req.params.userId;\n`);

  const bypassResults = scanAiCodeReviewControl([path.join(dirBypass, "auth.js")], dirBypass);
  const fixedResults = scanAiCodeReviewControl([path.join(dirFixed, "auth.js")], dirFixed);

  const s1 = scanAt("s1", "2026-01-01T00:00:00Z", bypassResults); // open
  const s2 = scanAt("s2", "2026-01-02T00:00:00Z", fixedResults); // fixed
  const s3 = scanAt("s3", "2026-01-03T00:00:00Z", bypassResults); // regressed
  const history = [s1, s2, s3];

  const openToFixed = compareScans(history, "s1", "s2");
  assert.ok(openToFixed.fixed.some((f) => f.finding.controlKey === "AICODE-002"));

  const fixedToRegressed = compareScans(history, "s2", "s3");
  assert.ok(fixedToRegressed.regressed.some((f) => f.finding.controlKey === "AICODE-002"));
  assert.equal(fixedToRegressed.summary.new, 0, "a regression must not be miscounted as NEW");

  fs.rmSync(dirBypass, { recursive: true, force: true });
  fs.rmSync(dirFixed, { recursive: true, force: true });
});
