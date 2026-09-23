import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "fs";
import os from "os";
import path from "path";
import "../src/scanner/controls";
import { getControl } from "../src/scanner/controls/registry";
import { hydrateCheckResult } from "../src/scanner/controls/hydrate";
import { scanAiContentDisclosureControl } from "../src/scanner/controls/checks/aiContentDisclosureControl";
import { compareScans, type ScanForComparison } from "../src/scanner/scanComparison";
import type { ScanReport, CheckResult } from "../src/scanner/types";

/**
 * Completes the aiDisclosure.ts migration onto the control library
 * (AI-005). aiDisclosure.ts itself has been deleted; its one check now
 * lives in scanAiContentDisclosureControl, with two fixes:
 *
 * 1. The legacy module called fs.readFileSync with no try/catch, so one
 *    unreadable file would throw and abort the entire scan -- same defect
 *    class already fixed for SECRET-001.
 * 2. The detection terminology ("generate", "avatar", ai-image/ai-content
 *    variants) is deliberately broad and matches plenty of ordinary,
 *    non-AI features (an /avatar upload route, for instance). The legacy
 *    finding asserted "California SB 942 requires this kind of content to
 *    be labeled" as settled fact from that weak signal. Confidence is now
 *    40 (triggers the release gate's two-step low-confidence downgrade)
 *    and the language was softened to a review prompt, matching the same
 *    legal-framing correction applied to LEGAL-001/003 in the previous
 *    round.
 */

function writeTempFile(dir: string, name: string, content: string): string {
  const file = path.join(dir, name);
  fs.writeFileSync(file, content, "utf8");
  return file;
}

function tmpDir(prefix: string): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

test("AI-005 is registered", () => {
  assert.ok(getControl("AI-005"));
});

test("scanAiContentDisclosureControl: FAIL when content-generation terminology is present with no disclosure marker", () => {
  const dir = tmpDir("nettle-aidisc-");
  const file = writeTempFile(dir, "images.js", `async function generateAvatar(prompt) { return await ai.generate(prompt); }\n`);

  const results = scanAiContentDisclosureControl([file], dir);
  assert.equal(results.length, 1);
  assert.equal(results[0].status, "FAIL");
  assert.equal(results[0].controlKey, "AI-005");
  assert.equal(results[0].severity, "high");
  assert.equal(results[0].confidence, 40, "weak/generic heuristic must carry low confidence, not asserted certainty");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanAiContentDisclosureControl: PASS when a disclosure marker is present alongside content-generation terminology", () => {
  const dir = tmpDir("nettle-aidisc-");
  const file = writeTempFile(
    dir,
    "images.js",
    `async function generateAvatar(prompt) { return await ai.generate(prompt); }\n// AI-generated content notice shown in UI\n`
  );

  const results = scanAiContentDisclosureControl([file], dir);
  assert.equal(results.length, 1);
  assert.equal(results[0].status, "PASS");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanAiContentDisclosureControl: no unearned finding when there's no content-generation terminology at all", () => {
  const dir = tmpDir("nettle-aidisc-");
  const file = writeTempFile(dir, "util.js", `function add(a, b) { return a + b; }\n`);

  assert.equal(scanAiContentDisclosureControl([file], dir).length, 0);

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanAiContentDisclosureControl: NOT_VERIFIED when a file is unreadable and no signal was found elsewhere (legacy code would have thrown here)", () => {
  const dir = tmpDir("nettle-aidisc-unread-");
  const missing = path.join(dir, "does-not-exist.js");

  const results = scanAiContentDisclosureControl([missing], dir);
  assert.equal(results.length, 1);
  assert.equal(results[0].status, "NOT_VERIFIED");
  assert.equal(results[0].controlKey, "AI-005");

  fs.rmSync(dir, { recursive: true, force: true });
});

// --- hydration ---

test("hydration gives AI-005 a real fix, and its low confidence downgrades release impact two steps below its high default", () => {
  const hydrated = hydrateCheckResult({
    checkId: "x",
    status: "FAIL",
    category: "AI Disclosure",
    title: "Possible AI-generated content with no visible disclosure marker",
    severity: "high",
    confidence: 40,
    controlKey: "AI-005",
  });
  assert.ok(hydrated.recommendation);
  assert.match(hydrated.recommendation!.quickFix, /disclosure|label/i);
  // high -> REVIEW_BEFORE_RELEASE, downgraded twice at confidence < 50
  assert.equal(hydrated.releaseImpact, "IMPROVEMENT");
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

test("AI-005 (a newly-migrated control) participates fully in scan comparison: open -> fixed -> regressed", () => {
  const dirNoDisclosure = tmpDir("nettle-aidisc-cmp-none-");
  writeTempFile(dirNoDisclosure, "images.js", `async function generateAvatar(prompt) { return await ai.generate(prompt); }\n`);
  const dirWithDisclosure = tmpDir("nettle-aidisc-cmp-disc-");
  writeTempFile(
    dirWithDisclosure,
    "images.js",
    `async function generateAvatar(prompt) { return await ai.generate(prompt); }\n// AI-generated content notice shown in UI\n`
  );

  const noDisclosureResults = scanAiContentDisclosureControl([path.join(dirNoDisclosure, "images.js")], dirNoDisclosure);
  const withDisclosureResults = scanAiContentDisclosureControl([path.join(dirWithDisclosure, "images.js")], dirWithDisclosure);

  const s1 = scanAt("s1", "2026-01-01T00:00:00Z", noDisclosureResults); // open
  const s2 = scanAt("s2", "2026-01-02T00:00:00Z", withDisclosureResults); // fixed
  const s3 = scanAt("s3", "2026-01-03T00:00:00Z", noDisclosureResults); // regressed
  const history = [s1, s2, s3];

  const openToFixed = compareScans(history, "s1", "s2");
  assert.equal(openToFixed.summary.fixed, 1);
  assert.ok(openToFixed.fixed.some((f) => f.finding.controlKey === "AI-005"));

  const fixedToRegressed = compareScans(history, "s2", "s3");
  assert.equal(fixedToRegressed.summary.regressed, 1);
  assert.ok(fixedToRegressed.regressed.some((f) => f.finding.controlKey === "AI-005"));
  assert.equal(fixedToRegressed.summary.new, 0, "a regression must not be miscounted as NEW");

  fs.rmSync(dirNoDisclosure, { recursive: true, force: true });
  fs.rmSync(dirWithDisclosure, { recursive: true, force: true });
});
