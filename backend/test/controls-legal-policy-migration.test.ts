import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "fs";
import os from "os";
import path from "path";
import "../src/scanner/controls";
import { getControl } from "../src/scanner/controls/registry";
import { hydrateCheckResult } from "../src/scanner/controls/hydrate";
import { scanLegalPolicyControl } from "../src/scanner/controls/checks/legalPolicyControl";
import { compareScans, type ScanForComparison } from "../src/scanner/scanComparison";
import type { ScanReport, CheckResult } from "../src/scanner/types";

/**
 * Completes the legalPolicy.ts migration onto the control library
 * (LEGAL-001..004). legalPolicy.ts itself has been deleted; every check it
 * made now lives in scanLegalPolicyControl, with two changes:
 *
 * 1. Recursive, not shallow: the legacy module only checked the project's
 *    top-level directory (fs.readdirSync(root), no recursion). A privacy
 *    policy in legal/, docs/, or frontend/public/ was invisible to it.
 * 2. LEGAL-001 (privacy policy) and LEGAL-003 (cookie policy) no longer
 *    FAIL when absent — they report NOT_VERIFIED, since legal applicability
 *    depends on facts (what data is collected, which jurisdictions apply)
 *    this scanner cannot determine from source, and the document may exist
 *    outside the scanned file set entirely. LEGAL-002 (terms) and LEGAL-004
 *    (contact) were already framed as best-practice items, not compliance
 *    claims, so they keep the original FAIL/PASS shape.
 */

function tmpDir(prefix: string): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

test("LEGAL-001..004 are registered", () => {
  for (const key of ["LEGAL-001", "LEGAL-002", "LEGAL-003", "LEGAL-004"]) {
    assert.ok(getControl(key), `${key} should be registered`);
  }
});

test("scanLegalPolicyControl: all four NOT_VERIFIED/FAIL when nothing is present", () => {
  const dir = tmpDir("nettle-legal-empty-");
  fs.writeFileSync(path.join(dir, "index.js"), "console.log('hi');\n", "utf8");

  const results = scanLegalPolicyControl(dir);
  assert.equal(results.length, 4);

  const byKey = Object.fromEntries(results.map((r) => [r.controlKey, r]));
  assert.equal(byKey["LEGAL-001"].status, "NOT_VERIFIED");
  assert.equal(byKey["LEGAL-002"].status, "FAIL");
  assert.equal(byKey["LEGAL-003"].status, "NOT_VERIFIED");
  assert.equal(byKey["LEGAL-004"].status, "FAIL");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanLegalPolicyControl: all four PASS when all four docs are present", () => {
  const dir = tmpDir("nettle-legal-full-");
  fs.writeFileSync(path.join(dir, "PRIVACY_POLICY.md"), "# Privacy Policy\n", "utf8");
  fs.writeFileSync(path.join(dir, "TERMS.md"), "# Terms\n", "utf8");
  fs.writeFileSync(path.join(dir, "COOKIE_POLICY.md"), "# Cookies\n", "utf8");
  fs.writeFileSync(path.join(dir, "CONTACT.md"), "# Contact\n", "utf8");

  const results = scanLegalPolicyControl(dir);
  const byKey = Object.fromEntries(results.map((r) => [r.controlKey, r]));
  assert.equal(byKey["LEGAL-001"].status, "PASS");
  assert.equal(byKey["LEGAL-002"].status, "PASS");
  assert.equal(byKey["LEGAL-003"].status, "PASS");
  assert.equal(byKey["LEGAL-004"].status, "PASS");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanLegalPolicyControl: finds a privacy policy nested in a subdirectory (the legacy check was shallow)", () => {
  const dir = tmpDir("nettle-legal-nested-");
  fs.mkdirSync(path.join(dir, "legal"), { recursive: true });
  fs.writeFileSync(path.join(dir, "legal", "privacy-policy.html"), "<html></html>", "utf8");

  const results = scanLegalPolicyControl(dir);
  const legal001 = results.find((r) => r.controlKey === "LEGAL-001")!;
  assert.equal(legal001.status, "PASS");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanLegalPolicyControl: skips node_modules and .git when searching", () => {
  const dir = tmpDir("nettle-legal-skipdirs-");
  fs.mkdirSync(path.join(dir, "node_modules", "some-pkg"), { recursive: true });
  fs.writeFileSync(path.join(dir, "node_modules", "some-pkg", "PRIVACY_POLICY.md"), "vendored, not ours\n", "utf8");

  const results = scanLegalPolicyControl(dir);
  const legal001 = results.find((r) => r.controlKey === "LEGAL-001")!;
  assert.equal(legal001.status, "NOT_VERIFIED");

  fs.rmSync(dir, { recursive: true, force: true });
});

// --- hydration ---

test("hydration gives LEGAL-002 a real fix", () => {
  const hydrated = hydrateCheckResult(
    { checkId: "x", status: "FAIL", category: "Legal & Policy", title: "No terms of service found", severity: "medium", confidence: 85, controlKey: "LEGAL-002" },
    { detectedTechnology: "generic" }
  );
  assert.ok(hydrated.recommendation);
  assert.match(hydrated.recommendation!.quickFix, /TERMS/);
});

test("LEGAL-001 NOT_VERIFIED carries humanReviewRequired and no fabricated recommendation (never asserts non-compliance)", () => {
  const hydrated = hydrateCheckResult({
    checkId: "x",
    status: "NOT_VERIFIED",
    category: "Legal & Policy",
    title: "No privacy policy found in the scanned project",
    confidence: 0,
    controlKey: "LEGAL-001",
  });
  assert.equal(hydrated.recommendation, null);
  assert.equal(hydrated.humanReviewRequired, true);
  assert.equal(hydrated.releaseImpact, null);
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

test("LEGAL-002 (a newly-migrated control) participates fully in scan comparison: open -> fixed -> regressed", () => {
  const dirNoTerms = tmpDir("nettle-legal-cmp-none-");
  const dirWithTerms = tmpDir("nettle-legal-cmp-terms-");
  fs.writeFileSync(path.join(dirWithTerms, "TERMS.md"), "# Terms\n", "utf8");

  const noTermsResults = scanLegalPolicyControl(dirNoTerms);
  const withTermsResults = scanLegalPolicyControl(dirWithTerms);

  const s1 = scanAt("s1", "2026-01-01T00:00:00Z", noTermsResults); // open
  const s2 = scanAt("s2", "2026-01-02T00:00:00Z", withTermsResults); // fixed
  const s3 = scanAt("s3", "2026-01-03T00:00:00Z", noTermsResults); // regressed
  const history = [s1, s2, s3];

  const openToFixed = compareScans(history, "s1", "s2");
  assert.ok(openToFixed.fixed.some((f) => f.finding.controlKey === "LEGAL-002"));

  const fixedToRegressed = compareScans(history, "s2", "s3");
  assert.ok(fixedToRegressed.regressed.some((f) => f.finding.controlKey === "LEGAL-002"));
  assert.equal(fixedToRegressed.summary.new, 0, "a regression must not be miscounted as NEW");

  fs.rmSync(dirNoTerms, { recursive: true, force: true });
  fs.rmSync(dirWithTerms, { recursive: true, force: true });
});
