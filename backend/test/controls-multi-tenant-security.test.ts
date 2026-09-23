import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "fs";
import os from "os";
import path from "path";
import "../src/scanner/controls";
import { getControl } from "../src/scanner/controls/registry";
import { hydrateCheckResult } from "../src/scanner/controls/hydrate";
import { scanMultiTenantSecurityControl } from "../src/scanner/controls/checks/multiTenantSecurityControl";
import { compareScans, type ScanForComparison } from "../src/scanner/scanComparison";
import type { ScanReport, CheckResult } from "../src/scanner/types";

/**
 * MT-001/002: the third Phase B category (Multi-Tenant Security — master
 * spec §20), entirely new. No existing control covered tenant scoping or
 * object-level authorization — AUTH-001 only checks that SOME
 * authentication check exists on a route, not that a specific resource
 * lookup is scoped to its owner/tenant.
 *
 * Both gated on their own applicability: MT-001 only produces a result
 * when some tenant-scoped query pattern exists at all; MT-002 only when a
 * query looks up a resource by req.params.id at all.
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

test("MT-001/002 are registered", () => {
  assert.ok(getControl("MT-001"));
  assert.ok(getControl("MT-002"));
});

test("scanMultiTenantSecurityControl: no result at all when neither pattern applies", () => {
  const dir = tmpDir("nettle-mt-none-");
  const file = writeTempFile(dir, "app.js", `function add(a, b) { return a + b; }\n`);

  assert.equal(scanMultiTenantSecurityControl([file], dir).length, 0);

  fs.rmSync(dir, { recursive: true, force: true });
});

// --- MT-001: tenant ID not trusted from client ---

test("scanMultiTenantSecurityControl: MT-001 FAILs when the tenant ID comes from req.body", () => {
  const dir = tmpDir("nettle-mt-tenant-client-");
  const file = writeTempFile(dir, "projects.js", `db.query('SELECT * FROM projects WHERE tenant_id = ?', [req.body.tenantId]);\n`);

  const results = scanMultiTenantSecurityControl([file], dir);
  const result = results.find((r) => r.controlKey === "MT-001");
  assert.ok(result);
  assert.equal(result!.status, "FAIL");
  assert.equal(result!.severity, "critical");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanMultiTenantSecurityControl: MT-001 PASSes when the tenant ID comes from the session", () => {
  const dir = tmpDir("nettle-mt-tenant-session-");
  const file = writeTempFile(dir, "projects.js", `db.query('SELECT * FROM projects WHERE tenant_id = ?', [req.user.tenantId]);\n`);

  const results = scanMultiTenantSecurityControl([file], dir);
  const result = results.find((r) => r.controlKey === "MT-001");
  assert.ok(result);
  assert.equal(result!.status, "PASS");

  fs.rmSync(dir, { recursive: true, force: true });
});

// --- MT-002: object-level authorization ---

test("scanMultiTenantSecurityControl: MT-002 FAILs for a bare ID lookup with no scoping", () => {
  const dir = tmpDir("nettle-mt-bareid-");
  const file = writeTempFile(dir, "projects.js", `db.query('SELECT * FROM projects WHERE id = ?', [req.params.id]);\n`);

  const results = scanMultiTenantSecurityControl([file], dir);
  const result = results.find((r) => r.controlKey === "MT-002");
  assert.ok(result);
  assert.equal(result!.status, "FAIL");
  assert.equal(result!.severity, "high");
  assert.equal(result!.confidence, 55, "a single-query-text heuristic should carry honestly lower confidence, not asserted certainty");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanMultiTenantSecurityControl: MT-002 PASSes when the lookup is scoped by tenant/owner", () => {
  const dir = tmpDir("nettle-mt-scopedid-");
  const file = writeTempFile(dir, "projects.js", `db.query('SELECT * FROM projects WHERE id = ? AND tenant_id = ?', [req.params.id, req.user.tenantId]);\n`);

  const results = scanMultiTenantSecurityControl([file], dir);
  const result = results.find((r) => r.controlKey === "MT-002");
  assert.ok(result);
  assert.equal(result!.status, "PASS");
  assert.equal(result!.confidence, 80, "confirming a scoping term is present is more reliable than confirming its absence");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanMultiTenantSecurityControl: MT-001 and MT-002 are independent — only the applicable one produces a result", () => {
  const dir = tmpDir("nettle-mt-independent-");
  const file = writeTempFile(dir, "projects.js", `db.query('SELECT * FROM projects WHERE id = ?', [req.params.id]);\n`);

  const results = scanMultiTenantSecurityControl([file], dir);
  assert.equal(results.find((r) => r.controlKey === "MT-001"), undefined, "no tenant-query pattern exists, so MT-001 should produce nothing");
  assert.ok(results.find((r) => r.controlKey === "MT-002"));

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanMultiTenantSecurityControl: NOT_VERIFIED when a file is unreadable and no evidence was found elsewhere", () => {
  const dir = tmpDir("nettle-mt-unread-");
  const good = writeTempFile(dir, "projects.js", `db.query('SELECT * FROM projects WHERE tenant_id = ?', [req.user.tenantId]);\n`);
  const missing = path.join(dir, "missing.js");

  const results = scanMultiTenantSecurityControl([good, missing], dir);
  const result = results.find((r) => r.controlKey === "MT-001");
  assert.ok(result);
  assert.equal(result!.status, "NOT_VERIFIED");

  fs.rmSync(dir, { recursive: true, force: true });
});

// --- hydration ---

test("hydration gives MT-001 a real fix", () => {
  const hydrated = hydrateCheckResult(
    { checkId: "x", status: "FAIL", category: "Multi-Tenant Security", title: "Tenant/organization ID taken directly from the client request", severity: "critical", confidence: 80, controlKey: "MT-001" },
    { detectedTechnology: "generic" }
  );
  assert.ok(hydrated.recommendation);
  assert.match(hydrated.recommendation!.quickFix, /session/i);
  assert.equal(hydrated.releaseImpact, "BLOCK_RELEASE");
});

test("hydration gives MT-002 a real fix, and its low confidence downgrades release impact", () => {
  const hydrated = hydrateCheckResult(
    { checkId: "x", status: "FAIL", category: "Multi-Tenant Security", title: "Resource looked up by ID with no visible tenant/owner scoping", severity: "high", confidence: 55, controlKey: "MT-002" },
    { detectedTechnology: "generic" }
  );
  assert.ok(hydrated.recommendation);
  assert.match(hydrated.recommendation!.quickFix, /tenant_id|owner_id/);
  // high -> REVIEW_BEFORE_RELEASE, downgraded once at confidence < 75
  assert.equal(hydrated.releaseImpact, "FIX_RECOMMENDED");
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

test("MT-001 participates fully in scan comparison: open -> fixed -> regressed", () => {
  const dirClientSourced = tmpDir("nettle-mt-cmp-client-");
  writeTempFile(dirClientSourced, "projects.js", `db.query('SELECT * FROM projects WHERE tenant_id = ?', [req.body.tenantId]);\n`);
  const dirSessionSourced = tmpDir("nettle-mt-cmp-session-");
  writeTempFile(dirSessionSourced, "projects.js", `db.query('SELECT * FROM projects WHERE tenant_id = ?', [req.user.tenantId]);\n`);

  const clientResults = scanMultiTenantSecurityControl([path.join(dirClientSourced, "projects.js")], dirClientSourced);
  const sessionResults = scanMultiTenantSecurityControl([path.join(dirSessionSourced, "projects.js")], dirSessionSourced);

  const s1 = scanAt("s1", "2026-01-01T00:00:00Z", clientResults); // open
  const s2 = scanAt("s2", "2026-01-02T00:00:00Z", sessionResults); // fixed
  const s3 = scanAt("s3", "2026-01-03T00:00:00Z", clientResults); // regressed
  const history = [s1, s2, s3];

  const openToFixed = compareScans(history, "s1", "s2");
  assert.ok(openToFixed.fixed.some((f) => f.finding.controlKey === "MT-001"));

  const fixedToRegressed = compareScans(history, "s2", "s3");
  assert.ok(fixedToRegressed.regressed.some((f) => f.finding.controlKey === "MT-001"));
  assert.equal(fixedToRegressed.summary.new, 0, "a regression must not be miscounted as NEW");

  fs.rmSync(dirClientSourced, { recursive: true, force: true });
  fs.rmSync(dirSessionSourced, { recursive: true, force: true });
});
