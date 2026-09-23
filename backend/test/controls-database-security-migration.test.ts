import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "fs";
import os from "os";
import path from "path";
import "../src/scanner/controls";
import { getControl } from "../src/scanner/controls/registry";
import { hydrateCheckResult } from "../src/scanner/controls/hydrate";
import { scanDbCredentialExposureControl } from "../src/scanner/controls/checks/dbCredentialExposureControl";
import { scanParameterizedQueryControl } from "../src/scanner/controls/checks/parameterizedQueryControl";
import { compareScans, type ScanForComparison } from "../src/scanner/scanComparison";
import type { ScanReport, CheckResult } from "../src/scanner/types";

/**
 * Completes the databaseSecurity.ts migration onto the control library
 * (DB-002, DB-003) -- SQL-concatenation detection was already promoted to
 * DB-001 in an earlier round. databaseSecurity.ts itself has been deleted;
 * every check it made now lives here.
 */

function writeTempFile(dir: string, name: string, content: string): string {
  const file = path.join(dir, name);
  fs.writeFileSync(file, content, "utf8");
  return file;
}

function tmpDir(prefix: string): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

test("DB-002 and DB-003 are registered", () => {
  assert.ok(getControl("DB-002"));
  assert.ok(getControl("DB-003"));
});

// --- DB-002: hardcoded connection string ---

test("scanDbCredentialExposureControl: FAIL for a hardcoded connection string", () => {
  const dir = tmpDir("nettle-dburl-");
  const file = writeTempFile(dir, "config.js", `const DATABASE_URL = 'postgres://admin:hunter2@db.example.com/prod';\n`);

  const results = scanDbCredentialExposureControl([file], dir);
  const fail = results.find((r) => r.status === "FAIL");
  assert.ok(fail);
  assert.equal(fail!.controlKey, "DB-002");
  assert.equal(fail!.severity, "critical");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanDbCredentialExposureControl: PASS when the database is used but the URL comes from the environment", () => {
  const dir = tmpDir("nettle-dburl-");
  // "postgres" as a standalone word is what trips DB_USAGE_PATTERN (the
  // literal "DATABASE_URL" env var name does not: \bdatabase\b requires a
  // word boundary after "database", and "_" is a word character, so it
  // never matches inside "DATABASE_URL" itself).
  const file = writeTempFile(dir, "config.js", `// postgres connection\nconst { Pool } = require('pg');\nconst pool = new Pool({ connectionString: process.env.DATABASE_URL });\n`);

  const results = scanDbCredentialExposureControl([file], dir);
  assert.equal(results.length, 1);
  assert.equal(results[0].status, "PASS");
  assert.equal(results[0].controlKey, "DB-002");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanDbCredentialExposureControl: no unearned finding when the database isn't used at all", () => {
  const dir = tmpDir("nettle-dburl-");
  const file = writeTempFile(dir, "util.js", `function add(a, b) { return a + b; }\n`);

  assert.equal(scanDbCredentialExposureControl([file], dir).length, 0);

  fs.rmSync(dir, { recursive: true, force: true });
});

// --- DB-003: positive evidence of parameterization ---

test("scanParameterizedQueryControl: PASS when parameterized query syntax is present", () => {
  const dir = tmpDir("nettle-param-");
  const file = writeTempFile(dir, "db.js", `const { Pool } = require('pg');\npool.query('SELECT * FROM users WHERE id = $1', [id]);\n`);

  const results = scanParameterizedQueryControl([file], dir);
  assert.equal(results.length, 1);
  assert.equal(results[0].status, "PASS");
  assert.equal(results[0].controlKey, "DB-003");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanParameterizedQueryControl: PASS when an ORM is used, even without an explicit parameterized call", () => {
  const dir = tmpDir("nettle-param-");
  const file = writeTempFile(dir, "db.js", `import { PrismaClient } from '@prisma/client';\nconst prisma = new PrismaClient();\n`);

  const results = scanParameterizedQueryControl([file], dir);
  assert.equal(results.length, 1);
  assert.equal(results[0].status, "PASS");
  assert.match(results[0].title, /ORM/);

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanParameterizedQueryControl: FAIL when a raw driver is imported with no parameterization evidence anywhere", () => {
  const dir = tmpDir("nettle-param-");
  const file = writeTempFile(dir, "db.js", `const { Pool } = require('pg');\nconst pool = new Pool();\nfunction getUser(id) { return pool.query('SELECT * FROM users'); }\n`);

  const results = scanParameterizedQueryControl([file], dir);
  assert.equal(results.length, 1);
  assert.equal(results[0].status, "FAIL");
  assert.equal(results[0].controlKey, "DB-003");
  assert.equal(results[0].severity, "medium");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanParameterizedQueryControl: NOT_VERIFIED (not FAIL) when database usage is only a weak word-match, not a real driver import", () => {
  const dir = tmpDir("nettle-param-");
  // "database" appears only in a comment -- no actual driver, no ORM, no
  // parameterization pattern. Weak evidence must not produce a confident FAIL.
  const file = writeTempFile(dir, "notes.js", `// TODO: connect this to the database eventually\nfunction placeholder() {}\n`);

  const results = scanParameterizedQueryControl([file], dir);
  assert.equal(results.length, 1);
  assert.equal(results[0].status, "NOT_VERIFIED");
  assert.equal(results[0].controlKey, "DB-003");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanParameterizedQueryControl: no finding at all when there is no database signal whatsoever", () => {
  const dir = tmpDir("nettle-param-");
  const file = writeTempFile(dir, "util.js", `function add(a, b) { return a + b; }\n`);

  assert.equal(scanParameterizedQueryControl([file], dir).length, 0);

  fs.rmSync(dir, { recursive: true, force: true });
});

// --- hydration ---

test("hydration gives DB-002 a real fix and blocks release", () => {
  const hydrated = hydrateCheckResult(
    { checkId: "x", status: "FAIL", category: "Database", title: "Database connection string hardcoded in source", severity: "critical", confidence: 90, controlKey: "DB-002" },
    { detectedTechnology: "express" }
  );
  assert.ok(hydrated.recommendation);
  assert.match(hydrated.recommendation!.quickFix, /rotate/i);
  assert.equal(hydrated.releaseImpact, "BLOCK_RELEASE");
});

test("hydration gives DB-003 a real fix", () => {
  const hydrated = hydrateCheckResult({
    checkId: "x",
    status: "FAIL",
    category: "Database",
    title: "No evidence of parameterized queries alongside direct database driver usage",
    severity: "medium",
    confidence: 60,
    controlKey: "DB-003",
  });
  assert.ok(hydrated.recommendation);
  assert.match(hydrated.recommendation!.quickFix, /parameter/i);
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

test("DB-002 (a newly-migrated control) participates fully in scan comparison: open -> fixed -> regressed", () => {
  const dirExposed = tmpDir("nettle-dburl-cmp-exposed-");
  writeTempFile(dirExposed, "config.js", `const DATABASE_URL = 'postgres://admin:hunter2@db.example.com/prod';\n`);
  const dirFixed = tmpDir("nettle-dburl-cmp-fixed-");
  writeTempFile(dirFixed, "config.js", `const { Pool } = require('pg');\nconst pool = new Pool({ connectionString: process.env.DATABASE_URL });\n`);

  const exposedResults = scanDbCredentialExposureControl([path.join(dirExposed, "config.js")], dirExposed);
  const fixedResults = scanDbCredentialExposureControl([path.join(dirFixed, "config.js")], dirFixed);

  const s1 = scanAt("s1", "2026-01-01T00:00:00Z", exposedResults); // open
  const s2 = scanAt("s2", "2026-01-02T00:00:00Z", fixedResults); // fixed
  const s3 = scanAt("s3", "2026-01-03T00:00:00Z", exposedResults); // regressed
  const history = [s1, s2, s3];

  const openToFixed = compareScans(history, "s1", "s2");
  assert.equal(openToFixed.summary.fixed, 1);
  assert.ok(openToFixed.fixed.some((f) => f.finding.controlKey === "DB-002"));

  const fixedToRegressed = compareScans(history, "s2", "s3");
  assert.equal(fixedToRegressed.summary.regressed, 1);
  assert.ok(fixedToRegressed.regressed.some((f) => f.finding.controlKey === "DB-002"));
  assert.equal(fixedToRegressed.summary.new, 0, "a regression must not be miscounted as NEW");

  fs.rmSync(dirExposed, { recursive: true, force: true });
  fs.rmSync(dirFixed, { recursive: true, force: true });
});
