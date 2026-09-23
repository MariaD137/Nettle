import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "fs";
import os from "os";
import path from "path";
import "../src/scanner/controls";
import { getControl } from "../src/scanner/controls/registry";
import { hydrateCheckResult } from "../src/scanner/controls/hydrate";
import { scanCicdSecurityControl } from "../src/scanner/controls/checks/cicdSecurityControl";
import { compareScans, type ScanForComparison } from "../src/scanner/scanComparison";
import type { ScanReport, CheckResult } from "../src/scanner/types";

/**
 * CICD-001..003: the second Phase B category (CI/CD Security — master spec
 * §23), entirely new. No existing control covered GitHub Actions workflow
 * security. Requires .yml/.yaml in SCANNED_EXTENSIONS (added in
 * scanner/index.ts alongside this control) — workflow files were never in
 * the scanned file set before.
 *
 * Gated like PAY-*: nothing runs at all unless a .github/workflows/*.yml
 * file exists in the scanned files.
 */

function writeWorkflow(dir: string, name: string, content: string): string {
  const file = path.join(dir, ".github", "workflows", name);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, content, "utf8");
  return file;
}

function tmpDir(prefix: string): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

const ALL_KEYS = ["CICD-001", "CICD-002", "CICD-003"];

test("CICD-001..003 are registered", () => {
  for (const key of ALL_KEYS) {
    assert.ok(getControl(key), `${key} should be registered`);
  }
});

test("scanCicdSecurityControl: no result at all when there's no workflow file", () => {
  const dir = tmpDir("nettle-cicd-none-");
  const file = path.join(dir, "app.js");
  fs.writeFileSync(file, "function add(a, b) { return a + b; }\n", "utf8");

  assert.equal(scanCicdSecurityControl([file], dir).length, 0);

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanCicdSecurityControl: every control PASSes on a hardened workflow", () => {
  const dir = tmpDir("nettle-cicd-clean-");
  const file = writeWorkflow(
    dir,
    "ci.yml",
    `name: CI\non:\n  pull_request:\n    branches: [main]\npermissions:\n  contents: read\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@8f4b7f84864484a7bde6ceaf20ad2debeafb5a5c\n      - run: npm test\n`
  );

  const results = scanCicdSecurityControl([file], dir);
  const byKey = Object.fromEntries(results.map((r) => [r.controlKey, r]));

  for (const key of ALL_KEYS) {
    assert.equal(byKey[key]?.status, "PASS", `${key} should PASS on a hardened workflow`);
  }

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanCicdSecurityControl: CICD-001 FAILs when pull_request_target checks out the PR's own head", () => {
  const dir = tmpDir("nettle-cicd-prtarget-");
  const file = writeWorkflow(
    dir,
    "ci.yml",
    `name: CI\non:\n  pull_request_target:\n    branches: [main]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: \${{ github.event.pull_request.head.sha }}\n      - run: npm test\n`
  );

  const results = scanCicdSecurityControl([file], dir);
  const result = results.find((r) => r.controlKey === "CICD-001");
  assert.ok(result);
  assert.equal(result!.status, "FAIL");
  assert.equal(result!.severity, "critical");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanCicdSecurityControl: CICD-001 does not FAIL for pull_request_target alone (checking out the base ref, not the PR head, is safe)", () => {
  const dir = tmpDir("nettle-cicd-prtarget-safe-");
  const file = writeWorkflow(
    dir,
    "ci.yml",
    `name: CI\non:\n  pull_request_target:\n    branches: [main]\njobs:\n  comment:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - run: echo commenting\n`
  );

  const results = scanCicdSecurityControl([file], dir);
  assert.equal(results.find((r) => r.controlKey === "CICD-001")?.status, "PASS");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanCicdSecurityControl: CICD-002 FAILs for an action pinned to a mutable tag, not a SHA", () => {
  const dir = tmpDir("nettle-cicd-unpinned-");
  const file = writeWorkflow(
    dir,
    "ci.yml",
    `name: CI\non:\n  push:\n    branches: [main]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - run: npm test\n`
  );

  const results = scanCicdSecurityControl([file], dir);
  const result = results.find((r) => r.controlKey === "CICD-002");
  assert.ok(result);
  assert.equal(result!.status, "FAIL");
  assert.match(result!.detail!, /actions\/checkout@v4/);

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanCicdSecurityControl: CICD-002 PASSes when every action is SHA-pinned", () => {
  const dir = tmpDir("nettle-cicd-pinned-");
  const file = writeWorkflow(
    dir,
    "ci.yml",
    `name: CI\non:\n  push:\n    branches: [main]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@8f4b7f84864484a7bde6ceaf20ad2debeafb5a5c\n      - run: npm test\n`
  );

  const results = scanCicdSecurityControl([file], dir);
  assert.equal(results.find((r) => r.controlKey === "CICD-002")?.status, "PASS");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanCicdSecurityControl: CICD-003 FAILs for permissions: write-all", () => {
  const dir = tmpDir("nettle-cicd-writeall-");
  const file = writeWorkflow(
    dir,
    "ci.yml",
    `name: CI\non:\n  push:\n    branches: [main]\npermissions: write-all\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: npm test\n`
  );

  const results = scanCicdSecurityControl([file], dir);
  const result = results.find((r) => r.controlKey === "CICD-003");
  assert.ok(result);
  assert.equal(result!.status, "FAIL");
  assert.equal(result!.severity, "high");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanCicdSecurityControl: only .github/workflows YAML is scoped, not arbitrary YAML like docker-compose.yml", () => {
  const dir = tmpDir("nettle-cicd-notworkflow-");
  const file = path.join(dir, "docker-compose.yml");
  fs.writeFileSync(file, `permissions: write-all\n`, "utf8"); // an unrelated key that happens to collide textually

  assert.equal(scanCicdSecurityControl([file], dir).length, 0);

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanCicdSecurityControl: NOT_VERIFIED when a workflow file is unreadable and its check didn't otherwise fire", () => {
  const dir = tmpDir("nettle-cicd-unread-");
  const good = writeWorkflow(dir, "ci.yml", `name: CI\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: npm test\n`);
  const missing = path.join(dir, ".github", "workflows", "missing.yml");

  const results = scanCicdSecurityControl([good, missing], dir);
  for (const key of ALL_KEYS) {
    assert.equal(results.find((r) => r.controlKey === key)?.status, "NOT_VERIFIED", `${key} should be NOT_VERIFIED`);
  }

  fs.rmSync(dir, { recursive: true, force: true });
});

// --- hydration ---

test("hydration gives CICD-001 a real fix", () => {
  const hydrated = hydrateCheckResult(
    { checkId: "x", status: "FAIL", category: "CI/CD Security", title: "pull_request_target workflow checks out the PR's own head commit", severity: "critical", confidence: 80, controlKey: "CICD-001" },
    { detectedTechnology: "generic" }
  );
  assert.ok(hydrated.recommendation);
  assert.match(hydrated.recommendation!.quickFix, /pull_request\b/);
});

test("hydration gives CICD-003 a real fix", () => {
  const hydrated = hydrateCheckResult(
    { checkId: "x", status: "FAIL", category: "CI/CD Security", title: "Workflow grants write-all permissions", severity: "high", confidence: 95, controlKey: "CICD-003" },
    { detectedTechnology: "generic" }
  );
  assert.ok(hydrated.recommendation);
  assert.match(hydrated.recommendation!.quickFix, /contents: read/);
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

test("CICD-002 participates fully in scan comparison: open -> fixed -> regressed", () => {
  const dirUnpinned = tmpDir("nettle-cicd-cmp-unpinned-");
  writeWorkflow(dirUnpinned, "ci.yml", `name: CI\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n`);
  const dirPinned = tmpDir("nettle-cicd-cmp-pinned-");
  writeWorkflow(dirPinned, "ci.yml", `name: CI\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@8f4b7f84864484a7bde6ceaf20ad2debeafb5a5c\n`);

  const unpinnedResults = scanCicdSecurityControl([path.join(dirUnpinned, ".github", "workflows", "ci.yml")], dirUnpinned);
  const pinnedResults = scanCicdSecurityControl([path.join(dirPinned, ".github", "workflows", "ci.yml")], dirPinned);

  const s1 = scanAt("s1", "2026-01-01T00:00:00Z", unpinnedResults); // open
  const s2 = scanAt("s2", "2026-01-02T00:00:00Z", pinnedResults); // fixed
  const s3 = scanAt("s3", "2026-01-03T00:00:00Z", unpinnedResults); // regressed
  const history = [s1, s2, s3];

  const openToFixed = compareScans(history, "s1", "s2");
  assert.ok(openToFixed.fixed.some((f) => f.finding.controlKey === "CICD-002"));

  const fixedToRegressed = compareScans(history, "s2", "s3");
  assert.ok(fixedToRegressed.regressed.some((f) => f.finding.controlKey === "CICD-002"));
  assert.equal(fixedToRegressed.summary.new, 0, "a regression must not be miscounted as NEW");

  fs.rmSync(dirUnpinned, { recursive: true, force: true });
  fs.rmSync(dirPinned, { recursive: true, force: true });
});
