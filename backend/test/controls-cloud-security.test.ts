import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "fs";
import os from "os";
import path from "path";
import "../src/scanner/controls";
import { getControl } from "../src/scanner/controls/registry";
import { hydrateCheckResult } from "../src/scanner/controls/hydrate";
import { scanCloudSecurityControl } from "../src/scanner/controls/checks/cloudSecurityControl";
import { compareScans, type ScanForComparison } from "../src/scanner/scanComparison";
import type { ScanReport, CheckResult } from "../src/scanner/types";

/**
 * CLOUD-001..003: the fourth Phase B category (Cloud Security — master spec
 * §24), entirely new. No existing control covered Dockerfile or Terraform
 * configuration, confirmed via grep. Requires .tf and the literal
 * "dockerfile" in SCANNED_EXTENSIONS (added in scanner/index.ts alongside
 * this control) — neither file type was ever in the scanned file set
 * before.
 *
 * Each control gated on its own file-type applicability: CLOUD-001 only
 * when a Dockerfile exists, CLOUD-002 only when a Terraform ingress block
 * exists, CLOUD-003 only when a Terraform aws_s3_bucket resource exists.
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

test("CLOUD-001..003 are registered", () => {
  for (const key of ["CLOUD-001", "CLOUD-002", "CLOUD-003"]) {
    assert.ok(getControl(key), `${key} should be registered`);
  }
});

test("scanCloudSecurityControl: no result at all when there's no Dockerfile or Terraform file", () => {
  const dir = tmpDir("nettle-cloud-none-");
  const file = writeTempFile(dir, "app.js", `function add(a, b) { return a + b; }\n`);

  assert.equal(scanCloudSecurityControl([file], dir).length, 0);

  fs.rmSync(dir, { recursive: true, force: true });
});

// --- CLOUD-001: Docker root ---

test("scanCloudSecurityControl: CLOUD-001 FAILs when the Dockerfile has no USER instruction", () => {
  const dir = tmpDir("nettle-cloud-noroot-");
  const file = writeTempFile(dir, "Dockerfile", `FROM node:20\nWORKDIR /app\nCOPY . .\nRUN npm install\nCMD ["node", "server.js"]\n`);

  const results = scanCloudSecurityControl([file], dir);
  const result = results.find((r) => r.controlKey === "CLOUD-001");
  assert.ok(result);
  assert.equal(result!.status, "FAIL");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanCloudSecurityControl: CLOUD-001 FAILs when the Dockerfile explicitly sets USER root", () => {
  const dir = tmpDir("nettle-cloud-explicitroot-");
  const file = writeTempFile(dir, "Dockerfile", `FROM node:20\nUSER root\nCMD ["node", "server.js"]\n`);

  const results = scanCloudSecurityControl([file], dir);
  assert.equal(results.find((r) => r.controlKey === "CLOUD-001")?.status, "FAIL");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanCloudSecurityControl: CLOUD-001 PASSes when the Dockerfile's last USER instruction is non-root", () => {
  const dir = tmpDir("nettle-cloud-nonroot-");
  const file = writeTempFile(dir, "Dockerfile", `FROM node:20\nWORKDIR /app\nCOPY --chown=node:node . .\nRUN npm ci\nUSER node\nCMD ["node", "server.js"]\n`);

  const results = scanCloudSecurityControl([file], dir);
  const result = results.find((r) => r.controlKey === "CLOUD-001");
  assert.ok(result);
  assert.equal(result!.status, "PASS");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanCloudSecurityControl: CLOUD-001 uses the LAST USER instruction, not the first, in a multi-stage build", () => {
  const dir = tmpDir("nettle-cloud-multistage-");
  const file = writeTempFile(
    dir,
    "Dockerfile",
    `FROM node:20 AS build\nUSER root\nRUN npm run build\n\nFROM node:20-slim\nUSER node\nCOPY --from=build /app/dist /app\nCMD ["node", "app.js"]\n`
  );

  const results = scanCloudSecurityControl([file], dir);
  assert.equal(results.find((r) => r.controlKey === "CLOUD-001")?.status, "PASS");

  fs.rmSync(dir, { recursive: true, force: true });
});

// --- CLOUD-002: open security group ---

test("scanCloudSecurityControl: CLOUD-002 FAILs for SSH open to the world", () => {
  const dir = tmpDir("nettle-cloud-opensg-");
  const file = writeTempFile(
    dir,
    "main.tf",
    `resource "aws_security_group" "web" {\n  ingress {\n    from_port   = 22\n    to_port     = 22\n    protocol    = "tcp"\n    cidr_blocks = ["0.0.0.0/0"]\n  }\n}\n`
  );

  const results = scanCloudSecurityControl([file], dir);
  const result = results.find((r) => r.controlKey === "CLOUD-002");
  assert.ok(result);
  assert.equal(result!.status, "FAIL");
  assert.equal(result!.severity, "critical");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanCloudSecurityControl: CLOUD-002 PASSes when SSH is restricted to a private range", () => {
  const dir = tmpDir("nettle-cloud-safesg-");
  const file = writeTempFile(
    dir,
    "main.tf",
    `resource "aws_security_group" "web" {\n  ingress {\n    from_port   = 22\n    to_port     = 22\n    protocol    = "tcp"\n    cidr_blocks = ["10.0.0.0/16"]\n  }\n}\n`
  );

  const results = scanCloudSecurityControl([file], dir);
  assert.equal(results.find((r) => r.controlKey === "CLOUD-002")?.status, "PASS");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanCloudSecurityControl: CLOUD-002 does not FAIL for a non-sensitive port open to the world (e.g. 443)", () => {
  const dir = tmpDir("nettle-cloud-openhttps-");
  const file = writeTempFile(
    dir,
    "main.tf",
    `resource "aws_security_group" "web" {\n  ingress {\n    from_port   = 443\n    to_port     = 443\n    protocol    = "tcp"\n    cidr_blocks = ["0.0.0.0/0"]\n  }\n}\n`
  );

  const results = scanCloudSecurityControl([file], dir);
  assert.equal(results.find((r) => r.controlKey === "CLOUD-002")?.status, "PASS");

  fs.rmSync(dir, { recursive: true, force: true });
});

// --- CLOUD-003: public bucket ---

test("scanCloudSecurityControl: CLOUD-003 FAILs for acl = public-read", () => {
  const dir = tmpDir("nettle-cloud-publicbucket-");
  const file = writeTempFile(dir, "main.tf", `resource "aws_s3_bucket" "data" {\n  bucket = "my-data"\n  acl    = "public-read"\n}\n`);

  const results = scanCloudSecurityControl([file], dir);
  const result = results.find((r) => r.controlKey === "CLOUD-003");
  assert.ok(result);
  assert.equal(result!.status, "FAIL");
  assert.equal(result!.severity, "critical");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanCloudSecurityControl: CLOUD-003 PASSes for acl = private", () => {
  const dir = tmpDir("nettle-cloud-privatebucket-");
  const file = writeTempFile(dir, "main.tf", `resource "aws_s3_bucket" "data" {\n  bucket = "my-data"\n  acl    = "private"\n}\n`);

  const results = scanCloudSecurityControl([file], dir);
  assert.equal(results.find((r) => r.controlKey === "CLOUD-003")?.status, "PASS");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanCloudSecurityControl: NOT_VERIFIED when a Dockerfile is unreadable and its check didn't otherwise fire", () => {
  const dir = tmpDir("nettle-cloud-unread-");
  const good = writeTempFile(dir, "Dockerfile", `FROM node:20\nUSER node\nCMD ["node", "app.js"]\n`);
  const missingDockerfile = path.join(dir, "sub", "Dockerfile"); // path never written — fs.readFileSync will throw
  fs.mkdirSync(path.dirname(missingDockerfile), { recursive: true });

  const results = scanCloudSecurityControl([good, missingDockerfile], dir);
  const result = results.find((r) => r.controlKey === "CLOUD-001");
  assert.ok(result);
  assert.equal(result!.status, "NOT_VERIFIED");

  fs.rmSync(dir, { recursive: true, force: true });
});

// --- hydration ---

test("hydration gives CLOUD-001 a real fix", () => {
  const hydrated = hydrateCheckResult(
    { checkId: "x", status: "FAIL", category: "Cloud Security", title: "Docker container runs as root", severity: "medium", confidence: 75, controlKey: "CLOUD-001" },
    { detectedTechnology: "generic" }
  );
  assert.ok(hydrated.recommendation);
  assert.match(hydrated.recommendation!.quickFix, /USER/);
});

test("hydration gives CLOUD-003 a real fix", () => {
  const hydrated = hydrateCheckResult(
    { checkId: "x", status: "FAIL", category: "Cloud Security", title: "Storage bucket is publicly readable or writable", severity: "critical", confidence: 85, controlKey: "CLOUD-003" },
    { detectedTechnology: "generic" }
  );
  assert.ok(hydrated.recommendation);
  assert.match(hydrated.recommendation!.quickFix, /private/);
  assert.equal(hydrated.releaseImpact, "BLOCK_RELEASE");
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

test("CLOUD-003 participates fully in scan comparison: open -> fixed -> regressed", () => {
  const dirPublic = tmpDir("nettle-cloud-cmp-public-");
  writeTempFile(dirPublic, "main.tf", `resource "aws_s3_bucket" "data" {\n  bucket = "my-data"\n  acl    = "public-read"\n}\n`);
  const dirPrivate = tmpDir("nettle-cloud-cmp-private-");
  writeTempFile(dirPrivate, "main.tf", `resource "aws_s3_bucket" "data" {\n  bucket = "my-data"\n  acl    = "private"\n}\n`);

  const publicResults = scanCloudSecurityControl([path.join(dirPublic, "main.tf")], dirPublic);
  const privateResults = scanCloudSecurityControl([path.join(dirPrivate, "main.tf")], dirPrivate);

  const s1 = scanAt("s1", "2026-01-01T00:00:00Z", publicResults); // open
  const s2 = scanAt("s2", "2026-01-02T00:00:00Z", privateResults); // fixed
  const s3 = scanAt("s3", "2026-01-03T00:00:00Z", publicResults); // regressed
  const history = [s1, s2, s3];

  const openToFixed = compareScans(history, "s1", "s2");
  assert.ok(openToFixed.fixed.some((f) => f.finding.controlKey === "CLOUD-003"));

  const fixedToRegressed = compareScans(history, "s2", "s3");
  assert.ok(fixedToRegressed.regressed.some((f) => f.finding.controlKey === "CLOUD-003"));
  assert.equal(fixedToRegressed.summary.new, 0, "a regression must not be miscounted as NEW");

  fs.rmSync(dirPublic, { recursive: true, force: true });
  fs.rmSync(dirPrivate, { recursive: true, force: true });
});
