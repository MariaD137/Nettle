import { test } from "node:test";
import assert from "node:assert/strict";
import { createUser } from "../src/auth/users";
import { findProjectByApiKey, createProject } from "../src/patrol/projects";
import { recordScan, getLatestScan } from "../src/patrol/scans";
import type { ScanReport, ScanStatus } from "../src/scanner/types";

const PASSWORD = "correct horse battery staple";

function createSampleReport(status?: ScanStatus): ScanReport {
  return {
    scannedAt: new Date().toISOString(),
    target: "sample-app",
    scannerVersion: "1.3.0",
    score: 85,
    scoreConfidence: 100,
    status,
    findings: [],
    passed: [],
    summary: {
      critical: 0,
      high: 1,
      medium: 2,
      low: 1,
      info: 0,
      clear: 5,
    },
  };
}

test("H-7: Recorded scan includes status field", async () => {
  const user = await createUser("h7-status@example.com", PASSWORD);
  const project = await createProject(user.id, "Test Project");

  const report = createSampleReport("COMPLETED");
  const stored = await recordScan(project.id, report);

  assert.equal(stored.status, "COMPLETED");
  assert.ok(stored.id);
  assert.equal(stored.projectId, project.id);
});

test("H-7: Status defaults to COMPLETED if not specified", async () => {
  const user = await createUser("h7-default@example.com", PASSWORD);
  const project = await createProject(user.id, "Test Project");

  const report = createSampleReport(); // No status specified
  const stored = await recordScan(project.id, report);

  assert.equal(stored.status, "COMPLETED");
});

test("H-7: Status from report takes precedence", async () => {
  const user = await createUser("h7-report-status@example.com", PASSWORD);
  const project = await createProject(user.id, "Test Project");

  const report = createSampleReport("PARTIALLY_COMPLETED");
  const stored = await recordScan(project.id, report, "COMPLETED");

  // Report status should take precedence over parameter
  assert.equal(stored.status, "PARTIALLY_COMPLETED");
});

test("H-7: Latest scan retrieval includes status", async () => {
  const user = await createUser("h7-latest@example.com", PASSWORD);
  const project = await createProject(user.id, "Test Project");

  const report1 = createSampleReport("COMPLETED");
  await recordScan(project.id, report1);

  // Wait a tiny bit to ensure different timestamp
  await new Promise((r) => setTimeout(r, 10));

  const report2 = createSampleReport("FAILED");
  await recordScan(project.id, report2);

  const latest = await getLatestScan(project.id);
  assert.ok(latest);
  assert.equal(latest.status, "FAILED");
});

test("H-7: Partial scan shows reduced confidence", async () => {
  const user = await createUser("h7-partial@example.com", PASSWORD);
  const project = await createProject(user.id, "Test Project");

  const report = createSampleReport("PARTIALLY_COMPLETED");
  report.scoreConfidence = 67; // Some analyzers didn't run
  const stored = await recordScan(project.id, report);

  assert.equal(stored.status, "PARTIALLY_COMPLETED");
  assert.ok(stored.report.scoreConfidence && stored.report.scoreConfidence < 100);
});

test("H-7: Failed scan status preserved", async () => {
  const user = await createUser("h7-failed@example.com", PASSWORD);
  const project = await createProject(user.id, "Test Project");

  const report = createSampleReport("FAILED");
  report.score = 0; // Failed scans have no score
  const stored = await recordScan(project.id, report, "FAILED");

  assert.equal(stored.status, "FAILED");
  assert.equal(stored.score, 0);
});

test("H-7: Status values are recognized enum", () => {
  // Verify that all expected status values are valid
  const validStatuses: Array<ScanStatus> = [
    "CREATED",
    "SCANNING",
    "COMPLETED",
    "PARTIALLY_COMPLETED",
    "FAILED",
    "CANCELLED",
  ];

  for (const status of validStatuses) {
    const report = createSampleReport(status);
    assert.equal(report.status, status);
  }
});
