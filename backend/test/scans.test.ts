import { test, before } from "node:test";
import assert from "node:assert/strict";
import path from "path";
import { createUser } from "../src/auth/users";
import { createProject } from "../src/patrol/projects";
import { recordScan, listScans, getLatestScan } from "../src/patrol/scans";
import { runScan } from "../src/scanner";

const FLAWED_APP = path.join(__dirname, "fixtures", "sample-app");
const CLEAN_APP = path.join(__dirname, "fixtures", "clean-app");

let projectId: string;
before(async () => {
  const user = await createUser("scans-tests@example.com", "correct horse battery staple");
  projectId = (await createProject(user.id, "Scan Persistence Target")).id;
});

test("recordScan persists a real scan report and round-trips it", async () => {
  const report = runScan(FLAWED_APP);
  const stored = await recordScan(projectId, report);

  assert.equal(stored.projectId, projectId);
  assert.equal(stored.score, report.score);
  assert.equal(stored.criticalCount, report.summary.critical + report.summary.high);
  assert.deepEqual(stored.report.findings, report.findings);
});

test("getLatestScan returns the most recent scan for a project", async () => {
  await recordScan(projectId, runScan(CLEAN_APP));
  const latest = await getLatestScan(projectId);
  assert.ok(latest);
  assert.equal(latest!.projectId, projectId);
});

test("listScans returns scans newest first and only for the requested project", async () => {
  const user = await createUser("scans-isolation@example.com", "correct horse battery staple");
  const otherProjectId = (await createProject(user.id, "Other Project")).id;
  await recordScan(otherProjectId, runScan(FLAWED_APP));

  const scans = await listScans(projectId);
  assert.ok(scans.length >= 2);
  assert.ok(scans.every((s) => s.projectId === projectId));
  for (let i = 1; i < scans.length; i++) {
    assert.ok(new Date(scans[i - 1].scannedAt).getTime() >= new Date(scans[i].scannedAt).getTime());
  }
});

test("getLatestScan returns null for a project with no scans yet", async () => {
  const user = await createUser("scans-empty@example.com", "correct horse battery staple");
  const emptyProjectId = (await createProject(user.id, "No Scans Yet")).id;
  assert.equal(await getLatestScan(emptyProjectId), null);
});
