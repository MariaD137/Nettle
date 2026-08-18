import { test, before } from "node:test";
import assert from "node:assert/strict";
import path from "path";
import { createUser } from "../src/auth/users";
import { createProject, updateProject } from "../src/patrol/projects";
import { recordScan, listScans, getLatestScan } from "../src/patrol/scans";
import { runScan } from "../src/scanner";

const FLAWED_APP = path.join(__dirname, "fixtures", "sample-app");
const CLEAN_APP = path.join(__dirname, "fixtures", "clean-app");

let projectId: string;
before(async () => {
  const user = await createUser("scans-tests@example.com", "correct horse battery staple");
  projectId = createProject(user.id, "Scan Persistence Target").id;
});

test("recordScan persists a real scan report and round-trips it", () => {
  const report = runScan(FLAWED_APP);
  const stored = recordScan(projectId, report);

  assert.equal(stored.projectId, projectId);
  assert.equal(stored.score, report.score);
  assert.equal(stored.criticalCount, report.summary.critical + report.summary.high);
  assert.deepEqual(stored.report.findings, report.findings);
});

test("getLatestScan returns the most recent scan for a project", () => {
  recordScan(projectId, runScan(CLEAN_APP));
  const latest = getLatestScan(projectId);
  assert.ok(latest);
  assert.equal(latest!.projectId, projectId);
});

test("listScans returns scans newest first and only for the requested project", async () => {
  const user = await createUser("scans-isolation@example.com", "correct horse battery staple");
  const otherProjectId = createProject(user.id, "Other Project").id;
  recordScan(otherProjectId, runScan(FLAWED_APP));

  const scans = listScans(projectId);
  assert.ok(scans.length >= 2);
  assert.ok(scans.every((s) => s.projectId === projectId));
  for (let i = 1; i < scans.length; i++) {
    assert.ok(new Date(scans[i - 1].scannedAt).getTime() >= new Date(scans[i].scannedAt).getTime());
  }
});

test("getLatestScan returns null for a project with no scans yet", async () => {
  const user = await createUser("scans-empty@example.com", "correct horse battery staple");
  const emptyProjectId = createProject(user.id, "No Scans Yet").id;
  assert.equal(getLatestScan(emptyProjectId), null);
});

test("recordScan snapshots the project's environment onto the stored report", async () => {
  const user = await createUser("scans-env@example.com", "correct horse battery staple");
  const project = createProject(user.id, "Env Tag Target", { environment: "staging" });

  const report = runScan(CLEAN_APP);
  assert.equal(report.environment, undefined, "runScan itself has no notion of environment");

  const stored = recordScan(project.id, report);
  assert.equal(stored.report.environment, "staging");
  // Mutated in place — the original report object the caller is still
  // holding (e.g. to build an HTTP response from) reflects it too.
  assert.equal(report.environment, "staging");
});

test("a scan's environment tag is a permanent snapshot — relabeling the project later doesn't change it", async () => {
  const user = await createUser("scans-env-snapshot@example.com", "correct horse battery staple");
  const project = createProject(user.id, "Relabeled Project", { environment: "development" });

  const stored = recordScan(project.id, runScan(CLEAN_APP));
  assert.equal(stored.report.environment, "development");

  updateProject(project.id, { environment: "production" });

  const reloaded = getLatestScan(project.id);
  assert.equal(reloaded?.report.environment, "development", "the historical scan must not retroactively relabel itself");
});

test("recordScan persists scannerVersion and semgrepVersion as first-class, queryable fields", async () => {
  const user = await createUser("scans-version-tracking@example.com", "correct horse battery staple");
  const project = createProject(user.id, "Version Tracking Target").id;

  const report = runScan(FLAWED_APP);
  assert.ok(report.scannerVersion, "a real scan should always carry the scanner's own version");

  const stored = recordScan(project, report);
  assert.equal(stored.scannerVersion, report.scannerVersion);
  assert.equal(stored.semgrepVersion, report.semgrepVersion ?? null);

  // Round-trip through storage (not just the in-memory object recordScan
  // returns) — the dedicated columns, not just the report_json blob.
  const reloaded = getLatestScan(project);
  assert.equal(reloaded?.scannerVersion, report.scannerVersion);
  assert.equal(reloaded?.semgrepVersion, report.semgrepVersion ?? null);
});

test("a scan recorded with no semgrepVersion (e.g. a URL scan) stores null, not undefined or a crash", async () => {
  const user = await createUser("scans-version-no-semgrep@example.com", "correct horse battery staple");
  const project = createProject(user.id, "No Semgrep Version Target").id;

  const report = runScan(FLAWED_APP);
  delete report.semgrepVersion;

  const stored = recordScan(project, report);
  assert.equal(stored.semgrepVersion, null);
  assert.equal(getLatestScan(project)?.semgrepVersion, null);
});
