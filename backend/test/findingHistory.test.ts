import { test, before } from "node:test";
import assert from "node:assert/strict";
import path from "path";
import { db, newId } from "../src/db";
import { createUser } from "../src/auth/users";
import { createProject } from "../src/patrol/projects";
import { recordScan } from "../src/patrol/scans";
import { runScan } from "../src/scanner";
import { hashFinding } from "../src/patrol/findingStatuses";
import {
  recordFindingSeen,
  listFindingHistory,
  getFindingHistoryEntry,
  backfillFindingHistory,
} from "../src/patrol/findingHistory";

const FLAWED_APP = path.join(__dirname, "fixtures", "sample-app");

async function insertScanRowDirectly(projectId: string, scannedAt: string, reportJson: string) {
  await db.prepare(
    "INSERT INTO scans (id, project_id, scanned_at, score, critical_count, caution_count, clear_count, status, report_json) VALUES (?, ?, ?, 0, 0, 0, 0, 'COMPLETED', ?)"
  ).run(newId(), projectId, scannedAt, reportJson);
}

// This test runs first and deliberately bypasses recordScan (which would
// call recordFindingSeen itself) — it writes scan rows straight to the
// `scans` table via raw SQL, the same shape recordScan produces, so
// finding_history is still genuinely empty when backfillFindingHistory()
// runs. That's the only way to honestly test the "seed from scans that
// predate this feature" path instead of the ongoing incremental one.
test("backfillFindingHistory seeds first/last-seen from pre-existing scans when finding_history starts empty", async () => {
  const user = await createUser("finding-history-backfill@example.com", "correct horse battery staple");
  const project = (await createProject(user.id, "Backfill Target")).id;

  const report = runScan(FLAWED_APP);
  assert.ok(report.findings.length > 0, "fixture should produce real findings to backfill from");
  const finding = report.findings[0];
  const hash = hashFinding(finding.category, finding.title, finding.file);

  await insertScanRowDirectly(project, "2020-01-01T00:00:00.000Z", JSON.stringify({ ...report, scannedAt: "2020-01-01T00:00:00.000Z" }));
  await insertScanRowDirectly(project, "2020-06-01T00:00:00.000Z", JSON.stringify({ ...report, scannedAt: "2020-06-01T00:00:00.000Z" }));

  // backfillFindingHistory()'s real gate is genuinely global ("do nothing
  // if finding_history has any row at all, anywhere" — see
  // patrol/findingHistory.ts). Under the old per-file :memory: DB that gate
  // was trivially empty at the start of every file; now the database is
  // shared across the whole `npm test` run, so this test enforces its own
  // precondition instead of assuming it — clearing finding_history (only
  // this table, nothing else) is what actually exercises the from-scratch
  // backfill path deterministically. Every other test's own history rows
  // are independent, freshly created per test via recordScan()/
  // recordFindingSeen(), so this doesn't affect them.
  await db.prepare("DELETE FROM finding_history").run();
  const before = (await db.prepare("SELECT COUNT(*) as count FROM finding_history").get()) as { count: number | string };
  assert.equal(Number(before.count), 0, "finding_history must be empty immediately after the DELETE above");

  await backfillFindingHistory();

  const entry = await getFindingHistoryEntry(project, hash);
  assert.ok(entry, "backfill should have derived a history entry from the two pre-existing scans");
  assert.equal(entry!.firstSeenAt, "2020-01-01T00:00:00.000Z");
  assert.equal(entry!.lastSeenAt, "2020-06-01T00:00:00.000Z");

  // Second call is a no-op once the table has been seeded.
  await backfillFindingHistory();
  const unchanged = await getFindingHistoryEntry(project, hash);
  assert.deepEqual(unchanged, entry);
});

let projectId: string;
before(async () => {
  const user = await createUser("finding-history-tests@example.com", "correct horse battery staple");
  projectId = (await createProject(user.id, "Finding History Target")).id;
});

test("recordFindingSeen creates a new entry with matching first/last seen on first sighting", async () => {
  await recordFindingSeen(projectId, "hash-a", "2026-01-01T00:00:00.000Z");
  const entry = await getFindingHistoryEntry(projectId, "hash-a");
  assert.ok(entry);
  assert.equal(entry!.firstSeenAt, "2026-01-01T00:00:00.000Z");
  assert.equal(entry!.lastSeenAt, "2026-01-01T00:00:00.000Z");
});

test("recordFindingSeen advances lastSeenAt on a later sighting without moving firstSeenAt", async () => {
  await recordFindingSeen(projectId, "hash-b", "2026-01-01T00:00:00.000Z");
  await recordFindingSeen(projectId, "hash-b", "2026-02-01T00:00:00.000Z");
  const entry = await getFindingHistoryEntry(projectId, "hash-b");
  assert.equal(entry!.firstSeenAt, "2026-01-01T00:00:00.000Z");
  assert.equal(entry!.lastSeenAt, "2026-02-01T00:00:00.000Z");
});

test("recordFindingSeen widens firstSeenAt backward for an out-of-order (earlier) sighting", async () => {
  await recordFindingSeen(projectId, "hash-c", "2026-03-01T00:00:00.000Z");
  await recordFindingSeen(projectId, "hash-c", "2026-01-15T00:00:00.000Z");
  const entry = await getFindingHistoryEntry(projectId, "hash-c");
  assert.equal(entry!.firstSeenAt, "2026-01-15T00:00:00.000Z");
  assert.equal(entry!.lastSeenAt, "2026-03-01T00:00:00.000Z");
});

test("getFindingHistoryEntry returns null for a hash never recorded", async () => {
  assert.equal(await getFindingHistoryEntry(projectId, "never-seen"), null);
});

test("listFindingHistory only returns entries for the requested project", async () => {
  const user = await createUser("finding-history-isolation@example.com", "correct horse battery staple");
  const otherProjectId = (await createProject(user.id, "Other Project")).id;
  await recordFindingSeen(otherProjectId, "other-hash", "2026-01-01T00:00:00.000Z");

  const mine = await listFindingHistory(projectId);
  assert.ok(mine.every((e) => e.findingHash !== "other-hash"));
});

test("recordScan records first/last-detected for every finding in the report, and repeat scans advance lastSeenAt", async () => {
  const user = await createUser("finding-history-scan@example.com", "correct horse battery staple");
  const project = (await createProject(user.id, "Real Scan History Target")).id;

  const firstReport = runScan(FLAWED_APP);
  firstReport.scannedAt = "2026-01-01T00:00:00.000Z";
  await recordScan(project, firstReport);
  assert.ok(firstReport.findings.length > 0, "fixture should produce real findings to track");

  const firstHash = hashFinding(firstReport.findings[0].category, firstReport.findings[0].title, firstReport.findings[0].file);
  const afterFirst = await getFindingHistoryEntry(project, firstHash);
  assert.ok(afterFirst);
  assert.equal(afterFirst!.firstSeenAt, "2026-01-01T00:00:00.000Z");
  assert.equal(afterFirst!.lastSeenAt, "2026-01-01T00:00:00.000Z");

  const secondReport = runScan(FLAWED_APP);
  secondReport.scannedAt = "2026-02-01T00:00:00.000Z";
  await recordScan(project, secondReport);

  const afterSecond = await getFindingHistoryEntry(project, firstHash);
  assert.equal(afterSecond!.firstSeenAt, "2026-01-01T00:00:00.000Z", "first-seen should not move");
  assert.equal(afterSecond!.lastSeenAt, "2026-02-01T00:00:00.000Z", "last-seen should advance to the newer scan");
});
