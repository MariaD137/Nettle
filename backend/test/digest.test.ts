import { test } from "node:test";
import assert from "node:assert/strict";
import path from "path";
import { createUser } from "../src/auth/users";
import { createProject } from "../src/patrol/projects";
import { recordScan } from "../src/patrol/scans";
import { createAlert } from "../src/patrol/alerts";
import { createNotificationChannel } from "../src/patrol/notificationChannels";
import { composeDigest, sendDigests } from "../src/patrol/digest";
import { runScan } from "../src/scanner";
import { db } from "../src/db";

const CLEAN_APP = path.join(__dirname, "fixtures", "clean-app");

test("composeDigest summarizes scans and alerts within the period and returns null for an unknown project", async () => {
  const user = await createUser("digest-compose@example.com", "correct horse battery staple");
  const project = await createProject(user.id, "Digest Target");

  await recordScan(project.id, runScan(CLEAN_APP));
  await createAlert(project.id, "critical", "brute-force", "test alert");
  await createAlert(project.id, "medium", "high-request-rate", "test alert 2");

  const digest = await composeDigest(project.id, "daily");
  assert.ok(digest);
  assert.equal(digest!.projectName, "Digest Target");
  assert.equal(digest!.scanCount, 1);
  assert.equal(digest!.alertCount, 2);
  assert.equal(digest!.alertsBySeverity.critical, 1);
  assert.equal(digest!.alertsBySeverity.medium, 1);
  assert.match(digest!.subject, /Digest Target/);
  assert.match(digest!.text, /1 scan\(s\) run/);

  assert.equal(await composeDigest("nonexistent-project", "daily"), null);
});

test("composeDigest only counts activity within the requested period window", async () => {
  const user = await createUser("digest-window@example.com", "correct horse battery staple");
  const project = await createProject(user.id, "Digest Window Target");

  // A scan and alert dated well outside even the weekly window.
  const oldTimestamp = new Date(Date.now() - 30 * 24 * 3_600_000).toISOString();
  const report = runScan(CLEAN_APP);
  const stored = await recordScan(project.id, report);
  await db.prepare("UPDATE scans SET scanned_at = ? WHERE id = ?").run(oldTimestamp, stored.id);
  const alert = await createAlert(project.id, "critical", "brute-force", "old alert");
  await db.prepare("UPDATE alerts SET occurred_at = ? WHERE id = ?").run(oldTimestamp, alert.id);

  const daily = await composeDigest(project.id, "daily");
  assert.equal(daily!.scanCount, 0);
  assert.equal(daily!.alertCount, 0);

  const weekly = await composeDigest(project.id, "weekly");
  assert.equal(weekly!.scanCount, 0);
  assert.equal(weekly!.alertCount, 0);
});

test("sendDigests only notifies projects with an active digest.daily channel, and returns what it sent", async () => {
  const user = await createUser("digest-send@example.com", "correct horse battery staple");
  const subscribed = await createProject(user.id, "Digest Send Subscribed");
  const unsubscribed = await createProject(user.id, "Digest Send Unsubscribed");

  await createNotificationChannel(subscribed.id, "email", "ops@example.com", ["digest.daily"]);
  await createNotificationChannel(unsubscribed.id, "email", "ops2@example.com", ["scan.completed"]);

  const originalHost = process.env.SMTP_HOST;
  process.env.SMTP_HOST = "127.0.0.1"; // nothing listening — sendEmail fails but must not throw
  process.env.SMTP_PORT = "1";
  try {
    const results = await sendDigests("daily");
    assert.deepEqual(
      results.map((r) => r.projectId),
      [subscribed.id]
    );
  } finally {
    process.env.SMTP_HOST = originalHost;
  }
});
