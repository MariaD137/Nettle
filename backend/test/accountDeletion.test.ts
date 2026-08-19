import { test } from "node:test";
import assert from "node:assert/strict";
import { createUser, createPasswordResetToken, deleteUser } from "../src/auth/users";
import { createSession } from "../src/auth/sessions";
import { createProject } from "../src/patrol/projects";
import { recordScanUsage } from "../src/billing/scanQuota";
import { createWebhookConfig, queueWebhookEvent } from "../src/integrations/webhooks";
import { createNotificationChannel } from "../src/patrol/notificationChannels";
import { createApiKey } from "../src/patrol/apiKeys";
import { updateDetectionSettings } from "../src/patrol/detectionSettings";
import { recordFindingSeen } from "../src/patrol/findingHistory";
import { updateModelStatus } from "../src/patrol/mlAnalytics";
import { createAlert } from "../src/patrol/alerts";
import { recordEvent } from "../src/patrol/events";
import { recordScan } from "../src/patrol/scans";
import { upsertFindingStatus, hashFinding } from "../src/patrol/findingStatuses";
import { runScan } from "../src/scanner";
import { db, newId } from "../src/db";
import path from "path";

const CLEAN_APP = path.join(__dirname, "fixtures", "clean-app");

// Every table with a project_id/user_id FK back to an account — mirrors the
// list deleteUser() (auth/users.ts) is supposed to purge. Seeds exactly one
// row per table via the real code paths where a clean one exists, and a
// direct insert for the couple of tables with no standalone creator
// function (rule_versions/rule_test_results/ml_baselines).
async function seedFullAccount(emailPrefix: string) {
  const user = await createUser(`${emailPrefix}@example.com`, "correct horse battery staple");
  const project = await createProject(user.id, `${emailPrefix} project`);

  await createPasswordResetToken(user.id);
  await createSession(user.id);
  await recordScanUsage(user.id, project.id, "upload");

  const webhook = await createWebhookConfig(project.id, "generic", "https://example.com/hook", ["scan.completed"]);
  await queueWebhookEvent(webhook.id, "scan.completed", { ok: true });

  await createNotificationChannel(project.id, "email", `${emailPrefix}@ops.example.com`, ["scan.completed"]);
  await createApiKey(project.id, "Extra key", ["scan"]);
  await updateDetectionSettings(project.id, { bruteForceThreshold: 3 });
  await recordFindingSeen(project.id, "some-finding-hash", new Date().toISOString());
  await updateModelStatus(project.id, "isolation_forest", true, 0.9, 100);

  const now = new Date().toISOString();
  await db.prepare(
    "INSERT INTO ml_baselines (id, project_id, metric_name, aggregation_period, hour_of_day, value, updated_at) VALUES (?, ?, 'request_rate', 'hourly', 12, 10, ?)"
  ).run(newId(), project.id, now);
  await db.prepare(
    "INSERT INTO anomaly_scores (id, project_id, event_id, composite_score, is_anomaly, created_at) VALUES (?, ?, ?, 0.9, 1, ?)"
  ).run(newId(), project.id, newId(), now);

  const ruleId = newId();
  await db.prepare(
    "INSERT INTO custom_rules (id, project_id, name, pattern_type, pattern_value, weight, severity, version, created_by, created_at, updated_at) VALUES (?, ?, 'Test rule', 'exact', '/x', 50, 'medium', 1, ?, ?, ?)"
  ).run(ruleId, project.id, user.id, now, now);
  await db.prepare(
    "INSERT INTO rule_versions (id, rule_id, version, pattern_value, weight, severity, created_by, created_at) VALUES (?, ?, 1, '/x', 50, 'medium', ?, ?)"
  ).run(newId(), ruleId, user.id, now);
  await db.prepare(
    "INSERT INTO rule_test_results (id, rule_id, test_run_id, events_matched, created_at) VALUES (?, ?, ?, 1, ?)"
  ).run(newId(), ruleId, newId(), now);

  // No standalone creator that doesn't also attempt a real send — same
  // direct-insert pattern used above for ml_baselines/anomaly_scores/
  // rule_versions/rule_test_results. Regression coverage for H-6: this
  // table (a delivery outcome record that includes the account's real
  // destination email/phone) was previously missing from deleteUser()'s
  // purge list entirely.
  await db.prepare(
    "INSERT INTO notification_deliveries (id, project_id, channel, destination, event_type, status, attempt_count, created_at) VALUES (?, ?, 'email', ?, 'scan.completed', 'sent', 1, ?)"
  ).run(newId(), project.id, `${emailPrefix}@ops.example.com`, now);

  await createAlert(project.id, "critical", "brute-force", "test alert");
  await recordEvent(project.id, { ip: "203.0.113.1", method: "GET", path: "/", statusCode: 200 });
  const stored = await recordScan(project.id, runScan(CLEAN_APP));
  const hash = stored.report.findings[0]
    ? hashFinding(stored.report.findings[0].category, stored.report.findings[0].title, stored.report.findings[0].file)
    : "no-findings-fallback-hash";
  await upsertFindingStatus(project.id, hash, "in_progress");

  return { user, project };
}

async function countsForProject(projectId: string): Promise<Record<string, number>> {
  const tables = [
    "webhooks",
    "notification_channels",
    "notification_deliveries",
    "custom_rules",
    "api_keys",
    "detection_settings",
    "finding_history",
    "ml_baselines",
    "anomaly_scores",
    "ml_model_status",
    "alerts",
    "events",
    "scans",
    "finding_statuses",
  ];
  const counts: Record<string, number> = {};
  for (const table of tables) {
    const { count } = (await db.prepare(`SELECT COUNT(*) as count FROM ${table} WHERE project_id = ?`).get(projectId)) as { count: number };
    counts[table] = Number(count);
  }
  return counts;
}

async function countsForUser(userId: string): Promise<Record<string, number>> {
  const passwordResets = Number(
    ((await db.prepare("SELECT COUNT(*) as count FROM password_resets WHERE user_id = ?").get(userId)) as { count: number }).count
  );
  const sessions = Number(
    ((await db.prepare("SELECT COUNT(*) as count FROM sessions WHERE user_id = ?").get(userId)) as { count: number }).count
  );
  const scanUsage = Number(
    ((await db.prepare("SELECT COUNT(*) as count FROM scan_usage WHERE user_id = ?").get(userId)) as { count: number }).count
  );
  const projects = Number(
    ((await db.prepare("SELECT COUNT(*) as count FROM projects WHERE user_id = ?").get(userId)) as { count: number }).count
  );
  return { passwordResets, sessions, scanUsage, projects };
}

async function ruleChildCounts(projectId: string): Promise<{ versions: number; testResults: number; webhookEvents: number }> {
  const rule = (await db.prepare("SELECT id FROM custom_rules WHERE project_id = ?").get(projectId)) as { id: string } | undefined;
  const webhook = (await db.prepare("SELECT id FROM webhooks WHERE project_id = ?").get(projectId)) as { id: string } | undefined;
  const versions = rule
    ? Number(((await db.prepare("SELECT COUNT(*) as count FROM rule_versions WHERE rule_id = ?").get(rule.id)) as { count: number }).count)
    : 0;
  const testResults = rule
    ? Number(((await db.prepare("SELECT COUNT(*) as count FROM rule_test_results WHERE rule_id = ?").get(rule.id)) as { count: number }).count)
    : 0;
  const webhookEvents = webhook
    ? Number(((await db.prepare("SELECT COUNT(*) as count FROM webhook_events WHERE webhook_id = ?").get(webhook.id)) as { count: number }).count)
    : 0;
  return { versions, testResults, webhookEvents };
}

test("deleteUser purges every project-scoped and account-scoped table, leaving zero orphaned rows", async () => {
  const { user, project } = await seedFullAccount("purge-target");

  const before = await countsForProject(project.id);
  for (const [table, count] of Object.entries(before)) {
    assert.ok(count > 0, `expected a seeded row in ${table} before deletion`);
  }
  const ruleChildrenBefore = await ruleChildCounts(project.id);
  assert.ok(ruleChildrenBefore.versions > 0);
  assert.ok(ruleChildrenBefore.testResults > 0);
  assert.ok(ruleChildrenBefore.webhookEvents > 0);

  await deleteUser(user.id);

  const after = await countsForProject(project.id);
  for (const [table, count] of Object.entries(after)) {
    assert.equal(count, 0, `expected ${table} to be fully purged after account deletion`);
  }
  const ruleChildrenAfter = await ruleChildCounts(project.id);
  assert.equal(ruleChildrenAfter.versions, 0);
  assert.equal(ruleChildrenAfter.testResults, 0);
  assert.equal(ruleChildrenAfter.webhookEvents, 0);

  const userCounts = await countsForUser(user.id);
  assert.deepEqual(userCounts, { passwordResets: 0, sessions: 0, scanUsage: 0, projects: 0 });

  const userRow = await db.prepare("SELECT id FROM users WHERE id = ?").get(user.id);
  assert.equal(userRow, undefined);
});

test("deleteUser never touches another account's data", async () => {
  const target = await seedFullAccount("purge-isolation-target");
  const bystander = await seedFullAccount("purge-isolation-bystander");

  await deleteUser(target.user.id);

  const bystanderCounts = await countsForProject(bystander.project.id);
  for (const [table, count] of Object.entries(bystanderCounts)) {
    assert.ok(count > 0, `deleting another account must not remove ${table} rows belonging to this one`);
  }
  const bystanderUserCounts = await countsForUser(bystander.user.id);
  assert.ok(bystanderUserCounts.sessions > 0);
  assert.ok(bystanderUserCounts.projects > 0);

  const bystanderRow = await db.prepare("SELECT id FROM users WHERE id = ?").get(bystander.user.id);
  assert.ok(bystanderRow);
});
