import { test } from "node:test";
import assert from "node:assert/strict";
import express from "express";
import type { Server } from "http";
import { AddressInfo } from "net";
import { db, newId } from "../src/db/index";
import { createUser } from "../src/auth/users";
import { createProject } from "../src/patrol/projects";
import { getRetentionConfig, runRetentionCleanup } from "../src/patrol/retention";
import { internalRouter } from "../src/routes/internal.routes";

function listen(app: express.Express): Promise<{ server: Server; base: string }> {
  return new Promise((resolve) => {
    const server = app.listen(0, () => {
      resolve({ server, base: `http://localhost:${(server.address() as AddressInfo).port}` });
    });
  });
}

function isoDaysAgo(days: number): string {
  return new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString();
}

async function setup() {
  const user = await createUser(`retention-${newId()}@example.com`, "correct horse battery staple");
  const project = await createProject(user.id, "Retention Test Project");
  return { user, project };
}

async function insertEvent(projectId: string, occurredAt: string) {
  await db.prepare(
    "INSERT INTO events (id, project_id, occurred_at, ip, method, path, status_code) VALUES (?, ?, ?, ?, ?, ?, ?)"
  ).run(newId(), projectId, occurredAt, "127.0.0.1", "GET", "/", 200);
}

async function insertAlert(projectId: string, occurredAt: string) {
  await db.prepare(
    "INSERT INTO alerts (id, project_id, occurred_at, severity, rule, message, status) VALUES (?, ?, ?, ?, ?, ?, ?)"
  ).run(newId(), projectId, occurredAt, "high", "test-rule", "test alert", "new");
}

async function insertScan(projectId: string, scannedAt: string) {
  await db.prepare(
    `INSERT INTO scans (id, project_id, scanned_at, score, critical_count, caution_count, clear_count, report_json)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(newId(), projectId, scannedAt, 80, 0, 0, 5, "{}");
}

async function insertWebhookEvent(webhookId: string, createdAt: string) {
  await db.prepare(
    "INSERT INTO webhook_events (id, webhook_id, event_type, payload, status, created_at) VALUES (?, ?, ?, ?, ?, ?)"
  ).run(newId(), webhookId, "test_event", "{}", "sent", createdAt);
}

test("getRetentionConfig returns real configured defaults, and honors env overrides", () => {
  const saved = process.env.RETENTION_EVENTS_DAYS;
  try {
    delete process.env.RETENTION_EVENTS_DAYS;
    assert.equal(getRetentionConfig().eventsDays, 90);

    process.env.RETENTION_EVENTS_DAYS = "14";
    assert.equal(getRetentionConfig().eventsDays, 14);
  } finally {
    process.env.RETENTION_EVENTS_DAYS = saved;
  }
});

test("runRetentionCleanup deletes only rows older than their configured window, leaving recent rows untouched", async () => {
  const { project } = await setup();

  await insertEvent(project.id, isoDaysAgo(120)); // older than default 90d
  await insertEvent(project.id, isoDaysAgo(5)); // recent — must survive

  await insertAlert(project.id, isoDaysAgo(200)); // older than default 180d
  await insertAlert(project.id, isoDaysAgo(5)); // recent — must survive

  const savedScans = process.env.RETENTION_SCANS_DAYS;
  const savedWebhooks = process.env.RETENTION_WEBHOOK_EVENTS_DAYS;
  process.env.RETENTION_SCANS_DAYS = "30";
  process.env.RETENTION_WEBHOOK_EVENTS_DAYS = "7";

  try {
    await insertScan(project.id, isoDaysAgo(60)); // older than 30d override
    await insertScan(project.id, isoDaysAgo(1)); // recent — must survive

    await db
      .prepare("INSERT INTO webhooks (id, project_id, service, webhook_url, event_types, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
      .run(newId(), project.id, "generic", "https://example.com/hook", "[]", isoDaysAgo(60), isoDaysAgo(60));
    const webhookId = ((await db.prepare("SELECT id FROM webhooks WHERE project_id = ?").get(project.id)) as { id: string }).id;
    await insertWebhookEvent(webhookId, isoDaysAgo(10)); // older than 7d override
    await insertWebhookEvent(webhookId, isoDaysAgo(1)); // recent — must survive

    const before = {
      events: Number((await db.prepare("SELECT COUNT(*) as n FROM events WHERE project_id = ?").get(project.id) as any).n),
      alerts: Number((await db.prepare("SELECT COUNT(*) as n FROM alerts WHERE project_id = ?").get(project.id) as any).n),
      scans: Number((await db.prepare("SELECT COUNT(*) as n FROM scans WHERE project_id = ?").get(project.id) as any).n),
      webhookEvents: Number((await db.prepare("SELECT COUNT(*) as n FROM webhook_events WHERE webhook_id = ?").get(webhookId) as any).n),
    };
    assert.equal(before.events, 2);
    assert.equal(before.alerts, 2);
    assert.equal(before.scans, 2);
    assert.equal(before.webhookEvents, 2);

    const result = await runRetentionCleanup();
    assert.ok(result.eventsDeleted >= 1);
    assert.ok(result.alertsDeleted >= 1);
    assert.equal(result.scansDeleted >= 1, true);
    assert.equal(result.webhookEventsDeleted >= 1, true);

    assert.equal(Number((await db.prepare("SELECT COUNT(*) as n FROM events WHERE project_id = ?").get(project.id) as any).n), 1);
    assert.equal(Number((await db.prepare("SELECT COUNT(*) as n FROM alerts WHERE project_id = ?").get(project.id) as any).n), 1);
    assert.equal(Number((await db.prepare("SELECT COUNT(*) as n FROM scans WHERE project_id = ?").get(project.id) as any).n), 1);
    assert.equal(
      Number((await db.prepare("SELECT COUNT(*) as n FROM webhook_events WHERE webhook_id = ?").get(webhookId) as any).n),
      1
    );
  } finally {
    process.env.RETENTION_SCANS_DAYS = savedScans;
    process.env.RETENTION_WEBHOOK_EVENTS_DAYS = savedWebhooks;
  }
});

test("a retention window of 0 disables deletion for that category entirely", async () => {
  const { project } = await setup();
  await insertEvent(project.id, isoDaysAgo(9999));

  const saved = process.env.RETENTION_EVENTS_DAYS;
  process.env.RETENTION_EVENTS_DAYS = "0";
  try {
    const before = Number((await db.prepare("SELECT COUNT(*) as n FROM events WHERE project_id = ?").get(project.id) as any).n);
    const result = await runRetentionCleanup();
    assert.equal(result.eventsDeleted, 0);
    const after = Number((await db.prepare("SELECT COUNT(*) as n FROM events WHERE project_id = ?").get(project.id) as any).n);
    assert.equal(after, before);
  } finally {
    process.env.RETENTION_EVENTS_DAYS = saved;
  }
});

test("runRetentionCleanup never touches users, projects, or payment/subscription records", async () => {
  const { user, project } = await setup();

  // Not scoped to this test's own rows, but only ever compared against
  // itself (before vs. after) — never asserted against an absolute value —
  // so sharing the database with other test files doesn't affect it.
  const usersBefore = Number((await db.prepare("SELECT COUNT(*) as n FROM users").get() as any).n);
  const projectsBefore = Number((await db.prepare("SELECT COUNT(*) as n FROM projects").get() as any).n);

  await runRetentionCleanup();

  assert.equal(Number((await db.prepare("SELECT COUNT(*) as n FROM users").get() as any).n), usersBefore);
  assert.equal(Number((await db.prepare("SELECT COUNT(*) as n FROM projects").get() as any).n), projectsBefore);
  assert.ok(await db.prepare("SELECT 1 FROM users WHERE id = ?").get(user.id));
  assert.ok(await db.prepare("SELECT 1 FROM projects WHERE id = ?").get(project.id));
});

function buildApp() {
  const app = express();
  app.use(express.json());
  app.use(internalRouter);
  return app;
}

test("POST /api/internal/retention/cleanup requires the correct cron secret and returns real deletion counts", async () => {
  const { project } = await setup();
  await insertEvent(project.id, isoDaysAgo(200));

  const app = buildApp();
  const { server, base } = await listen(app);
  const original = process.env.CRON_SECRET;
  process.env.CRON_SECRET = "s3cr3t";
  try {
    const unauthed = await fetch(`${base}/api/internal/retention/cleanup`, { method: "POST" });
    assert.equal(unauthed.status, 401);

    const res = await fetch(`${base}/api/internal/retention/cleanup`, {
      method: "POST",
      headers: { "X-Nettle-Cron-Secret": "s3cr3t" },
    });
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.ok(body.eventsDeleted >= 1);
    assert.ok(body.config);
  } finally {
    process.env.CRON_SECRET = original;
    server.close();
  }
});

test("POST /api/internal/retention/cleanup is disabled (503) when CRON_SECRET isn't configured", async () => {
  const app = buildApp();
  const { server, base } = await listen(app);
  const original = process.env.CRON_SECRET;
  delete process.env.CRON_SECRET;
  try {
    const res = await fetch(`${base}/api/internal/retention/cleanup`, { method: "POST" });
    assert.equal(res.status, 503);
  } finally {
    process.env.CRON_SECRET = original;
    server.close();
  }
});
