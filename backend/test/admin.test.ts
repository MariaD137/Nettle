import { test } from "node:test";
import assert from "node:assert/strict";
import express from "express";
import path from "path";
import type { Server } from "http";
import { AddressInfo } from "net";
import { adminRouter } from "../src/routes/admin.routes";
import { authRouter } from "../src/routes/auth.routes";
import { createUser, syncAdminEmails, getUserById } from "../src/auth/users";
import { createSession } from "../src/auth/sessions";
import { createProject } from "../src/patrol/projects";
import { recordScan } from "../src/patrol/scans";
import { runScan } from "../src/scanner";
import { createAlert } from "../src/patrol/alerts";

const CLEAN_APP = path.join(__dirname, "fixtures", "clean-app");

function listen(app: express.Express): Promise<{ server: Server; base: string }> {
  return new Promise((resolve) => {
    const server = app.listen(0, () => {
      resolve({ server, base: `http://localhost:${(server.address() as AddressInfo).port}` });
    });
  });
}

function buildApp() {
  const app = express();
  app.use(express.json());
  app.use(authRouter);
  app.use(adminRouter);
  return app;
}

test("admin routes require authentication", async () => {
  const { server, base } = await listen(buildApp());
  try {
    const res = await fetch(`${base}/api/admin/overview`);
    assert.equal(res.status, 401);
  } finally {
    server.close();
  }
});

test("admin routes reject a real, authenticated, non-admin user with 403", async () => {
  const user = await createUser("not-an-admin@example.com", "correct horse battery staple");
  const token = createSession(user.id);

  const { server, base } = await listen(buildApp());
  try {
    const res = await fetch(`${base}/api/admin/overview`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    assert.equal(res.status, 403);
  } finally {
    server.close();
  }
});

test("syncAdminEmails grants access declaratively via NETTLE_ADMIN_EMAILS and revokes it when removed", async () => {
  const user = await createUser("grant-test@example.com", "correct horse battery staple");
  const token = createSession(user.id);

  const savedEnv = process.env.NETTLE_ADMIN_EMAILS;
  try {
    process.env.NETTLE_ADMIN_EMAILS = "someone-else@example.com";
    syncAdminEmails();
    assert.equal(getUserById(user.id)!.isAdmin, false);

    process.env.NETTLE_ADMIN_EMAILS = "Grant-Test@example.com"; // case-insensitive
    syncAdminEmails();
    assert.equal(getUserById(user.id)!.isAdmin, true);

    const { server, base } = await listen(buildApp());
    try {
      const res = await fetch(`${base}/api/admin/overview`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      assert.equal(res.status, 200);
    } finally {
      server.close();
    }

    // Removing the email from the list actually revokes it, not just
    // "stops re-granting" — an admin flag must not silently outlive being
    // taken off the allowlist.
    process.env.NETTLE_ADMIN_EMAILS = "";
    syncAdminEmails();
    assert.equal(getUserById(user.id)!.isAdmin, false);
  } finally {
    process.env.NETTLE_ADMIN_EMAILS = savedEnv;
  }
});

test("admin overview returns real aggregate counts across accounts, not per-caller-scoped data", async () => {
  const admin = await createUser("overview-admin@example.com", "correct horse battery staple");
  const adminToken = createSession(admin.id);
  process.env.NETTLE_ADMIN_EMAILS = "overview-admin@example.com";
  syncAdminEmails();

  const otherUser = await createUser("overview-other@example.com", "correct horse battery staple");
  const project = createProject(otherUser.id, "Overview Test Project");
  const report = runScan(CLEAN_APP);
  recordScan(project.id, report, "FAILED");
  createAlert(project.id, "high", "test-rule", "A real test alert for the overview count");

  const { server, base } = await listen(buildApp());
  try {
    const res = await fetch(`${base}/api/admin/overview`, {
      headers: { Authorization: `Bearer ${adminToken}` },
    });
    assert.equal(res.status, 200);
    const body = await res.json();

    assert.ok(body.totals.users >= 2);
    assert.ok(body.totals.scans >= 1);
    assert.ok(body.last24h.failedScans >= 1);
    assert.ok(body.activeAlerts >= 1);
    assert.ok(body.scanQueue);
    assert.ok(Array.isArray(body.subscriptionBreakdown));

    // Must never leak another account's credentials.
    const raw = JSON.stringify(body);
    assert.ok(!raw.includes("password"));
  } finally {
    server.close();
    process.env.NETTLE_ADMIN_EMAILS = "";
    syncAdminEmails();
  }
});

test("admin metrics endpoint returns the real live metrics snapshot", async () => {
  const admin = await createUser("metrics-admin@example.com", "correct horse battery staple");
  const adminToken = createSession(admin.id);
  process.env.NETTLE_ADMIN_EMAILS = "metrics-admin@example.com";
  syncAdminEmails();

  const { server, base } = await listen(buildApp());
  try {
    const res = await fetch(`${base}/api/admin/metrics`, {
      headers: { Authorization: `Bearer ${adminToken}` },
    });
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.ok(typeof body.uptimeSeconds === "number");
    assert.ok(typeof body.counters === "object");
    assert.ok(typeof body.durations === "object");
  } finally {
    server.close();
    process.env.NETTLE_ADMIN_EMAILS = "";
    syncAdminEmails();
  }
});

test("admin failed-scans lists a real failed scan with its real project name", async () => {
  const admin = await createUser("failedscans-admin@example.com", "correct horse battery staple");
  const adminToken = createSession(admin.id);
  process.env.NETTLE_ADMIN_EMAILS = "failedscans-admin@example.com";
  syncAdminEmails();

  const otherUser = await createUser("failedscans-owner@example.com", "correct horse battery staple");
  const project = createProject(otherUser.id, "Failed Scans List Project");
  recordScan(project.id, runScan(CLEAN_APP), "FAILED");

  const { server, base } = await listen(buildApp());
  try {
    const res = await fetch(`${base}/api/admin/failed-scans`, {
      headers: { Authorization: `Bearer ${adminToken}` },
    });
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.ok(body.scans.some((s: any) => s.project_name === "Failed Scans List Project" && s.status === "FAILED"));
  } finally {
    server.close();
    process.env.NETTLE_ADMIN_EMAILS = "";
    syncAdminEmails();
  }
});

test("admin notification-failures lists a real failed delivery, and overview counts it", async () => {
  const admin = await createUser("notiffailures-admin@example.com", "correct horse battery staple");
  const adminToken = createSession(admin.id);
  process.env.NETTLE_ADMIN_EMAILS = "notiffailures-admin@example.com";
  syncAdminEmails();

  const otherUser = await createUser("notiffailures-owner@example.com", "correct horse battery staple");
  const project = createProject(otherUser.id, "Notification Failures Project");

  const { db, newId } = await import("../src/db/index");
  db.prepare(
    "INSERT INTO notification_deliveries (id, project_id, channel, destination, event_type, status, attempt_count, last_error, created_at) VALUES (?, ?, ?, ?, ?, 'failed', ?, ?, ?)"
  ).run(newId(), project.id, "sms", "+15550001111", "incident_alert", 3, "SMS is not configured", new Date().toISOString());

  const { server, base } = await listen(buildApp());
  try {
    const listRes = await fetch(`${base}/api/admin/notification-failures`, {
      headers: { Authorization: `Bearer ${adminToken}` },
    });
    assert.equal(listRes.status, 200);
    const listBody = await listRes.json();
    assert.ok(listBody.failures.some((f: any) => f.project_id === project.id && f.channel === "sms"));
    // Destination (a phone number/email — PII) is deliberately not exposed here.
    assert.ok(!listBody.failures.some((f: any) => "destination" in f));

    const overviewRes = await fetch(`${base}/api/admin/overview`, {
      headers: { Authorization: `Bearer ${adminToken}` },
    });
    const overviewBody = await overviewRes.json();
    assert.ok(overviewBody.last24h.notificationFailures >= 1);
  } finally {
    server.close();
    process.env.NETTLE_ADMIN_EMAILS = "";
    syncAdminEmails();
  }
});
