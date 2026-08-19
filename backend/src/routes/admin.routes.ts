import { Router } from "express";
import { db } from "../db/index";
import { requireAuth, requireAdmin } from "../auth/middleware";
import { getMetricsSnapshot } from "../observability/metrics";
import { getQueueStats } from "../jobs/scanJobs";

// Minimal operator visibility, not an admin platform: read-only aggregate
// counts and recent-failure lists an operator actually needs to triage a
// production incident, gated behind the existing session auth plus
// requireAdmin (see auth/middleware.ts). Nothing here is reachable by a
// normal user, and nothing here returns another user's password hash,
// session tokens, encrypted credentials, or Stripe/webhook secrets.
export const adminRouter = Router();

const RECENT_WINDOW = "-24 hours";

adminRouter.get("/api/admin/overview", requireAuth, requireAdmin, (_req, res) => {
  const totalUsers = (db.prepare("SELECT COUNT(*) as n FROM users").get() as { n: number }).n;
  const totalProjects = (db.prepare("SELECT COUNT(*) as n FROM projects WHERE archived_at IS NULL").get() as { n: number }).n;
  const totalScans = (db.prepare("SELECT COUNT(*) as n FROM scans").get() as { n: number }).n;

  const failedScansRecent = (
    db
      .prepare("SELECT COUNT(*) as n FROM scans WHERE status IN ('FAILED', 'PARTIALLY_COMPLETED') AND scanned_at > datetime('now', ?)")
      .get(RECENT_WINDOW) as { n: number }
  ).n;

  const activeAlerts = (db.prepare("SELECT COUNT(*) as n FROM alerts WHERE status = 'new'").get() as { n: number }).n;

  const subscriptionBreakdown = db
    .prepare("SELECT plan, subscription_status, COUNT(*) as n FROM users GROUP BY plan, subscription_status")
    .all() as unknown as { plan: string; subscription_status: string; n: number }[];

  const webhookFailuresRecent = (
    db
      .prepare("SELECT COUNT(*) as n FROM webhook_events WHERE status = 'failed' AND created_at > datetime('now', ?)")
      .get(RECENT_WINDOW) as { n: number }
  ).n;

  const paymentFailuresRecent = (
    db
      .prepare("SELECT COUNT(*) as n FROM payment_failures WHERE occurred_at > datetime('now', ?)")
      .get(RECENT_WINDOW) as { n: number }
  ).n;

  const notificationFailuresRecent = (
    db
      .prepare("SELECT COUNT(*) as n FROM notification_deliveries WHERE status = 'failed' AND created_at > datetime('now', ?)")
      .get(RECENT_WINDOW) as { n: number }
  ).n;

  // Tier 2 abuse/security signal — counted by severity, not itemized, so
  // this stays a triage summary rather than a feed of raw attacker data.
  const alertsBySeverityRecent = db
    .prepare("SELECT severity, COUNT(*) as n FROM alerts WHERE occurred_at > datetime('now', ?) GROUP BY severity")
    .all(RECENT_WINDOW) as unknown as { severity: string; n: number }[];

  res.json({
    totals: { users: totalUsers, activeProjects: totalProjects, scans: totalScans },
    last24h: {
      failedScans: failedScansRecent,
      webhookFailures: webhookFailuresRecent,
      paymentFailures: paymentFailuresRecent,
      notificationFailures: notificationFailuresRecent,
      alertsBySeverity: Object.fromEntries(alertsBySeverityRecent.map((r) => [r.severity, r.n])),
    },
    activeAlerts,
    subscriptionBreakdown,
    scanQueue: getQueueStats(),
  });
});

adminRouter.get("/api/admin/metrics", requireAuth, requireAdmin, (_req, res) => {
  res.json(getMetricsSnapshot());
});

adminRouter.get("/api/admin/failed-scans", requireAuth, requireAdmin, (req, res) => {
  const limit = Math.min(parseInt(String(req.query.limit ?? "50"), 10) || 50, 200);
  const rows = db
    .prepare(
      `SELECT scans.id, scans.project_id, projects.name as project_name, scans.status, scans.scanned_at
       FROM scans JOIN projects ON projects.id = scans.project_id
       WHERE scans.status IN ('FAILED', 'PARTIALLY_COMPLETED')
       ORDER BY scans.scanned_at DESC LIMIT ?`
    )
    .all(limit);
  res.json({ scans: rows });
});

adminRouter.get("/api/admin/notification-failures", requireAuth, requireAdmin, (req, res) => {
  const limit = Math.min(parseInt(String(req.query.limit ?? "50"), 10) || 50, 200);
  const rows = db
    .prepare(
      `SELECT id, project_id, channel, event_type, attempt_count, last_error, created_at
       FROM notification_deliveries
       WHERE status = 'failed'
       ORDER BY created_at DESC LIMIT ?`
    )
    .all(limit);
  res.json({ failures: rows });
});

adminRouter.get("/api/admin/webhook-failures", requireAuth, requireAdmin, (req, res) => {
  const limit = Math.min(parseInt(String(req.query.limit ?? "50"), 10) || 50, 200);
  const rows = db
    .prepare(
      `SELECT webhook_events.id, webhook_events.webhook_id, webhooks.service, webhooks.project_id,
              webhook_events.event_type, webhook_events.attempt_count, webhook_events.last_error,
              webhook_events.created_at
       FROM webhook_events JOIN webhooks ON webhooks.id = webhook_events.webhook_id
       WHERE webhook_events.status = 'failed'
       ORDER BY webhook_events.created_at DESC LIMIT ?`
    )
    .all(limit);
  res.json({ failures: rows });
});
