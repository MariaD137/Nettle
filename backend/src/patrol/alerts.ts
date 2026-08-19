import { db, newId } from "../db";
import type { Alert, AlertSeverity, AlertStatus } from "./types";
import { getWebhookConfigs, sendWebhook } from "../integrations/webhooks";
import { sendSlackAlert } from "../integrations/slack";
import { sendPagerDutyAlert } from "../integrations/pagerduty";
import { sendSplunkAlert } from "../integrations/splunk";
import { sendDatadogAlert } from "../integrations/datadog";
import { notifyChannels } from "./notificationChannels";
import { incrementCounter, Metric } from "../observability/metrics";

interface AlertRow {
  id: string;
  project_id: string;
  occurred_at: string;
  severity: string;
  rule: string;
  message: string;
  status: string;
}

function toAlert(row: AlertRow): Alert {
  return {
    id: row.id,
    projectId: row.project_id,
    occurredAt: row.occurred_at,
    severity: row.severity as AlertSeverity,
    rule: row.rule,
    message: row.message,
    status: (row.status || "new") as AlertStatus,
  };
}

export async function createAlert(projectId: string, severity: AlertSeverity, rule: string, message: string): Promise<Alert> {
  const alert: Alert = {
    id: newId(),
    projectId,
    occurredAt: new Date().toISOString(),
    severity,
    rule,
    message,
    status: "new",
  };
  await db
    .prepare("INSERT INTO alerts (id, project_id, occurred_at, severity, rule, message, status) VALUES (?, ?, ?, ?, ?, ?, ?)")
    .run(alert.id, alert.projectId, alert.occurredAt, alert.severity, alert.rule, alert.message, alert.status);
  incrementCounter(Metric.AlertsGenerated);
  notifyAlertWebhooks(alert).catch((err) => console.error("notifyAlertWebhooks failed:", err));
  notifyChannels(alert.projectId, "incident_alert", `Nettle alert (${alert.severity}): ${alert.rule}`, alert.message);
  return alert;
}

/**
 * Fans a newly-created alert out to every active webhook configured for the
 * project, using the right per-service payload shape. Fire-and-forget by
 * design — a slow or unreachable webhook (deliverWebhook retries with
 * backoff up to ~8 minutes) must never block or fail the caller, matching
 * the same "monitoring can't break the thing it's monitoring" principle as
 * nettleMonitor.ts. Errors are swallowed after being logged.
 */
async function notifyAlertWebhooks(alert: Alert): Promise<void> {
  const webhooks = await getWebhookConfigs(alert.projectId);
  const services = new Set(webhooks.filter((w) => w.is_active).map((w) => w.service));
  const details = { rule: alert.rule, message: alert.message, alert_id: alert.id };

  const deliveries: Promise<void>[] = [];
  if (services.has("slack")) deliveries.push(sendSlackAlert(alert.projectId, alert.rule, alert.severity, details));
  if (services.has("pagerduty")) deliveries.push(sendPagerDutyAlert(alert.projectId, alert.rule, alert.severity, details));
  if (services.has("splunk")) deliveries.push(sendSplunkAlert(alert.projectId, alert.rule, alert.severity, details));
  if (services.has("datadog")) deliveries.push(sendDatadogAlert(alert.projectId, alert.rule, alert.severity, details));
  if (services.has("generic")) {
    deliveries.push(sendWebhook(alert.projectId, "incident_alert", { alert, ...details }, "generic"));
  }

  Promise.allSettled(deliveries).then((results) => {
    for (const r of results) {
      if (r.status === "rejected") console.error("Alert webhook delivery failed:", r.reason);
    }
  });
}

export async function listAlerts(projectId: string): Promise<Alert[]> {
  const rows = (await db
    .prepare("SELECT * FROM alerts WHERE project_id = ? ORDER BY occurred_at DESC")
    .all(projectId)) as unknown as AlertRow[];
  return rows.map(toAlert);
}

export async function getAlert(alertId: string): Promise<Alert | null> {
  const row = (await db.prepare("SELECT * FROM alerts WHERE id = ?").get(alertId)) as AlertRow | undefined;
  return row ? toAlert(row) : null;
}

const VALID_STATUSES: AlertStatus[] = ["new", "acknowledged", "resolved", "false_positive"];

export async function updateAlertStatus(alertId: string, status: AlertStatus): Promise<Alert | null> {
  if (!VALID_STATUSES.includes(status)) return null;
  await db.prepare("UPDATE alerts SET status = ? WHERE id = ?").run(status, alertId);
  return getAlert(alertId);
}

export async function hasRecentAlert(projectId: string, rule: string, withinSeconds: number): Promise<boolean> {
  const since = new Date(Date.now() - withinSeconds * 1000).toISOString();
  const row = await db
    .prepare("SELECT 1 FROM alerts WHERE project_id = ? AND rule = ? AND occurred_at >= ? LIMIT 1")
    .get(projectId, rule, since);
  return row !== undefined;
}

export async function countAlertsByStatus(projectId: string): Promise<Record<AlertStatus, number>> {
  const counts: Record<AlertStatus, number> = { new: 0, acknowledged: 0, resolved: 0, false_positive: 0 };
  const rows = (await db
    .prepare("SELECT status, COUNT(*) as count FROM alerts WHERE project_id = ? GROUP BY status")
    .all(projectId)) as unknown as { status: string; count: number | string }[];
  for (const row of rows) {
    if (row.status in counts) counts[row.status as AlertStatus] = Number(row.count);
  }
  return counts;
}
