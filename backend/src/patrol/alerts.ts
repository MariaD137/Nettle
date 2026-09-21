import { db, newId } from "../db";
import type { Alert, AlertSeverity, AlertStatus } from "./types";

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
  await db.run(
    "INSERT INTO alerts (id, project_id, occurred_at, severity, rule, message, status) VALUES (?, ?, ?, ?, ?, ?, ?)",
    [alert.id, alert.projectId, alert.occurredAt, alert.severity, alert.rule, alert.message, alert.status]
  );
  return alert;
}

export async function listAlerts(projectId: string): Promise<Alert[]> {
  const rows = await db.all<AlertRow>(
    "SELECT * FROM alerts WHERE project_id = ? ORDER BY occurred_at DESC",
    [projectId]
  );
  return rows.map(toAlert);
}

export async function getAlert(alertId: string): Promise<Alert | null> {
  const row = await db.get<AlertRow>("SELECT * FROM alerts WHERE id = ?", [alertId]);
  return row ? toAlert(row) : null;
}

const VALID_STATUSES: AlertStatus[] = ["new", "acknowledged", "resolved", "false_positive"];

export async function updateAlertStatus(alertId: string, status: AlertStatus): Promise<Alert | null> {
  if (!VALID_STATUSES.includes(status)) return null;
  await db.run("UPDATE alerts SET status = ? WHERE id = ?", [status, alertId]);
  return getAlert(alertId);
}

export async function hasRecentAlert(projectId: string, rule: string, withinSeconds: number): Promise<boolean> {
  const since = new Date(Date.now() - withinSeconds * 1000).toISOString();
  const row = await db.get(
    "SELECT 1 AS present FROM alerts WHERE project_id = ? AND rule = ? AND occurred_at >= ? LIMIT 1",
    [projectId, rule, since]
  );
  return row !== null;
}

export async function countAlertsByStatus(projectId: string): Promise<Record<AlertStatus, number>> {
  const counts: Record<AlertStatus, number> = { new: 0, acknowledged: 0, resolved: 0, false_positive: 0 };
  // CAST plus Number(): PostgreSQL returns COUNT(*) as bigint, which the pg
  // driver hands back as a *string* to avoid precision loss. Assigning that
  // straight into a number field would quietly produce "3" instead of 3.
  const rows = await db.all<{ status: string; count: number | string }>(
    "SELECT status, CAST(COUNT(*) AS INTEGER) as count FROM alerts WHERE project_id = ? GROUP BY status",
    [projectId]
  );
  for (const row of rows) {
    if (row.status in counts) counts[row.status as AlertStatus] = Number(row.count);
  }
  return counts;
}
