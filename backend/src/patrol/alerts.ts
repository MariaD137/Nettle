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

export function createAlert(projectId: string, severity: AlertSeverity, rule: string, message: string): Alert {
  const alert: Alert = {
    id: newId(),
    projectId,
    occurredAt: new Date().toISOString(),
    severity,
    rule,
    message,
    status: "new",
  };
  db.prepare(
    "INSERT INTO alerts (id, project_id, occurred_at, severity, rule, message, status) VALUES (?, ?, ?, ?, ?, ?, ?)"
  ).run(alert.id, alert.projectId, alert.occurredAt, alert.severity, alert.rule, alert.message, alert.status);
  return alert;
}

export function listAlerts(projectId: string): Alert[] {
  const rows = db
    .prepare("SELECT * FROM alerts WHERE project_id = ? ORDER BY occurred_at DESC")
    .all(projectId) as unknown as AlertRow[];
  return rows.map(toAlert);
}

export function getAlert(alertId: string): Alert | null {
  const row = db.prepare("SELECT * FROM alerts WHERE id = ?").get(alertId) as AlertRow | undefined;
  return row ? toAlert(row) : null;
}

const VALID_STATUSES: AlertStatus[] = ["new", "acknowledged", "resolved", "false_positive"];

export function updateAlertStatus(alertId: string, status: AlertStatus): Alert | null {
  if (!VALID_STATUSES.includes(status)) return null;
  db.prepare("UPDATE alerts SET status = ? WHERE id = ?").run(status, alertId);
  return getAlert(alertId);
}

export function hasRecentAlert(projectId: string, rule: string, withinSeconds: number): boolean {
  const since = new Date(Date.now() - withinSeconds * 1000).toISOString();
  const row = db
    .prepare("SELECT 1 FROM alerts WHERE project_id = ? AND rule = ? AND occurred_at >= ? LIMIT 1")
    .get(projectId, rule, since);
  return row !== undefined;
}

export function countAlertsByStatus(projectId: string): Record<AlertStatus, number> {
  const counts: Record<AlertStatus, number> = { new: 0, acknowledged: 0, resolved: 0, false_positive: 0 };
  const rows = db
    .prepare("SELECT status, COUNT(*) as count FROM alerts WHERE project_id = ? GROUP BY status")
    .all(projectId) as unknown as { status: string; count: number }[];
  for (const row of rows) {
    if (row.status in counts) counts[row.status as AlertStatus] = row.count;
  }
  return counts;
}
