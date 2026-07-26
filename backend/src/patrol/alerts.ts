import { db, newId } from "../db";
import type { Alert, AlertSeverity } from "./types";

interface AlertRow {
  id: string;
  project_id: string;
  occurred_at: string;
  severity: string;
  rule: string;
  message: string;
}

function toAlert(row: AlertRow): Alert {
  return {
    id: row.id,
    projectId: row.project_id,
    occurredAt: row.occurred_at,
    severity: row.severity as AlertSeverity,
    rule: row.rule,
    message: row.message,
  };
}

export function createAlert(projectId: string, severity: AlertSeverity, rule: string, message: string): Alert {
  const alert: Alert = { id: newId(), projectId, occurredAt: new Date().toISOString(), severity, rule, message };
  db.prepare("INSERT INTO alerts (id, project_id, occurred_at, severity, rule, message) VALUES (?, ?, ?, ?, ?, ?)").run(
    alert.id,
    alert.projectId,
    alert.occurredAt,
    alert.severity,
    alert.rule,
    alert.message
  );
  return alert;
}

export function listAlerts(projectId: string): Alert[] {
  const rows = db
    .prepare("SELECT * FROM alerts WHERE project_id = ? ORDER BY occurred_at DESC")
    .all(projectId) as unknown as AlertRow[];
  return rows.map(toAlert);
}

/** Avoid re-alerting on the same ongoing pattern every single request. */
export function hasRecentAlert(projectId: string, rule: string, withinSeconds: number): boolean {
  const since = new Date(Date.now() - withinSeconds * 1000).toISOString();
  const row = db
    .prepare("SELECT 1 FROM alerts WHERE project_id = ? AND rule = ? AND occurred_at >= ? LIMIT 1")
    .get(projectId, rule, since);
  return row !== undefined;
}
