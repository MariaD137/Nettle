import { db, newId } from "../db";
import type { ScanReport, ScanStatus } from "../scanner/types";
import { getProject } from "./projects";
import { hashFinding } from "./findingStatuses";
import { recordFindingSeen } from "./findingHistory";

export interface StoredScan {
  id: string;
  projectId: string;
  scannedAt: string;
  score: number;
  criticalCount: number;
  cautionCount: number;
  clearCount: number;
  status: ScanStatus;
  report: ScanReport;
}

interface ScanRow {
  id: string;
  project_id: string;
  scanned_at: string;
  score: number;
  critical_count: number;
  caution_count: number;
  clear_count: number;
  status: string;
  report_json: string;
}

function toScan(row: ScanRow): StoredScan {
  return {
    id: row.id,
    projectId: row.project_id,
    scannedAt: row.scanned_at,
    score: row.score,
    criticalCount: row.critical_count,
    cautionCount: row.caution_count,
    clearCount: row.clear_count,
    status: (row.status || "COMPLETED") as ScanStatus,
    report: JSON.parse(row.report_json),
  };
}

export function recordScan(projectId: string, report: ScanReport, status: ScanStatus = "COMPLETED"): StoredScan {
  // Mutated in place, not spread into a copy: callers that hold their own
  // reference to this same report object (e.g. the response already being
  // built for the request that triggered this scan) pick up the tag too,
  // without every call site having to remember to re-read it back out.
  if (report.environment === undefined) {
    report.environment = getProject(projectId)?.environment ?? null;
  }

  const criticalCount = report.summary.critical + report.summary.high;
  const cautionCount = report.summary.medium + report.summary.low + report.summary.info;
  const stored: StoredScan = {
    id: newId(),
    projectId,
    scannedAt: report.scannedAt,
    score: report.score,
    criticalCount,
    cautionCount,
    clearCount: report.summary.clear,
    status: report.status || status, // Use report status if set, otherwise fall back to parameter
    report,
  };
  db.prepare(
    "INSERT INTO scans (id, project_id, scanned_at, score, critical_count, caution_count, clear_count, status, report_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
  ).run(
    stored.id,
    stored.projectId,
    stored.scannedAt,
    stored.score,
    stored.criticalCount,
    stored.cautionCount,
    stored.clearCount,
    stored.status,
    JSON.stringify(report)
  );

  for (const finding of report.findings) {
    const hash = hashFinding(finding.category, finding.title, finding.file);
    recordFindingSeen(projectId, hash, report.scannedAt);
  }

  return stored;
}

export function listScans(projectId: string): StoredScan[] {
  const rows = db
    .prepare("SELECT * FROM scans WHERE project_id = ? ORDER BY scanned_at DESC")
    .all(projectId) as unknown as ScanRow[];
  return rows.map(toScan);
}

export function getLatestScan(projectId: string): StoredScan | null {
  const row = db
    .prepare("SELECT * FROM scans WHERE project_id = ? ORDER BY scanned_at DESC LIMIT 1")
    .get(projectId) as ScanRow | undefined;
  return row ? toScan(row) : null;
}
