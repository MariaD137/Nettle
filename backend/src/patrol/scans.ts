import { db, newId } from "../db";
import type { ScanReport, ScanStatus } from "../scanner/types";
export type { ScanStatus };

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

export async function recordScan(projectId: string, report: ScanReport, status: ScanStatus = "COMPLETED"): Promise<StoredScan> {
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
  await db.run("INSERT INTO scans (id, project_id, scanned_at, score, critical_count, caution_count, clear_count, status, report_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", [stored.id, stored.projectId, stored.scannedAt, stored.score, stored.criticalCount, stored.cautionCount, stored.clearCount, stored.status, JSON.stringify(report)]);
  return stored;
}

export async function listScans(projectId: string): Promise<StoredScan[]> {
  const rows = await db.all("SELECT * FROM scans WHERE project_id = ? ORDER BY scanned_at DESC", [projectId]) as unknown as ScanRow[];
  return rows.map(toScan);
}

export async function getLatestScan(projectId: string): Promise<StoredScan | null> {
  const row = await db.get("SELECT * FROM scans WHERE project_id = ? ORDER BY scanned_at DESC LIMIT 1", [projectId]) as ScanRow | undefined;
  return row ? toScan(row) : null;
}

export async function getScanById(scanId: string): Promise<StoredScan | null> {
  const row = await db.get("SELECT * FROM scans WHERE id = ?", [scanId]) as ScanRow | undefined;
  return row ? toScan(row) : null;
}

/** A ScanReport shape with no real content — every required field present,
 *  nothing fabricated. Used only for the placeholder row a queued scan gets
 *  before the worker has actually run (see scanner/scanQueue.ts). Any
 *  consumer must check `status` before treating `report` as meaningful; a
 *  CREATED/SCANNING row's `report` is this stub, not "a clean scan". */
function placeholderReport(status: ScanStatus): ScanReport {
  return {
    scannedAt: new Date().toISOString(),
    target: "",
    scannerVersion: "",
    score: 0,
    status,
    findings: [],
    passed: [],
    summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0, clear: 0 },
  };
}

/**
 * Creates the scan record BEFORE any scanning happens — the async
 * equivalent of what recordScan used to do all at once. The caller gets
 * this row's id back immediately (see routes/scans.routes.ts) and the
 * actual scan work happens afterward, off the request path, via
 * scanner/scanQueue.ts, which calls completeQueuedScan/failQueuedScan below
 * once it's done.
 */
export async function createQueuedScan(projectId: string): Promise<StoredScan> {
  const stored: StoredScan = {
    id: newId(),
    projectId,
    scannedAt: new Date().toISOString(),
    score: 0,
    criticalCount: 0,
    cautionCount: 0,
    clearCount: 0,
    status: "CREATED",
    report: placeholderReport("CREATED"),
  };
  await db.run(
    "INSERT INTO scans (id, project_id, scanned_at, score, critical_count, caution_count, clear_count, status, report_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    [stored.id, stored.projectId, stored.scannedAt, stored.score, stored.criticalCount, stored.cautionCount, stored.clearCount, stored.status, JSON.stringify(stored.report)]
  );
  return stored;
}

export async function markScanStatus(scanId: string, status: ScanStatus): Promise<void> {
  await db.run("UPDATE scans SET status = ? WHERE id = ?", [status, scanId]);
}

/**
 * Fills in a queued scan's row with the real result once the worker has
 * actually finished — the point at which the API is allowed to report
 * COMPLETED (§9: "The API should not report COMPLETED until the worker has
 * actually persisted the scan result"). scanned_at is updated to the real
 * completion time, matching what a synchronous scan's scanned_at always
 * meant (when the scan actually ran, not when it was requested).
 */
export async function completeQueuedScan(scanId: string, report: ScanReport): Promise<StoredScan | null> {
  const criticalCount = report.summary.critical + report.summary.high;
  const cautionCount = report.summary.medium + report.summary.low + report.summary.info;
  const status: ScanStatus = report.status || "COMPLETED";
  await db.run(
    "UPDATE scans SET scanned_at = ?, score = ?, critical_count = ?, caution_count = ?, clear_count = ?, report_json = ?, status = ? WHERE id = ?",
    [report.scannedAt, report.score, criticalCount, cautionCount, report.summary.clear, JSON.stringify(report), status, scanId]
  );
  return getScanById(scanId);
}

/**
 * A worker failure must produce a real FAILED scan record, never a
 * fabricated result (§9/§19) — the placeholder report is replaced with one
 * that honestly says nothing was measured, and status flips to FAILED so
 * every consumer (dashboard, Fix Center, CLI) can tell the difference
 * between "clean scan, 0 findings" and "the scan never actually completed".
 */
export async function failQueuedScan(scanId: string, errorMessage: string): Promise<StoredScan | null> {
  const report = { ...placeholderReport("FAILED"), scannedAt: new Date().toISOString() };
  await db.run(
    "UPDATE scans SET scanned_at = ?, status = ?, report_json = ? WHERE id = ?",
    [report.scannedAt, "FAILED", JSON.stringify({ ...report, error: errorMessage }), scanId]
  );
  return getScanById(scanId);
}
