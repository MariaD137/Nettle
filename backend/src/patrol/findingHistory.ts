import { db } from "../db";
import { hashFinding } from "./findingStatuses";
import type { ScanReport } from "../scanner/types";

export interface FindingHistoryEntry {
  findingHash: string;
  firstSeenAt: string;
  lastSeenAt: string;
}

interface FindingHistoryRow {
  finding_hash: string;
  first_seen_at: string;
  last_seen_at: string;
}

function toEntry(row: FindingHistoryRow): FindingHistoryEntry {
  return { findingHash: row.finding_hash, firstSeenAt: row.first_seen_at, lastSeenAt: row.last_seen_at };
}

/**
 * Records that a given finding was observed in a scan at `seenAt`. Widens
 * the stored first/last-seen window rather than overwriting it, so calls
 * can arrive out of chronological order (as the one-time backfill below
 * does, replaying old scans) without corrupting the timeline.
 *
 * A single atomic upsert on the (project_id, finding_hash) primary key —
 * LEAST/GREATEST express the same "widen, don't overwrite" logic the old
 * SELECT-then-INSERT-or-UPDATE shape had, without a separate read that
 * could race a concurrent call for the same finding under PostgreSQL's
 * real cross-connection concurrency (timestamps are stored as ISO 8601
 * text, which LEAST/GREATEST compare correctly lexically, same as the
 * original string comparison did).
 */
export async function recordFindingSeen(projectId: string, findingHash: string, seenAt: string): Promise<void> {
  await db
    .prepare(
      `INSERT INTO finding_history (project_id, finding_hash, first_seen_at, last_seen_at)
       VALUES (?, ?, ?, ?)
       ON CONFLICT (project_id, finding_hash) DO UPDATE SET
         first_seen_at = LEAST(finding_history.first_seen_at, EXCLUDED.first_seen_at),
         last_seen_at = GREATEST(finding_history.last_seen_at, EXCLUDED.last_seen_at)`
    )
    .run(projectId, findingHash, seenAt, seenAt);
}

export async function listFindingHistory(projectId: string): Promise<FindingHistoryEntry[]> {
  const rows = (await db
    .prepare("SELECT finding_hash, first_seen_at, last_seen_at FROM finding_history WHERE project_id = ?")
    .all(projectId)) as unknown as FindingHistoryRow[];
  return rows.map(toEntry);
}

export async function getFindingHistoryEntry(
  projectId: string,
  findingHash: string
): Promise<FindingHistoryEntry | null> {
  const row = (await db
    .prepare("SELECT finding_hash, first_seen_at, last_seen_at FROM finding_history WHERE project_id = ? AND finding_hash = ?")
    .get(projectId, findingHash)) as FindingHistoryRow | undefined;
  return row ? toEntry(row) : null;
}

/**
 * One-time seed for projects that already had scan history before this
 * table existed: replays every stored scan, oldest first, and derives
 * first/last-seen from when each finding hash actually appeared —
 * otherwise every pre-existing finding would misleadingly show "first
 * detected: today" the moment this feature ships. Gated on the table
 * being empty, so it only ever does real work once; recordFindingSeen
 * takes over incrementally from the next recordScan() call onward.
 */
export async function backfillFindingHistory(): Promise<void> {
  const { count } = (await db.prepare("SELECT COUNT(*) as count FROM finding_history").get()) as {
    count: number | string;
  };
  if (Number(count) > 0) return;

  const scans = (await db
    .prepare("SELECT project_id, scanned_at, report_json FROM scans ORDER BY scanned_at ASC")
    .all()) as unknown as { project_id: string; scanned_at: string; report_json: string }[];

  for (const row of scans) {
    let report: ScanReport;
    try {
      report = JSON.parse(row.report_json);
    } catch {
      continue;
    }
    for (const finding of report.findings ?? []) {
      const hash = hashFinding(finding.category, finding.title, finding.file);
      await recordFindingSeen(row.project_id, hash, row.scanned_at);
    }
  }
}
