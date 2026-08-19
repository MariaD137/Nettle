import crypto from "crypto";
import { db, newId } from "../db";
import type { FindingStatus, StoredFindingStatus } from "./types";

interface FindingStatusRow {
  id: string;
  project_id: string;
  finding_hash: string;
  status: string;
  notes: string | null;
  created_at: string;
  updated_at: string;
}

function toFindingStatus(row: FindingStatusRow): StoredFindingStatus {
  return {
    id: row.id,
    projectId: row.project_id,
    findingHash: row.finding_hash,
    status: row.status as FindingStatus,
    notes: row.notes,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

export function hashFinding(category: string, title: string, file: string | null): string {
  return crypto.createHash("sha256").update(`${category}::${title}::${file ?? ""}`).digest("hex").slice(0, 16);
}

const VALID_STATUSES: FindingStatus[] = ["open", "in_progress", "resolved", "false_positive", "accepted_risk"];

/**
 * Atomic upsert on (project_id, finding_hash) — idx_finding_statuses_unique
 * enforces that pair is unique, so a single INSERT ... ON CONFLICT DO
 * UPDATE is both the insert-if-absent and update-if-present path in one
 * statement, with no separate SELECT beforehand. The old
 * SELECT-then-INSERT-or-UPDATE shape relied on node:sqlite's synchronous
 * execution to never interleave; under PostgreSQL's genuine cross-
 * connection concurrency, two concurrent upserts for the same finding
 * could both observe "no existing row" and both attempt an INSERT — the
 * unique index would then reject the second one outright rather than
 * silently duplicating data, but that's a spurious error under ordinary
 * concurrent use (e.g. two overlapping scans surfacing the same finding),
 * not a bug this migration should introduce.
 */
export async function upsertFindingStatus(
  projectId: string,
  findingHash: string,
  status: FindingStatus,
  notes?: string
): Promise<StoredFindingStatus | null> {
  if (!VALID_STATUSES.includes(status)) return null;
  const now = new Date().toISOString();
  const newRowId = newId();
  const row = (await db
    .prepare(
      `INSERT INTO finding_statuses (id, project_id, finding_hash, status, notes, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT (project_id, finding_hash) DO UPDATE SET
         status = EXCLUDED.status,
         notes = COALESCE(EXCLUDED.notes, finding_statuses.notes),
         updated_at = EXCLUDED.updated_at
       RETURNING *`
    )
    .get(newRowId, projectId, findingHash, status, notes ?? null, now, now)) as FindingStatusRow | undefined;
  return row ? toFindingStatus(row) : null;
}

export async function getFindingStatus(id: string): Promise<StoredFindingStatus | null> {
  const row = (await db.prepare("SELECT * FROM finding_statuses WHERE id = ?").get(id)) as
    | FindingStatusRow
    | undefined;
  return row ? toFindingStatus(row) : null;
}

export async function listFindingStatuses(projectId: string): Promise<StoredFindingStatus[]> {
  const rows = (await db
    .prepare("SELECT * FROM finding_statuses WHERE project_id = ? ORDER BY updated_at DESC")
    .all(projectId)) as unknown as FindingStatusRow[];
  return rows.map(toFindingStatus);
}

export async function getFindingStatusByHash(
  projectId: string,
  findingHash: string
): Promise<StoredFindingStatus | null> {
  const row = (await db
    .prepare("SELECT * FROM finding_statuses WHERE project_id = ? AND finding_hash = ?")
    .get(projectId, findingHash)) as FindingStatusRow | undefined;
  return row ? toFindingStatus(row) : null;
}
