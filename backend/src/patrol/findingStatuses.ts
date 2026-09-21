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

export async function upsertFindingStatus(projectId: string, findingHash: string, status: FindingStatus, notes?: string): Promise<StoredFindingStatus | null> {
  if (!VALID_STATUSES.includes(status)) return null;
  const now = new Date().toISOString();
  const existing = await db.get("SELECT * FROM finding_statuses WHERE project_id = ? AND finding_hash = ?", [projectId, findingHash]) as FindingStatusRow | undefined;
  if (existing) {
    await db.run("UPDATE finding_statuses SET status = ?, notes = COALESCE(?, notes), updated_at = ? WHERE id = ?", [status, notes ?? null, now, existing.id]);
    return getFindingStatus(existing.id);
  }
  const id = newId();
  await db.run("INSERT INTO finding_statuses (id, project_id, finding_hash, status, notes, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)", [id, projectId, findingHash, status, notes ?? null, now, now]);
  return getFindingStatus(id);
}

export async function getFindingStatus(id: string): Promise<StoredFindingStatus | null> {
  const row = await db.get("SELECT * FROM finding_statuses WHERE id = ?", [id]) as FindingStatusRow | undefined;
  return row ? toFindingStatus(row) : null;
}

export async function listFindingStatuses(projectId: string): Promise<StoredFindingStatus[]> {
  const rows = await db.all("SELECT * FROM finding_statuses WHERE project_id = ? ORDER BY updated_at DESC", [projectId]) as unknown as FindingStatusRow[];
  return rows.map(toFindingStatus);
}

export async function getFindingStatusByHash(projectId: string, findingHash: string): Promise<StoredFindingStatus | null> {
  const row = await db.get("SELECT * FROM finding_statuses WHERE project_id = ? AND finding_hash = ?", [projectId, findingHash]) as FindingStatusRow | undefined;
  return row ? toFindingStatus(row) : null;
}
