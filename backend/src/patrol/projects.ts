import { db, newId, newApiKey } from "../db";
import type { Project } from "./types";

interface ProjectRow {
  id: string;
  user_id: string;
  organization_id: string | null;
  name: string;
  api_key: string;
  url: string | null;
  description: string | null;
  environment: string;
  archived_at: string | null;
  created_at: string;
}

function toProject(row: ProjectRow): Project {
  return {
    id: row.id,
    userId: row.user_id,
    organizationId: row.organization_id ?? null,
    name: row.name,
    apiKey: row.api_key,
    url: row.url ?? null,
    description: row.description ?? null,
    environment: row.environment ?? "production",
    archivedAt: row.archived_at ?? null,
    createdAt: row.created_at,
  };
}

export async function createProject(userId: string, name: string, opts?: { url?: string; description?: string; environment?: string; organizationId?: string }): Promise<Project> {
  const project: Project = {
    id: newId(),
    userId,
    organizationId: opts?.organizationId ?? null,
    name,
    apiKey: newApiKey(),
    url: opts?.url ?? null,
    description: opts?.description ?? null,
    environment: opts?.environment ?? "production",
    archivedAt: null,
    createdAt: new Date().toISOString(),
  };
  await db.run(
    "INSERT INTO projects (id, user_id, organization_id, name, api_key, url, description, environment, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    [project.id, project.userId, project.organizationId, project.name, project.apiKey, project.url, project.description, project.environment, project.createdAt]
  );
  return project;
}

export async function updateProject(id: string, updates: { name?: string; url?: string; description?: string; environment?: string }): Promise<Project | null> {
  const existing = await getProject(id);
  if (!existing) return null;
  const name = updates.name ?? existing.name;
  const url = updates.url !== undefined ? updates.url : existing.url;
  const description = updates.description !== undefined ? updates.description : existing.description;
  const environment = updates.environment ?? existing.environment;
  await db.run("UPDATE projects SET name = ?, url = ?, description = ?, environment = ? WHERE id = ?", [name, url, description, environment, id]);
  return getProject(id);
}

export async function deleteProject(id: string): Promise<void> {
  await db.run("DELETE FROM alerts WHERE project_id = ?", [id]);
  await db.run("DELETE FROM events WHERE project_id = ?", [id]);
  await db.run("DELETE FROM scans WHERE project_id = ?", [id]);
  await db.run("DELETE FROM finding_statuses WHERE project_id = ?", [id]);
  await db.run("DELETE FROM projects WHERE id = ?", [id]);
}

export async function archiveProject(id: string): Promise<Project | null> {
  await db.run("UPDATE projects SET archived_at = ? WHERE id = ?", [new Date().toISOString(), id]);
  return getProject(id);
}

export async function restoreProject(id: string): Promise<Project | null> {
  await db.run("UPDATE projects SET archived_at = NULL WHERE id = ?", [id]);
  return getProject(id);
}

export async function rotateApiKey(id: string): Promise<Project | null> {
  const key = newApiKey();
  await db.run("UPDATE projects SET api_key = ? WHERE id = ?", [key, id]);
  return getProject(id);
}

/**
 * Everywhere a Project reaches an HTTP response EXCEPT the moment a key is
 * actually created (createProject) or deliberately regenerated
 * (rotateApiKey), the full secret must never be sent again — see
 * routes/projects.routes.ts's withMaskedKey, which is the only caller. A
 * scanning product that lectures its customers about not exposing secrets
 * to the browser (SECRET-001's own "browser-delivered code cannot contain a
 * secret" fix advice) cannot itself keep re-serving a live API key on every
 * ordinary page load.
 *
 * Keeps the "nettle_" prefix and last 4 characters — enough for a customer
 * to recognize which key they're looking at (e.g. to confirm a rotation
 * took effect) without the masked value being usable as a credential.
 */
export function maskApiKey(apiKey: string): string {
  const prefixMatch = apiKey.match(/^([a-z]+_)/);
  const prefix = prefixMatch ? prefixMatch[1] : "";
  const rest = apiKey.slice(prefix.length);
  const last4 = rest.slice(-4);
  const hidden = Math.max(rest.length - 4, 8);
  return `${prefix}${"•".repeat(hidden)}${last4}`;
}

export async function findProjectByApiKey(apiKey: string): Promise<Project | null> {
  const row = await db.get("SELECT * FROM projects WHERE api_key = ?", [apiKey]) as ProjectRow | undefined;
  return row ? toProject(row) : null;
}

export async function getProject(id: string): Promise<Project | null> {
  const row = await db.get("SELECT * FROM projects WHERE id = ?", [id]) as ProjectRow | undefined;
  return row ? toProject(row) : null;
}

export async function listProjectsByUser(userId: string, includeArchived = false): Promise<Project[]> {
  const sql = includeArchived
    ? "SELECT * FROM projects WHERE user_id = ? ORDER BY created_at DESC"
    : "SELECT * FROM projects WHERE user_id = ? AND archived_at IS NULL ORDER BY created_at DESC";
  const rows = await db.all(sql, [userId]) as unknown as ProjectRow[];
  return rows.map(toProject);
}

/**
 * Every project a user can see: their own personal projects (organization_id
 * IS NULL), plus every project belonging to an organization they're
 * currently a member of — regardless of which member created it, and
 * governed by current membership, not who happened to create it (removed
 * from the org means the project drops out of this list too).
 */
export async function listAccessibleProjects(userId: string, includeArchived = false): Promise<Project[]> {
  const archivedClause = includeArchived ? "" : "AND archived_at IS NULL";
  const sql = `
    SELECT * FROM projects
    WHERE (
      (user_id = ? AND organization_id IS NULL)
      OR organization_id IN (SELECT organization_id FROM organization_members WHERE user_id = ?)
    )
    ${archivedClause}
    ORDER BY created_at DESC
  `;
  const rows = await db.all(sql, [userId, userId]) as unknown as ProjectRow[];
  return rows.map(toProject);
}

/** True when userId has access to this project — either as its personal owner, or as a member of the organization it belongs to. */
export async function canAccessProject(userId: string, project: Project): Promise<boolean> {
  if (project.organizationId === null) return project.userId === userId;
  const row = await db.get("SELECT 1 AS present FROM organization_members WHERE organization_id = ? AND user_id = ?", [project.organizationId, userId]);
  return !!row;
}

export async function countProjectsByUser(userId: string): Promise<number> {
  const row = await db.get("SELECT COUNT(*) as count FROM projects WHERE user_id = ? AND archived_at IS NULL", [userId]) as { count: number };
  return row.count;
}
