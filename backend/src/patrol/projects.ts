import { db, newId, newApiKey } from "../db";
import type { Project } from "./types";

interface ProjectRow {
  id: string;
  user_id: string;
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
    name: row.name,
    apiKey: row.api_key,
    url: row.url ?? null,
    description: row.description ?? null,
    environment: row.environment ?? "production",
    archivedAt: row.archived_at ?? null,
    createdAt: row.created_at,
  };
}

export function createProject(userId: string, name: string, opts?: { url?: string; description?: string; environment?: string }): Project {
  const project: Project = {
    id: newId(),
    userId,
    name,
    apiKey: newApiKey(),
    url: opts?.url ?? null,
    description: opts?.description ?? null,
    environment: opts?.environment ?? "production",
    archivedAt: null,
    createdAt: new Date().toISOString(),
  };
  db.prepare(
    "INSERT INTO projects (id, user_id, name, api_key, url, description, environment, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
  ).run(project.id, project.userId, project.name, project.apiKey, project.url, project.description, project.environment, project.createdAt);
  return project;
}

export function updateProject(id: string, updates: { name?: string; url?: string; description?: string; environment?: string }): Project | null {
  const existing = getProject(id);
  if (!existing) return null;
  const name = updates.name ?? existing.name;
  const url = updates.url !== undefined ? updates.url : existing.url;
  const description = updates.description !== undefined ? updates.description : existing.description;
  const environment = updates.environment ?? existing.environment;
  db.prepare("UPDATE projects SET name = ?, url = ?, description = ?, environment = ? WHERE id = ?").run(name, url, description, environment, id);
  return getProject(id);
}

export function deleteProject(id: string): void {
  db.prepare("DELETE FROM alerts WHERE project_id = ?").run(id);
  db.prepare("DELETE FROM events WHERE project_id = ?").run(id);
  db.prepare("DELETE FROM scans WHERE project_id = ?").run(id);
  db.prepare("DELETE FROM finding_statuses WHERE project_id = ?").run(id);
  db.prepare("DELETE FROM projects WHERE id = ?").run(id);
}

export function archiveProject(id: string): Project | null {
  db.prepare("UPDATE projects SET archived_at = ? WHERE id = ?").run(new Date().toISOString(), id);
  return getProject(id);
}

export function restoreProject(id: string): Project | null {
  db.prepare("UPDATE projects SET archived_at = NULL WHERE id = ?").run(id);
  return getProject(id);
}

export function rotateApiKey(id: string): Project | null {
  const key = newApiKey();
  db.prepare("UPDATE projects SET api_key = ? WHERE id = ?").run(key, id);
  return getProject(id);
}

export function findProjectByApiKey(apiKey: string): Project | null {
  const row = db.prepare("SELECT * FROM projects WHERE api_key = ?").get(apiKey) as ProjectRow | undefined;
  return row ? toProject(row) : null;
}

export function getProject(id: string): Project | null {
  const row = db.prepare("SELECT * FROM projects WHERE id = ?").get(id) as ProjectRow | undefined;
  return row ? toProject(row) : null;
}

export function listProjectsByUser(userId: string, includeArchived = false): Project[] {
  const sql = includeArchived
    ? "SELECT * FROM projects WHERE user_id = ? ORDER BY created_at DESC"
    : "SELECT * FROM projects WHERE user_id = ? AND archived_at IS NULL ORDER BY created_at DESC";
  const rows = db.prepare(sql).all(userId) as unknown as ProjectRow[];
  return rows.map(toProject);
}

export function countProjectsByUser(userId: string): number {
  const row = db.prepare("SELECT COUNT(*) as count FROM projects WHERE user_id = ? AND archived_at IS NULL").get(userId) as { count: number };
  return row.count;
}
