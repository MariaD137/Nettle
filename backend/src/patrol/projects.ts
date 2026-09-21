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

export async function createProject(userId: string, name: string, opts?: { url?: string; description?: string; environment?: string }): Promise<Project> {
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
  await db.run("INSERT INTO projects (id, user_id, name, api_key, url, description, environment, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", [project.id, project.userId, project.name, project.apiKey, project.url, project.description, project.environment, project.createdAt]);
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

export async function countProjectsByUser(userId: string): Promise<number> {
  const row = await db.get("SELECT COUNT(*) as count FROM projects WHERE user_id = ? AND archived_at IS NULL", [userId]) as { count: number };
  return row.count;
}
