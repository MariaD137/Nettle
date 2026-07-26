import { db, newId, newApiKey } from "../db";
import type { Project } from "./types";

interface ProjectRow {
  id: string;
  user_id: string;
  name: string;
  api_key: string;
  created_at: string;
}

function toProject(row: ProjectRow): Project {
  return { id: row.id, userId: row.user_id, name: row.name, apiKey: row.api_key, createdAt: row.created_at };
}

export function createProject(userId: string, name: string): Project {
  const project: Project = {
    id: newId(),
    userId,
    name,
    apiKey: newApiKey(),
    createdAt: new Date().toISOString(),
  };
  db.prepare("INSERT INTO projects (id, user_id, name, api_key, created_at) VALUES (?, ?, ?, ?, ?)").run(
    project.id,
    project.userId,
    project.name,
    project.apiKey,
    project.createdAt
  );
  return project;
}

export function findProjectByApiKey(apiKey: string): Project | null {
  const row = db.prepare("SELECT * FROM projects WHERE api_key = ?").get(apiKey) as ProjectRow | undefined;
  return row ? toProject(row) : null;
}

export function getProject(id: string): Project | null {
  const row = db.prepare("SELECT * FROM projects WHERE id = ?").get(id) as ProjectRow | undefined;
  return row ? toProject(row) : null;
}

export function listProjectsByUser(userId: string): Project[] {
  const rows = db.prepare("SELECT * FROM projects WHERE user_id = ? ORDER BY created_at DESC").all(userId) as unknown as ProjectRow[];
  return rows.map(toProject);
}
