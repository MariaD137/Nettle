import { db, newId, newApiKey } from "../db";
import type { Project } from "./types";

interface ProjectRow {
  id: string;
  name: string;
  api_key: string;
  created_at: string;
}

function toProject(row: ProjectRow): Project {
  return { id: row.id, name: row.name, apiKey: row.api_key, createdAt: row.created_at };
}

export function createProject(name: string): Project {
  const project: Project = {
    id: newId(),
    name,
    apiKey: newApiKey(),
    createdAt: new Date().toISOString(),
  };
  db.prepare("INSERT INTO projects (id, name, api_key, created_at) VALUES (?, ?, ?, ?)").run(
    project.id,
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
