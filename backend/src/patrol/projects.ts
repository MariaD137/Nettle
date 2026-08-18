import { db, newId, newApiKey } from "../db";
import type { Project } from "./types";
import { encryptToken, decryptToken } from "../security/tokenEncryption";
import { seedDefaultApiKey, getDefaultApiKeyRow, resolveApiKey, type ApiKeyScope } from "./apiKeys";

interface ProjectRow {
  id: string;
  user_id: string;
  name: string;
  api_key: string;
  url: string | null;
  repo_url: string | null;
  repo_branch: string | null;
  repo_access_token_encrypted: string | null;
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
    repoUrl: row.repo_url ?? null,
    repoBranch: row.repo_branch ?? null,
    hasRepoAccessToken: row.repo_access_token_encrypted != null,
    description: row.description ?? null,
    environment: row.environment ?? "production",
    archivedAt: row.archived_at ?? null,
    createdAt: row.created_at,
  };
}

export function createProject(
  userId: string,
  name: string,
  opts?: { url?: string; repoUrl?: string; repoBranch?: string; description?: string; environment?: string }
): Project {
  const project: Project = {
    id: newId(),
    userId,
    name,
    apiKey: newApiKey(),
    url: opts?.url ?? null,
    repoUrl: opts?.repoUrl ?? null,
    repoBranch: opts?.repoBranch ?? null,
    hasRepoAccessToken: false,
    description: opts?.description ?? null,
    environment: opts?.environment ?? "production",
    archivedAt: null,
    createdAt: new Date().toISOString(),
  };
  db.prepare(
    "INSERT INTO projects (id, user_id, name, api_key, url, repo_url, repo_branch, description, environment, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
  ).run(
    project.id,
    project.userId,
    project.name,
    project.apiKey,
    project.url,
    project.repoUrl,
    project.repoBranch,
    project.description,
    project.environment,
    project.createdAt
  );
  seedDefaultApiKey(project.id, project.apiKey, project.createdAt);
  return project;
}

export function updateProject(
  id: string,
  updates: { name?: string; url?: string; repoUrl?: string; repoBranch?: string; description?: string; environment?: string }
): Project | null {
  const existing = getProject(id);
  if (!existing) return null;
  const name = updates.name ?? existing.name;
  const url = updates.url !== undefined ? updates.url : existing.url;
  const repoUrl = updates.repoUrl !== undefined ? updates.repoUrl : existing.repoUrl;
  const repoBranch = updates.repoBranch !== undefined ? updates.repoBranch : existing.repoBranch;
  const description = updates.description !== undefined ? updates.description : existing.description;
  const environment = updates.environment ?? existing.environment;
  db.prepare(
    "UPDATE projects SET name = ?, url = ?, repo_url = ?, repo_branch = ?, description = ?, environment = ? WHERE id = ?"
  ).run(name, url, repoUrl, repoBranch, description, environment, id);
  return getProject(id);
}

/**
 * Sets, replaces, or clears (pass null/empty string) a project's private
 * repository access token. Deliberately separate from `updateProject` so
 * the encryption happens in exactly one place and a token can never be set
 * via the generic updates object by accident. Returns the Project as usual
 * — `hasRepoAccessToken` reflects the change, the token value itself never
 * does.
 */
export function setRepoAccessToken(id: string, token: string | null): Project | null {
  const encrypted = token ? encryptToken(token) : null;
  db.prepare("UPDATE projects SET repo_access_token_encrypted = ? WHERE id = ?").run(encrypted, id);
  return getProject(id);
}

/**
 * The one place the plaintext token is ever reconstructed — server-side,
 * immediately before a git clone, never returned from an API route.
 */
export function getDecryptedRepoAccessToken(id: string): string | null {
  const row = db.prepare("SELECT repo_access_token_encrypted FROM projects WHERE id = ?").get(id) as
    | { repo_access_token_encrypted: string | null }
    | undefined;
  if (!row?.repo_access_token_encrypted) return null;
  return decryptToken(row.repo_access_token_encrypted);
}

export function deleteProject(id: string): void {
  db.prepare("DELETE FROM alerts WHERE project_id = ?").run(id);
  db.prepare("DELETE FROM events WHERE project_id = ?").run(id);
  db.prepare("DELETE FROM scans WHERE project_id = ?").run(id);
  db.prepare("DELETE FROM finding_statuses WHERE project_id = ?").run(id);
  db.prepare("DELETE FROM api_keys WHERE project_id = ?").run(id);
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

/**
 * Rotates the project's default key. Mirrors the change into both the
 * legacy `projects.api_key` column (what project creation and this
 * endpoint have always returned, and what the dashboard's own scan/
 * onboarding flows read directly) and the corresponding api_keys row, so
 * the two stay in sync regardless of which surface — this endpoint or the
 * newer per-key management UI — touches the default key next.
 */
export function rotateApiKey(id: string): Project | null {
  const key = newApiKey();
  const defaultRow = getDefaultApiKeyRow(id);
  if (defaultRow) {
    db.prepare("UPDATE api_keys SET key = ?, last_used_at = NULL WHERE id = ?").run(key, defaultRow.id);
  }
  db.prepare("UPDATE projects SET api_key = ? WHERE id = ?").run(key, id);
  return getProject(id);
}

/**
 * The other direction of the same mirroring: called when the *default*
 * api_keys row is rotated through the newer per-key endpoint
 * (POST /api/projects/:id/api-keys/:keyId/rotate), so the legacy
 * projects.api_key column reflects it too.
 */
export function setDefaultApiKeyValue(id: string, key: string): void {
  db.prepare("UPDATE projects SET api_key = ? WHERE id = ?").run(key, id);
}

/**
 * Resolves a raw API key to its owning project — revoked keys never
 * match. Every existing caller (event ingestion, scan attribution) keeps
 * calling this exact function with its exact signature, so revocation
 * and last-used tracking (both handled inside resolveApiKey()) apply
 * everywhere automatically. Use findProjectByApiKeyForScope() instead
 * wherever the caller should also enforce what the key is allowed to do.
 */
export function findProjectByApiKey(apiKey: string): Project | null {
  const resolved = resolveApiKey(apiKey);
  return resolved ? getProject(resolved.projectId) : null;
}

/**
 * Same as findProjectByApiKey(), but additionally requires the key to
 * carry `scope` — a key missing it is treated exactly like an unknown
 * key (null), matching how every caller already handles "no valid key"
 * (fall back to anonymous/unattributed rather than hard-failing), not a
 * distinct error path.
 */
export function findProjectByApiKeyForScope(apiKey: string, scope: ApiKeyScope): Project | null {
  const resolved = resolveApiKey(apiKey, scope);
  return resolved ? getProject(resolved.projectId) : null;
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
