import { db, newId, newApiKey } from "../db";

export type ApiKeyScope = "scan" | "events";
export const VALID_API_KEY_SCOPES: ApiKeyScope[] = ["scan", "events"];

export interface StoredApiKey {
  id: string;
  projectId: string;
  name: string;
  // The masked form (e.g. "nettle_a1b2…c3d4") everywhere except the
  // moment a key is created or rotated — see maskKey() below. Never the
  // real secret on a list/get response.
  key: string;
  scopes: ApiKeyScope[];
  isDefault: boolean;
  lastUsedAt: string | null;
  revokedAt: string | null;
  createdAt: string;
}

interface ApiKeyRow {
  id: string;
  project_id: string;
  name: string;
  key: string;
  scopes: string;
  is_default: number;
  last_used_at: string | null;
  revoked_at: string | null;
  created_at: string;
}

function toStoredApiKey(row: ApiKeyRow, revealFullKey: boolean): StoredApiKey {
  return {
    id: row.id,
    projectId: row.project_id,
    name: row.name,
    key: revealFullKey ? row.key : maskKey(row.key),
    scopes: JSON.parse(row.scopes) as ApiKeyScope[],
    isDefault: row.is_default === 1,
    lastUsedAt: row.last_used_at,
    revokedAt: row.revoked_at,
    createdAt: row.created_at,
  };
}

// Real keys are "nettle_" + 48 hex chars (see newApiKey() in db/index.ts).
// Shows enough of both ends to tell keys apart in a list without exposing
// anything usable — the same "prefix…suffix" convention Stripe/GitHub use.
export function maskKey(key: string): string {
  const withoutPrefix = key.startsWith("nettle_") ? key.slice("nettle_".length) : key;
  if (withoutPrefix.length <= 8) return "nettle_" + "*".repeat(withoutPrefix.length);
  return `nettle_${withoutPrefix.slice(0, 4)}…${withoutPrefix.slice(-4)}`;
}

function sanitizeScopes(scopes: unknown): ApiKeyScope[] {
  if (!Array.isArray(scopes)) return [...VALID_API_KEY_SCOPES];
  const filtered = scopes.filter((s): s is ApiKeyScope => VALID_API_KEY_SCOPES.includes(s as ApiKeyScope));
  return filtered.length > 0 ? [...new Set(filtered)] : [...VALID_API_KEY_SCOPES];
}

/**
 * Creates a new, additional key for a project. Only ever called for
 * genuinely new keys — the project's original/default key is seeded by
 * createProject()/backfillApiKeys() instead, never through here.
 */
export function createApiKey(projectId: string, name: string, scopes: unknown): StoredApiKey {
  const row: ApiKeyRow = {
    id: newId(),
    project_id: projectId,
    name: name.trim() || "Untitled key",
    key: newApiKey(),
    scopes: JSON.stringify(sanitizeScopes(scopes)),
    is_default: 0,
    last_used_at: null,
    revoked_at: null,
    created_at: new Date().toISOString(),
  };
  db.prepare(
    "INSERT INTO api_keys (id, project_id, name, key, scopes, is_default, last_used_at, revoked_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
  ).run(row.id, row.project_id, row.name, row.key, row.scopes, row.is_default, row.last_used_at, row.revoked_at, row.created_at);
  // Full key revealed exactly once, right here — every other read of this
  // key (list, get) comes back masked.
  return toStoredApiKey(row, true);
}

export function listApiKeys(projectId: string): StoredApiKey[] {
  const rows = db
    .prepare("SELECT * FROM api_keys WHERE project_id = ? ORDER BY created_at ASC")
    .all(projectId) as unknown as ApiKeyRow[];
  return rows.map((r) => toStoredApiKey(r, false));
}

/** For ownership checks — masked, since it's never meant to reveal the secret. */
export function getApiKeyRecord(id: string): StoredApiKey | null {
  const row = db.prepare("SELECT * FROM api_keys WHERE id = ?").get(id) as ApiKeyRow | undefined;
  return row ? toStoredApiKey(row, false) : null;
}

export function updateApiKey(id: string, updates: { name?: string; scopes?: unknown }): StoredApiKey | null {
  const row = db.prepare("SELECT * FROM api_keys WHERE id = ?").get(id) as ApiKeyRow | undefined;
  if (!row) return null;
  const name = updates.name !== undefined ? updates.name.trim() || row.name : row.name;
  const scopes = updates.scopes !== undefined ? JSON.stringify(sanitizeScopes(updates.scopes)) : row.scopes;
  db.prepare("UPDATE api_keys SET name = ?, scopes = ? WHERE id = ?").run(name, scopes, id);
  return getApiKeyRecord(id);
}

/**
 * Immediate, total revoke — no grace period, matching how the existing
 * project-level rotate already behaves. Doesn't delete the row: name,
 * scopes, and lastUsedAt stay visible as history. Idempotent.
 */
export function revokeApiKey(id: string): StoredApiKey | null {
  const row = db.prepare("SELECT * FROM api_keys WHERE id = ?").get(id) as ApiKeyRow | undefined;
  if (!row) return null;
  if (!row.revoked_at) {
    db.prepare("UPDATE api_keys SET revoked_at = ? WHERE id = ?").run(new Date().toISOString(), id);
  }
  return getApiKeyRecord(id);
}

/**
 * Regenerates just this one key's secret — same "old value stops working
 * immediately" semantics as the project-level rotate-key endpoint. If this
 * happens to be the project's default key, the caller (patrol/projects.ts)
 * is responsible for mirroring the new value into projects.api_key too.
 */
export function rotateApiKeyById(id: string): StoredApiKey | null {
  const row = db.prepare("SELECT * FROM api_keys WHERE id = ?").get(id) as ApiKeyRow | undefined;
  if (!row) return null;
  const newKey = newApiKey();
  db.prepare("UPDATE api_keys SET key = ?, last_used_at = NULL WHERE id = ?").run(newKey, id);
  const updated = db.prepare("SELECT * FROM api_keys WHERE id = ?").get(id) as unknown as ApiKeyRow;
  return toStoredApiKey(updated, true);
}

export function getDefaultApiKeyRow(projectId: string): ApiKeyRow | null {
  const row = db.prepare("SELECT * FROM api_keys WHERE project_id = ? AND is_default = 1").get(projectId) as ApiKeyRow | undefined;
  return row ?? null;
}

/**
 * Seeds a project's default key row — called once at project creation
 * (mirroring the api_key just written to the projects table) and, for
 * projects that predate this table, once by backfillApiKeys() below.
 */
export function seedDefaultApiKey(projectId: string, key: string, createdAt: string): void {
  db.prepare(
    "INSERT INTO api_keys (id, project_id, name, key, scopes, is_default, last_used_at, revoked_at, created_at) VALUES (?, ?, ?, ?, ?, 1, NULL, NULL, ?)"
  ).run(newId(), projectId, "Default key", key, JSON.stringify(VALID_API_KEY_SCOPES), createdAt);
}

/**
 * The single place every API-key-authenticated request resolves a raw
 * key string. Rejects revoked keys and, when a scope is given, keys that
 * don't carry it — then records the use. Called through by
 * findProjectByApiKey()/findProjectByApiKeyForScope() in projects.ts,
 * which is what every route actually imports.
 */
export function resolveApiKey(rawKey: string, requiredScope?: ApiKeyScope): { projectId: string } | null {
  const row = db.prepare("SELECT * FROM api_keys WHERE key = ?").get(rawKey) as ApiKeyRow | undefined;
  if (!row) return null;
  if (row.revoked_at) return null;
  if (requiredScope) {
    const scopes = JSON.parse(row.scopes) as ApiKeyScope[];
    if (!scopes.includes(requiredScope)) return null;
  }
  db.prepare("UPDATE api_keys SET last_used_at = ? WHERE id = ?").run(new Date().toISOString(), row.id);
  return { projectId: row.project_id };
}

/**
 * One-time seed for projects that already existed before this table did:
 * every project without any api_keys row yet gets one, mirroring its
 * current projects.api_key as the default key. Gated on there being zero
 * api_keys rows at all, so it only ever does real work once — same
 * pattern as findingHistory.ts#backfillFindingHistory.
 */
export function backfillApiKeys(): void {
  const { count } = db.prepare("SELECT COUNT(*) as count FROM api_keys").get() as { count: number };
  if (count > 0) return;

  const projects = db.prepare("SELECT id, api_key, created_at FROM projects").all() as unknown as {
    id: string;
    api_key: string;
    created_at: string;
  }[];
  for (const p of projects) {
    seedDefaultApiKey(p.id, p.api_key, p.created_at);
  }
}
