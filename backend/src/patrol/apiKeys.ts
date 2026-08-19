import crypto from "crypto";
import { db, newId, newApiKey } from "../db";

// Every key created through the multi-key UI (createApiKey/rotateApiKeyById
// on a non-default row) stores SHA-256(key) in the `key` column instead of
// the real secret — a plaintext API key at rest is directly usable by
// anyone with DB read access, same reasoning as session tokens (see
// auth/sessions.ts). The one row this can't apply to is is_default=1:
// projects.api_key mirrors that exact value and is *by product design*
// always redisplayable from a project's Settings, not reveal-once like
// every other key — hashing it here while it stays plaintext there would
// protect nothing (the same secret would still sit in projects.api_key in
// the clear) while breaking the "view your key anytime" behavior existing
// users rely on. That's a real, separate product decision, not made here;
// this only closes the gap for keys that don't have that constraint.
function hashKey(key: string): string {
  return crypto.createHash("sha256").update(key).digest("hex");
}

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

export interface ApiKeyRow {
  id: string;
  project_id: string;
  name: string;
  key: string;
  key_masked: string | null;
  scopes: string;
  is_default: number;
  last_used_at: string | null;
  revoked_at: string | null;
  created_at: string;
}

/**
 * `revealKey`, when given, is the real secret to show — it can no longer
 * be derived from `row.key` for a non-default row, since that column holds
 * a hash now. `row.key_masked` (precomputed at creation/rotation) is the
 * masked display form; `maskKey(row.key)` is only a fallback for a row
 * that predates key_masked existing at all and hasn't been backfilled yet.
 */
function toStoredApiKey(row: ApiKeyRow, revealKey?: string): StoredApiKey {
  return {
    id: row.id,
    projectId: row.project_id,
    name: row.name,
    key: revealKey ?? row.key_masked ?? maskKey(row.key),
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
export async function createApiKey(projectId: string, name: string, scopes: unknown): Promise<StoredApiKey> {
  const rawKey = newApiKey();
  const row: ApiKeyRow = {
    id: newId(),
    project_id: projectId,
    name: name.trim() || "Untitled key",
    key: hashKey(rawKey),
    key_masked: maskKey(rawKey),
    scopes: JSON.stringify(sanitizeScopes(scopes)),
    is_default: 0,
    last_used_at: null,
    revoked_at: null,
    created_at: new Date().toISOString(),
  };
  await db
    .prepare(
      "INSERT INTO api_keys (id, project_id, name, key, key_masked, scopes, is_default, last_used_at, revoked_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    )
    .run(
      row.id,
      row.project_id,
      row.name,
      row.key,
      row.key_masked,
      row.scopes,
      row.is_default,
      row.last_used_at,
      row.revoked_at,
      row.created_at
    );
  // Full key revealed exactly once, right here — every other read of this
  // key (list, get) comes back masked. Only this function's local rawKey
  // variable ever holds it; the row itself never does.
  return toStoredApiKey(row, rawKey);
}

export async function listApiKeys(projectId: string): Promise<StoredApiKey[]> {
  const rows = (await db
    .prepare("SELECT * FROM api_keys WHERE project_id = ? ORDER BY created_at ASC")
    .all(projectId)) as unknown as ApiKeyRow[];
  return rows.map((r) => toStoredApiKey(r));
}

/** For ownership checks — masked, since it's never meant to reveal the secret. */
export async function getApiKeyRecord(id: string): Promise<StoredApiKey | null> {
  const row = (await db.prepare("SELECT * FROM api_keys WHERE id = ?").get(id)) as ApiKeyRow | undefined;
  return row ? toStoredApiKey(row) : null;
}

export async function updateApiKey(
  id: string,
  updates: { name?: string; scopes?: unknown }
): Promise<StoredApiKey | null> {
  const row = (await db.prepare("SELECT * FROM api_keys WHERE id = ?").get(id)) as ApiKeyRow | undefined;
  if (!row) return null;
  const name = updates.name !== undefined ? updates.name.trim() || row.name : row.name;
  const scopes = updates.scopes !== undefined ? JSON.stringify(sanitizeScopes(updates.scopes)) : row.scopes;
  await db.prepare("UPDATE api_keys SET name = ?, scopes = ? WHERE id = ?").run(name, scopes, id);
  return getApiKeyRecord(id);
}

/**
 * Immediate, total revoke — no grace period, matching how the existing
 * project-level rotate already behaves. Doesn't delete the row: name,
 * scopes, and lastUsedAt stay visible as history. Idempotent.
 */
export async function revokeApiKey(id: string): Promise<StoredApiKey | null> {
  const row = (await db.prepare("SELECT * FROM api_keys WHERE id = ?").get(id)) as ApiKeyRow | undefined;
  if (!row) return null;
  if (!row.revoked_at) {
    await db.prepare("UPDATE api_keys SET revoked_at = ? WHERE id = ?").run(new Date().toISOString(), id);
  }
  return getApiKeyRecord(id);
}

/**
 * Regenerates just this one key's secret — same "old value stops working
 * immediately" semantics as the project-level rotate-key endpoint. If this
 * happens to be the project's default key, the caller (patrol/projects.ts)
 * is responsible for mirroring the new value into projects.api_key too —
 * and that row keeps storing its key in plain (see the module comment
 * above); every other row is hashed like createApiKey() does.
 */
export async function rotateApiKeyById(id: string): Promise<StoredApiKey | null> {
  const row = (await db.prepare("SELECT * FROM api_keys WHERE id = ?").get(id)) as ApiKeyRow | undefined;
  if (!row) return null;
  const newKey = newApiKey();
  const stored = row.is_default === 1 ? newKey : hashKey(newKey);
  await db
    .prepare("UPDATE api_keys SET key = ?, key_masked = ?, last_used_at = NULL WHERE id = ?")
    .run(stored, maskKey(newKey), id);
  const updated = (await db.prepare("SELECT * FROM api_keys WHERE id = ?").get(id)) as unknown as ApiKeyRow;
  return toStoredApiKey(updated, newKey);
}

export async function getDefaultApiKeyRow(projectId: string): Promise<ApiKeyRow | null> {
  const row = (await db.prepare("SELECT * FROM api_keys WHERE project_id = ? AND is_default = 1").get(
    projectId
  )) as ApiKeyRow | undefined;
  return row ?? null;
}

/**
 * Seeds a project's default key row — called once at project creation
 * (mirroring the api_key just written to the projects table) and, for
 * projects that predate this table, once by backfillApiKeys() below.
 * Stored in plain, per the module comment above: this row's value is
 * always redisplayable as projects.api_key, so hashing it here wouldn't
 * protect anything.
 */
export async function seedDefaultApiKey(projectId: string, key: string, createdAt: string): Promise<void> {
  await db
    .prepare(
      "INSERT INTO api_keys (id, project_id, name, key, key_masked, scopes, is_default, last_used_at, revoked_at, created_at) VALUES (?, ?, ?, ?, ?, ?, 1, NULL, NULL, ?)"
    )
    .run(newId(), projectId, "Default key", key, maskKey(key), JSON.stringify(VALID_API_KEY_SCOPES), createdAt);
}

/**
 * The single place every API-key-authenticated request resolves a raw
 * key string. Rejects revoked keys and, when a scope is given, keys that
 * don't carry it — then records the use. Called through by
 * findProjectByApiKey()/findProjectByApiKeyForScope() in projects.ts,
 * which is what every route actually imports.
 *
 * Tries an exact match first (the default row's plaintext key, or a
 * pre-migration row not yet backfilled) and falls back to a hash match
 * (every hashed non-default row) — `key` is UNIQUE, so at most one of the
 * two ever finds anything.
 */
export async function resolveApiKey(
  rawKey: string,
  requiredScope?: ApiKeyScope
): Promise<{ projectId: string } | null> {
  const row =
    ((await db.prepare("SELECT * FROM api_keys WHERE key = ?").get(rawKey)) as ApiKeyRow | undefined) ??
    ((await db.prepare("SELECT * FROM api_keys WHERE key = ?").get(hashKey(rawKey))) as ApiKeyRow | undefined);
  if (!row) return null;
  if (row.revoked_at) return null;
  if (requiredScope) {
    const scopes = JSON.parse(row.scopes) as ApiKeyScope[];
    if (!scopes.includes(requiredScope)) return null;
  }
  await db.prepare("UPDATE api_keys SET last_used_at = ? WHERE id = ?").run(new Date().toISOString(), row.id);
  return { projectId: row.project_id };
}

/**
 * One-time seed for projects that already existed before this table did:
 * every project without any api_keys row yet gets one, mirroring its
 * current projects.api_key as the default key. Gated on there being zero
 * api_keys rows at all, so it only ever does real work once — same
 * pattern as findingHistory.ts#backfillFindingHistory.
 */
export async function backfillApiKeys(): Promise<void> {
  const { count } = (await db.prepare("SELECT COUNT(*) as count FROM api_keys").get()) as { count: number | string };
  if (Number(count) > 0) return;

  const projects = (await db.prepare("SELECT id, api_key, created_at FROM projects").all()) as unknown as {
    id: string;
    api_key: string;
    created_at: string;
  }[];
  for (const p of projects) {
    await seedDefaultApiKey(p.id, p.api_key, p.created_at);
  }
}

/**
 * Migrates rows created before hashing/key_masked existed: every row with
 * no key_masked yet still has its real secret sitting in `key` in plain.
 * For a default row that's expected (see the module comment above) — it
 * only needed key_masked filled in. For a non-default row, `key` gets
 * replaced with its hash too, closing the same gap createApiKey() closes
 * for anything created from here on. Unlike backfillApiKeys() above, this
 * isn't gated on the table being empty — it runs every startup and is a
 * no-op once every row has key_masked set.
 */
export async function backfillHashedApiKeys(): Promise<void> {
  const rows = (await db.prepare("SELECT * FROM api_keys WHERE key_masked IS NULL").all()) as unknown as ApiKeyRow[];
  for (const row of rows) {
    const masked = maskKey(row.key);
    const stored = row.is_default === 1 ? row.key : hashKey(row.key);
    await db.prepare("UPDATE api_keys SET key = ?, key_masked = ? WHERE id = ?").run(stored, masked, row.id);
  }
}
