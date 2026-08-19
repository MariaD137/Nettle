import { test } from "node:test";
import assert from "node:assert/strict";
import crypto from "crypto";
import { createUser } from "../src/auth/users";
import { createProject } from "../src/patrol/projects";
import { createApiKey, rotateApiKeyById, getDefaultApiKeyRow, resolveApiKey, backfillHashedApiKeys, maskKey } from "../src/patrol/apiKeys";
import { db, newId } from "../src/db";

function sha256(value: string): string {
  return crypto.createHash("sha256").update(value).digest("hex");
}

test("a non-default key's secret is never stored in the api_keys table — only its hash", async () => {
  const user = await createUser("apikey-hashing-nondefault@example.com", "correct horse battery staple");
  const project = await createProject(user.id, "Hashing Target");

  const created = await createApiKey(project.id, "CI key", ["scan"]);
  const row = (await db.prepare("SELECT key, key_masked FROM api_keys WHERE id = ?").get(created.id)) as { key: string; key_masked: string };

  assert.notEqual(row.key, created.key, "the real key must not be returned/stored verbatim after creation");
  assert.equal(row.key, sha256(created.key));
  assert.equal(row.key_masked, maskKey(created.key));

  // Still authenticates correctly through the real resolution path.
  assert.deepEqual(await resolveApiKey(created.key, "scan"), { projectId: project.id });
});

test("the default key row still stores its secret in plain, matching projects.api_key — a documented, deliberate exception", async () => {
  const user = await createUser("apikey-hashing-default@example.com", "correct horse battery staple");
  const project = await createProject(user.id, "Default Key Target");

  const defaultRow = (await getDefaultApiKeyRow(project.id))!;
  assert.equal(defaultRow.key, project.apiKey, "still a plaintext mirror of projects.api_key, by design");

  assert.deepEqual(await resolveApiKey(project.apiKey, "scan"), { projectId: project.id });
});

test("rotating a non-default key stores the new secret hashed too, and the old value stops working", async () => {
  const user = await createUser("apikey-hashing-rotate@example.com", "correct horse battery staple");
  const project = await createProject(user.id, "Rotate Target");

  const created = await createApiKey(project.id, "CI key", ["scan"]);
  const rotated = (await rotateApiKeyById(created.id))!;

  assert.notEqual(rotated.key, created.key);
  const row = (await db.prepare("SELECT key FROM api_keys WHERE id = ?").get(created.id)) as { key: string };
  assert.equal(row.key, sha256(rotated.key));

  assert.equal(await resolveApiKey(created.key), null, "the pre-rotation key must be dead");
  assert.deepEqual(await resolveApiKey(rotated.key, "scan"), { projectId: project.id });
});

test("rotating the default key keeps storing it in plain", async () => {
  const user = await createUser("apikey-hashing-rotate-default@example.com", "correct horse battery staple");
  const project = await createProject(user.id, "Rotate Default Target");

  const defaultRow = (await getDefaultApiKeyRow(project.id))!;
  const rotated = (await rotateApiKeyById(defaultRow.id))!;

  const row = (await db.prepare("SELECT key FROM api_keys WHERE id = ?").get(defaultRow.id)) as { key: string };
  assert.equal(row.key, rotated.key);
});

test("backfillHashedApiKeys migrates a pre-existing plaintext non-default row to hashed, and it keeps authenticating", async () => {
  const user = await createUser("apikey-hashing-backfill@example.com", "correct horse battery staple");
  const project = await createProject(user.id, "Backfill Target");

  // Simulate a row created before hashing existed: a real plaintext key,
  // no key_masked, inserted the way pre-migration code would have.
  const legacyKey = "nettle_" + crypto.randomBytes(24).toString("hex");
  const id = newId();
  await db.prepare(
    "INSERT INTO api_keys (id, project_id, name, key, key_masked, scopes, is_default, last_used_at, revoked_at, created_at) VALUES (?, ?, 'Legacy key', ?, NULL, '[\"scan\"]', 0, NULL, NULL, ?)"
  ).run(id, project.id, legacyKey, new Date().toISOString());

  assert.equal((await resolveApiKey(legacyKey))?.projectId, project.id, "a not-yet-backfilled plaintext row must still authenticate");

  await backfillHashedApiKeys();

  const row = (await db.prepare("SELECT key, key_masked FROM api_keys WHERE id = ?").get(id)) as { key: string; key_masked: string };
  assert.equal(row.key, sha256(legacyKey));
  assert.equal(row.key_masked, maskKey(legacyKey));
  assert.deepEqual(await resolveApiKey(legacyKey), { projectId: project.id }, "must still authenticate after migration to the hashed form");
});

test("backfillHashedApiKeys is a no-op for rows that already have key_masked set", async () => {
  const user = await createUser("apikey-hashing-backfill-noop@example.com", "correct horse battery staple");
  const project = await createProject(user.id, "Backfill Noop Target");
  const created = await createApiKey(project.id, "Already hashed", ["scan"]);

  const before = await db.prepare("SELECT key, key_masked FROM api_keys WHERE id = ?").get(created.id);
  await backfillHashedApiKeys();
  const after = await db.prepare("SELECT key, key_masked FROM api_keys WHERE id = ?").get(created.id);

  assert.deepEqual(before, after);
});
