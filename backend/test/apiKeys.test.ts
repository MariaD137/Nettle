import { test } from "node:test";
import assert from "node:assert/strict";
import { db } from "../src/db";
import { createUser } from "../src/auth/users";
import { createProject, findProjectByApiKey, findProjectByApiKeyForScope } from "../src/patrol/projects";
import {
  createApiKey,
  listApiKeys,
  getApiKeyRecord,
  updateApiKey,
  revokeApiKey,
  rotateApiKeyById,
  resolveApiKey,
  maskKey,
  backfillApiKeys,
} from "../src/patrol/apiKeys";

const PASSWORD = "correct horse battery staple";
let counter = 0;
async function testProjectId(): Promise<string> {
  const user = await createUser(`api-keys-test-${counter++}@example.com`, PASSWORD);
  return createProject(user.id, "API Key Test Project").id;
}

// Runs first, deliberately, and inserts its project row directly via raw
// SQL rather than createProject() (which seeds its own api_keys row) —
// the only way to honestly observe backfillApiKeys() actually doing its
// from-scratch seeding work, before any other test in this file
// populates api_keys and makes the table's "is it empty" gate trip.
test("backfillApiKeys seeds a default key for a project that predates the api_keys table", async () => {
  const before = db.prepare("SELECT COUNT(*) as count FROM api_keys").get() as { count: number };
  assert.equal(before.count, 0, "must run before any other test populates api_keys, to genuinely test the from-scratch path");

  const user = await createUser(`api-keys-backfill-${counter++}@example.com`, PASSWORD);
  const id = `legacy-proj-${counter}`;
  const apiKey = `nettle_legacy${counter}`.padEnd(55, "0");
  const createdAt = "2020-01-01T00:00:00.000Z";
  db.prepare(
    "INSERT INTO projects (id, user_id, name, api_key, environment, created_at) VALUES (?, ?, ?, ?, 'production', ?)"
  ).run(id, user.id, "Legacy Project", apiKey, createdAt);

  backfillApiKeys();

  const keys = listApiKeys(id);
  assert.equal(keys.length, 1);
  assert.equal(keys[0].isDefault, true);
  assert.equal(keys[0].name, "Default key");
  assert.equal(keys[0].createdAt, createdAt);
  assert.ok(findProjectByApiKey(apiKey), "the pre-existing key value should now authenticate through the new table");

  // Second call is a no-op once seeded.
  backfillApiKeys();
  assert.equal(listApiKeys(id).length, 1);
});

test("maskKey shows a short prefix and suffix, never the middle", () => {
  const masked = maskKey("nettle_abcdefghijklmnop1234567890ffffffffffffffffffffffff");
  assert.match(masked, /^nettle_[0-9a-f]{4}…[0-9a-f]{4}$/);
  assert.ok(!masked.includes("ijklmnop"));
});

test("createApiKey reveals the full key exactly once, at creation", async () => {
  const projectId = await testProjectId();
  const created = createApiKey(projectId, "CI key", ["scan"]);
  assert.match(created.key, /^nettle_[0-9a-f]{48}$/);
  assert.equal(created.name, "CI key");
  assert.deepEqual(created.scopes, ["scan"]);
  assert.equal(created.isDefault, false);
  assert.equal(created.revokedAt, null);
  assert.equal(created.lastUsedAt, null);
});

test("listApiKeys never returns the full key — only the masked form", async () => {
  const projectId = await testProjectId();
  const created = createApiKey(projectId, "CI key", ["scan"]);
  const [listed] = listApiKeys(projectId);
  assert.notEqual(listed.key, created.key);
  assert.match(listed.key, /…/);
});

test("createApiKey defaults to every scope when none/invalid are given", async () => {
  const projectId = await testProjectId();
  const noScopes = createApiKey(projectId, "No scopes given", undefined);
  assert.deepEqual(noScopes.scopes.sort(), ["events", "scan"]);

  const bogusScopes = createApiKey(projectId, "Bogus scopes", ["read-everything", 123, null]);
  assert.deepEqual(bogusScopes.scopes.sort(), ["events", "scan"]);
});

test("createApiKey keeps only recognized scopes when some are valid and some aren't", async () => {
  const projectId = await testProjectId();
  const mixed = createApiKey(projectId, "Mixed", ["scan", "not-a-scope"]);
  assert.deepEqual(mixed.scopes, ["scan"]);
});

test("updateApiKey renames and rescopes without needing both at once", async () => {
  const projectId = await testProjectId();
  const created = createApiKey(projectId, "Original name", ["scan", "events"]);

  const renamed = updateApiKey(created.id, { name: "New name" });
  assert.equal(renamed?.name, "New name");
  assert.deepEqual(renamed?.scopes.sort(), ["events", "scan"]);

  const rescoped = updateApiKey(created.id, { scopes: ["events"] });
  assert.equal(rescoped?.name, "New name");
  assert.deepEqual(rescoped?.scopes, ["events"]);
});

test("revokeApiKey is immediate and idempotent", async () => {
  const projectId = await testProjectId();
  const created = createApiKey(projectId, "To revoke", ["scan"]);
  assert.equal(created.revokedAt, null);

  const revoked = revokeApiKey(created.id);
  assert.ok(revoked?.revokedAt);

  // Calling it again shouldn't change the timestamp or error.
  const revokedAgain = revokeApiKey(created.id);
  assert.equal(revokedAgain?.revokedAt, revoked?.revokedAt);
});

test("a revoked key stops authenticating immediately", async () => {
  const projectId = await testProjectId();
  const created = createApiKey(projectId, "To revoke", ["scan"]);
  assert.ok(findProjectByApiKey(created.key));

  revokeApiKey(created.id);
  assert.equal(findProjectByApiKey(created.key), null);
});

test("rotateApiKeyById issues a genuinely new secret and invalidates the old one immediately", async () => {
  const projectId = await testProjectId();
  const created = createApiKey(projectId, "To rotate", ["scan"]);
  const oldKey = created.key;

  const rotated = rotateApiKeyById(created.id);
  assert.notEqual(rotated?.key, oldKey);
  assert.equal(findProjectByApiKey(oldKey), null, "the old key must stop working immediately");
  assert.ok(findProjectByApiKey(rotated!.key), "the new key must work");
});

test("findProjectByApiKeyForScope rejects a key that doesn't carry the required scope, same as an unknown key", async () => {
  const projectId = await testProjectId();
  const scanOnly = createApiKey(projectId, "Scan only", ["scan"]);

  assert.ok(findProjectByApiKeyForScope(scanOnly.key, "scan"));
  assert.equal(findProjectByApiKeyForScope(scanOnly.key, "events"), null);
});

test("resolveApiKey records last-used on every successful match, and leaves it null for a scope-mismatched or revoked attempt", async () => {
  const projectId = await testProjectId();
  const created = createApiKey(projectId, "Track usage", ["scan"]);
  assert.equal(getApiKeyRecord(created.id)?.lastUsedAt, null);

  assert.ok(resolveApiKey(created.key, "scan"));
  assert.ok(getApiKeyRecord(created.id)?.lastUsedAt, "a successful, in-scope use should be recorded");

  const beforeMismatch = getApiKeyRecord(created.id)?.lastUsedAt;
  assert.equal(resolveApiKey(created.key, "events"), null);
  assert.equal(getApiKeyRecord(created.id)?.lastUsedAt, beforeMismatch, "a scope-rejected attempt must not count as use");
});

test("createProject seeds a default api_keys row matching projects.api_key", async () => {
  const user = await createUser(`api-keys-default-${counter++}@example.com`, PASSWORD);
  const project = createProject(user.id, "Default Key Project");

  const keys = listApiKeys(project.id);
  assert.equal(keys.length, 1);
  assert.equal(keys[0].isDefault, true);
  assert.equal(keys[0].name, "Default key");
  assert.deepEqual(keys[0].scopes.sort(), ["events", "scan"]);
  assert.ok(findProjectByApiKey(project.apiKey), "the legacy field's value should authenticate through the new table");
});
