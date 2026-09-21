import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "fs";
import os from "os";
import path from "path";
import { loadMigrations, runMigrations } from "../src/db/migrate";
import { SqliteDriver } from "../src/db/sqliteDriver";
import { toPositionalPlaceholders } from "../src/db/driver";

function tempDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "nettle-migrations-"));
}

test("the shipped migrations load and are ordered by version", () => {
  const migrations = loadMigrations();
  assert.ok(migrations.length > 0, "at least the baseline must be present");
  const versions = migrations.map((m) => m.version);
  assert.deepEqual([...versions].sort(), versions, "migrations must be applied in version order");
});

test("migrations are idempotent — a second run applies nothing", async () => {
  const db = new SqliteDriver(":memory:");
  const first = await runMigrations(db);
  assert.ok(first.length > 0);
  const second = await runMigrations(db);
  assert.deepEqual(second, [], "re-running must be a no-op");
  await db.close();
});

test("every application table exists after the baseline", async () => {
  const db = new SqliteDriver(":memory:");
  await runMigrations(db);
  const rows = await db.all<{ name: string }>("SELECT name FROM sqlite_master WHERE type = 'table'");
  const names = new Set(rows.map((r) => r.name));
  for (const table of [
    "users", "sessions", "password_resets", "projects", "events",
    "alerts", "scans", "finding_statuses", "notification_preferences",
    "scan_usage", "schema_migrations",
  ]) {
    assert.ok(names.has(table), `missing table: ${table}`);
  }
  await db.close();
});

test("a destructive migration is refused unless it opts in explicitly", () => {
  const dir = tempDir();
  fs.writeFileSync(path.join(dir, "001_drop.sql"), "DROP TABLE users;");
  assert.throws(() => loadMigrations(dir), /destructive/i);

  // With the marker it is allowed — deleting data must be a deliberate act,
  // not something a careless edit does on the next deploy.
  fs.writeFileSync(
    path.join(dir, "001_drop.sql"),
    "-- nettle:allow-destructive\nDROP TABLE users;"
  );
  assert.equal(loadMigrations(dir).length, 1);
});

test("a migration filename without a numeric version is rejected", () => {
  const dir = tempDir();
  fs.writeFileSync(path.join(dir, "baseline.sql"), "SELECT 1;");
  assert.throws(() => loadMigrations(dir), /numeric version/i);
});

test("a failing migration rolls back and is not recorded", async () => {
  const dir = tempDir();
  fs.writeFileSync(path.join(dir, "001_ok.sql"), "CREATE TABLE a (id TEXT PRIMARY KEY);");
  fs.writeFileSync(path.join(dir, "002_broken.sql"), "CREATE TABLE b (id TEXT PRIMARY KEY); THIS IS NOT SQL;");

  const db = new SqliteDriver(":memory:");
  await assert.rejects(() => runMigrations(db, dir));

  const applied = await db.all<{ version: string }>("SELECT version FROM schema_migrations");
  assert.deepEqual(applied.map((r) => r.version), ["001"], "only the good migration should be recorded");
  const tables = await db.all<{ name: string }>("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'b'");
  assert.equal(tables.length, 0, "the failed migration's table must be rolled back");
  await db.close();
});

// --- placeholder translation, the one dialect difference in the SQL itself ---

test("placeholders are rewritten to PostgreSQL positional form", () => {
  assert.equal(
    toPositionalPlaceholders("SELECT * FROM users WHERE id = ? AND plan = ?"),
    "SELECT * FROM users WHERE id = $1 AND plan = $2"
  );
});

test("a ? inside a string literal is not treated as a placeholder", () => {
  assert.equal(
    toPositionalPlaceholders("SELECT ? FROM t WHERE label = 'why?' AND x = ?"),
    "SELECT $1 FROM t WHERE label = 'why?' AND x = $2"
  );
});

test("escaped quotes inside literals do not desynchronise the scanner", () => {
  assert.equal(
    toPositionalPlaceholders("SELECT ? WHERE a = 'it''s ok?' AND b = ?"),
    "SELECT $1 WHERE a = 'it''s ok?' AND b = $2"
  );
});
