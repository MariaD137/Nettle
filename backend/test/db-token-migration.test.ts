import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "fs";
import os from "os";
import path from "path";
import crypto from "crypto";
import { execFileSync } from "child_process";
import { DatabaseSync } from "node:sqlite";

// The sessions/password_resets tables used to key on the raw bearer token.
// Migrating must (a) leave no raw token behind and (b) not sign everybody out,
// so these assertions run against a database built in the OLD shape.

function seedLegacyDatabase(): { dbPath: string; sessionToken: string; resetToken: string; userId: string } {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "nettle-migration-"));
  const dbPath = path.join(dir, "legacy.db");
  const legacy = new DatabaseSync(dbPath);

  legacy.exec(`
    CREATE TABLE users (
      id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL,
      plan TEXT NOT NULL DEFAULT 'free', stripe_customer_id TEXT,
      subscription_status TEXT NOT NULL DEFAULT 'none', created_at TEXT NOT NULL
    );
    CREATE TABLE sessions (
      token TEXT PRIMARY KEY, user_id TEXT NOT NULL,
      created_at TEXT NOT NULL, expires_at TEXT NOT NULL
    );
    CREATE TABLE password_resets (
      token TEXT PRIMARY KEY, user_id TEXT NOT NULL, expires_at TEXT NOT NULL
    );
  `);

  const userId = crypto.randomUUID();
  const now = new Date();
  const later = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000).toISOString();
  const sessionToken = crypto.randomBytes(32).toString("hex");
  const resetToken = crypto.randomBytes(32).toString("hex");

  legacy
    .prepare("INSERT INTO users (id, email, password_hash, created_at) VALUES (?, ?, ?, ?)")
    .run(userId, "legacy@example.com", "salt:hash", now.toISOString());
  legacy
    .prepare("INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)")
    .run(sessionToken, userId, now.toISOString(), later);
  legacy
    .prepare("INSERT INTO password_resets (token, user_id, expires_at) VALUES (?, ?, ?)")
    .run(resetToken, userId, later);
  legacy.close();

  return { dbPath, sessionToken, resetToken, userId };
}

// The schema module applies migrations at import time, so it is exercised in a
// child process against the seeded file.
function openThroughApp(dbPath: string, sessionToken: string, resetToken: string): any {
  const script = `
    process.env.NETTLE_DB_PATH = ${JSON.stringify(dbPath)};
    (async () => {
      const { db } = require("./src/db");
      const { resolveSession } = require("./src/auth/sessions");
      const { resolvePasswordResetToken } = require("./src/auth/users");
      console.log(JSON.stringify({
        sessionStillValid: await resolveSession(${JSON.stringify(sessionToken)}),
        resetStillValid: await resolvePasswordResetToken(${JSON.stringify(resetToken)}),
        sessionRows: await db.all("SELECT * FROM sessions"),
        resetRows: await db.all("SELECT * FROM password_resets"),
        userCount: await db.get("SELECT COUNT(*) AS n FROM users"),
      }));
    })().catch((e) => { console.error(e); process.exit(1); });
  `;
  // This migration is SQLite-only: PostgreSQL never had the raw-token schema,
  // and the fixture above is a SQLite file. DATABASE_URL is stripped so the
  // child opens that file rather than inheriting a PostgreSQL connection from
  // a cross-engine test run.
  const env = { ...process.env };
  delete env.DATABASE_URL;

  const out = execFileSync(process.execPath, ["--import", "tsx", "-e", script], {
    cwd: path.join(__dirname, ".."),
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    env,
  });
  return JSON.parse(out.trim().split("\n").pop()!);
}

test("migrating a legacy database rehashes tokens without signing anyone out", () => {
  const { dbPath, sessionToken, resetToken, userId } = seedLegacyDatabase();
  const result = openThroughApp(dbPath, sessionToken, resetToken);

  assert.deepEqual(result.sessionStillValid, { userId }, "an existing session must survive the migration");
  assert.deepEqual(result.resetStillValid, { userId }, "an outstanding reset link must survive the migration");
  assert.equal(result.userCount.n, 1, "the migration must not touch user rows");
});

test("after migration no raw token remains in the database", () => {
  const { dbPath, sessionToken, resetToken } = seedLegacyDatabase();
  const result = openThroughApp(dbPath, sessionToken, resetToken);

  const dump = JSON.stringify([result.sessionRows, result.resetRows]);
  assert.ok(!dump.includes(sessionToken), "raw session token survived the migration");
  assert.ok(!dump.includes(resetToken), "raw reset token survived the migration");
  assert.ok(dump.includes("token_hash"), "rows should be keyed by token_hash after migration");
});

test("migration is idempotent across restarts", () => {
  const { dbPath, sessionToken, resetToken, userId } = seedLegacyDatabase();
  openThroughApp(dbPath, sessionToken, resetToken);
  const second = openThroughApp(dbPath, sessionToken, resetToken);

  assert.deepEqual(second.sessionStillValid, { userId }, "a second startup must not re-migrate or drop rows");
  assert.equal(second.sessionRows.length, 1);
});
