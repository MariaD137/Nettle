import { test } from "node:test";
import assert from "node:assert/strict";
import crypto from "crypto";
import { Pool } from "pg";
import { getPostgresPool, _resetPostgresPoolForTests, MissingDatabaseUrlError } from "../src/db/postgres/pool";
import { runMigrations } from "../src/db/postgres/migrate";

// This suite needs a real, reachable PostgreSQL server — there is no mock
// here, on the theory that a mocked pg client would only prove the mock
// behaves as configured, not that the DDL is valid or that constraints
// actually hold. CI does not currently provision Postgres (see
// .github/workflows/ci.yml), so this probes for one and skips with a clear
// reason instead of failing the whole suite when none is reachable —
// exactly what actually ran should always be knowable from the output,
// never silently assumed.
const TEST_DATABASE_URL =
  process.env.NETTLE_TEST_DATABASE_URL || "postgres://nettle:nettle_test_password@localhost:5432/nettle_test";

async function isPostgresReachable(): Promise<boolean> {
  const probe = new Pool({ connectionString: TEST_DATABASE_URL, ssl: false, connectionTimeoutMillis: 2000 });
  try {
    await probe.query("SELECT 1");
    return true;
  } catch {
    return false;
  } finally {
    await probe.end();
  }
}

test("PostgreSQL migration suite", async (t) => {
  if (!(await isPostgresReachable())) {
    t.skip(
      `No PostgreSQL reachable at ${TEST_DATABASE_URL} (set NETTLE_TEST_DATABASE_URL to point elsewhere) — ` +
        "skipping real-database migration tests rather than mocking them."
    );
    return;
  }

  process.env.DATABASE_URL = TEST_DATABASE_URL;
  process.env.DATABASE_SSL = "disable";
  await _resetPostgresPoolForTests();

  // Clean slate: this suite owns nettle_test entirely and resets it every
  // run, so tests are never order-dependent on some prior run's leftovers.
  const setupPool = getPostgresPool();
  await setupPool.query("DROP SCHEMA public CASCADE; CREATE SCHEMA public;");

  await t.test("getPostgresPool throws MissingDatabaseUrlError with no DATABASE_URL configured", async () => {
    const saved = process.env.DATABASE_URL;
    delete process.env.DATABASE_URL;
    await _resetPostgresPoolForTests();
    try {
      assert.throws(() => getPostgresPool(), MissingDatabaseUrlError);
    } finally {
      process.env.DATABASE_URL = saved;
      await _resetPostgresPoolForTests();
    }
  });

  await t.test("runMigrations creates every table from the live SQLite schema", async () => {
    const { applied } = await runMigrations();
    assert.deepEqual(applied, ["0001_initial_schema.sql"]);

    const pool = getPostgresPool();
    const { rows } = await pool.query(
      "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' ORDER BY table_name"
    );
    const tableNames = rows.map((r) => r.table_name);

    // Every table src/db/index.ts creates, per the current SQLite schema.
    const expectedTables = [
      "alerts", "anomaly_scores", "api_keys", "custom_rules", "detection_settings",
      "email_verifications", "events", "finding_history", "finding_statuses",
      "ml_baselines", "ml_model_status", "notification_channels", "notification_preferences",
      "password_resets", "payment_failures", "projects", "rule_test_results", "rule_versions",
      "scan_usage", "scans", "schema_migrations", "sessions", "stripe_events", "users",
      "webhook_events", "webhooks",
    ];
    for (const table of expectedTables) {
      assert.ok(tableNames.includes(table), `expected table "${table}" to exist`);
    }
  });

  await t.test("runMigrations is idempotent — a second run applies nothing", async () => {
    const { applied } = await runMigrations();
    assert.deepEqual(applied, []);
  });

  await t.test("foreign keys are actually enforced — inserting a session for a nonexistent user fails", async () => {
    const pool = getPostgresPool();
    await assert.rejects(
      () =>
        pool.query("INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES ($1, $2, $3, $4)", [
          crypto.randomBytes(16).toString("hex"),
          "nonexistent-user-id",
          new Date().toISOString(),
          new Date().toISOString(),
        ]),
      /foreign key constraint/
    );
  });

  await t.test("a real insert/select round trip works end to end through the migrated schema", async () => {
    const pool = getPostgresPool();
    const userId = crypto.randomUUID();
    const now = new Date().toISOString();

    await pool.query(
      "INSERT INTO users (id, email, password_hash, created_at) VALUES ($1, $2, $3, $4)",
      [userId, `pg-roundtrip-${userId}@example.com`, "hash", now]
    );

    const projectId = crypto.randomUUID();
    await pool.query(
      "INSERT INTO projects (id, user_id, name, api_key, created_at) VALUES ($1, $2, $3, $4, $5)",
      [projectId, userId, "PG Roundtrip Project", `nettle_${crypto.randomBytes(8).toString("hex")}`, now]
    );

    const { rows } = await pool.query("SELECT id, name, user_id FROM projects WHERE id = $1", [projectId]);
    assert.equal(rows.length, 1);
    assert.equal(rows[0].name, "PG Roundtrip Project");
    assert.equal(rows[0].user_id, userId);
  });

  await _resetPostgresPoolForTests();
});
