/**
 * Resets the backend test suite's PostgreSQL database to a clean,
 * fully-migrated state before the real test run starts (wired as `pretest`
 * in package.json). Real Postgres is now the only database this backend
 * speaks, so unlike the old node:sqlite `:memory:` setup — where every
 * test *file* got its own private, automatically-clean in-process
 * database for free — the whole suite now shares one real external
 * database across every file. This script is what makes each full test
 * run start from the same clean slate that per-file `:memory:` isolation
 * used to provide implicitly.
 *
 * Fails loudly (non-zero exit) if no PostgreSQL is reachable, rather than
 * silently skipping — a test run that can't tell you it never ran for a
 * real reason is worse than one that fails fast with a clear message.
 */
import { Pool } from "pg";
import { runMigrations } from "../src/db/postgres/migrate";
import { _resetPostgresPoolForTests } from "../src/db/postgres/pool";

const TEST_DATABASE_URL =
  process.env.NETTLE_TEST_DATABASE_URL || "postgres://nettle:nettle_test_password@localhost:5432/nettle_test";

async function main(): Promise<void> {
  process.env.DATABASE_URL = TEST_DATABASE_URL;
  process.env.DATABASE_SSL = process.env.DATABASE_SSL ?? "disable";

  const pool = new Pool({ connectionString: TEST_DATABASE_URL, ssl: false, connectionTimeoutMillis: 5000 });
  try {
    await pool.query("SELECT 1");
  } catch (err) {
    console.error(
      `Cannot reach the test PostgreSQL database at ${TEST_DATABASE_URL}.\n` +
        `Set NETTLE_TEST_DATABASE_URL to point elsewhere, or start a local PostgreSQL 16 server ` +
        `(see backend/src/db/postgres/README.md).\n\nUnderlying error: ${(err as Error).message}`
    );
    process.exit(1);
  }

  await pool.query("DROP SCHEMA public CASCADE; CREATE SCHEMA public;");
  await pool.end();

  await _resetPostgresPoolForTests();
  const { applied } = await runMigrations();
  console.log(`Test database reset. Applied ${applied.length} migration(s): ${applied.join(", ") || "(none)"}`);
  await _resetPostgresPoolForTests();
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
