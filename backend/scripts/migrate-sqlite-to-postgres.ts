/**
 * One-way data migration: an existing SQLite Nettle database -> PostgreSQL.
 *
 *   npx tsx scripts/migrate-sqlite-to-postgres.ts --source ./nettle.db [--dry-run]
 *
 * DATABASE_URL must point at the target. The target schema is created by the
 * normal versioned migrations before any row is copied.
 *
 * Safety properties:
 *  - never writes to the source,
 *  - refuses to run against a target that already holds user rows unless
 *    --force is given, so it cannot silently double-import,
 *  - copies inside a single transaction: either every table lands or none does,
 *  - verifies row counts per table afterwards and exits non-zero on mismatch,
 *  - prints counts and IDs only. Password hashes, session/reset token hashes
 *    and Stripe identifiers are copied but never logged.
 */
import path from "path";
import fs from "fs";
import { SqliteDriver } from "../src/db/sqliteDriver";
import { PostgresDriver } from "../src/db/postgresDriver";
import { runMigrations } from "../src/db/migrate";
import type { SqlDriver } from "../src/db/driver";

// Parents before children: the foreign keys are enforced on PostgreSQL, so
// order is not cosmetic here.
const TABLES = [
  "users",
  "projects",
  "sessions",
  "password_resets",
  "events",
  "alerts",
  "scans",
  "finding_statuses",
  "notification_preferences",
  "scan_usage",
] as const;

const COLUMNS: Record<string, string[]> = {
  users: ["id", "email", "password_hash", "plan", "stripe_customer_id", "subscription_status", "created_at", "billing_anchor"],
  projects: ["id", "user_id", "name", "api_key", "url", "description", "environment", "archived_at", "created_at"],
  sessions: ["token_hash", "user_id", "created_at", "expires_at"],
  password_resets: ["token_hash", "user_id", "expires_at"],
  events: ["id", "project_id", "occurred_at", "ip", "method", "path", "status_code", "user_agent"],
  alerts: ["id", "project_id", "occurred_at", "severity", "rule", "message", "status"],
  scans: ["id", "project_id", "scanned_at", "score", "critical_count", "caution_count", "clear_count", "report_json", "scanner_version", "status"],
  finding_statuses: ["id", "project_id", "finding_hash", "status", "notes", "created_at", "updated_at"],
  notification_preferences: ["user_id", "email_critical_alerts", "email_scan_complete", "email_weekly_summary", "slack_webhook_url"],
  scan_usage: ["id", "user_id", "project_id", "source", "occurred_at"],
};

function arg(name: string): string | undefined {
  const i = process.argv.indexOf(`--${name}`);
  return i === -1 ? undefined : process.argv[i + 1];
}
const has = (name: string) => process.argv.includes(`--${name}`);

async function countRows(db: SqlDriver, table: string): Promise<number> {
  const row = await db.get<{ n: number | string }>(`SELECT CAST(COUNT(*) AS INTEGER) AS n FROM ${table}`);
  return Number(row?.n ?? 0);
}

async function main(): Promise<void> {
  const source = arg("source") ?? path.join(process.cwd(), "nettle.db");
  const dryRun = has("dry-run");
  const force = has("force");
  const targetUrl = process.env.DATABASE_URL;

  if (!targetUrl) throw new Error("DATABASE_URL must point at the target PostgreSQL database");
  if (!fs.existsSync(source)) throw new Error(`Source SQLite database not found: ${source}`);

  const sqlite = new SqliteDriver(source);
  const postgres = new PostgresDriver(targetUrl, { ssl: !/sslmode=disable/.test(targetUrl) });

  try {
    await runMigrations(postgres);

    const existingUsers = await countRows(postgres, "users");
    if (existingUsers > 0 && !force) {
      throw new Error(
        `Target already contains ${existingUsers} user(s). Refusing to import on top of existing data. ` +
          `Re-run with --force only if you are certain this is not a double-import.`
      );
    }

    const sourceCounts: Record<string, number> = {};
    for (const table of TABLES) sourceCounts[table] = await countRows(sqlite, table);

    console.log("Source row counts:");
    for (const table of TABLES) console.log(`  ${table.padEnd(26)} ${sourceCounts[table]}`);

    if (dryRun) {
      console.log("\n--dry-run: nothing was written.");
      return;
    }

    await postgres.transaction(async (tx) => {
      for (const table of TABLES) {
        const cols = COLUMNS[table];
        const rows = await sqlite.all<Record<string, unknown>>(`SELECT ${cols.join(", ")} FROM ${table}`);
        if (rows.length === 0) continue;
        const placeholders = cols.map(() => "?").join(", ");
        for (const row of rows) {
          await tx.run(
            `INSERT INTO ${table} (${cols.join(", ")}) VALUES (${placeholders})`,
            cols.map((c) => row[c] ?? null)
          );
        }
        console.log(`  copied ${rows.length} row(s) into ${table}`);
      }
    });

    // Verification: counts must match exactly, and the relationships that
    // matter must still resolve.
    let mismatch = false;
    console.log("\nVerification:");
    for (const table of TABLES) {
      const after = await countRows(postgres, table);
      const ok = after === sourceCounts[table];
      if (!ok) mismatch = true;
      console.log(`  ${table.padEnd(26)} ${sourceCounts[table]} -> ${after} ${ok ? "OK" : "MISMATCH"}`);
    }

    const orphanProjects = await countRows(
      postgres,
      "projects p WHERE p.user_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM users u WHERE u.id = p.user_id)"
    );
    const orphanSessions = await countRows(
      postgres,
      "sessions s WHERE NOT EXISTS (SELECT 1 FROM users u WHERE u.id = s.user_id)"
    );
    const billingLinked = await countRows(postgres, "users WHERE stripe_customer_id IS NOT NULL");
    console.log(`  orphaned projects           ${orphanProjects}`);
    console.log(`  orphaned sessions           ${orphanSessions}`);
    console.log(`  users with a Stripe customer ${billingLinked}`);

    if (mismatch || orphanProjects > 0 || orphanSessions > 0) {
      throw new Error("Verification failed — the transaction was committed, inspect the target before use.");
    }
    console.log("\nMigration complete and verified.");
  } finally {
    await sqlite.close();
    await postgres.close();
  }
}

main().catch((err) => {
  console.error(`Migration failed: ${(err as Error).message}`);
  process.exit(1);
});
