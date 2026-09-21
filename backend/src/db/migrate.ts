import fs from "fs";
import path from "path";
import type { SqlDriver } from "./driver";

/**
 * Versioned SQL migrations.
 *
 * There is no ORM here and none is being introduced — the application is raw
 * SQL over a thin driver, so migrations are plain .sql files applied in
 * filename order and recorded in `schema_migrations`.
 *
 * Properties this guarantees:
 *  - versioned:     filename prefix is the version, applied in ascending order
 *  - idempotent:    an already-recorded version is skipped
 *  - transactional: each migration commits as a unit, or not at all
 *  - safe to run at deploy time, including concurrently by several App Runner
 *    instances starting at once (see the lock below)
 *  - never destructive by default: DROP/TRUNCATE are refused unless the file
 *    opts in explicitly
 */

const MIGRATIONS_DIR = path.join(__dirname, "migrations");

// A migration that genuinely must drop something has to say so, in a comment,
// on purpose. Without this a careless edit could silently delete production
// data on the next deploy.
const DESTRUCTIVE = /\b(DROP\s+TABLE|DROP\s+COLUMN|TRUNCATE)\b/i;
const DESTRUCTIVE_OPT_IN = /--\s*nettle:allow-destructive/i;

export interface MigrationFile {
  version: string;
  name: string;
  sql: string;
}

export function loadMigrations(dir: string = MIGRATIONS_DIR): MigrationFile[] {
  if (!fs.existsSync(dir)) return [];
  return fs
    .readdirSync(dir)
    .filter((f) => f.endsWith(".sql"))
    .sort()
    .map((file) => {
      const sql = fs.readFileSync(path.join(dir, file), "utf8");
      const version = file.split("_")[0];
      if (!/^\d+$/.test(version)) {
        throw new Error(`Migration "${file}" must start with a numeric version, e.g. 001_name.sql`);
      }
      if (DESTRUCTIVE.test(sql) && !DESTRUCTIVE_OPT_IN.test(sql)) {
        throw new Error(
          `Migration "${file}" contains a destructive statement without an explicit ` +
            `"-- nettle:allow-destructive" marker. Refusing to run it.`
        );
      }
      return { version, name: file, sql };
    });
}

async function ensureMigrationsTable(db: SqlDriver): Promise<void> {
  await db.exec(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      version TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      applied_at TEXT NOT NULL
    )
  `);
}

/**
 * Applies every migration not yet recorded. Returns the versions applied.
 *
 * Concurrency: several App Runner instances can boot simultaneously and race
 * here. On PostgreSQL an advisory lock serialises them, so the second waits
 * and then finds the work already recorded. SQLite is single-process in this
 * application, so it needs no equivalent.
 */
export async function runMigrations(db: SqlDriver, dir?: string): Promise<string[]> {
  const migrations = loadMigrations(dir);
  if (migrations.length === 0) return [];

  if (db.dialect === "postgres") {
    await db.exec("SELECT pg_advisory_lock(4159153)"); // arbitrary, stable app id
  }
  try {
    await ensureMigrationsTable(db);

    const appliedRows = await db.all<{ version: string }>("SELECT version FROM schema_migrations");
    const applied = new Set(appliedRows.map((r) => r.version));
    const runNow: string[] = [];

    for (const migration of migrations) {
      if (applied.has(migration.version)) continue;

      await db.transaction(async (tx) => {
        await tx.exec(migration.sql);
        await tx.run("INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)", [
          migration.version,
          migration.name,
          new Date().toISOString(),
        ]);
      });

      runNow.push(migration.version);
      console.log(`[db] applied migration ${migration.name}`);
    }
    return runNow;
  } finally {
    if (db.dialect === "postgres") {
      await db.exec("SELECT pg_advisory_unlock(4159153)");
    }
  }
}
