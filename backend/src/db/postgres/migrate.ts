import fs from "fs";
import path from "path";
import { getPostgresPool } from "./pool";

const MIGRATIONS_DIR = path.join(__dirname, "migrations");

interface MigrationFile {
  name: string;
  fullPath: string;
}

function listMigrationFiles(): MigrationFile[] {
  return fs
    .readdirSync(MIGRATIONS_DIR)
    .filter((f) => f.endsWith(".sql"))
    .sort() // filenames are zero-padded (0001_, 0002_, ...) so lexical == numeric order
    .map((f) => ({ name: f, fullPath: path.join(MIGRATIONS_DIR, f) }));
}

/**
 * Applies every migration in migrations/ that isn't already recorded in
 * schema_migrations, each inside its own transaction — one migration's
 * failure doesn't leave a later one half-applied, and a migration that's
 * already been applied is never re-run. Safe to call on every deploy.
 */
export async function runMigrations(): Promise<{ applied: string[] }> {
  const pool = getPostgresPool();
  const client = await pool.connect();
  const applied: string[] = [];

  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS schema_migrations (
        name TEXT PRIMARY KEY,
        applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
      );
    `);

    const alreadyApplied = new Set(
      (await client.query("SELECT name FROM schema_migrations")).rows.map((r) => r.name as string)
    );

    for (const file of listMigrationFiles()) {
      if (alreadyApplied.has(file.name)) continue;

      const sql = fs.readFileSync(file.fullPath, "utf8");
      await client.query("BEGIN");
      try {
        await client.query(sql);
        await client.query("INSERT INTO schema_migrations (name) VALUES ($1)", [file.name]);
        await client.query("COMMIT");
        applied.push(file.name);
      } catch (err) {
        await client.query("ROLLBACK");
        throw new Error(`Migration ${file.name} failed: ${(err as Error).message}`);
      }
    }
  } finally {
    client.release();
  }

  return { applied };
}

if (require.main === module) {
  runMigrations()
    .then(({ applied }) => {
      if (applied.length === 0) {
        console.log("No pending migrations — database is up to date.");
      } else {
        console.log(`Applied ${applied.length} migration(s): ${applied.join(", ")}`);
      }
      process.exit(0);
    })
    .catch((err) => {
      console.error(err.message || err);
      process.exit(1);
    });
}
