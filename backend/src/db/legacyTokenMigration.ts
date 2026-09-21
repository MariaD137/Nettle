import crypto from "crypto";
import type { SqlDriver } from "./driver";

/**
 * Pre-baseline migration for SQLite databases created before session and
 * password-reset tokens were hashed.
 *
 * Those tables used the raw bearer token as their primary key. The versioned
 * migrations cannot do this job: `CREATE TABLE IF NOT EXISTS` is a no-op
 * against the existing legacy table, so the application would then query a
 * `token_hash` column that does not exist. Rehashing also needs SHA-256 over
 * each row, which portable SQL cannot express.
 *
 * SQLite only. PostgreSQL is new to this application and never had the legacy
 * shape, so there is nothing there to convert.
 *
 * Existing rows are rehashed rather than dropped, so introducing hashing does
 * not sign everyone out. Raw tokens are read solely to derive their hash and
 * are never logged.
 */

function sha256Hex(value: string): string {
  return crypto.createHash("sha256").update(value, "utf8").digest("hex");
}

async function columnExists(db: SqlDriver, table: string, column: string): Promise<boolean> {
  try {
    const rows = await db.all<{ name: string }>(`PRAGMA table_info(${table})`);
    return rows.some((r) => r.name === column);
  } catch {
    return false;
  }
}

async function tableExists(db: SqlDriver, table: string): Promise<boolean> {
  const row = await db.get("SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?", [table]);
  return row !== null;
}

async function migrateTable(db: SqlDriver, table: "sessions" | "password_resets"): Promise<void> {
  if (!(await tableExists(db, table))) return;
  if (await columnExists(db, table, "token_hash")) return;
  if (!(await columnExists(db, table, "token"))) return;

  const isSessions = table === "sessions";
  const extra = isSessions ? ", created_at" : "";
  const legacy = await db.all<{ token: string; user_id: string; expires_at: string; created_at?: string }>(
    `SELECT token, user_id, expires_at${extra} FROM ${table}`
  );

  await db.transaction(async (tx) => {
    if (isSessions) {
      await tx.exec(`CREATE TABLE sessions_hashed (
        token_hash TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL
      )`);
      for (const row of legacy) {
        await tx.run(
          "INSERT INTO sessions_hashed (token_hash, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
          [sha256Hex(row.token), row.user_id, row.created_at ?? new Date().toISOString(), row.expires_at]
        );
      }
      await tx.exec("DROP TABLE sessions");
      await tx.exec("ALTER TABLE sessions_hashed RENAME TO sessions");
      await tx.exec("CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id)");
    } else {
      await tx.exec(`CREATE TABLE password_resets_hashed (
        token_hash TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        expires_at TEXT NOT NULL
      )`);
      for (const row of legacy) {
        await tx.run("INSERT INTO password_resets_hashed (token_hash, user_id, expires_at) VALUES (?, ?, ?)", [
          sha256Hex(row.token),
          row.user_id,
          row.expires_at,
        ]);
      }
      await tx.exec("DROP TABLE password_resets");
      await tx.exec("ALTER TABLE password_resets_hashed RENAME TO password_resets");
    }
  });

  console.log(`[db] rehashed legacy ${table} tokens`);
}

export async function migrateLegacyTokenColumns(db: SqlDriver): Promise<void> {
  if (db.dialect !== "sqlite") return;
  await migrateTable(db, "sessions");
  await migrateTable(db, "password_resets");
}
