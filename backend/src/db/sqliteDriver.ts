import { DatabaseSync } from "node:sqlite";
import type { SqlDriver } from "./driver";

/**
 * SQLite driver — local development and the automated test suite.
 *
 * Not used in production: the container filesystem is ephemeral, so anything
 * written here is lost when App Runner replaces the instance. See
 * src/db/index.ts for how the engine is selected.
 *
 * node:sqlite is synchronous, so every method resolves immediately. The async
 * signatures exist to match the PostgreSQL driver, not because work is
 * deferred.
 */
export class SqliteDriver implements SqlDriver {
  readonly dialect = "sqlite" as const;
  private readonly db: DatabaseSync;

  constructor(dbPath: string) {
    try {
      this.db = new DatabaseSync(dbPath);
    } catch (err) {
      throw new Error(
        `Could not open the Nettle SQLite database at "${dbPath}": ${(err as Error).message}\n` +
          "The directory must exist and be writable by the user running the process. " +
          "Set NETTLE_DB_PATH to a writable location."
      );
    }
    // Foreign keys are OFF by default in SQLite, which is why orphaned rows
    // went unnoticed. On, so local development enforces what PostgreSQL will.
    this.db.exec("PRAGMA foreign_keys = ON");
  }

  async all<T>(sql: string, params: readonly unknown[] = []): Promise<T[]> {
    return this.db.prepare(sql).all(...(params as never[])) as unknown as T[];
  }

  async get<T>(sql: string, params: readonly unknown[] = []): Promise<T | null> {
    const row = this.db.prepare(sql).get(...(params as never[]));
    return (row ?? null) as T | null;
  }

  async run(sql: string, params: readonly unknown[] = []): Promise<{ changes: number }> {
    const result = this.db.prepare(sql).run(...(params as never[]));
    return { changes: Number(result.changes ?? 0) };
  }

  async exec(sql: string): Promise<void> {
    this.db.exec(sql);
  }

  async transaction<T>(fn: (tx: SqlDriver) => Promise<T>): Promise<T> {
    this.db.exec("BEGIN");
    try {
      // Same connection: node:sqlite has a single handle, so the nested calls
      // already run inside the transaction opened above.
      const result = await fn(this);
      this.db.exec("COMMIT");
      return result;
    } catch (err) {
      this.db.exec("ROLLBACK");
      throw err;
    }
  }

  async close(): Promise<void> {
    this.db.close();
  }
}
