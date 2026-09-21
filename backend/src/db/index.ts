import path from "path";
import crypto from "crypto";
import type { SqlDriver } from "./driver";
import { SqliteDriver } from "./sqliteDriver";
import { PostgresDriver } from "./postgresDriver";
import { runMigrations } from "./migrate";
import { migrateLegacyTokenColumns } from "./legacyTokenMigration";

/**
 * Engine selection.
 *
 * Production runs PostgreSQL (RDS). SQLite is for local development and the
 * test suite only — App Runner's filesystem is replaced with the container on
 * every deployment, so a SQLite file there loses every user, session, project,
 * scan and billing anchor each time the service is redeployed or scaled.
 *
 * DATABASE_URL decides: set it and PostgreSQL is used; leave it unset and the
 * SQLite file at NETTLE_DB_PATH is used. That means a developer needs no
 * database server to run the tests, and production cannot accidentally fall
 * back to SQLite — see assertProductionPersistence() below.
 */

const DATABASE_URL = process.env.DATABASE_URL;
const SQLITE_PATH = process.env.NETTLE_DB_PATH || path.join(process.cwd(), "nettle.db");

/**
 * Refuses to start a production process on ephemeral storage.
 *
 * Without this the service would boot happily on SQLite in the container and
 * appear healthy right up until the first redeploy silently discarded every
 * account. Failing at startup is the cheaper failure.
 */
export function assertProductionPersistence(
  env: NodeJS.ProcessEnv = process.env
): void {
  if (env.NODE_ENV === "production" && !env.DATABASE_URL) {
    throw new Error(
      "DATABASE_URL is not set. Nettle refuses to run in production on SQLite: " +
        "the container filesystem is ephemeral, so all users, sessions, projects, " +
        "scans and billing state would be destroyed on the next deployment. " +
        "Point DATABASE_URL at the RDS instance."
    );
  }
}

function createDriver(): SqlDriver {
  if (DATABASE_URL) {
    // sslmode is carried in the URL for RDS; the driver enables TLS unless the
    // URL explicitly disables it (local docker-compose, for instance).
    const ssl = !/sslmode=disable/.test(DATABASE_URL);
    return new PostgresDriver(DATABASE_URL, { ssl });
  }
  return new SqliteDriver(SQLITE_PATH);
}

/**
 * Wraps the real driver so schema migrations run exactly once, on first use,
 * and every caller after that waits on the same promise.
 *
 * Doing it here rather than at import time keeps migrations asynchronous
 * (PostgreSQL has no synchronous client) without forcing every call site and
 * test to remember an explicit init step.
 */
class MigratingDriver implements SqlDriver {
  private ready: Promise<void> | null = null;
  constructor(private readonly inner: SqlDriver) {}

  get dialect() {
    return this.inner.dialect;
  }

  private ensureReady(): Promise<void> {
    if (!this.ready) {
      // Legacy rehash first: it converts a pre-hashing SQLite database into
      // the shape the baseline migration expects. Running it afterwards would
      // be too late, since CREATE TABLE IF NOT EXISTS silently skips the
      // already-present legacy table.
      this.ready = migrateLegacyTokenColumns(this.inner)
        .then(() => runMigrations(this.inner))
        .then(() => undefined);
    }
    return this.ready;
  }

  async all<T>(sql: string, params?: readonly unknown[]): Promise<T[]> {
    await this.ensureReady();
    return this.inner.all<T>(sql, params);
  }
  async get<T>(sql: string, params?: readonly unknown[]): Promise<T | null> {
    await this.ensureReady();
    return this.inner.get<T>(sql, params);
  }
  async run(sql: string, params?: readonly unknown[]): Promise<{ changes: number }> {
    await this.ensureReady();
    return this.inner.run(sql, params);
  }
  async exec(sql: string): Promise<void> {
    await this.ensureReady();
    return this.inner.exec(sql);
  }
  async transaction<T>(fn: (tx: SqlDriver) => Promise<T>): Promise<T> {
    await this.ensureReady();
    return this.inner.transaction(fn);
  }
  async close(): Promise<void> {
    return this.inner.close();
  }
}

export const db: SqlDriver = new MigratingDriver(createDriver());

/**
 * Applies migrations eagerly. Production calls this at startup so a broken
 * migration fails the deployment rather than the first request that happens to
 * touch the database.
 */
export async function initializeDatabase(): Promise<void> {
  await db.get("SELECT 1 AS ok");
}

export function newId(): string {
  return crypto.randomUUID();
}

export function newApiKey(): string {
  return "nettle_" + crypto.randomBytes(24).toString("hex");
}

export function newSessionToken(): string {
  return crypto.randomBytes(32).toString("hex");
}

export type { SqlDriver };
