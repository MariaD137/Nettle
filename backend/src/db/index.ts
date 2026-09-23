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
 * DATABASE_URL decides: set it (directly, or assembled from DB_HOST/
 * DB_USERNAME/DB_PASSWORD — see resolveDatabaseUrl below) and PostgreSQL is
 * used; leave both unset and the SQLite file at NETTLE_DB_PATH is used. That
 * means a developer needs no database server to run the tests, and
 * production cannot accidentally fall back to SQLite — see
 * assertProductionPersistence() below.
 */

const SQLITE_PATH = process.env.NETTLE_DB_PATH || path.join(process.cwd(), "nettle.db");

/**
 * Resolves the PostgreSQL connection string, either directly from
 * DATABASE_URL or assembled from discrete DB_HOST/DB_PORT/DB_NAME/
 * DB_USERNAME/DB_PASSWORD parts.
 *
 * The discrete-parts path exists specifically for infra/lib/api-stack.ts:
 * App Runner has two separate mechanisms for configuration —
 * runtimeEnvironmentVariables (plain values, visible in the console and via
 * DescribeService) and runtimeEnvironmentSecrets (a Secrets Manager/SSM ARN,
 * resolved by App Runner only inside the running container, never stored in
 * App Runner's own service configuration). A single composite DATABASE_URL
 * containing the RDS password can only go through the first mechanism,
 * because runtimeEnvironmentSecrets substitutes one whole env var with one
 * whole secret JSON key's value — it can't interpolate a literal
 * "postgresql://" prefix and a hostname around two separate secret fields.
 * Accepting the credentials as discrete parts lets the CDK stack put
 * DB_USERNAME and DB_PASSWORD through runtimeEnvironmentSecrets (the RDS
 * secret's own "username"/"password" keys, same native mechanism already
 * used for the Stripe secrets) and assemble the actual connection string
 * here, inside the container, where it's never visible to anything with
 * apprunner:DescribeService but no secretsmanager:GetSecretValue on this
 * specific secret.
 *
 * DATABASE_URL still wins when set directly — local development,
 * docker-compose, and the test suite all keep working exactly as before.
 */
export function resolveDatabaseUrl(env: NodeJS.ProcessEnv = process.env): string | undefined {
  if (env.DATABASE_URL) return env.DATABASE_URL;

  const { DB_HOST, DB_USERNAME, DB_PASSWORD } = env;
  if (!DB_HOST || !DB_USERNAME || !DB_PASSWORD) return undefined;

  const port = env.DB_PORT || "5432";
  const name = env.DB_NAME || "nettle";
  // encodeURIComponent defensively, in case a credential ever contains a
  // URL-significant character (RDS's generated password excludes those by
  // default, but this constructor shouldn't rely on that holding forever).
  const user = encodeURIComponent(DB_USERNAME);
  const pass = encodeURIComponent(DB_PASSWORD);
  return `postgresql://${user}:${pass}@${DB_HOST}:${port}/${name}`;
}

const DATABASE_URL = resolveDatabaseUrl();

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
  if (env.NODE_ENV === "production" && !resolveDatabaseUrl(env)) {
    throw new Error(
      "DATABASE_URL is not set (directly, or via DB_HOST/DB_USERNAME/DB_PASSWORD). " +
        "Nettle refuses to run in production on SQLite: the container filesystem " +
        "is ephemeral, so all users, sessions, projects, scans and billing state " +
        "would be destroyed on the next deployment. Point it at the RDS instance."
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

/**
 * Lazy by construction: `createDriver()` must not run at import time.
 *
 * `index.ts`'s `start()` calls `assertProductionPersistence()` before it
 * calls `initializeDatabase()` (the first thing that actually touches `db`).
 * If `db` were a plain module-level `const`, `createDriver()` would run the
 * instant anything imports this module — including `index.ts`'s own
 * top-level import — which is before `start()` gets a chance to run its
 * guard. In production with DATABASE_URL unset, that meant the process
 * crashed on the SqliteDriver constructor's "directory must exist and be
 * writable" error instead of the intended, actionable
 * assertProductionPersistence() message. The Proxy defers construction
 * until the first real call, by which point the guard has already run.
 */
let instance: SqlDriver | null = null;
function getInstance(): SqlDriver {
  if (!instance) {
    instance = new MigratingDriver(createDriver());
  }
  return instance;
}

export const db: SqlDriver = new Proxy({} as SqlDriver, {
  get(_target, prop, receiver) {
    const value = Reflect.get(getInstance() as object, prop, receiver);
    return typeof value === "function" ? value.bind(getInstance()) : value;
  },
});

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
