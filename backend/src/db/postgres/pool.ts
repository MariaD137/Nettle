import { Pool } from "pg";

// The real, only connection to the app's database — src/db/index.ts's
// async adapter is built on top of this pool. Accepts two configuration
// shapes so both a local/dev setup and App Runner's Secrets Manager
// integration work without a code change on either side:
//
//   1. DATABASE_URL — a single connection string. Natural for local dev,
//      docker-compose, and anywhere a full URL is easy to hand-configure.
//   2. Discrete PGHOST/PGPORT/PGUSER/PGPASSWORD/PGDATABASE — needed
//      because App Runner's `runtimeEnvironmentSecrets` maps exactly one
//      Secrets Manager JSON key to one environment variable; it cannot
//      interpolate several secret fields into a single DATABASE_URL
//      string. RDS's CDK-generated credentials secret (see
//      infra/lib/database-stack.ts) stores host/port/username/password/
//      dbname as separate JSON keys for exactly this reason, so
//      infra/lib/api-stack.ts maps each one to its own PG* env var (see
//      that file's REQUIRES AWS CONFIGURATION note on actually wiring
//      DATABASE_SECRET_ARN through). `pg`'s Pool reads these PG* variables
//      itself when no `connectionString` is supplied — this module only
//      needs to check that at least one of the two forms is present.

export class MissingDatabaseUrlError extends Error {
  constructor() {
    super(
      "No PostgreSQL connection is configured — there is no default and no SQLite fallback. " +
        "Set DATABASE_URL to a connection string (e.g. postgres://user:password@host:5432/dbname), " +
        "or set PGHOST/PGPORT/PGUSER/PGPASSWORD/PGDATABASE individually."
    );
  }
}

function hasDiscretePgEnv(): boolean {
  return Boolean(process.env.PGHOST && process.env.PGUSER && process.env.PGDATABASE);
}

let pool: Pool | null = null;

// Lazy singleton, same pattern as billing/stripeClient.ts's getStripeClient
// — importing this module must not crash a process that never intends to
// use Postgres (e.g. a script that only needs other exports from db/index.ts).
export function getPostgresPool(): Pool {
  if (!pool) {
    const connectionString = process.env.DATABASE_URL;
    if (!connectionString && !hasDiscretePgEnv()) throw new MissingDatabaseUrlError();
    pool = new Pool({
      // Omitting connectionString when unset lets `pg` fall back to the
      // standard PGHOST/PGPORT/PGUSER/PGPASSWORD/PGDATABASE environment
      // variables itself — passing `connectionString: undefined` here is
      // equivalent to not passing the key at all.
      connectionString,
      max: parseInt(process.env.DATABASE_POOL_MAX || "10", 10),
      idleTimeoutMillis: 30_000,
      connectionTimeoutMillis: 10_000,
      // RDS requires TLS but its default certificate isn't in Node's root
      // store; verifying against a bundled CA is a real future improvement,
      // not something to fake here. DATABASE_SSL=disable is for local/dev
      // Postgres, which typically isn't configured for TLS at all.
      ssl: process.env.DATABASE_SSL === "disable" ? false : { rejectUnauthorized: false },
    });
  }
  return pool;
}

// Test-only: drops the singleton so a test can point a fresh pool at a
// different DATABASE_URL. Not used by any production code path.
export async function _resetPostgresPoolForTests(): Promise<void> {
  if (pool) {
    await pool.end();
    pool = null;
  }
}
