import { Pool } from "pg";

// Deliberately separate from src/db/index.ts, which remains the app's real
// (SQLite) data layer for now — see README.md in this directory for why.
// This module is not imported by any live request path; it exists so the
// connection/pooling piece of Postgres-readiness is real, tested code
// rather than a stub, ready for the migration runner and for whichever
// future change actually switches the app's data access over.

export class MissingDatabaseUrlError extends Error {
  constructor() {
    super(
      "DATABASE_URL is not configured — there is no default. Set it to a PostgreSQL " +
        "connection string, e.g. postgres://user:password@host:5432/dbname"
    );
  }
}

let pool: Pool | null = null;

// Lazy singleton, same pattern as billing/stripeClient.ts's getStripeClient
// — importing this module must not crash a process that never intends to
// use Postgres (every environment today, until the deferred call-site
// conversion happens).
export function getPostgresPool(): Pool {
  if (!pool) {
    const connectionString = process.env.DATABASE_URL;
    if (!connectionString) throw new MissingDatabaseUrlError();
    pool = new Pool({
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
