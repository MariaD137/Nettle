import crypto from "crypto";
import type { PoolClient } from "pg";
import { getPostgresPool } from "./postgres/pool";
import { runMigrations } from "./postgres/migrate";

// PostgreSQL is now the single production database. This module used to
// wrap node:sqlite's synchronous DatabaseSync directly against a local
// nettle.db file; that file, node:sqlite, and NETTLE_DB_PATH are gone from
// every production code path (see db/postgres/README.md for why the
// project carried both for a while, and test/dbAdapter.test.ts for the
// adapter contract this file implements).
//
// Every call site in this codebase was written against node:sqlite's
// `db.prepare(sql).get/all/run(...args)` shape. Rather than rewriting
// ~211 call sites' SQL and call structure in the same pass as the
// backing-store swap, this module reproduces that exact call shape as a
// thin async adapter over the real `pg` pool (db/postgres/pool.ts) — every
// call site's diff is "add `await`", not "rewrite the query" (a handful of
// genuinely SQLite-only constructs — INSERT OR REPLACE, datetime('now', ..),
// PRAGMA table_info — still needed real per-site rewrites; see git history
// for those). This is the "necessary" async wrapper referenced by
// db/postgres/README.md's deferred-follow-up note, not a second competing
// database abstraction: all it does is translate `?` placeholders to `$n`
// and forward to pool.query — there is exactly one real database client
// underneath, `getPostgresPool()`.

function toPositionalSql(sql: string): string {
  let n = 0;
  // A `?` can legitimately appear inside a quoted SQL string literal in
  // this codebase's queries (none currently do, but this is cheap
  // insurance): skip over single-quoted spans rather than blindly
  // replacing every `?`.
  let out = "";
  let inString = false;
  for (let i = 0; i < sql.length; i++) {
    const ch = sql[i];
    if (ch === "'") inString = !inString;
    if (ch === "?" && !inString) {
      n += 1;
      out += `$${n}`;
    } else {
      out += ch;
    }
  }
  return out;
}

export interface RunResult {
  changes: number;
}

type Row = Record<string, unknown>;

// Minimal subset of pg's Pool/PoolClient this adapter needs — lets
// PreparedStatement run against either the shared pool or a single
// checked-out transaction client with identical code.
interface Queryable {
  query(text: string, params?: unknown[]): Promise<{ rows: Row[]; rowCount: number | null }>;
}

class PreparedStatement {
  constructor(private readonly conn: Queryable, private readonly sql: string) {}

  async get(...params: unknown[]): Promise<Row | undefined> {
    const result = await this.conn.query(toPositionalSql(this.sql), params);
    return result.rows[0];
  }

  async all(...params: unknown[]): Promise<Row[]> {
    const result = await this.conn.query(toPositionalSql(this.sql), params);
    return result.rows;
  }

  async run(...params: unknown[]): Promise<RunResult> {
    const result = await this.conn.query(toPositionalSql(this.sql), params);
    return { changes: result.rowCount ?? 0 };
  }
}

export interface DbHandle {
  prepare(sql: string): PreparedStatement;
}

function makeHandle(conn: Queryable): DbHandle {
  return {
    prepare(sql: string) {
      return new PreparedStatement(conn, sql);
    },
  };
}

// The real handle every call site imports. Backed by the pool directly —
// each statement borrows a pooled connection for the duration of that one
// query, same as every other `pg` consumer.
export const db: DbHandle = makeHandle({
  query: (text, params) => getPostgresPool().query(text, params),
});

/**
 * Runs `fn` against a single checked-out connection inside a real
 * PostgreSQL transaction (BEGIN/COMMIT, ROLLBACK on throw). Needed only by
 * call sites that must observe their own writes atomically across more
 * than one statement — SQLite's single-threaded DatabaseSync gave every
 * multi-statement sequence that for free; PostgreSQL's genuine
 * cross-connection concurrency does not. See billing/scanQuota.ts for the
 * one place this closes a real race (concurrent scan-quota reservation).
 */
export async function withTransaction<T>(fn: (tx: DbHandle, client: PoolClient) => Promise<T>): Promise<T> {
  const pool = getPostgresPool();
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const tx = makeHandle({ query: (text, params) => client.query(text, params) });
    const result = await fn(tx, client);
    await client.query("COMMIT");
    return result;
  } catch (err) {
    await client.query("ROLLBACK");
    throw err;
  } finally {
    client.release();
  }
}

let migrated = false;
let migrating: Promise<void> | null = null;

/**
 * Applies pending PostgreSQL migrations. Called once at process startup
 * (see index.ts's start()) before the server begins accepting requests —
 * fails loudly (rejects) rather than falling back to any other database or
 * silently starting up against an unmigrated schema. Idempotent: safe to
 * call more than once (e.g. from a test's beforeEach), and concurrent
 * callers within one process share a single in-flight migration run
 * rather than racing the migration runner's own transactional apply.
 */
export async function initDb(): Promise<void> {
  if (migrated) return;
  if (!migrating) {
    migrating = runMigrations()
      .then(() => {
        migrated = true;
      })
      .finally(() => {
        migrating = null;
      });
  }
  await migrating;
}

// Test-only: forces the next initDb() call to actually re-run the
// migration check instead of short-circuiting. Not used by any production
// code path.
export function _resetDbInitForTests(): void {
  migrated = false;
  migrating = null;
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
