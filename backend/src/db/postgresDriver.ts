import { Pool, type PoolClient } from "pg";
import type { SqlDriver } from "./driver";
import { toPositionalPlaceholders } from "./driver";

/**
 * PostgreSQL driver — the production engine (RDS).
 *
 * A pool rather than a single connection: App Runner scales horizontally and
 * each instance serves concurrent requests. `max` is deliberately modest
 * because db.t4g.micro has a low connection ceiling and several App Runner
 * instances share it.
 */
export class PostgresDriver implements SqlDriver {
  readonly dialect = "postgres" as const;
  private readonly pool: Pool;

  constructor(connectionString: string, options: { max?: number; ssl?: boolean } = {}) {
    this.pool = new Pool({
      connectionString,
      max: options.max ?? 5,
      idleTimeoutMillis: 30_000,
      connectionTimeoutMillis: 10_000,
      // RDS presents an AWS-issued certificate. Verifying it properly needs
      // the RDS CA bundle in the image; until that is added, this is
      // encrypted-but-unverified rather than plaintext. Called out in the
      // deployment notes rather than left silent.
      ssl: options.ssl ? { rejectUnauthorized: false } : undefined,
    });

    // A pool error outside a query (a dropped backend, a failover) is emitted
    // on the pool. Without a listener it would take the process down.
    this.pool.on("error", (err) => {
      console.error(`[db] idle client error: ${err.message}`);
    });
  }

  async all<T>(sql: string, params: readonly unknown[] = []): Promise<T[]> {
    const result = await this.pool.query(toPositionalPlaceholders(sql), params as unknown[]);
    return result.rows as T[];
  }

  async get<T>(sql: string, params: readonly unknown[] = []): Promise<T | null> {
    const result = await this.pool.query(toPositionalPlaceholders(sql), params as unknown[]);
    return (result.rows[0] ?? null) as T | null;
  }

  async run(sql: string, params: readonly unknown[] = []): Promise<{ changes: number }> {
    const result = await this.pool.query(toPositionalPlaceholders(sql), params as unknown[]);
    return { changes: result.rowCount ?? 0 };
  }

  async exec(sql: string): Promise<void> {
    await this.pool.query(sql);
  }

  async transaction<T>(fn: (tx: SqlDriver) => Promise<T>): Promise<T> {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const result = await fn(new PostgresTransaction(client));
      await client.query("COMMIT");
      return result;
    } catch (err) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw err;
    } finally {
      client.release();
    }
  }

  async close(): Promise<void> {
    await this.pool.end();
  }
}

/**
 * A transaction is pinned to one client. Statements issued against the pool
 * instead would land on a different connection and run outside the
 * transaction, which is the classic way to lose atomicity silently.
 */
class PostgresTransaction implements SqlDriver {
  readonly dialect = "postgres" as const;
  constructor(private readonly client: PoolClient) {}

  async all<T>(sql: string, params: readonly unknown[] = []): Promise<T[]> {
    const result = await this.client.query(toPositionalPlaceholders(sql), params as unknown[]);
    return result.rows as T[];
  }

  async get<T>(sql: string, params: readonly unknown[] = []): Promise<T | null> {
    const result = await this.client.query(toPositionalPlaceholders(sql), params as unknown[]);
    return (result.rows[0] ?? null) as T | null;
  }

  async run(sql: string, params: readonly unknown[] = []): Promise<{ changes: number }> {
    const result = await this.client.query(toPositionalPlaceholders(sql), params as unknown[]);
    return { changes: result.rowCount ?? 0 };
  }

  async exec(sql: string): Promise<void> {
    await this.client.query(sql);
  }

  async transaction<T>(fn: (tx: SqlDriver) => Promise<T>): Promise<T> {
    // Already inside one; PostgreSQL has no true nesting without savepoints,
    // and nothing in this application needs them.
    return fn(this);
  }

  async close(): Promise<void> {
    // The pool owns the client's lifetime; released in PostgresDriver.
  }
}
