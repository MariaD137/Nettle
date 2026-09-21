/**
 * The database seam.
 *
 * Application code talks to this interface instead of to `node:sqlite`
 * directly, so the storage engine is a deployment choice rather than something
 * welded into 67 query sites across nine modules.
 *
 * The interface is asynchronous because PostgreSQL is. `node:sqlite` is
 * synchronous and its driver simply resolves immediately; that costs nothing
 * and keeps one shape for both engines rather than two parallel code paths.
 *
 * SQL is written once, in SQLite's `?` placeholder style, and the PostgreSQL
 * driver rewrites it to `$1, $2, …`. Every other construct the application
 * uses (TEXT/INTEGER columns, `CREATE TABLE IF NOT EXISTS`, plain
 * INSERT/SELECT/UPDATE/DELETE) is already valid in both engines, so no
 * statement needs a dialect branch.
 */
export interface SqlDriver {
  /** Rows from a SELECT. Returns [] when nothing matches. */
  all<T = Record<string, unknown>>(sql: string, params?: readonly unknown[]): Promise<T[]>;

  /** The first row, or null. */
  get<T = Record<string, unknown>>(sql: string, params?: readonly unknown[]): Promise<T | null>;

  /** INSERT/UPDATE/DELETE. `changes` is the affected row count. */
  run(sql: string, params?: readonly unknown[]): Promise<{ changes: number }>;

  /** Multi-statement DDL. Not parameterised — never build this from input. */
  exec(sql: string): Promise<void>;

  /**
   * Runs `fn` inside a transaction, committing on return and rolling back on
   * throw. The driver passed to `fn` must be used for the statements inside;
   * using the outer driver would run them outside the transaction.
   */
  transaction<T>(fn: (tx: SqlDriver) => Promise<T>): Promise<T>;

  /** Which engine this is, for the few places that must know. */
  readonly dialect: "sqlite" | "postgres";

  close(): Promise<void>;
}

/**
 * Rewrites `?` placeholders to PostgreSQL's `$1, $2, …`.
 *
 * Quoted string literals are skipped so a `?` inside `'why?'` is left alone.
 * The application parameterises everything, so literals containing `?` are
 * rare, but getting this wrong would corrupt a query rather than fail loudly.
 */
export function toPositionalPlaceholders(sql: string): string {
  let out = "";
  let index = 0;
  let inSingle = false;
  let inDouble = false;

  for (let i = 0; i < sql.length; i++) {
    const ch = sql[i];
    if (ch === "'" && !inDouble) {
      // '' inside a string is an escaped quote, not a terminator.
      if (inSingle && sql[i + 1] === "'") {
        out += "''";
        i++;
        continue;
      }
      inSingle = !inSingle;
      out += ch;
      continue;
    }
    if (ch === '"' && !inSingle) {
      inDouble = !inDouble;
      out += ch;
      continue;
    }
    if (ch === "?" && !inSingle && !inDouble) {
      out += `$${++index}`;
      continue;
    }
    out += ch;
  }
  return out;
}
