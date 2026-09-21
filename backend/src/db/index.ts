import { DatabaseSync } from "node:sqlite";
import path from "path";
import crypto from "crypto";

// node:sqlite is experimental in Node 22 — real persistence with zero extra
// infra, which is the right tradeoff at this stage. Swap for RDS/Aurora once
// there's actual concurrent multi-tenant write load to justify the ops cost.
const DB_PATH = process.env.NETTLE_DB_PATH || path.join(process.cwd(), "nettle.db");

function openDatabase(dbPath: string): DatabaseSync {
  try {
    return new DatabaseSync(dbPath);
  } catch (err) {
    // This runs at import time, so a failure here takes the whole process
    // down before it serves a request. SQLite reports it as a bare
    // ERR_SQLITE_ERROR, which says nothing about the actual cause — in the
    // container it was that the default path lands in the root-owned /app
    // while the process runs as a non-root user. Say which path failed and
    // which knob fixes it.
    const detail = (err as Error).message;
    throw new Error(
      `Could not open the Nettle database at "${dbPath}": ${detail}\n` +
        "The directory must exist and be writable by the user running the process. " +
        "Set NETTLE_DB_PATH to a writable location (the container image uses /data)."
    );
  }
}

export const db = openDatabase(DB_PATH);

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    plan TEXT NOT NULL DEFAULT 'free',
    stripe_customer_id TEXT,
    subscription_status TEXT NOT NULL DEFAULT 'none',
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );
  CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

  CREATE TABLE IF NOT EXISTS projects (
    id TEXT PRIMARY KEY,
    user_id TEXT,
    name TEXT NOT NULL,
    api_key TEXT NOT NULL UNIQUE,
    url TEXT,
    description TEXT,
    environment TEXT NOT NULL DEFAULT 'production',
    archived_at TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );
  CREATE INDEX IF NOT EXISTS idx_projects_user ON projects(user_id);

  CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    ip TEXT,
    method TEXT,
    path TEXT,
    status_code INTEGER,
    user_agent TEXT,
    FOREIGN KEY (project_id) REFERENCES projects(id)
  );
  CREATE INDEX IF NOT EXISTS idx_events_project_time ON events(project_id, occurred_at);

  CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    severity TEXT NOT NULL,
    rule TEXT NOT NULL,
    message TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'new',
    FOREIGN KEY (project_id) REFERENCES projects(id)
  );
  CREATE INDEX IF NOT EXISTS idx_alerts_project_time ON alerts(project_id, occurred_at);

  CREATE TABLE IF NOT EXISTS password_resets (
    token_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    scanned_at TEXT NOT NULL,
    score INTEGER NOT NULL,
    critical_count INTEGER NOT NULL,
    caution_count INTEGER NOT NULL,
    clear_count INTEGER NOT NULL,
    report_json TEXT NOT NULL,
    FOREIGN KEY (project_id) REFERENCES projects(id)
  );
  CREATE INDEX IF NOT EXISTS idx_scans_project_time ON scans(project_id, scanned_at);

  CREATE TABLE IF NOT EXISTS finding_statuses (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    finding_hash TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    notes TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (project_id) REFERENCES projects(id)
  );
  CREATE UNIQUE INDEX IF NOT EXISTS idx_finding_statuses_unique ON finding_statuses(project_id, finding_hash);

  CREATE TABLE IF NOT EXISTS notification_preferences (
    user_id TEXT PRIMARY KEY,
    email_critical_alerts INTEGER NOT NULL DEFAULT 1,
    email_scan_complete INTEGER NOT NULL DEFAULT 1,
    email_weekly_summary INTEGER NOT NULL DEFAULT 0,
    slack_webhook_url TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );
`);

function columnExists(table: string, column: string): boolean {
  const rows = db.prepare(`PRAGMA table_info(${table})`).all() as unknown as { name: string }[];
  return rows.some((r) => r.name === column);
}

if (!columnExists("projects", "url")) {
  db.exec("ALTER TABLE projects ADD COLUMN url TEXT");
}
if (!columnExists("projects", "description")) {
  db.exec("ALTER TABLE projects ADD COLUMN description TEXT");
}
if (!columnExists("projects", "environment")) {
  db.exec("ALTER TABLE projects ADD COLUMN environment TEXT NOT NULL DEFAULT 'production'");
}
if (!columnExists("projects", "archived_at")) {
  db.exec("ALTER TABLE projects ADD COLUMN archived_at TEXT");
}
if (!columnExists("scans", "scanner_version")) {
  db.exec("ALTER TABLE scans ADD COLUMN scanner_version TEXT");
}
// Billable scans are recorded here rather than counted off the `scans`
// table. A scan run without a project API key never lands in `scans` at
// all, so counting stored reports would let a subscriber take unlimited
// full-price scans simply by omitting the key. The ledger tracks usage
// independently of whether a report was persisted against a project.
db.exec(`
  CREATE TABLE IF NOT EXISTS scan_usage (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    project_id TEXT,
    source TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );
  CREATE INDEX IF NOT EXISTS idx_scan_usage_user_time
    ON scan_usage(user_id, occurred_at);
`);

// Anchor for the monthly scan allowance. Set when a subscription first goes
// active and then left alone — the current period is derived by rolling this
// date forward a month at a time, which is how Stripe's own billing cycle
// behaves, so the two line up once Stripe is wired in.
if (!columnExists("users", "billing_anchor")) {
  db.exec("ALTER TABLE users ADD COLUMN billing_anchor TEXT");
}

// Scan status: CREATED, SCANNING, COMPLETED, PARTIALLY_COMPLETED, FAILED, CANCELLED
if (!columnExists("scans", "status")) {
  db.exec("ALTER TABLE scans ADD COLUMN status TEXT NOT NULL DEFAULT 'COMPLETED'");
}

// --- Migration: store only hashes of session / password-reset tokens ---
//
// Both tables used to hold the raw bearer token as their primary key, so any
// read of the database yielded directly replayable credentials. Existing rows
// are rehashed in place rather than dropped, so nobody is logged out by the
// deploy that introduces this. The raw tokens are read here only to derive
// their hash; they are never logged and do not survive the rebuild.
//
// SQLite cannot rename or retype a PRIMARY KEY column in place, hence the
// table rebuild. Both run inside a transaction so a crash mid-migration
// cannot leave a half-converted table behind.
function migrateTokenColumnToHash(table: string): void {
  if (columnExists(table, "token_hash") || !columnExists(table, "token")) return;

  const extraColumns = table === "sessions" ? ", created_at" : "";
  const legacy = db
    .prepare(`SELECT token, user_id, expires_at${extraColumns} FROM ${table}`)
    .all() as unknown as { token: string; user_id: string; expires_at: string; created_at?: string }[];

  db.exec("BEGIN");
  try {
    if (table === "sessions") {
      db.exec(`CREATE TABLE sessions_hashed (
        token_hash TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id)
      )`);
      const insert = db.prepare(
        "INSERT OR REPLACE INTO sessions_hashed (token_hash, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)"
      );
      for (const row of legacy) {
        insert.run(sha256Hex(row.token), row.user_id, row.created_at ?? new Date().toISOString(), row.expires_at);
      }
      db.exec("DROP TABLE sessions");
      db.exec("ALTER TABLE sessions_hashed RENAME TO sessions");
      db.exec("CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id)");
    } else {
      db.exec(`CREATE TABLE password_resets_hashed (
        token_hash TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id)
      )`);
      const insert = db.prepare(
        "INSERT OR REPLACE INTO password_resets_hashed (token_hash, user_id, expires_at) VALUES (?, ?, ?)"
      );
      for (const row of legacy) {
        insert.run(sha256Hex(row.token), row.user_id, row.expires_at);
      }
      db.exec("DROP TABLE password_resets");
      db.exec("ALTER TABLE password_resets_hashed RENAME TO password_resets");
    }
    db.exec("COMMIT");
  } catch (err) {
    db.exec("ROLLBACK");
    throw err;
  }
}

// Local copy rather than importing auth/tokenHash, so the schema module stays
// free of dependencies on the auth layer that sits above it.
function sha256Hex(value: string): string {
  return crypto.createHash("sha256").update(value, "utf8").digest("hex");
}

migrateTokenColumnToHash("sessions");
migrateTokenColumnToHash("password_resets");

export function newId(): string {
  return crypto.randomUUID();
}

export function newApiKey(): string {
  return "nettle_" + crypto.randomBytes(24).toString("hex");
}

export function newSessionToken(): string {
  return crypto.randomBytes(32).toString("hex");
}
