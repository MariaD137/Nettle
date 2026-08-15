import { DatabaseSync } from "node:sqlite";
import path from "path";
import crypto from "crypto";

// node:sqlite is experimental in Node 22 — real persistence with zero extra
// infra, which is the right tradeoff at this stage. Swap for RDS/Aurora once
// there's actual concurrent multi-tenant write load to justify the ops cost.
const DB_PATH = process.env.NETTLE_DB_PATH || path.join(process.cwd(), "nettle.db");

export const db = new DatabaseSync(DB_PATH);

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
    token TEXT PRIMARY KEY,
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
    token TEXT PRIMARY KEY,
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

export function newId(): string {
  return crypto.randomUUID();
}

export function newApiKey(): string {
  return "nettle_" + crypto.randomBytes(24).toString("hex");
}

export function newSessionToken(): string {
  return crypto.randomBytes(32).toString("hex");
}
