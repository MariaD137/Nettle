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

// Phase 13: ML Analytics & Baselines
db.exec(`
  CREATE TABLE IF NOT EXISTS ml_baselines (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    metric_name TEXT NOT NULL,
    aggregation_period TEXT NOT NULL,
    hour_of_day INTEGER,
    day_of_week INTEGER,
    value REAL NOT NULL,
    std_dev REAL,
    percentile_50 REAL,
    percentile_95 REAL,
    percentile_99 REAL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (project_id) REFERENCES projects(id)
  );
  CREATE INDEX IF NOT EXISTS idx_ml_baselines_project_metric
    ON ml_baselines(project_id, metric_name, aggregation_period);

  CREATE TABLE IF NOT EXISTS anomaly_scores (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    z_score REAL,
    isolation_score REAL,
    composite_score REAL,
    anomaly_type TEXT,
    is_anomaly INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    FOREIGN KEY (project_id) REFERENCES projects(id)
  );
  CREATE INDEX IF NOT EXISTS idx_anomaly_scores_project_time
    ON anomaly_scores(project_id, created_at DESC);

  CREATE TABLE IF NOT EXISTS ml_model_status (
    project_id TEXT PRIMARY KEY,
    model_type TEXT,
    trained_at TEXT,
    training_samples INTEGER,
    accuracy REAL,
    is_active INTEGER NOT NULL DEFAULT 0,
    last_update_at TEXT,
    FOREIGN KEY (project_id) REFERENCES projects(id)
  );
`);

// Tier 2: Custom Detection Rules
db.exec(`
  CREATE TABLE IF NOT EXISTS custom_rules (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    pattern_type TEXT NOT NULL,
    pattern_value TEXT NOT NULL,
    weight INTEGER NOT NULL,
    severity TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    version INTEGER NOT NULL DEFAULT 1,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (project_id) REFERENCES projects(id),
    FOREIGN KEY (created_by) REFERENCES users(id)
  );
  CREATE INDEX IF NOT EXISTS idx_custom_rules_project_enabled ON custom_rules(project_id, enabled);
  CREATE INDEX IF NOT EXISTS idx_custom_rules_project_type ON custom_rules(project_id, pattern_type);

  CREATE TABLE IF NOT EXISTS rule_versions (
    id TEXT PRIMARY KEY,
    rule_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    pattern_value TEXT NOT NULL,
    weight INTEGER NOT NULL,
    severity TEXT NOT NULL,
    changes TEXT,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (rule_id) REFERENCES custom_rules(id),
    FOREIGN KEY (created_by) REFERENCES users(id)
  );
  CREATE INDEX IF NOT EXISTS idx_rule_versions_rule ON rule_versions(rule_id, version DESC);

  CREATE TABLE IF NOT EXISTS rule_test_results (
    id TEXT PRIMARY KEY,
    rule_id TEXT NOT NULL,
    test_run_id TEXT NOT NULL,
    events_matched INTEGER NOT NULL DEFAULT 0,
    true_positives INTEGER NOT NULL DEFAULT 0,
    false_positives INTEGER NOT NULL DEFAULT 0,
    accuracy REAL,
    execution_time_ms INTEGER,
    created_at TEXT NOT NULL,
    FOREIGN KEY (rule_id) REFERENCES custom_rules(id)
  );
  CREATE INDEX IF NOT EXISTS idx_rule_test_results_rule ON rule_test_results(rule_id, created_at DESC);
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

// Phase 14: Integration Ecosystem (Webhooks)
db.exec(`
  CREATE TABLE IF NOT EXISTS webhooks (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    service TEXT NOT NULL,
    webhook_url TEXT NOT NULL,
    is_active INTEGER NOT NULL DEFAULT 1,
    event_types TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (project_id) REFERENCES projects(id)
  );
  CREATE INDEX IF NOT EXISTS idx_webhooks_project_service
    ON webhooks(project_id, service);

  CREATE TABLE IF NOT EXISTS webhook_events (
    id TEXT PRIMARY KEY,
    webhook_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    payload TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    attempt_count INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,
    created_at TEXT NOT NULL,
    sent_at TEXT,
    FOREIGN KEY (webhook_id) REFERENCES webhooks(id)
  );
  CREATE INDEX IF NOT EXISTS idx_webhook_events_status
    ON webhook_events(status, created_at DESC);
  CREATE INDEX IF NOT EXISTS idx_webhook_events_webhook
    ON webhook_events(webhook_id, created_at DESC);
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

export function newId(): string {
  return crypto.randomUUID();
}

export function newApiKey(): string {
  return "nettle_" + crypto.randomBytes(24).toString("hex");
}

export function newSessionToken(): string {
  return crypto.randomBytes(32).toString("hex");
}
