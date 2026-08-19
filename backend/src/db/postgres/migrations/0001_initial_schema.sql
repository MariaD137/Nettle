-- Baseline schema for a fresh PostgreSQL database, translated from the live
-- SQLite schema in src/db/index.ts (that file remains the source of truth
-- for local/dev — this is a parallel target for AWS RDS, not a replacement
-- for it yet; see backend/src/db/postgres/README.md).
--
-- This represents the *current end state* of the SQLite schema, not its
-- historical ALTER-by-ALTER journey — a brand-new database doesn't need
-- the journey, just where it ends up. Table order is dependency order
-- (every table referenced by a FOREIGN KEY is created before the table
-- that references it) because, unlike SQLite's default, PostgreSQL always
-- enforces foreign key constraints.

CREATE TABLE users (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  plan TEXT NOT NULL DEFAULT 'free',
  stripe_customer_id TEXT,
  subscription_status TEXT NOT NULL DEFAULT 'none',
  billing_anchor TEXT,
  onboarding_completed_at TEXT,
  email_verified_at TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE sessions (
  token TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);
CREATE INDEX idx_sessions_user ON sessions(user_id);

CREATE TABLE projects (
  id TEXT PRIMARY KEY,
  user_id TEXT REFERENCES users(id),
  name TEXT NOT NULL,
  api_key TEXT NOT NULL UNIQUE,
  url TEXT,
  description TEXT,
  environment TEXT NOT NULL DEFAULT 'production',
  archived_at TEXT,
  repo_url TEXT,
  repo_branch TEXT,
  repo_access_token_encrypted TEXT,
  created_at TEXT NOT NULL
);
CREATE INDEX idx_projects_user ON projects(user_id);

CREATE TABLE events (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id),
  occurred_at TEXT NOT NULL,
  ip TEXT,
  method TEXT,
  path TEXT,
  status_code INTEGER,
  user_agent TEXT
);
CREATE INDEX idx_events_project_time ON events(project_id, occurred_at);
CREATE INDEX idx_events_occurred_at ON events(occurred_at DESC);

CREATE TABLE alerts (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id),
  occurred_at TEXT NOT NULL,
  severity TEXT NOT NULL,
  rule TEXT NOT NULL,
  message TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'new'
);
CREATE INDEX idx_alerts_project_time ON alerts(project_id, occurred_at);
CREATE INDEX idx_alerts_severity ON alerts(severity);
CREATE INDEX idx_alerts_status ON alerts(status);

CREATE TABLE password_resets (
  token TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  expires_at TEXT NOT NULL
);

CREATE TABLE scans (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id),
  scanned_at TEXT NOT NULL,
  score INTEGER NOT NULL,
  critical_count INTEGER NOT NULL,
  caution_count INTEGER NOT NULL,
  clear_count INTEGER NOT NULL,
  report_json TEXT NOT NULL,
  scanner_version TEXT,
  semgrep_version TEXT,
  status TEXT NOT NULL DEFAULT 'COMPLETED'
);
CREATE INDEX idx_scans_project_time ON scans(project_id, scanned_at);
CREATE INDEX idx_scans_project_status ON scans(project_id, status);
CREATE INDEX idx_scans_created_at ON scans(scanned_at DESC);

CREATE TABLE finding_statuses (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id),
  finding_hash TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open',
  notes TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE UNIQUE INDEX idx_finding_statuses_unique ON finding_statuses(project_id, finding_hash);
CREATE INDEX idx_findings_scan_id ON finding_statuses(finding_hash);
CREATE INDEX idx_findings_status ON finding_statuses(status);

CREATE TABLE notification_preferences (
  user_id TEXT PRIMARY KEY REFERENCES users(id),
  email_critical_alerts INTEGER NOT NULL DEFAULT 1,
  email_scan_complete INTEGER NOT NULL DEFAULT 1,
  email_weekly_summary INTEGER NOT NULL DEFAULT 0,
  slack_webhook_url TEXT
);

CREATE TABLE ml_baselines (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id),
  metric_name TEXT NOT NULL,
  aggregation_period TEXT NOT NULL,
  hour_of_day INTEGER,
  day_of_week INTEGER,
  value REAL NOT NULL,
  std_dev REAL,
  percentile_50 REAL,
  percentile_95 REAL,
  percentile_99 REAL,
  updated_at TEXT NOT NULL
);
CREATE INDEX idx_ml_baselines_project_metric ON ml_baselines(project_id, metric_name, aggregation_period);
CREATE INDEX idx_ml_baselines_updated_at ON ml_baselines(updated_at DESC);

CREATE TABLE anomaly_scores (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id),
  event_id TEXT NOT NULL,
  z_score REAL,
  isolation_score REAL,
  composite_score REAL,
  anomaly_type TEXT,
  is_anomaly INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);
CREATE INDEX idx_anomaly_scores_project_time ON anomaly_scores(project_id, created_at DESC);
CREATE INDEX idx_anomaly_scores_project_composite ON anomaly_scores(project_id, composite_score DESC);
CREATE INDEX idx_anomaly_scores_anomaly_type ON anomaly_scores(anomaly_type);

CREATE TABLE ml_model_status (
  project_id TEXT PRIMARY KEY REFERENCES projects(id),
  model_type TEXT,
  trained_at TEXT,
  training_samples INTEGER,
  accuracy REAL,
  is_active INTEGER NOT NULL DEFAULT 0,
  last_update_at TEXT
);

CREATE TABLE custom_rules (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id),
  name TEXT NOT NULL,
  description TEXT,
  pattern_type TEXT NOT NULL,
  pattern_value TEXT NOT NULL,
  weight INTEGER NOT NULL,
  severity TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  version INTEGER NOT NULL DEFAULT 1,
  created_by TEXT NOT NULL REFERENCES users(id),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX idx_custom_rules_project_enabled ON custom_rules(project_id, enabled);
CREATE INDEX idx_custom_rules_project_type ON custom_rules(project_id, pattern_type);
CREATE INDEX idx_custom_rules_severity ON custom_rules(severity, enabled);

CREATE TABLE rule_versions (
  id TEXT PRIMARY KEY,
  rule_id TEXT NOT NULL REFERENCES custom_rules(id),
  version INTEGER NOT NULL,
  pattern_value TEXT NOT NULL,
  weight INTEGER NOT NULL,
  severity TEXT NOT NULL,
  changes TEXT,
  created_by TEXT NOT NULL REFERENCES users(id),
  created_at TEXT NOT NULL
);
CREATE INDEX idx_rule_versions_rule ON rule_versions(rule_id, version DESC);

CREATE TABLE rule_test_results (
  id TEXT PRIMARY KEY,
  rule_id TEXT NOT NULL REFERENCES custom_rules(id),
  test_run_id TEXT NOT NULL,
  events_matched INTEGER NOT NULL DEFAULT 0,
  true_positives INTEGER NOT NULL DEFAULT 0,
  false_positives INTEGER NOT NULL DEFAULT 0,
  accuracy REAL,
  execution_time_ms INTEGER,
  created_at TEXT NOT NULL
);
CREATE INDEX idx_rule_test_results_rule ON rule_test_results(rule_id, created_at DESC);

CREATE TABLE scan_usage (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  project_id TEXT,
  source TEXT NOT NULL,
  occurred_at TEXT NOT NULL
);
CREATE INDEX idx_scan_usage_user_time ON scan_usage(user_id, occurred_at);

CREATE TABLE webhooks (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id),
  service TEXT NOT NULL,
  webhook_url TEXT NOT NULL,
  is_active INTEGER NOT NULL DEFAULT 1,
  event_types TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX idx_webhooks_project_service ON webhooks(project_id, service);

CREATE TABLE webhook_events (
  id TEXT PRIMARY KEY,
  webhook_id TEXT NOT NULL REFERENCES webhooks(id),
  event_type TEXT NOT NULL,
  payload TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  attempt_count INTEGER NOT NULL DEFAULT 0,
  last_error TEXT,
  created_at TEXT NOT NULL,
  sent_at TEXT
);
CREATE INDEX idx_webhook_events_status ON webhook_events(status, created_at DESC);
CREATE INDEX idx_webhook_events_webhook ON webhook_events(webhook_id, created_at DESC);
CREATE INDEX idx_webhook_events_created_at ON webhook_events(created_at DESC);

CREATE TABLE finding_history (
  project_id TEXT NOT NULL REFERENCES projects(id),
  finding_hash TEXT NOT NULL,
  first_seen_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL,
  PRIMARY KEY (project_id, finding_hash)
);
CREATE INDEX idx_finding_history_project ON finding_history(project_id);

CREATE TABLE api_keys (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id),
  name TEXT NOT NULL,
  key TEXT NOT NULL UNIQUE,
  key_masked TEXT,
  scopes TEXT NOT NULL,
  is_default INTEGER NOT NULL DEFAULT 0,
  last_used_at TEXT,
  revoked_at TEXT,
  created_at TEXT NOT NULL
);
CREATE INDEX idx_api_keys_project ON api_keys(project_id);

CREATE TABLE detection_settings (
  project_id TEXT PRIMARY KEY REFERENCES projects(id),
  brute_force_threshold INTEGER NOT NULL,
  high_request_rate_threshold INTEGER NOT NULL,
  credential_stuffing_min_ips INTEGER NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE notification_channels (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id),
  channel TEXT NOT NULL,
  destination TEXT NOT NULL,
  is_active INTEGER NOT NULL DEFAULT 1,
  event_types TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX idx_notification_channels_project ON notification_channels(project_id, channel);

CREATE TABLE stripe_events (
  event_id TEXT PRIMARY KEY,
  event_type TEXT NOT NULL,
  processed_at TEXT NOT NULL
);

CREATE TABLE payment_failures (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  stripe_invoice_id TEXT NOT NULL,
  amount_due INTEGER,
  currency TEXT,
  failure_reason TEXT,
  occurred_at TEXT NOT NULL,
  resolved_at TEXT
);
CREATE INDEX idx_payment_failures_user ON payment_failures(user_id, occurred_at DESC);

CREATE TABLE email_verifications (
  token TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  expires_at TEXT NOT NULL
);
