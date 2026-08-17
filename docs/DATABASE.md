# Database

## Overview

Nettle uses Node.js 22's built-in `node:sqlite` module (the `DatabaseSync` class). The database is a single SQLite file — no external database server required.

## Configuration

| Variable | Default | Purpose |
|----------|---------|---------|
| `NETTLE_DB_PATH` | `./nettle.db` | Path to the SQLite database file |

For tests: `NETTLE_DB_PATH=:memory:` creates an in-memory database that is discarded after the process exits.

## Schema

Defined in `backend/src/db/index.ts`. Tables are created with `CREATE TABLE IF NOT EXISTS` on application startup.

### Tables

| Table | Purpose | Key columns |
|-------|---------|------------|
| `users` | User accounts | `id`, `email`, `password_hash`, `plan`, `stripe_customer_id` |
| `sessions` | Auth session tokens | `token`, `user_id`, `expires_at` |
| `projects` | Monitored projects (Tier 2) | `id`, `user_id`, `name`, `api_key` |
| `events` | Ingested request events | `id`, `project_id`, `ip`, `method`, `path`, `status_code` |
| `alerts` | Detection alerts | `id`, `project_id`, `severity`, `rule`, `message` |
| `scans` | Scan results | `id`, `project_id`, `score`, `critical_count`, `report_json` |
| `password_resets` | Password reset tokens | `token`, `user_id`, `expires_at` |

### Indexes

- `idx_sessions_user` on `sessions(user_id)`
- `idx_projects_user` on `projects(user_id)`
- `idx_events_project_time` on `events(project_id, occurred_at)`
- `idx_alerts_project_time` on `alerts(project_id, occurred_at)`
- `idx_scans_project_time` on `scans(project_id, scanned_at)`

## Migration Strategy

There is no migration framework. All schema changes must be:

1. **Additive** — use `CREATE TABLE IF NOT EXISTS` and `ALTER TABLE ... ADD COLUMN`
2. **Backwards compatible** — new columns must have defaults or be nullable
3. **Reviewed** — schema changes must go through a pull request

### Adding a new table

Add the `CREATE TABLE IF NOT EXISTS` statement to `backend/src/db/index.ts`.

### Adding a column

Use `ALTER TABLE` with a try/catch or check if the column exists first. SQLite does not support `ADD COLUMN IF NOT EXISTS`.

### Destructive changes

SQLite does not support `DROP COLUMN`, `RENAME COLUMN` (before 3.25.0), or `ALTER TABLE ... ALTER COLUMN`. Destructive changes require:

1. Create a new table with the desired schema
2. Copy data from the old table
3. Drop the old table
4. Rename the new table

This must be done in a single transaction and tested thoroughly before deploying.

## Development Database

```bash
cd backend
NETTLE_DB_PATH=./dev.db npm run dev
```

The dev database is gitignored. Delete it to start fresh.

## Test Database

```bash
cd backend
npm test  # automatically uses :memory: (see package.json scripts)
```

Each test run gets a clean database. No cleanup needed.

## Production Considerations

### Current limitation

App Runner uses ephemeral storage. The SQLite file is lost on each deployment or instance restart. This is acceptable for the current scale (scan results are returned immediately and badges are recomputed from the latest scan).

### When to migrate to a managed database

Migrate to RDS (PostgreSQL) or DynamoDB when:
- Multiple instances are needed (SQLite doesn't support concurrent writes across processes)
- Data must persist across deployments
- The database grows beyond what fits in memory

### Backup

For single-instance deployments, back up the SQLite file:

```bash
sqlite3 /path/to/nettle.db ".backup /path/to/backup.db"
```

## Rollback

Since there is no migration framework, rollback means:

1. Revert the code change (which reverts the schema change in `db/index.ts`)
2. If the schema change was destructive, restore from backup
3. If the schema change was additive (new table/column), the old code simply ignores the extra table/column — no rollback needed
