# PostgreSQL — the production database

## What this is

PostgreSQL is now the single production database for this backend.
`src/db/index.ts` no longer wraps `node:sqlite`; it's a thin async adapter
(`db.prepare(sql).get/all/run(...)`, same call shape every route/service
already used, now returning Promises) over the real connection pool in
this directory (`pool.ts`), with the schema created by the migration
runner (`migrate.ts`) and the versioned SQL files in `migrations/`.

There is no SQLite fallback anywhere in production code. `getPostgresPool()`
fails closed with a clear `MissingDatabaseUrlError` if `DATABASE_URL` is
unset, and the server's startup sequence (`src/index.ts`'s `start()`) awaits
`initDb()` — which runs every pending migration — before it starts
accepting requests, exiting (after alerting) if that fails.

The one remaining `node:sqlite` import left anywhere in `src/` is
`src/scanner/osvVulnerabilities.ts`, and it is not this application's
database: it opens a bundled, read-only, point-in-time npm vulnerability
snapshot (`src/scanner/osv-data/npm-vulnerabilities.db`, built by
`scripts/build-osv-db.js`) shipped as a static asset alongside the app,
analogous to the bundled Semgrep rule YAML files — nothing in the running
application ever writes to it. Converting that to PostgreSQL would mean
building an ingestion pipeline for a static reference dataset, which is a
different, unrelated piece of work from migrating the app's own
persistent state.

## Using it

```bash
# Point at any reachable PostgreSQL 16+ instance.
export DATABASE_URL="postgres://user:password@host:5432/dbname"
# DATABASE_SSL=disable only for a local Postgres with no TLS configured —
# never set this against a real production database.
npm run db:migrate:postgres   # or just start the server — it migrates on boot
```

`getPostgresPool()` (`pool.ts`) fails closed with a clear
`MissingDatabaseUrlError` if `DATABASE_URL` is unset — there is no silent
fallback to SQLite or to any default connection string.

## AWS RDS

The same schema and migration runner target RDS once it exists —
`DATABASE_URL` becomes an RDS connection string retrieved from AWS Secrets
Manager at runtime (see `infra/` and `AWS_GITHUB_DEPLOYMENT.md`). Actually
provisioning and connecting to a real RDS instance requires an AWS account
and has not been done or verified from this repository — that step is
labeled `REQUIRES AWS ACCOUNT` / `REQUIRES AWS CONFIGURATION` throughout
the docs referenced above, and nothing here should be read as claiming
otherwise.

## Testing

Local backend tests (`npm test`) now run against a real local PostgreSQL
server by default — `package.json`'s `pretest` script
(`test/resetTestDb.ts`) resets the schema and applies every migration
before the suite runs, pointed at `NETTLE_TEST_DATABASE_URL` (default
`postgres://nettle:nettle_test_password@localhost:5432/nettle_test`), and
fails loudly if that database isn't reachable rather than silently
skipping the whole suite. To run it locally:

```bash
createdb nettle_test   # or: docker run -p 5432:5432 -e POSTGRES_PASSWORD=... postgres:16
npm test
```

`test/postgresMigration.test.ts` additionally verifies the migrated schema
directly (every table exists, foreign keys are enforced, migrations are
idempotent) rather than through the application layer.
