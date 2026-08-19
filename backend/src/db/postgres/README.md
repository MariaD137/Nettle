# PostgreSQL readiness — status and how to use it

## What this is, honestly

This directory contains real, tested PostgreSQL infrastructure: a
connection pool (`pool.ts`), a migration runner (`migrate.ts`), and a
baseline schema (`migrations/0001_initial_schema.sql`) translated from the
live SQLite schema in `src/db/index.ts`. All of it has been run and
verified against a real local PostgreSQL 16 server — the migration creates
every table, foreign keys are genuinely enforced, and a real insert/select
round trip works.

**What this is not:** the app's actual data layer. `src/db/index.ts` (SQLite,
via `node:sqlite`) is still what every route handler in this codebase reads
and writes through — nothing in `src/` imports anything from this directory.
Nothing here is wired into a live request path.

## Why it's split this way

`node:sqlite`'s `DatabaseSync` is fully synchronous. `pg` (and any real
PostgreSQL driver) is inherently asynchronous. There are 171 `db.prepare()`
call sites across this codebase — routes, services, tests — all written
assuming synchronous execution. Actually switching the app over to
PostgreSQL means converting that data-access code to async, which cascades
into most route handlers. That is a large, genuinely risky rewrite, not a
driver swap, and doing it blind (as part of an unrelated hardening pass)
was explicitly decided against — see the project's Postgres-readiness
decision: build this infrastructure now, defer the call-site conversion as
its own explicitly-scoped follow-up.

So this directory exists to make that follow-up smaller and lower-risk
when it happens: the schema translation, connection handling, and
migration tooling are already done and already proven against a real
database. What's left is exactly the async conversion described above —
nothing more.

## The migration path

1. **Local dev (current default, unchanged):** SQLite via `node:sqlite`,
   `NETTLE_DB_PATH` (defaults to `./nettle.db`, or `:memory:` in tests).
   Nothing about this changes — no existing developer workflow is affected.
2. **PostgreSQL (this directory, ready but unused):** point `DATABASE_URL`
   at a real Postgres instance and run `npm run db:migrate:postgres` to
   create the schema. Verified against a real local PostgreSQL 16 server
   during this work (`backend/test/postgresMigration.test.ts`).
3. **AWS RDS PostgreSQL (not deployed, not tested):** the same schema and
   migration runner target RDS once it exists — `DATABASE_URL` becomes an
   RDS connection string retrieved from AWS Secrets Manager at runtime (see
   `infra/` and `AWS_GITHUB_DEPLOYMENT.md`). This has not been deployed or
   tested against real RDS; do not treat it as verified until it is.

## Using it

```bash
# Point at any reachable PostgreSQL 16+ instance.
export DATABASE_URL="postgres://user:password@host:5432/dbname"
# DATABASE_SSL=disable only for a local Postgres with no TLS configured —
# never set this against a real production database.
npm run db:migrate:postgres
```

`getPostgresPool()` (`pool.ts`) fails closed with a clear
`MissingDatabaseUrlError` if `DATABASE_URL` is unset — there is no silent
fallback to SQLite or to any default connection string. That guard only
applies to code that actually calls this module, though: since nothing in
`src/` does yet, it does not currently affect how the live app starts up
or behaves. It will matter once something does.

## Testing

`test/postgresMigration.test.ts` runs against a real PostgreSQL server —
no mocking. It probes for one at `NETTLE_TEST_DATABASE_URL` (default
`postgres://nettle:nettle_test_password@localhost:5432/nettle_test`) and
skips with a clear reason if none is reachable, rather than failing CI
environments that don't provision Postgres. To run it locally:

```bash
createdb nettle_test   # or: docker run -p 5432:5432 -e POSTGRES_PASSWORD=... postgres:16
npm test -- test/postgresMigration.test.ts
```
