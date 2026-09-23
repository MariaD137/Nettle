# Monitoring Component (Tier 2)

## Purpose

Continuous monitoring of customer applications. Customer apps embed a middleware SDK that streams request events to Nettle. A detection engine watches for anomalies and raises alerts.

## Location

- `backend/src/patrol/` — Core monitoring logic
- `backend/src/middleware/nettleMonitor.ts` — Customer-facing SDK middleware
- `backend/src/routes/events.routes.ts` — Event ingestion endpoint
- `backend/src/routes/projects.routes.ts` — Project management

## Files

| File | Purpose |
|------|---------|
| `patrol/projects.ts` | Project CRUD (each project gets an API key) |
| `patrol/events.ts` | Event storage and queries |
| `patrol/detectionQueue.ts` | In-process async queue decoupling detection from ingestion |
| `patrol/detection.ts` | Rule-based anomaly detection |
| `patrol/alerts.ts` | Alert creation and queries |
| `patrol/badge.ts` | Trust badge state computation |
| `patrol/scans.ts` | Scan result persistence |
| `middleware/nettleMonitor.ts` | Express middleware for customer apps |

## API Endpoints

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| POST | `/api/projects` | Yes | Create a project |
| GET | `/api/projects` | Yes | List user's projects |
| POST | `/api/events` | API Key + PROTECT plan | Ingest request events |
| GET/PATCH | `/api/projects/:id/alerts` | Yes + PROTECT plan | List/update project alerts |

Continuous monitoring — event ingestion and alert viewing both — is a
PROTECT-only entitlement as of the pricing rework (see
`billing/entitlements.ts`'s `canUseContinuousMonitoring`/`canUseLiveAlerts`
and `billing/subscription.ts`'s `requireProtect`). A FREE or BUILD account's
API key is still valid for project lookup, but `POST /api/events` refuses
with 402 unless the project owner's entitled plan is PROTECT.

## Database Tables

- `projects` — `id`, `user_id`, `name`, `api_key`
- `events` — `id`, `project_id`, `occurred_at`, `ip`, `method`, `path`, `status_code`, `user_agent`
- `alerts` — `id`, `project_id`, `severity`, `rule`, `message`, `status`

## Detection Rules

Defined in `patrol/detection.ts`, run asynchronously via
`patrol/detectionQueue.ts` (jobs process serially, one at a time, to avoid a
cooldown race — see that file's comment). `POST /api/events` records the
event synchronously and returns immediately; detection runs afterward, off
the request's critical path. The four rules that actually exist, each
keyed per source IP within the project and cooled down for 5 minutes after
firing (`ALERT_COOLDOWN_SECONDS`) so an ongoing pattern doesn't re-alert on
every single request:
- **Brute-force**: 5+ `401`/`403` responses from the same IP within the
  last 60s (`critical`).
- **High request rate**: 50+ requests from the same IP within the last 10s
  — possible scraping or DoS probing (`medium`).
- **Suspicious path**: the request path matches a known attack-probe
  pattern — path traversal (`../`), an exposed `.env` or `.git/` path, a
  common CMS admin path (`/wp-admin`, `/wp-login`, `/phpmyadmin`), or
  `/etc/passwd` (`critical`).
- **SQL-injection-shaped path**: the request path matches a SQLi-shaped
  pattern (`' OR '1'='1`, `UNION SELECT`, `; DROP TABLE`, a trailing SQL
  comment) (`critical`).

Two rules previously documented here do not exist in the code and never
did — corrected, not implemented, per the rule that code is authoritative
over documentation:
- **Credential stuffing** is a distinct pattern from brute-force (many
  different username/password pairs tried across many accounts, often from
  a distributed set of IPs) that `detection.ts` does not attempt to
  distinguish from ordinary repeated failed-auth brute-forcing.
- **Suspicious user agents**: `StoredEvent.userAgent` is recorded on every
  event (see `patrol/events.ts`), but nothing in `detection.ts` reads or
  scores it — there is no user-agent-based rule of any kind today.

## Dependencies

- `backend/src/db/index.ts` — Database
- `backend/src/middleware/rateLimit.ts` — Rate limiting for event ingestion

## Tests

- `backend/test/patrol.test.ts` — Alert creation, project isolation
- `backend/test/detectionQueue.test.ts` — Async queue: non-blocking enqueue, serial processing, cooldown-race safety, failure isolation
- `backend/test/nettleMonitor.test.ts` — End-to-end middleware test

## Common Failures

- Events not being recorded: Wrong API key or rate limit exceeded
- Alerts not firing: Detection rules require minimum event volume, or haven't been processed by the queue yet (async — poll, don't assume immediately-after-ingest)
- Badge not updating: Badge reads from both scans and alerts tables

## How to Repair

```bash
git checkout -b fix/monitoring-<problem>
NETTLE_DB_PATH=:memory: node --import tsx --test test/patrol.test.ts test/detectionQueue.test.ts test/nettleMonitor.test.ts
```
