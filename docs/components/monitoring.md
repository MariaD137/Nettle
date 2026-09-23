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
| POST | `/api/events` | API Key | Ingest request events |
| GET | `/api/projects/:id/alerts` | Yes | List project alerts |

## Database Tables

- `projects` — `id`, `user_id`, `name`, `api_key`
- `events` — `id`, `project_id`, `occurred_at`, `ip`, `method`, `path`, `status_code`, `user_agent`
- `alerts` — `id`, `project_id`, `severity`, `rule`, `message`, `status`

## Detection Rules

Defined in `patrol/detection.ts`, run asynchronously via
`patrol/detectionQueue.ts` (jobs process serially, one at a time, to avoid a
cooldown race — see that file's comment). `POST /api/events` records the
event synchronously and returns immediately; detection runs afterward, off
the request's critical path. Current rules detect:
- Brute-force login attempts
- Credential stuffing patterns
- Unusual request volumes
- Suspicious user agents

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
