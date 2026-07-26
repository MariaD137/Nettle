# Nettle — backend

Tier 1 "Dry Dock" scan engine and API. Scans an AI-built app's codebase for
launch-readiness gaps: hardcoded secrets, known-vulnerable dependencies,
missing privacy policy / terms of service, undisclosed AI-generated content,
and routes with no visible authentication check.

This isn't a mockup — the scan engine is real static analysis, covered by
tests that assert on actual findings against two fixture apps: one seeded
with real issues (`test/fixtures/sample-app`) and one clean
(`test/fixtures/clean-app`).

## Use it

```bash
npm install
npm run build

# CLI
node bin/nettle.js scan /path/to/some/app

# API
npm start                 # listens on :8080
curl -X POST http://localhost:8080/api/scans \
  -F "codebase=@/path/to/app.zip"
```

## Develop

```bash
npm run dev     # tsx watch, hot reload
npm test        # real assertions against the fixture apps
npm run lint    # tsc --noEmit
```

## What's actually checked today

| Check | How |
|---|---|
| Hardcoded secrets | Regex patterns for AWS keys, Stripe live keys, GitHub tokens, Slack tokens, JWT/signing secrets, private key blocks |
| Vulnerable dependencies | `package.json` versions checked against a small hand-curated known-CVE list (seed data — production version should call a real OSV/CVE feed) |
| Missing lockfile | Checks for `package-lock.json` / `yarn.lock` / `pnpm-lock.yaml` |
| Missing privacy policy / terms | Looks for a root-level file matching the name |
| Undisclosed AI-generated content | Heuristic: content-generation-shaped code with no disclosure/C2PA marker nearby |
| Missing auth check | Heuristic: a file defining Express routes with no reference to a JWT/auth-middleware/passport call anywhere in it |

Every one of these is intentionally simple and will have false positives —
the point right now is a real, working, testable pipeline end to end, not
completeness. Next real gaps to close: wrap an actual OSS scanner (Semgrep,
gitleaks) instead of hand-rolled regex, and pull dependency vulnerabilities
from a live OSV feed instead of the hardcoded seed list.

## Tier 2 — "Open Water" continuous monitoring

Real and tested, not a mockup either. A customer creates a project, gets an
API key, drops one middleware line into their own app, and Nettle watches
their live traffic for attack patterns.

```bash
# 1. create a project (no auth on this yet — see "known gaps" below)
curl -X POST http://localhost:8080/api/projects \
  -H "Content-Type: application/json" -d '{"name":"My App"}'
# -> { "id": "...", "apiKey": "nettle_...", ... }

# 2. in the customer's own Express app — today this means copying
#    src/middleware/nettleMonitor.ts in directly, since it isn't published
#    as its own installable package yet (that's the real next step for
#    actual customer distribution, not just an oversight):
```
```ts
import { nettleMonitor } from "./nettleMonitor";
app.use(nettleMonitor({ apiKey: "nettle_..." }));
```
```bash
# 3. see what it caught
curl http://localhost:8080/api/projects/<id>/alerts
```

**What it detects today** (all rule-based, all covered by real tests in
`test/patrol.test.ts` and `test/nettleMonitor.test.ts` — the latter runs the
actual middleware against a real ingestion server, not a mock):

| Rule | Trigger |
|---|---|
| `brute-force` | 5+ responses with status 401/403 from the same IP within 60s |
| `high-request-rate` | 50+ requests from the same IP within 10s |
| `suspicious-path-*` | Path matches a common attack-probe pattern: traversal (`../`), exposed `.env`/`.git`, known CMS admin paths |
| `sqli-shaped-*` | Path/query matches a SQL-injection-shaped pattern |

Repeated triggers of the same rule are suppressed for 5 minutes so an
ongoing attack doesn't spam alerts once per request.

**The one property that actually matters for this middleware**: it must
never be the reason a customer's app breaks or slows down. Reporting is
fire-and-restore on `res.on("finish")` (after the response is already sent),
wrapped so a network failure, timeout, or Nettle's own API being down can
never throw into the customer's request handling. This is directly tested,
not just asserted in a comment — see "the middleware never blocks or breaks
the customer's response when the ingestion endpoint is unreachable" in
`test/nettleMonitor.test.ts`.

**Storage**: `node:sqlite` (built into Node 22, experimental). Real
persistence with zero extra infrastructure — the right tradeoff until there's
actual concurrent multi-tenant write volume to justify running RDS.

## Architecture

See the full system diagram (this Tier 1 piece plus the Tier 2 "Open Water"
continuous monitoring, trust badge, and platform core) in the published
artifact from the design pass. Tier 2 is no longer "doesn't exist yet" —
the diagram's boxes for intake -> event queue -> detection -> alerting are
now real code, just without the queue in between yet (see known gaps).

## Known gaps

**Tier 1 sandboxing.** The `/api/scans` endpoint currently extracts and reads
the uploaded zip directly on the host running the API. That's fine for local
development — it is **not** fine for production, since this endpoint runs
static analysis over code an attacker fully controls. Before this goes
anywhere near real traffic, extraction and scanning need to happen in an
isolated, network-less sandbox (see the AWS architecture notes: ECS Fargate
tasks with no NAT/egress, or a service like e2b/Modal purpose-built for
executing untrusted code).

**Tier 2 has no auth on project creation.** `POST /api/projects` is wide
open right now — anyone can create a project and get an API key. Fine for
early testing, not fine once this is reachable by the public internet;
needs real accounts/billing gating it, same as the rest of the platform
core that doesn't exist yet.

**Tier 2 processes events synchronously, in-process, with no queue.**
The architecture diagram shows an event queue between intake and detection;
today, `POST /api/events` runs detection inline on the request itself. Fine
at low volume, but a burst of traffic to a monitored app becomes a burst of
synchronous SQLite writes on the Nettle API itself. Add the queue (Kinesis,
per the AWS architecture notes) once there's real traffic to justify it —
not speculatively now.

**`node:sqlite` is single-file, single-instance.** It doesn't work if the
API ever runs as more than one container (App Runner today runs one). That's
the actual trigger for migrating to RDS/Aurora — not a fixed timeline, a
specific condition to watch for.

**No alert delivery beyond the API.** Alerts are queryable via
`GET /api/projects/:id/alerts` but nothing pushes them anywhere yet — no
email, Slack, or SMS. That's the next real piece of Tier 2 to build.
