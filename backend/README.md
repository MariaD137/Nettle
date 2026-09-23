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
| Vulnerable dependencies | `package.json` versions checked against a real, bundled snapshot of OSV's npm vulnerability database (215k+ known vulnerability ranges) — see below |
| Missing lockfile | Checks for `package-lock.json` / `yarn.lock` / `pnpm-lock.yaml` |
| Missing privacy policy / terms | Looks for a root-level file matching the name |
| Undisclosed AI-generated content | Heuristic: content-generation-shaped code with no disclosure/C2PA marker nearby |
| Missing auth check | Heuristic: a file defining Express routes with no reference to a JWT/auth-middleware/passport call anywhere in it |
| Semgrep static analysis | Real, industry-standard static analysis (not hand-rolled regex) — see below |

Every hand-rolled check above is intentionally simple and will have false
positives — the point is a real, working, testable pipeline end to end, not
completeness.

### OSV vulnerability database

`osvVulnerabilities.ts` checks every dependency in `package.json` against a
real, bundled snapshot of [OSV](https://osv.dev)'s npm vulnerability data —
215,156 known vulnerability ranges across the npm ecosystem, not a
hand-picked list of 2-4 examples. It correctly flags real severities (e.g.
`lodash@4.17.4` → 10 known vulnerabilities, worst CRITICAL) and, in testing,
caught a real vulnerability in `express@4.19.2` — a version our old
hardcoded list would have called clean.

**Snapshot, not live — and deliberately so.** OSV's live query API
(`api.osv.dev`) needs network access the production API doesn't have (zero
egress by design, same reasoning as the Semgrep integration above). OSV also
publishes a bulk data export specifically for offline use, which is what
this is built from: `scripts/build-osv-db.js` processes an extracted copy of
[OSV's npm bulk export](https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip)
into a compact, indexed SQLite database (`src/scanner/osv-data/npm-vulnerabilities.db`,
~29MB, checked into the repo like the Semgrep ruleset) queried locally at
scan time. Real known gap: this is frozen at whatever date it was last
built — there's no refresh mechanism yet. Re-run the build script
periodically (or wire it into a scheduled job) to pick up new
vulnerabilities; there's no fixed cadence decided yet.

If the bundled database is missing, this degrades to a caution finding
rather than crashing the scan, same pattern as the Semgrep integration.

### Semgrep integration

The scanner shells out to [Semgrep](https://semgrep.dev) — real static
analysis, not more regex — against our own bundled, offline ruleset
(`src/scanner/semgrep-rules/nettle-js-rules.yaml`), covering patterns the
hand-rolled checks above don't: command injection (`exec` built from a
template literal), SQL injection (query built from a template literal),
inline hardcoded JWT secrets, disabled TLS certificate verification, and
wildcard CORS.

**Deliberately offline, not just for this sandbox.** Semgrep's `--config=auto`
mode fetches rules from Semgrep's registry over the network — but the
production API has zero internet egress by design (see `infra/README.md`).
Relying on a network-fetched ruleset would mean shipping a check that
silently can't run at all once deployed. Bundling our own rules file and
running fully offline works the same way in development, CI, and production.

**A real bug caught building this, worth knowing about**: Semgrep's version
check (`--enable-version-check`, on by default) also phones home on every
single invocation — and with the proxy/network blocked, that call doesn't
fail fast, it hangs for roughly 90 seconds before giving up. Left as
default, every single scan request would silently take an extra ~90s (or
outright time out) in production, for a check that has nothing to do with
the actual analysis. Fixed with `--disable-version-check --metrics=off`;
real invocations now take ~1-2s. If you ever see Semgrep scans mysteriously
slow again, this is the first thing to check.

If Semgrep isn't installed or fails to run for any reason, this degrades to
a caution finding rather than crashing the whole scan request — see
`src/scanner/semgrepScanner.ts`.

**Not yet run**: an actual `docker build` of the updated Dockerfile (which
now installs Python + pip + Semgrep in the runtime image) — no Docker daemon
in this sandbox, same limitation noted in `infra/README.md`'s validation
table. Build it yourself once before deploying.

## Accounts, billing, and the trust badge

Real accounts now gate project creation — `POST /api/projects` requires a
session, and a project is only visible to the user who owns it (see
`test/auth.test.ts`, `test/projects.routes.ts` ownership checks).

```bash
# sign up, get a bearer token
curl -X POST http://localhost:8080/api/auth/signup \
  -H "Content-Type: application/json" \
  -d '{"email":"you@example.com","password":"at least 8 characters"}'
# -> { "token": "...", "user": {...} }
```

Passwords are hashed with Node's built-in `scrypt` (no bcrypt/argon2
dependency needed) — see `src/auth/passwords.ts`. Sessions are opaque
random tokens in a `sessions` table (30-day expiry), not JWTs — simpler to
revoke (`POST /api/auth/logout` just deletes the row) and nothing to get
wrong cryptographically.

**Pricing & entitlements** (`src/billing/entitlements.ts`): three plans —
FREE ($0, 1 project, no real scans — control-library preview and sample
findings only), BUILD ($49/mo, 10 scans/billing-period, 3 projects, Fix
Center, scan history, 3 team members), PROTECT ($199/mo, unlimited/fair-use
scans and projects, continuous monitoring, live alerts, API access, 10 team
members). `entitlements.ts` is the single source of truth every route asks
(`canRunScan`, `canUseFixCenter`, `canUseContinuousMonitoring`, ...) rather
than hardcoding plan checks per-route. FREE is a real, capped dashboard
tier now, not a walled-off pre-payment state — see `billing/subscription.ts`'s
`requireSubscription` (BUILD+) and `requireProtect` (PROTECT-only) for the
two gate levels layered on top of plain `requireAuth`. Scan quota
enforcement (`billing/scanQuota.ts`) reserves each scan atomically via a
single `INSERT ... ON CONFLICT DO UPDATE ... RETURNING` against the same
`rate_limit_buckets` table the rate limiter uses, specifically so two
concurrent requests near the monthly limit can't both win the last slot —
see `test/scanQuota.test.ts` and `test/pricingEntitlements.test.ts` for
that race actually exercised, not just asserted. Organization-aware since
`billing/orgSubscription.ts`'s `resolveQuotaSubject`: a project owned by an
organization that's actively subscribed itself draws from that
organization's own shared monthly pool (every member's scans count against
ONE limit, not one each — `reserveOrgScanSlot`/`getOrgQuotaState`, same
atomicity guarantee, its own `rate_limit_buckets` namespace), falling back
to the triggering account's personal quota otherwise — see
`test/organizationScanQuota.test.ts`.

**Billing** (`src/routes/billing.routes.ts`) is real Stripe integration code
— `POST /api/billing/checkout-session` creates a real Checkout Session,
`POST /api/billing/webhook` verifies Stripe's signature and activates the
plan on `checkout.session.completed`. **Not validated against a live Stripe
account** — no test-mode keys available in this sandbox — but the signature
verification itself is tested for real: `test/billing.test.ts` constructs a
genuinely, correctly HMAC-signed webhook payload using Stripe's actual
signing scheme (not a mock) and confirms the handler updates the user's
plan. Set `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`, `STRIPE_PRICE_BUILD`,
`STRIPE_PRICE_PROTECT` to actually use this. Note in `src/index.ts`: the
webhook route is mounted *before* `express.json()` — Stripe signs the exact
raw request bytes, and parsing the body first would break every real
signature check.

**Trust badge** (`src/routes/badge.routes.ts`, public, no auth by design —
it's embedded with a plain `<img>` tag on a customer's own site, which can't
send an Authorization header): `GET /api/projects/:id/badge.svg` and
`/badge.json` reflect a real read of project state, not a static image —
the latest Tier 1 scan's score plus whether Tier 2 has caught anything
critical in the last 48 hours. Either one being bad makes the badge bad; see
`src/patrol/badge.ts` and `test/badge.test.ts` for all four states
(protected/caution/critical/unknown).

## Tier 2 — "Open Water" continuous monitoring

Real and tested, not a mockup either. A customer creates a project, gets an
API key, drops one middleware line into their own app, and Nettle watches
their live traffic for attack patterns.

```bash
# 1. create a project (requires the bearer token from signup/login above)
curl -X POST http://localhost:8080/api/projects \
  -H "Content-Type: application/json" -H "Authorization: Bearer <token>" \
  -d '{"name":"My App"}'
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

**Storage**: `node:sqlite` (built into Node 22, experimental) — `users`,
`sessions`, `projects`, `events`, `alerts`, and now `scans` (Tier 1 results
persisted when a scan includes a project's API key, so the badge and
dashboard have real history to show). Real persistence with zero extra
infrastructure — the right tradeoff until there's actual concurrent
multi-tenant write volume to justify running RDS.

## Architecture

See the full system diagram (this Tier 1 piece plus the Tier 2 "Open Water"
continuous monitoring, trust badge, and platform core) in the published
artifact from the design pass. Tier 2 is no longer "doesn't exist yet" —
the diagram's boxes for intake -> event queue -> detection -> alerting are
now real code, including the queue between intake and detection (an
in-process one — see known gaps for what that does and doesn't cover).

## Known gaps

**Tier 1 sandboxing — now real in production, with two disclosed gaps.**
A project-tied scan (`scanner/scanQueue.ts`) dispatches to
`scanner/isolatedExecution.ts`, which runs the scan inside its own ECS
Fargate task (`infra/lib/scan-worker-stack.ts`) — a separate process,
container, filesystem, and network path from the API, in the VPC's
isolated subnets (no internet route at all), with a task IAM role that has
exactly two scoped S3 permissions and nothing else (no Secrets Manager, no
database, no Stripe/SES). Extraction itself still happens on the API host
before the workspace is handed off (it's the cheap, security-critical step
— symlink/decompression-bomb/path-traversal checks in
`scanner/safeExtraction.ts`, unchanged — that must reject a bad archive
before anything is queued), but the actual analysis of the untrusted
content runs isolated, closing the gap this note used to describe.
Two disclosed limits: (1) this is production-only — the in-process
fallback (same-process, same-host execution this note originally warned
about) is what still runs locally, in tests, and on the staging App Runner
service, since a Fargate task definition is pinned to one image tag and
staging wasn't given its own; (2) `isIsolatedExecutionConfigured()` is the
switch, so any environment that deploys `Nettle-Api` without also
deploying `Nettle-ScanWorker` (or that predates this change) silently
falls back to in-process execution rather than failing — intentional for
backward compatibility, but worth knowing if isolation is assumed present
everywhere `Nettle-Api` is.

**Billing is untested against a live Stripe account.** The webhook's
signature verification is genuinely tested (see above), but the actual
Checkout Session creation flow, real webhook delivery, and plan-gating
behavior have never run against real Stripe test-mode keys — there are
none in this sandbox. Get a Stripe test account, set the four env vars
above, and run through a real checkout once before trusting this in
production.

**No password reset flow, and no rate limiting on the auth endpoints.**
Sign up and log in only — worth closing both gaps before this is reachable
by real, hostile internet traffic (an unrate-limited login endpoint is a
brute-force target in its own right).

**Tier 2's queue is in-process, not a durable/distributed one.**
`POST /api/events` used to run detection inline on the request itself, so a
burst of traffic to a monitored app became a burst of synchronous SQLite
work blocking the ingestion endpoint's own response. That's fixed:
`patrol/detectionQueue.ts` decouples detection from the request — the
response returns as soon as the event is durably recorded, and detection
for that event runs afterward, off the critical path, one job at a time (see
that file's comment for why serial rather than concurrent). What this
*doesn't* give you is durability across a restart (an enqueued-but-not-yet-
processed job is only in memory — the event itself is safe, already written
to `events` before it's enqueued, so a lost job only means a missed
detection pass for that one event) or fan-out across more than one API
instance. Both of those need a real queue (Kinesis/SQS, per the AWS
architecture notes) — still deliberately not added speculatively, since
`node:sqlite` being single-instance today (see below) means a durable
cross-instance queue wouldn't change anything until that's solved too.

**`node:sqlite` is single-file, single-instance.** It doesn't work if the
API ever runs as more than one container (App Runner today runs one). That's
the actual trigger for migrating to RDS/Aurora — not a fixed timeline, a
specific condition to watch for.

**No alert delivery beyond the API.** Alerts are queryable via
`GET /api/projects/:id/alerts` but nothing pushes them anywhere yet — no
email, Slack, or SMS. That's the next real piece of Tier 2 to build.
