# Nettle — Pre-AWS Production Status

Final deliverable of the pre-AWS production readiness hardening pass. Every
item below is labeled **VERIFIED** / **PARTIALLY VERIFIED** / **NOT
VERIFIED** / **NOT DEPLOYED**, states what was actually changed, which
files, what tests were run, and what remains unverified. "Production
ready" is not used anywhere in this document unless the evidence directly
supports it for that specific item — most items do not qualify for that
phrase, because AWS and Stripe live verification haven't happened yet.

Companion documents: `PRE_AWS_AUDIT.md` (the Phase 1 read-only audit this
pass started from), `AWS_GITHUB_DEPLOYMENT.md` (the deployment runbook).

---

## 1. FIXED BEFORE AWS

Code-level fixes, each with real tests, that don't depend on AWS or Stripe
existing to be true today.

### 1.1 Fail-open webhook signing secret — **VERIFIED**
`NETTLE_WEBHOOK_SECRET || 'nettle-webhook'` in `backend/src/integrations/webhooks.ts`
removed. Signing now throws `MissingWebhookSecretError` with no default.
Files: `backend/src/integrations/webhooks.ts`, plus two existing tests
(`phase14-integration.test.ts`, `scanCompletedWebhook.test.ts`) updated to
set an explicit test secret instead of relying on the removed fallback.
Tests: dedicated fail-closed assertion + all existing webhook delivery
tests pass. Nothing unverified — this is a pure code-level guarantee.

### 1.2 Fabricated ML confidence score — **VERIFIED**
`mlAnalytics.ts`'s `isolationScore = Math.random()` replaced with the
codebase's own (previously unused) `IsolationForest` implementation,
trained on each project's real recent event history and cached per
project (retrained at most every 30 minutes). Returns no signal (not a
fake one) when there's too little history to train on.
Files: `backend/src/patrol/mlAnalytics.ts`. Tests: existing 21-test ML
suite passes unmodified; the training/scoring path is exercised by
`phase13-ml-analytics.test.ts`'s Isolation Forest tests.

### 1.3 OSV database freshness — **VERIFIED**
`build-osv-db.js` now writes a `metadata` table (generated_at,
record_count, source). `getOSVDatabaseFreshness()` reads it and computes
real CURRENT/STALE/UNKNOWN status; `scanOSVVulnerabilities()` surfaces it
in every scan report. The currently-*shipped* `.db` file predates this
table and correctly reports UNKNOWN (not fabricated) until it's rebuilt.
Files: `backend/scripts/build-osv-db.js`, `backend/src/scanner/osvVulnerabilities.ts`.
Tests: 8 dedicated tests (`osvFreshness.test.ts`), including against the
real bundled database file. Unverified: freshness of the actual bundled
`.db` — it will report UNKNOWN until someone runs `build-osv-db.js` again
against a fresh OSV export, which needs network access this environment
doesn't have.

### 1.4 False "PASS" claims in the internal audit report — **VERIFIED**
`phase5-final-audit.ts`'s C-2 (worker isolation) and H-5 (OSV freshness,
before 1.3 above) entries claimed PASS on code that existed but wasn't
wired into the real scan pipeline. C-2 corrected to FAIL with evidence
(workerIsolation.ts is unwired, its task handler is a stub); H-5 corrected
back to PASS once 1.3 made the underlying claim true. The unqualified
"production-ready" line was removed from the report's conclusion.
Files: `backend/src/audit/phase5-final-audit.ts`. Tests: the test that had
encoded the false claim as a required invariant now asserts the honest
state instead (`phase5-final-audit.test.ts`).

### 1.5 Whole-scan timeout — **VERIFIED**
A top-level timeout (default 10 min, `NETTLE_SCAN_JOB_TIMEOUT_MS`) now
wraps each queued scan job on top of the scanner's existing per-step
timeouts. On timeout: the worker is terminated, the job is marked failed
with which stage was running, and its temp directory (reported back via a
new worker message) is cleaned up — the same cleanup now also applies to
manual cancellation, which previously leaked temp dirs on `.terminate()`.
Files: `backend/src/jobs/scanJobs.ts`, `backend/src/scanner/scanWorker.ts`.
Tests: all 15 existing scan-job tests pass.

### 1.6 Stripe Customer Portal, payment-failure handling, webhook idempotency — **VERIFIED** (code) / see §3 for live Stripe
- `POST /api/billing/portal-session` — real Stripe Billing Portal session creation.
- `invoice.payment_failed` handler — marks the user `past_due` (an already-recognized status), records history in a new `payment_failures` table, emails the customer.
- `stripe_events` table — every webhook event id is recorded; a redelivery is recognized and skipped.
- Frontend: a Billing card in Settings with a real "Manage billing" button and a past-due warning.
Files: `backend/src/routes/billing.routes.ts`, `backend/src/billing/stripeEvents.ts`,
`backend/src/db/index.ts`, `frontend/src/pages/SettingsPage.tsx`, `frontend/src/api.ts`.
Tests: 10 tests in `billing.test.ts` — checkout, portal, payment-failure
handling, and redelivery idempotency, all against real HMAC-signed webhook
payloads (Stripe's actual signing scheme, not a mock).

### 1.7 Production email verification — **VERIFIED**
Reuses the existing password-reset token pattern exactly (32-byte random
hex token, 24h expiry, single-use, existing SMTP integration). Signup
sends a real verification email; `POST /api/auth/verify-email` and
`POST /api/auth/resend-verification` (rate-limited to 5/hour, separate
from the general auth rate limit). Deliberately not access-gating —
verification status is tracked and surfaced (a Settings banner + resend
button), but existing routes aren't blocked behind it, which would have
been a materially larger behavior change than "add verification."
Files: `backend/src/auth/users.ts`, `backend/src/routes/auth.routes.ts`,
`backend/src/db/index.ts`, `frontend/src/pages/VerifyEmailPage.tsx`,
`frontend/src/pages/SettingsPage.tsx`. Tests: 4 backend tests against a
real local SMTP receiver (token extraction from the actual email body,
including a quoted-printable decoding fix needed to read it correctly),
3 frontend tests.

### 1.8 Data retention with a scheduled-trigger endpoint — **VERIFIED** (code) / see §4 for the actual schedule
Configurable per-category retention windows (events 90d, alerts 180d,
scans 365d, webhook records 30d — all env-overridable, 0 disables a
category) with real `DELETE ... WHERE <ts> < datetime('now', ?)` queries.
Never touches users/projects/sessions/payment records. Reuses the exact
CRON_SECRET-gated pattern the existing digest trigger already used.
Files: `backend/src/patrol/retention.ts`, `backend/src/routes/internal.routes.ts`.
Tests: 6 tests inserting real rows with real timestamps and asserting
exactly what survives vs. gets deleted, including an explicit check that
account/subscription data is provably untouched.

### 1.9 Observability: structured logging + metrics + real health check — **VERIFIED**
JSON logging to stdout (real CloudWatch-Logs-ready format the moment this
is on App Runner — no claim CloudWatch itself is operational). In-process
counters/duration stats for requests, errors, scan duration/failures, auth
failures, rate limiting, Stripe webhook failures, webhook/notification
delivery failures, alerts generated. `GET /health` upgraded from a static
`{status:"ok"}` to a real DB connectivity check + uptime + live scan queue
depth, with no secrets or per-customer data.
Files: `backend/src/observability/{logger,metrics}.ts`, wired into
`index.ts`, `scanJobs.ts`, `rateLimit.ts`, `billing.routes.ts`,
`webhooks.ts`, `alerts.ts`. Tests: 4 metrics unit tests, a dedicated health
test asserting the response contains no string matching "secret",
"password", "token", "key", or "database_url".

### 1.10 Minimal admin/operator visibility — **VERIFIED**
`users.is_admin`, granted only by `syncAdminEmails()` reading
`NETTLE_ADMIN_EMAILS` at every process start — no API/UI path can grant
it, and removing an email from the list actually revokes access on next
restart. `GET /api/admin/{overview,metrics,failed-scans,webhook-failures,notification-failures}`,
gated by a fail-closed `requireAdmin` middleware.
Files: `backend/src/routes/admin.routes.ts`, `backend/src/auth/middleware.ts`,
`backend/src/auth/users.ts`. Tests: 8 tests including a real declarative
grant-then-revoke cycle and a check that responses never contain a
password hash or session token.

### 1.11 Tier 2 alert delivery retry + failure tracking + recommended actions — **VERIFIED**
Direct email/SMS notification delivery (`notifyChannels`) previously had
no retry and no persisted failure record (unlike outbound webhooks, which
already had both). Now retries with backoff (2 retries) and persists every
outcome to a new `notification_deliveries` table. Every detection rule's
alert message now ends with a concrete recommended action.
Files: `backend/src/patrol/notificationChannels.ts`, `backend/src/patrol/detection.ts`,
`backend/src/db/index.ts`. Tests: 2 new tests against a real local
SMTP/HTTP stub verifying real retry timing and persisted outcomes, plus
all 5 pre-existing notification-channel tests pass unmodified.
Verification of the pre-existing severity/cooldown/deduplication behavior
(not new this pass, but re-confirmed): real — `ALERT_COOLDOWN_SECONDS =
300` gates every rule, so a sustained attack produces one alert per
5-minute window, not one per request.

### 1.12 Frontend: fail loud on missing API URL — **VERIFIED**
Production builds (`import.meta.env.PROD`) now throw a clear error if
`VITE_API_BASE_URL` wasn't set at build time. Verified with two real
`vite build` runs (with and without the var) — an earlier version put the
check as a bare top-level throw in `api.ts` and a real build confirmed it
broke: Rolldown (Vite's bundler) tree-shook the module's later exports
away, treating the throw as proof they were unreachable. Moved into a
function called from `main.tsx` instead; confirmed fixed with both builds
plus a grep of the built bundle for the error string.
Files: `frontend/src/api.ts`, `frontend/src/main.tsx`.

### 1.13 CORS restricted from wide-open — **VERIFIED**
`CORS_ALLOWED_ORIGINS` (or, falling back, the existing `FRONTEND_URL`)
now scopes the API's CORS policy. Unset — local dev by default — behaves
identically to before (reflects any origin), so no dev workflow changed.
Files: `backend/src/index.ts`, `backend/src/corsConfig.ts`. Tests: 4 tests
including a real cross-origin `fetch()` confirming the `Access-Control-
Allow-Origin` header only matches an allowed origin.

### 1.14 PostgreSQL-readiness infrastructure — **VERIFIED** (infra) / **NOT WIRED** (app)
Real schema (25 tables translated from the live SQLite schema), a real
connection pool, and a real migration runner — verified against an actual
local PostgreSQL 16 server: the migration creates every table, foreign
keys are genuinely enforced, a real insert/select round trip works.
**Not consumed by the application** — `src/db/index.ts` still exclusively
reads/writes SQLite. This is a deliberate, explicit decision (see
"Remaining Blockers" and `backend/src/db/postgres/README.md`): `node:sqlite`
is synchronous across 171 call sites; `pg` is async; converting is a large,
separate, deferred piece of work.
Files: `backend/src/db/postgres/*`. Tests: 6 tests against a real local
Postgres instance (skips cleanly with a clear message if none is
reachable — CI doesn't currently provision one).

---

## 2. PREPARED FOR AWS BUT NOT DEPLOYED

Real, `cdk synth`-verified CDK code. **None of it has been applied to a
real AWS account** — no AWS account exists in this environment, by design
(see the security constraints in `AWS_GITHUB_DEPLOYMENT.md`).

| Item | Status | Evidence |
|---|---|---|
| VPC with NAT egress (was zero-egress; now needs egress for Stripe/SMTP/Twilio/webhooks/git/scan-target calls this app genuinely makes) | **NOT DEPLOYED** | `cdk synth Nettle-Network` succeeds |
| App Runner service pulling secrets from Secrets Manager at startup | **NOT DEPLOYED** | `cdk synth Nettle-Api` succeeds; inspected the synthesized template directly — secret values are real ARN references (`arn:...:secret:nettle/app-secrets:<key>::`), never literals |
| RDS PostgreSQL (optional, not in the default deploy) | **NOT DEPLOYED** | `cdk synth Nettle-Database` succeeds; inspected the template — the master password is a `{{resolve:secretsmanager:...}}` dynamic reference, never a literal |
| S3 + CloudFront frontend hosting | **NOT DEPLOYED** | `cdk synth Nettle-Frontend` succeeds; private bucket (no public access), Origin Access Control, SPA routing (403/404 → index.html) |
| Extended GitHub OIDC deploy role (S3 sync + CloudFront invalidation, still no `cdk deploy` permission) | **NOT DEPLOYED** | `cdk synth Nettle-CI` succeeds; caught and fixed a real bug this way — an ARN that serialized the literal word "undefined" for the account id in environment-agnostic synthesis |
| `.github/workflows/frontend-deploy.yml` | **NOT VERIFIED** | Written, mirrors the existing verified `backend-deploy.yml` pattern; never actually run — no AWS credentials or GitHub environment configured in this session to run it against |
| Route53 / custom domain | **NOT DEPLOYED, NOT EVEN WRITTEN** | Honestly not prepared this pass — see `AWS_GITHUB_DEPLOYMENT.md` §11 |
| EventBridge (or equivalent) schedule calling the digest/retention-cleanup endpoints | **NOT DEPLOYED, NOT WRITTEN** | The endpoints exist and are tested (§1.8); nothing yet calls them on a schedule — see `AWS_GITHUB_DEPLOYMENT.md` §17.7 |

---

## 3. REQUIRES STRIPE TEST/LIVE VERIFICATION

- Real Stripe checkout session completion end-to-end — code path tested
  with hand-signed webhook payloads (real HMAC verification), never against
  a real Stripe test-mode account.
- Real Customer Portal session creation/redirect — same: code is real and
  tested for auth/error handling, never exercised against Stripe's actual
  API.
- Real `invoice.payment_failed` delivery from Stripe — the handler is
  tested against a hand-constructed, correctly-signed payload matching
  Stripe's real event shape; never received a genuine event from Stripe.
- Live-mode keys/prices/webhook — not configured or tested at all; test
  mode and live mode are separate, sequential steps (see
  `AWS_GITHUB_DEPLOYMENT.md` §12).

All of the above are marked **NOT VERIFIED** against real Stripe — no test
or live Stripe credentials exist in this environment, by design.

---

## 4. REQUIRES REAL AWS VERIFICATION

- Every item in §2's table — CDK synthesis being valid CloudFormation is
  real evidence the code is *correct*; it is not evidence anything has
  been *deployed* or *works* against a real account.
- App Runner's health check actually passing against a real running
  container.
- The App Runner instance role's `secretsmanager:GetSecretValue`
  permission actually resolving real secret values at container startup.
- RDS actually being reachable from the API's VPC connector once both are
  real.
- CloudFront actually serving the frontend and its SPA-routing error
  responses actually working for a direct load of a client-side route.
- The GitHub OIDC role actually being assumable by a real GitHub Actions
  run (the trust policy is correct by inspection; it's never been
  exercised).
- NAT gateway egress actually reaching Stripe/SMTP/Twilio/arbitrary
  webhook URLs/git hosts/scan targets from inside the VPC.

All items in this section are **NOT DEPLOYED** / **NOT VERIFIED** — this
category exists specifically so those two words aren't quietly dropped
once AWS access exists; re-verify explicitly against the real thing, don't
assume `cdk synth` succeeding was the finish line.

---

## 5. DEFERRED

Explicitly considered and not built, with the reasoning, per Phase 8's
"do not overbuild" instruction:

- **Full SQLite → Postgres call-site conversion** (171 `db.prepare()`
  sites, async rewrite cascading through most route handlers) — see §1.14.
  Deliberately deferred per an explicit decision made mid-pass: build the
  real infrastructure now, convert later as its own scoped effort.
- **Escalation rules** for Tier 2 alerts (re-notify with increasing
  urgency if an incident continues) — considered during Phase 3; there was
  no clear spec beyond the phrase itself, and a shallow version would have
  been exactly the kind of premature complexity this pass was supposed to
  avoid.
- **Route53/custom domain, App Runner custom domain association** — see §2.
- SSO, enterprise RBAC, complex teams, advanced global search, elaborate
  PDF generation, highly customizable badges, enterprise analytics,
  unnecessary microservices/ML infrastructure — confirmed via a repo-wide
  search that none of this was accidentally built; Phase 8's list required
  no action beyond not building it.

---

## 6. REMAINING BLOCKERS

Ranked by what actually blocks a real launch, not by effort:

1. **No AWS account exists.** Every item in §2 is written and locally
   verified but has never touched a real account. This is the single
   largest remaining gap — nothing in §2/§4 can move to VERIFIED without it.
2. **No Stripe test-mode account is connected.** §3's items can't move
   past "tested against a hand-signed payload" without one.
3. **SQLite is still the only thing the app actually reads/writes.** Real
   production deployment with more than one App Runner instance is unsafe
   until either the Postgres conversion (§1.14/§5) happens, or the service
   stays pinned to `maxSize: 1` indefinitely (which the CDK already
   enforces — see `infra/lib/api-stack.ts`'s comment — but is a real
   scaling ceiling, not a hidden one).
4. **No scheduled trigger exists yet** for the digest or retention-cleanup
   endpoints — they're real and tested, but nothing calls them on a
   recurring basis (§2's table, `AWS_GITHUB_DEPLOYMENT.md` §17.7).
5. **No custom domain/DNS is prepared** — deploying today would leave the
   app reachable only at raw App Runner/CloudFront URLs.
6. **Docker image build has never been run in this environment** (no
   Docker daemon available in this sandbox) — the Dockerfile is real and
   was written/verified in earlier work this engagement, but a fresh build
   of the current `backend/` hasn't been executed here.

None of these are code defects — every one is "needs a real account /
real infrastructure to take the next step," which is the expected state
for a pass that was explicitly constrained to never touch real AWS or
Stripe credentials.

---

## Test evidence (this pass, cumulative)

- Backend: all 751 tests pass via `node --test` (`npm test`) — confirmed
  with a single combined run of all 87 test files together (no
  concurrency/shared-state issues between suites), including the
  real-Postgres suite (skips cleanly without a reachable database) and the
  real-network Stripe integration suite (`phase14-integration.test.ts`,
  ~4-minute real-network latency).
- Frontend: 67 tests passing via `vitest run` (`npm test`).
- Both `npm run build` (backend `tsc` + asset copy, frontend `tsc -b && vite build`)
  succeed.
- `cd infra && npx cdk synth` succeeds for all five stacks.
- `tsc --noEmit` clean across `backend/`, `frontend/`, and `infra/`.

No test result in this document or its companions was claimed without
actually running it.
