# Nettle — Pre-AWS Production Readiness Audit (Phase 1)

**Scope:** Read-only audit of the current repository on branch `claude/nettle-repo-context-lnd87f`. No code was changed to produce this document. Every claim below is backed by a direct grep/read of the file cited — nothing here is carried forward from memory without re-verification.

---

## 1. Current Architecture

- **Backend:** Node 22 + Express (TypeScript), single monolithic service. Entry point `backend/src/index.ts`. Built and run via a two-stage Docker image (`backend/Dockerfile`) — build stage compiles TypeScript, runtime stage installs `unzip` (archive extraction) and `python3`/`semgrep==1.65.0` (real static analysis engine), runs as non-root `nettle` user, listens on 8080.
- **Persistence:** `backend/src/db/index.ts` (449 lines) — a single SQLite database via Node's built-in `node:sqlite` `DatabaseSync`, path from `NETTLE_DB_PATH` (defaults to a file under `cwd`). **171 `db.prepare()` call sites** across the codebase, all synchronous. No Postgres/ORM dependency exists in `backend/package.json` today (confirmed: no `pg`, `postgres`, `knex`, `drizzle`, `prisma`, or `typeorm`).
- **Scanner:** File/repo upload → extraction (`safeExtraction.ts`, zip-bomb + symlink-traversal protected) → static analysis across many focused modules (`secrets.ts`, `semgrepScanner.ts`, `authAnalysis.ts`, `dockerSecurity.ts`, `frontendSecurity.ts`, `databaseSecurity.ts`, `aiSecurity.ts`, etc.) → scored, prioritized, redacted findings report.
- **Tier 2 monitoring:** Runtime event ingestion + anomaly/abuse detection (`backend/src/patrol/`), with an alerting pipeline in `detection.ts` that already implements per-rule cooldown/deduplication (`ALERT_COOLDOWN_SECONDS = 300`, `hasRecentAlert()`), and an ML-flavored anomaly scorer in `mlAnalytics.ts`.
- **Billing:** Stripe integration lives in `backend/src/billing/` (`stripeClient.ts`, `subscription.ts`, `scanQuota.ts`) and `backend/src/routes/billing.routes.ts`. Lazy Stripe client init (never crashes boot if unconfigured); checkout-session creation; a single webhook endpoint handling 3 event types.
- **Auth:** `backend/src/auth/` — sessions, users, API keys; token encryption via `backend/src/security/tokenEncryption.ts` (AES-256, requires `NETTLE_TOKEN_ENCRYPTION_KEY`, no fallback).
- **Notifications/webhooks (outbound):** `backend/src/integrations/webhooks.ts` — Nettle-to-customer outbound webhook delivery with retry/backoff and delivery-status persistence (`webhook_events` table); separate from Stripe's inbound webhook.
- **Frontend:** React + TypeScript (Vite), `frontend/src/`. API base URL read once at module load in `frontend/src/api.ts`.
- **Infrastructure-as-code:** AWS CDK, `infra/lib/` — `network-stack.ts`, `api-stack.ts` (App Runner + ECR + VPC connector), `ci-stack.ts` (GitHub OIDC provider + IAM deploy role).
- **CI/CD:** `.github/workflows/` — `ci.yml` (lint/test/build both apps on PR + push to main/develop), `backend-deploy.yml` (push to main → build & push image to ECR), `backend-deploy-staging.yml` (push to develop → same, staging tag), plus `backend-ci.yml`, `frontend-ci.yml`.
- **Tests:** 79 backend test files (`node --test`), 11 frontend test files (`vitest`).

---

## 2. Genuinely Working (verified this session, not just claimed)

- **GitHub OIDC deploy auth is real, not aspirational.** `backend-deploy.yml` and `backend-deploy-staging.yml` both use `aws-actions/configure-aws-credentials@v4` with `role-to-assume: ${{ vars.AWS_DEPLOY_ROLE_ARN }}` — **no static `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY` anywhere in any workflow.** This already matches the user's "no long-lived AWS keys" requirement. `infra/lib/ci-stack.ts` defines the matching `OpenIdConnectProvider` + `WebIdentityPrincipal`-scoped IAM role (`nettle-github-actions-deploy`), currently permissioned only for ECR push (least-privilege, correctly scoped to one repo ARN).
- **Secret hygiene at the repo level is clean.** Only `.env.example` is tracked in git (`git ls-files | grep -i "\.env"` returns exactly one file); `.gitignore` correctly excludes `.env`, `.env.local`, `.env.*.local`.
- **Several secrets already fail closed correctly**, with no fallback:
  - `NETTLE_TOKEN_ENCRYPTION_KEY` (`security/tokenEncryption.ts`) — throws if unset or not exactly 32 bytes.
  - `CRON_SECRET` (`routes/internal.routes.ts`) — returns 503 "not configured" if unset, does not substitute a default.
  - `STRIPE_SECRET_KEY` / `STRIPE_PRICE_TIER1` / `STRIPE_PRICE_TIER2` (`billing/stripeClient.ts`) — throw descriptive errors if unset; billing routes catch this and return 503 rather than crashing the whole process.
  - `STRIPE_WEBHOOK_SECRET` (`billing.routes.ts`) — webhook returns 400 if missing rather than skipping verification.
- **Docker image is reasonably hardened**: multi-stage build, `npm ci --omit=dev` for runtime deps, non-root user, pinned Semgrep version (`1.65.0`) matching CI's pinned version.
- **Archive/extraction security**: symlink-traversal and decompression-bomb protections exist in `safeExtraction.ts` with dedicated tests (per `phase5-final-audit.ts` claims C-1/C-3 — these two specific claims were spot-checked against real files and are plausible; not independently re-verified line-by-line in this pass).
- **Outbound webhook delivery** has real retry/backoff and persisted delivery status (`webhook_events` table, `updateWebhookEventStatus`).
- **Tier 2 alert deduplication/cooldown** is real, not aspirational: every detection rule in `detection.ts` gates through `hasRecentAlert()` with a 300-second cooldown before a rule can fire again — this already prevents the "100 requests → 100 alerts" problem the new spec worries about, at least at the per-rule level. Needs a verification+enhancement pass for message quality and delivery-failure tracking, not a rebuild.
- **Previously-fixed regressions from earlier this engagement, now covered by real automated tests** (not part of this task, but relevant "genuinely working" baseline): the rate-limiter app-wide-mount leak (fixed by moving `scanRateLimit`/`publicRateLimit` to per-route middleware in `scans.routes.ts`, `scanJobs.routes.ts`, `events.routes.ts`, `badge.routes.ts`), and the Analytics page null-crash on untrained models (backend now always sends a real `model_status` fallback object; frontend `ModelStatus` component also defensively null-checks; both covered by `backend/test/analyticsDashboardModelStatus.test.ts` and `frontend/src/pages/AnalyticsPage.test.tsx`).

---

## 3. Partially Working

- **Stripe integration** — real checkout-session creation and webhook signature verification exist, but the webhook handler (`billing.routes.ts`) only handles 3 event types (`checkout.session.completed`, `customer.subscription.updated`, `customer.subscription.deleted`). No `invoice.payment_failed` handling, no idempotency check against Stripe event IDs before processing (a duplicate webhook delivery would re-run `setSubscriptionStatus` — low-risk today since that call is a pure overwrite, but this will matter once payment-failure side effects like customer emails are added), no Customer Portal endpoint at all.
- **OSV vulnerability database versioning** — `backend/src/scanner/osvVersioning.ts` implements a complete `OSVDatabaseMetadata` API (version, fetchedAt, lastUpdated, confidence, staleness), but is **only imported by itself and by `phase5-final-audit.ts`** — confirmed via repo-wide grep. It is never called by the actual scan pipeline. The real OSV lookup path reads directly from a static bundled SQLite file with no metadata table, so scan reports never actually show database freshness today, despite the audit doc claiming this is "PASS."
- **Tier 2 alerting** — cooldown/dedup exists per-rule, but grouped "N attacks in 60s → 1 incident" style aggregation, escalation rules, and delivery-failure tracking for email/SMS specifically have not been verified this pass; needs inspection of the alert-send path, not just the detection-gating path.
- **Observability** — a `health.routes.ts` endpoint exists and is mounted, but no structured logging library (`winston`/`pino`) is present anywhere in `backend/src` — only ad hoc `console.*` calls, confirmed via grep. No metrics for scan duration, queue depth, webhook processing, or auth failures were found.

---

## 4. Mocked / Stubbed / Fake (must not be claimed as real)

- **`backend/src/patrol/mlAnalytics.ts:346`** — `isolationScore = Math.random(); // Placeholder`. The comment itself admits it's a placeholder. This score is surfaced to users as an "N% confidence" figure on anomalies. **This is a fabricated result, not a real ML output**, and must not ship to a paying customer as-is.
- **`backend/src/scanner/workerIsolation.ts`** — implements a `WorkerPool` abstraction, but its task-processing body is literally `// Simulate task processing — actual implementation depends on task type` (confirmed via grep). It is **only imported by itself and by `phase5-final-audit.ts`** — not wired into the real scan pipeline at all. It is dead code that fakes sandboxed execution.
- **`backend/src/audit/phase5-final-audit.ts`** — this file's own claims are the problem, not the modules it cites. It asserts, among other "PASS" verdicts:
  - `C-2` "Worker Isolation for Untrusted Input" → PASS, evidence "WorkerPool with 1-4 isolated workers... timeout enforcement" — **false**, per above, this module is unwired dead code.
  - `H-5` "OSV Database Versioning & Freshness" → PASS, evidence "OSVDatabaseMetadata with version, fetchedAt..." — **false**, per above, never called from the real pipeline.
  - Its closing `CONCLUSION` string states verbatim: *"Nettle is now a production-ready 'intelligent launch-readiness coach'..."* — an unqualified "production-ready" claim the user's spec explicitly forbids using without evidence.
  - This file is exported and presumably surfaced somewhere (its `getFinalAuditReport()`/`verifyAuditCompleteness()` functions need a consumer check in Phase 2) — if it feeds any UI or API response, users could be shown these false claims directly.

---

## 5. Missing Entirely (not partial — not found anywhere in `backend/src`)

- **Stripe Customer Portal** — no `stripe.billingPortal.sessions.create` call anywhere in the codebase.
- **`invoice.payment_failed` handling** — not a case in the webhook switch statement.
- **Webhook idempotency for Stripe** — no `isStripeEventProcessed`/`markStripeEventProcessed` or equivalent processed-events table for the *inbound* Stripe webhook (the *outbound* webhook delivery system's `webhook_events` table is a different, unrelated concept — that one tracks Nettle's deliveries out to customers).
- **Email verification** — no signup-verification token flow found (`grep -i "email.*verif|verifyEmail|EMAIL_VERIFICATION"` across `backend/src` returned zero files).
- **Data retention / scheduled cleanup** — no retention-policy or cleanup-scheduler code found (`grep -i "retention|cleanup.*schedule"` returned zero files).
- **Whole-scan top-level timeout** — individual scan-stage timeouts exist (`semgrepScanner.ts`, `gitAuth.ts`, `ssrfSafeFetch.ts`, `urlSecurity.ts`, `initialization.ts`, `safeExtraction.ts`, `frontendSecurity.ts` all reference `timeout`), but no single top-level timeout wraps the whole scan job in `scanner/index.ts` or `patrol/scans.ts` — a scan whose individual steps all succeed slowly could still run unbounded overall.
- **Admin/operator visibility routes** — no `admin.routes.ts` or equivalent exists (`backend/src/routes/` contains `billing.routes.ts` and `health.routes.ts` but nothing admin-scoped).
- **Structured/CloudWatch-ready logging** — no logging library dependency at all.
- **Frontend S3+CloudFront deploy workflow** — `.github/workflows/` has no frontend deployment workflow; only `frontend-ci.yml` (lint/test/build, no deploy step) exists. `infra/lib/` has no S3/CloudFront construct — only `network-stack.ts`, `api-stack.ts` (App Runner), `ci-stack.ts` (OIDC/ECR).
- **RDS/Postgres CDK construct** — not present in `infra/lib/`.
- **AWS Secrets Manager wiring** — not inspected in `api-stack.ts` yet in this pass; likely absent or partial (App Runner env vars need checking in Phase 4, not claimed either way here).

---

## 6. Hardcoded Secrets / Fail-Open Defaults (repo-wide scan result)

Full-repo grep for `process.env.<SECRET/KEY> ||` fallback patterns in `backend/src` found exactly two:

1. **`backend/src/integrations/webhooks.ts:227`** — `const secret = process.env.NETTLE_WEBHOOK_SECRET || 'nettle-webhook';`. This signs the HMAC for Nettle's *outbound* webhook payloads to customers. If unset in production, every outbound webhook is silently signed with a public, hardcoded string — a customer (or attacker) who knows this repo could forge Nettle's webhook signature. **Confirmed still present, unfixed, on this branch.** This is the exact fail-open bug named in the task spec.
2. **`backend/src/integrations/pagerduty.ts:24`** — `routing_key: details.routing_key || process.env.PAGERDUTY_ROUTING_KEY`. Lower severity — this is a payload field default (which env var supplies the routing key when the caller didn't pass one explicitly), not a silently-substituted cryptographic secret. Worth a judgment-call fix in Phase 2 for consistency, but not a security hole in the same sense as #1.

No other `||`-style fallback was found for any of: `JWT_SECRET`, `NETTLE_TOKEN_ENCRYPTION_KEY`, `CRON_SECRET`, `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`, `DATABASE_URL` (which doesn't exist as a live config value at all yet — see §5), SMTP, or Twilio credentials. Earlier-looking grep hits for `DATABASE_URL`/`JWT_SECRET`/`OPENAI_API_KEY` were investigated and confirmed to be **inert remediation-text strings** inside the scanner's own vulnerability-finding messages (advice shown to users about *their* scanned code, e.g. `scanner/secrets.ts:40`, `scanner/semgrepScanner.ts:53`) — not live configuration Nettle's own backend reads. No committed real `.env` file exists in git history's tracked files.

---

## 7. AWS-Dependent (cannot be verified or completed until an AWS account exists)

- RDS PostgreSQL provisioning and actual connectivity.
- App Runner deployment execution and runtime behavior (image build/push is real and automated; the deploy itself relies on App Runner's `AutoDeploymentsEnabled` watching the `:latest` ECR tag — this triggers automatically but has never been observed to actually deploy, since no AWS account exists).
- S3+CloudFront hosting of the frontend.
- AWS Secrets Manager actually holding and serving secret values.
- CloudWatch log/metric ingestion.
- Route53/DNS and HTTPS/ACM certificate provisioning.
- Any IAM permission boundary testing beyond static CDK code review.

## 8. Stripe-Dependent (cannot be verified without test-mode credentials)

- Actual checkout-session completion end-to-end.
- Actual webhook delivery and signature verification against a real Stripe account (code-level signature check logic can be reviewed, not live-tested).
- Customer Portal session creation/behavior once built.
- `invoice.payment_failed` dunning flow once built.

---

## 9. Launch Blockers (ranked, pre-AWS)

1. **Fabricated ML confidence score shown to users** (`mlAnalytics.ts:346`) — actively misleading, not just incomplete.
2. **Fail-open webhook signing secret** (`webhooks.ts:227`) — a real forgeable-signature vulnerability if `NETTLE_WEBHOOK_SECRET` is ever left unset in production.
3. **False "production-ready" and false "PASS" claims in `phase5-final-audit.ts`** — actively dishonest documentation that could mislead the user or future engineers about real security posture (worker isolation, OSV freshness).
4. **No whole-scan timeout** — a hung scan step (or a slow-but-successful chain of steps) can run indefinitely, tying up server resources.
5. **No Stripe payment-failure handling or idempotent webhook processing** — real revenue-risk and duplicate-notification-risk once live.
6. **No email verification** — accounts can be created with unowned email addresses today.
7. **No data retention/cleanup** — Tier 2 events and scan artifacts will grow unbounded.
8. **No structured logging/observability** — production incidents will be hard to diagnose blind.
9. **Database is SQLite-only** — will not survive multi-instance App Runner scaling (`minSize`/`maxSize` are currently pinned to 1 specifically because of this); needs a real architectural decision (see note below) before AWS deployment with more than one instance.
10. **No admin/operator visibility** — no way to see failed scans, webhook failures, or abuse events without direct DB access.

**Note on the database migration (#9):** `node:sqlite`'s `DatabaseSync` API is fully synchronous; all 171 `db.prepare()` call sites in this codebase assume synchronous execution. A real Postgres driver (`pg`) is inherently asynchronous. A genuine "swap SQLite for Postgres" migration is not a drop-in driver change — it requires converting data-access code to async, which cascades up through most route handlers. This is in direct tension with "do not rewrite working functionality." Phase 2 will build the safe, additive parts first (real `pg` dependency, connection/pooling module, Postgres-translated schema DDL, migration runner, `DATABASE_URL`-driven fail-safe config) and will raise the deeper "convert all call sites to async now vs. defer as an explicitly-scoped follow-up" decision to the user directly before touching the 171 call sites, rather than silently picking a path or faking shallow Postgres "support" that isn't actually wired to real queries.

---

## 10. Recommended Order of Fixes (Phase 2)

Small, unambiguous, low-risk, high-value first:

1. Remove the `webhooks.ts` fail-open secret; apply fail-closed pattern consistently to `pagerduty.ts`.
2. Fix the fake ML confidence score (deterministic completeness-based calc, or honest rename).
3. Correct the false claims in `phase5-final-audit.ts` (mark worker isolation and OSV freshness accurately; remove the unqualified "production-ready" line).
4. Add the whole-scan top-level timeout.
5. Wire `osvVersioning.ts` into the real scan pipeline (or explicitly document why not, if scope requires deferring) so OSV freshness claims become true instead of false.
6. Database: build additive Postgres-readiness infrastructure; raise the async-conversion-scope question to the user via `AskUserQuestion` before touching the 171 call sites.
7. Stripe: Customer Portal, `invoice.payment_failed` handling, webhook idempotency.
8. Email verification flow (reusing existing email infrastructure).
9. Data retention policies + cleanup scheduling hooks.
10. Observability: structured logging, meaningful health endpoint, CloudWatch-ready format.
11. Minimal admin/operator visibility routes.
12. Phase 3 (Tier 2 alerting verification/enhancement), Phase 4 (AWS CDK prep), Phase 5 (frontend prod prep — including the `VITE_API_BASE_URL` localhost fallback at `frontend/src/api.ts:1`), Phase 6 (final security review pass), Phase 7 (testing throughout).

---

*This document reflects only what was directly verified by reading source files and running greps against the actual repository on `claude/nettle-repo-context-lnd87f`. No code was modified to produce it. Proceeding now to Phase 2 implementation per the phase gate.*
