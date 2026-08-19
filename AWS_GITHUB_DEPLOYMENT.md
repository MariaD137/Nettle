# AWS + GitHub Deployment Runbook

What Claude prepared, what still needs a human with a real AWS account and/or
Stripe account, and the exact order to do it in. Every item below is marked:

- **[CLAUDE CAN COMPLETE NOW]** — code/config already written and verified
  (typechecked, tested, or `cdk synth`'d against real tooling) in this repo.
- **[REQUIRES AWS ACCOUNT]** — needs a real AWS account and console/CLI
  access. Claude has not done this and cannot do it — no AWS credentials
  exist in this session, by design (see Security below).
- **[REQUIRES STRIPE ACCOUNT]** — needs a real Stripe account (test or live).
- **[REQUIRES USER ACTION]** — a decision or manual step only a human should
  make (DNS ownership, choosing a domain, approving spend, etc).

Nothing in this document should be read as "deployed." Every AWS-dependent
item here has been prepared and, where possible, verified locally (`cdk
synth` producing valid CloudFormation, `npm run build` producing a real
Docker-buildable image) — never verified against a real deployment, because
none exists.

## Security model (read this first)

Claude did not, and will not, receive, request, store, print, or use any
real AWS access keys, Stripe secret keys, database passwords, SMTP
passwords, Twilio credentials, or other production credentials in this
repository or this conversation. Every secret referenced below is a
**name** the app or infrastructure expects to exist — never a value typed
into a chat, committed to git, or hardcoded into CDK source.

- GitHub Actions authenticates to AWS via OIDC (`.github/workflows/*.yml`,
  `infra/lib/ci-stack.ts`) — there are no long-lived `AWS_ACCESS_KEY_ID`/
  `AWS_SECRET_ACCESS_KEY` anywhere in this repository.
- The GitHub Actions deploy role is deliberately **not** permitted to run
  `cdk deploy` or otherwise create/modify infrastructure. Infrastructure
  provisioning (`cdk deploy`) is a human-run step, from your own machine,
  with your own AWS credentials — never something CI does automatically.
  CI only gets the narrow, repeatable actions it needs after infrastructure
  already exists: push a Docker image to ECR, sync built frontend files to
  S3, invalidate a CloudFront cache.
- Production secret values (Stripe keys, the webhook/token-encryption
  secrets, SMTP/Twilio credentials) live only in AWS Secrets Manager,
  created and populated by you, and are retrieved by the running App
  Runner service at container startup — never present in the Docker image,
  never in this git repository, never in a GitHub Actions log.
- `.env.example` at the repo root lists every environment variable the
  backend reads, with placeholder values only.
- A repository-wide secret scan was run before this document was written
  (see the end of this file) — only `.env.example` is tracked among any
  `.env*`-named file, and it contains no real values.

---

## 1. AWS account setup — **[REQUIRES AWS ACCOUNT]** / **[REQUIRES USER ACTION]**

Create (or choose) an AWS account for Nettle. Recommended: a dedicated
account or a separate account within an AWS Organization, not a personal
account already running other production workloads — this makes IAM
scoping, billing, and eventual teardown much simpler. Note the account ID;
several steps below need it.

## 2. IAM / OIDC setup — **[CLAUDE CAN COMPLETE NOW]** (code), **[REQUIRES AWS ACCOUNT]** (apply it)

`infra/lib/ci-stack.ts` (the `Nettle-CI` stack) defines the GitHub OIDC
provider and the deploy role GitHub Actions assumes. The code is written,
typechecked, and `cdk synth`'d clean. Deploying it (step 6 below) creates:

- An `OpenIdConnectProvider` for `token.actions.githubusercontent.com`.
- A role (`nettle-github-actions-deploy`) assumable only by workflows
  running in `MariaD137/Nettle`, scoped to: push images to the one ECR
  repo, `s3:PutObject`/`DeleteObject`/`ListBucket` on the one frontend
  bucket, `cloudfront:CreateInvalidation` on the one distribution.

Nothing further to do here beyond deploying the stack (step 6).

## 3. GitHub repository settings — **[REQUIRES USER ACTION]**

1. Settings → Environments → create a `production` environment. Add
   required reviewers if you want a manual approval gate before every
   push to `main` touches AWS (recommended, referenced by
   `backend-deploy.yml`, `frontend-deploy.yml`).
2. Settings → Secrets and variables → Actions → **Variables** (not
   Secrets — none of these are sensitive), add:
   - `AWS_REGION` — e.g. `us-east-1`.
   - `AWS_DEPLOY_ROLE_ARN` — the `Nettle-CI` stack's `DeployRoleArn`
     output (step 6).
   - `ECR_REPOSITORY_URI` — the `Nettle-Api` stack's `RepositoryUri`
     output.
   - `FRONTEND_BUCKET_NAME` — the `Nettle-Frontend` stack's
     `FrontendBucketName` output.
   - `FRONTEND_DISTRIBUTION_ID` — the `Nettle-Frontend` stack's
     `FrontendDistributionId` output.
   - `VITE_API_BASE_URL` — the real API origin (e.g.
     `https://<apprunner-url>` from the `Nettle-Api` stack's `ServiceUrl`
     output, or your custom API domain once one exists). Frontend
     production builds have no localhost fallback for this (see
     `frontend/src/api.ts`) — the build fails to be useful without it.

## 4. GitHub Actions configuration — **[CLAUDE CAN COMPLETE NOW]**

Already in place, using the variables from step 3:

- `.github/workflows/ci.yml` — lint/test/build on every PR and push to
  `main`/`develop`. Not a deploy workflow.
- `.github/workflows/backend-deploy.yml` — on push to `main` touching
  `backend/**`: OIDC-authenticates, builds and pushes the Docker image to
  ECR. App Runner's `AutoDeploymentsEnabled` picks up the new `:latest`
  tag automatically — no separate deploy call.
- `.github/workflows/backend-deploy-staging.yml` — same, for a `develop`
  branch / `staging` tag, if you use one.
- `.github/workflows/frontend-deploy.yml` — on push to `main` touching
  `frontend/**`: builds with `VITE_API_BASE_URL` baked in, OIDC-
  authenticates, syncs `dist/` to the frontend S3 bucket, invalidates
  CloudFront.

## 5. Secrets Manager secret names — **[CLAUDE CAN COMPLETE NOW]** (references), **[REQUIRES AWS ACCOUNT]** + **[REQUIRES STRIPE ACCOUNT]** (create and populate)

`infra/lib/api-stack.ts` references a secret named exactly
**`nettle/app-secrets`** and expects it to already exist — the CDK code
never creates or populates its value. Create it yourself (AWS Console →
Secrets Manager → "Other type of secret" → plaintext/key-value, or via
`aws secretsmanager create-secret`) as a single JSON secret with exactly
these keys:

| JSON key | Env var it becomes | Where the value comes from |
|---|---|---|
| `stripeSecretKey` | `STRIPE_SECRET_KEY` | Stripe Dashboard → Developers → API keys (§12) |
| `stripeWebhookSecret` | `STRIPE_WEBHOOK_SECRET` | Stripe Dashboard → Developers → Webhooks, after creating the endpoint (§12) |
| `stripePriceTier1` | `STRIPE_PRICE_TIER1` | Stripe Dashboard → Product catalog (§12) |
| `stripePriceTier2` | `STRIPE_PRICE_TIER2` | Stripe Dashboard → Product catalog (§12) |
| `nettleTokenEncryptionKey` | `NETTLE_TOKEN_ENCRYPTION_KEY` | Generate yourself: `openssl rand -base64 32` |
| `nettleWebhookSecret` | `NETTLE_WEBHOOK_SECRET` | Generate yourself: `openssl rand -hex 32` |
| `cronSecret` | `CRON_SECRET` | Generate yourself: `openssl rand -hex 32` |
| `smtpUser` | `SMTP_USER` | Your email provider (§13) |
| `smtpPass` | `SMTP_PASS` | Your email provider (§13) |
| `twilioAccountSid` | `TWILIO_ACCOUNT_SID` | Twilio Console (§14) |
| `twilioAuthToken` | `TWILIO_AUTH_TOKEN` | Twilio Console (§14) |

The App Runner service (`Nettle-Api`) has an instance role scoped to
`secretsmanager:GetSecretValue` on exactly this secret's ARN (plus the RDS
secret's ARN, if `Nettle-Database` is deployed) — nothing broader.

Separately, **if you deploy `Nettle-Database`**, CDK itself generates a
second secret (name shown in that stack's `DatabaseSecretArn` output)
holding the RDS master username/password — you never type or see that
password; CDK/CloudFormation generates it via a dynamic reference at
deploy time.

## 6. RDS configuration — **[CLAUDE CAN COMPLETE NOW]** (code), **[REQUIRES AWS ACCOUNT]** + **[REQUIRES USER ACTION]** (deploy it, decide when)

`infra/lib/database-stack.ts` (the `Nettle-Database` stack) is written and
`cdk synth`'s clean: PostgreSQL 16, `db.t4g.micro`, single-AZ, encrypted
storage, private subnets only, security group allowing inbound 5432 from
the API's connector security group only.

**The backend's code side of this is done**: `backend/src/db/index.ts` is
PostgreSQL-only now, with no SQLite fallback — it requires a real
`DATABASE_URL` (or `PGHOST`/`PGPORT`/`PGUSER`/`PGPASSWORD`/`PGDATABASE`) to
start at all, and the full application (auth, projects, scans, billing,
alerts, everything) has been verified end-to-end against a real local
PostgreSQL 16 server. **What's still pending is purely the AWS side**: this
stack is not part of the default `cdk deploy --all` flow (see
`infra/bin/app.ts`) and has never been applied to a real AWS account — no
RDS instance exists yet, and nothing in this repository creates one on its
own. Deploy it when you're ready to actually run the API against it —
deploying it earlier just means paying for an idle RDS instance.

To deploy it on its own once you're ready:
```bash
cd infra && npx cdk deploy Nettle-Database
```
This prints two outputs, `DatabaseEndpoint` and `DatabaseSecretArn`. Fill
both into `Nettle-Api`'s `databaseEndpointAddress`/`databaseSecretArn`
props (see `infra/bin/app.ts`'s REQUIRES AWS CONFIGURATION comment there)
and redeploy `Nettle-Api` (§7) — that's what actually connects the running
API container to this database; deploying `Nettle-Database` alone doesn't.
Then run `npm run db:migrate:postgres` from `backend/` against the same
connection details to create the schema before the API's first request.

## 7. App Runner configuration — **[CLAUDE CAN COMPLETE NOW]** (code), **[REQUIRES AWS ACCOUNT]** (deploy it)

`infra/lib/api-stack.ts` (the `Nettle-Api` stack): ECR repo, App Runner
service (0.25 vCPU / 0.5 GB, `minSize: 1, maxSize: 1` — see `infra/README.md`
for why the cap stays at 1), VPC connector for egress, health check against
`GET /health` (upgraded this pass to report real DB connectivity and scan
queue depth, not a static `{status:"ok"}`), and `runtimeEnvironmentSecrets`
pulling every value in §5's table from Secrets Manager at container start —
plus, once `databaseSecretArn`/`databaseEndpointAddress` are filled in per
§6, the `PGHOST`/`PGPORT`/`PGUSER`/`PGPASSWORD`/`PGDATABASE` variables the
backend needs to reach RDS.

## 8. ECR configuration — **[CLAUDE CAN COMPLETE NOW]**

Created by `Nettle-Api` (§7) — no separate step. `backend/Dockerfile` is
the real, already-tested multi-stage build `backend-deploy.yml` pushes.

## 9. S3 configuration — **[CLAUDE CAN COMPLETE NOW]** (code), **[REQUIRES AWS ACCOUNT]** (deploy it)

`infra/lib/frontend-stack.ts` (the `Nettle-Frontend` stack): a private S3
bucket with `BLOCK_ALL` public access — the bucket is never publicly
reachable; only CloudFront can read it, via Origin Access Control.

## 10. CloudFront configuration — **[CLAUDE CAN COMPLETE NOW]** (code), **[REQUIRES AWS ACCOUNT]** (deploy it)

Same stack as §9: HTTPS-only, GET/HEAD only, and 403/404 responses
rewritten to `index.html` so the frontend's client-side routing (react-
router) survives a direct load or refresh on any route.

## 11. Route53 / DNS requirements — **[REQUIRES USER ACTION]** + **[REQUIRES AWS ACCOUNT]** — not yet prepared

No custom domain is wired up anywhere in this CDK app — the API is reached
at its raw App Runner URL and the frontend at its raw CloudFront domain,
both shown as stack outputs after deploy. If you want a real domain (e.g.
`app.nettle.com` / `api.nettle.com`):

1. Register or transfer the domain into Route53 (or point your existing
   registrar's DNS at Route53) — a decision only you should make.
2. Request an ACM certificate for the domain **in `us-east-1`**
   specifically (a CloudFront requirement, regardless of which region the
   rest of the stack runs in), and add the domain to the CloudFront
   distribution's `domainNames`/`certificate` props in
   `frontend-stack.ts`.
3. For the API: App Runner supports custom domains directly (console or
   `AWS::AppRunner::VpcConnector`'s sibling `CustomDomainAssociation`
   resource) — not yet added to `api-stack.ts`.

This is real, scoped follow-up work, not done in this pass — adding it
without a real domain to test against risks producing CDK that looks right
but has never actually resolved a real DNS record.

## 12. Stripe configuration — **[REQUIRES STRIPE ACCOUNT]**

1. Create products/prices for Tier 1 and Tier 2 in the Stripe Dashboard
   (test mode first). Note both price IDs → `stripePriceTier1`/
   `stripePriceTier2` in §5.
2. Copy the secret key (test mode: `sk_test_...`) → `stripeSecretKey`.
3. After `Nettle-Api` is deployed and has a real URL: Dashboard →
   Developers → Webhooks → add endpoint
   `https://<api-url>/api/billing/webhook`, subscribe to at minimum
   `checkout.session.completed`, `customer.subscription.updated`,
   `customer.subscription.deleted`, `invoice.payment_failed`. Copy the
   signing secret → `stripeWebhookSecret`.
4. Set `BILLING_SUCCESS_URL`, `BILLING_CANCEL_URL`,
   `BILLING_PORTAL_RETURN_URL` (non-secret — set as `runtimeEnvironmentVariables`
   in `api-stack.ts` or App Runner console config) to your real frontend
   URLs once deployed.
5. **Live mode** is a separate, later step — repeat with live keys/prices/
   webhook once test mode is verified end-to-end. Do not claim live Stripe
   verification has happened until it actually has.

## 13. SMTP/email configuration — **[REQUIRES USER ACTION]**

Any real SMTP provider works (`backend/src/integrations/email.ts` uses
plain nodemailer) — SES, Postmark, SendGrid, etc. Set `SMTP_HOST`,
`SMTP_PORT`, `SMTP_SECURE`, `SMTP_FROM` as non-secret runtime env vars, and
`smtpUser`/`smtpPass` in the §5 secret. Verify sending domain/DKIM per your
provider's instructions — outside this repo's scope.

## 14. Twilio/SMS configuration — **[REQUIRES USER ACTION]**

Create a Twilio account, buy/verify a sending number → `TWILIO_FROM_NUMBER`
(non-secret env var), and put the account SID/auth token in the §5 secret
(`twilioAccountSid`/`twilioAuthToken`). SMS delivery (Tier 2 alerts) is
optional — channels default to none configured, and the app degrades
safely (delivery failures are retried and tracked, not silently dropped —
see `GET /api/admin/notification-failures`).

## 15. Required environment variables — **[CLAUDE CAN COMPLETE NOW]**

The complete, current list (every variable the backend actually reads) is
`.env.example` at the repo root — kept in sync with the code this pass,
with inline comments on which are secret (→ §5) vs. plain config
(→ `runtimeEnvironmentVariables` in `api-stack.ts` or App Runner console).

## 16. Deployment order — **[REQUIRES AWS ACCOUNT]**

```bash
cd infra
npm install
npx cdk bootstrap                       # once per account/region
npx cdk deploy Nettle-Network
npx cdk deploy Nettle-CI                # needs Nettle-Api's ECR repo ARN + Nettle-Frontend's bucket/distribution — deploy Api and Frontend first, or use `cdk deploy --all` and let CDK order it
npx cdk deploy Nettle-Api
npx cdk deploy Nettle-Frontend
# npx cdk deploy Nettle-Database        # required before Nettle-Api can actually start — see §6; deploy it, fill its outputs into Nettle-Api's props, then deploy/redeploy Nettle-Api
```
(`npx cdk deploy --all` handles dependency ordering automatically; the
explicit order above is for deploying stacks individually.)

Then, in order:
1. Create and populate the `nettle/app-secrets` Secrets Manager secret (§5)
   — App Runner won't start cleanly without it once secrets are wired in.
2. Manually push a first Docker image (App Runner's `AutoDeploymentsEnabled`
   only triggers on *new* pushes to `:latest`; it needs one image to exist
   first):
   ```bash
   cd backend
   docker build -t nettle-api .
   aws ecr get-login-password --region <region> | docker login --username AWS --password-stdin <account-id>.dkr.ecr.<region>.amazonaws.com
   docker tag nettle-api:latest <account-id>.dkr.ecr.<region>.amazonaws.com/nettle-api:latest
   docker push <account-id>.dkr.ecr.<region>.amazonaws.com/nettle-api:latest
   ```
3. Wire GitHub repository variables (§3) from the stack outputs.
4. Complete Stripe (§12), SMTP (§13), Twilio (§14) setup and update the
   secret/env vars accordingly.
5. From here on, pushes to `main` touching `backend/**` or `frontend/**`
   deploy automatically via GitHub Actions.

## 17. Smoke tests — **[REQUIRES AWS ACCOUNT]** (to actually run against a deployment)

Once deployed, verify in this order:
1. `curl https://<apprunner-url>/health` → `{"status":"ok","database":"ok",...}`.
2. Load the CloudFront URL → the frontend loads and can reach the API
   (check the browser network tab, not just that the page renders).
3. Sign up a real test account → confirm a verification email actually
   arrives (§13 must be configured).
4. Complete a Stripe test-mode checkout → confirm the webhook fires and
   the account's plan/subscription status updates (check
   `GET /api/admin/overview` with an admin-granted account, §NETTLE_ADMIN_EMAILS
   in `.env.example`).
5. Trigger a real scan (upload or repo) end to end.
6. `POST /api/internal/digest/daily` and
   `POST /api/internal/retention/cleanup` with the real `X-Nettle-Cron-Secret`
   header → both should respond `200`, not `503`.
7. **Set up the actual scheduled triggers** for the two internal endpoints
   above (§16 doesn't do this) — an EventBridge Scheduler rule (or App
   Runner cron, if using a different compute target later) hitting each
   endpoint on a recurring schedule with the `CRON_SECRET` header. Not
   built in this pass — the endpoints exist and are tested, the schedule
   that calls them does not yet.

## 18. Rollback procedure — **[REQUIRES USER ACTION]**

- **Backend:** App Runner keeps prior image digests in ECR. Re-tag a known-
  good digest as `:latest` and push (triggers `AutoDeploymentsEnabled`), or
  use the App Runner console's "Deploy" on a specific prior deployment.
- **Frontend:** re-run `frontend-deploy.yml` from a prior commit (or
  `git revert` + push), or manually `aws s3 sync` a prior local build and
  invalidate CloudFront.
- **Database (once `Nettle-Database` is actually in use):** RDS automated
  backups (7-day default retention) + the `RemovalPolicy.SNAPSHOT` on the
  instance mean a snapshot exists before any stack-level deletion; point-
  in-time restore is available through the RDS console.
- **Infrastructure:** `cdk deploy` is declarative — re-deploying an older
  commit's CDK code reverts infrastructure changes the same way. CDK does
  not automatically roll back a failed deploy's *application* changes; it
  rolls back the *stack* to its last known-good CloudFormation state.

## 19. Production verification checklist — **[REQUIRES AWS ACCOUNT]** + **[REQUIRES STRIPE ACCOUNT]**

Do not consider Nettle "launched" until every one of these has actually
been done, not just prepared:

- [ ] `Nettle-Network`, `Nettle-Api`, `Nettle-Frontend`, `Nettle-CI` deployed
- [ ] `nettle/app-secrets` created and fully populated (§5)
- [ ] First Docker image manually pushed; App Runner service healthy
- [ ] Frontend deployed and reachable; API calls from it succeed
- [ ] Custom domain + ACM cert wired up, if wanted (§11 — not prepared yet)
- [ ] Stripe test-mode checkout, portal, and webhook verified end to end
- [ ] Stripe **live-mode** keys/prices/webhook configured and verified (§12)
- [ ] SMTP verified — a real signup produces a real, deliverable
      verification email
- [ ] Twilio verified, if SMS alerts are wanted
- [ ] `NETTLE_ADMIN_EMAILS` set to your real operator account(s)
- [ ] Scheduled triggers for digest + retention cleanup actually created
      (§17.7 — not done by `cdk deploy`)
- [ ] A real scan run end to end against the deployed service
- [ ] Rollback procedure (§18) actually rehearsed once, not just documented

---

## Repository-wide secret scan (performed before writing this document)

- `git ls-files | grep -i '\.env'` → only `.env.example` is tracked;
  `.gitignore` covers `.env`, `.env.local`, `.env.*.local`.
- Repo-wide grep for `process.env.<SECRET>` fallback patterns
  (`... || 'default'`) across `backend/src` → the one genuine case found
  this pass (`NETTLE_WEBHOOK_SECRET || 'nettle-webhook'`) was removed; see
  `PRE_AWS_AUDIT.md` and `PRE_AWS_PRODUCTION_STATUS.md` for the full audit
  trail.
- No AWS access keys, Stripe secret keys, database passwords, or other
  production credentials appear anywhere in this repository, any Dockerfile,
  any CDK source file, any GitHub Actions workflow, or any test fixture —
  test files use obviously-fake values (`sk_test_fake_key_for_local_tests_only`,
  `whsec_test_secret_for_local_tests_only`) that are not, and could not be,
  real credentials.

The repository is safe to hand to GitHub Actions / an AWS deployment
pipeline without granting Claude (or anyone reading this repo) access to
any production AWS or Stripe credential.
