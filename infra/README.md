# Nettle infra

Eight stacks (six production, plus a staging pair mirroring two of them), each scoped to one concern:

- **Nettle-Network** — a VPC. One NAT gateway (not one per AZ) plus
  public/private-egress/isolated subnet tiers, and a Secrets Manager
  interface endpoint. The NAT is required, not a convenience: App Runner's
  `egressType: "VPC"` routes *all* outbound traffic through this VPC, and the
  API has hard dependencies on the public internet (Stripe, GitHub/GitLab/
  Bitbucket for repo scans) that have no AWS-native VPC endpoint. The
  database sits in the isolated tier, with no route to the internet in
  either direction, regardless of what happens to the API's egress.
- **Nettle-Database** — PostgreSQL 16 on RDS (`db.t4g.micro`), private,
  encrypted at rest, 7-day backups (default; configurable via backupRetentionDays — capped lower on AWS Free Tier accounts), deletion protection on. This is where
  all application state actually lives — users, sessions, projects, scans,
  billing anchors, rate-limit counters. See `../docs/DATABASE.md` for why
  RDS rather than SQLite-on-App-Runner (short version: App Runner has no
  persistent-filesystem option at all — `AWS::AppRunner::Service` exposes no
  volume/mount/EFS property — so durable state cannot live in the container).
- **Nettle-Ecr** — just the ECR repository, deliberately its own stack. See
  "Deploy order" below for why this can't live inside Nettle-Api.
- **Nettle-Api** — the App Runner service running the API: 1 vCPU / 2 GB,
  egress routed through the VPC connector, database credentials and Stripe
  secrets injected via Secrets Manager (`runtimeEnvironmentSecrets` —
  resolved by App Runner at start-up, never rendered into the template or a
  log line).
- **Nettle-Frontend** — static hosting for `frontend/`'s Vite build: a
  private S3 bucket (all public access blocked, HTTPS-only bucket policy)
  behind a CloudFront distribution using Origin Access Control, never a
  public bucket or S3 website endpoint. SPA client-side routing (403/404 →
  `/index.html` with an explicit 200) and a strict `ResponseHeadersPolicy`
  (CSP with no `unsafe-inline`/`unsafe-eval` — the Vite build emits no
  inline script/style at all — HSTS, `X-Content-Type-Options: nosniff`,
  `X-Frame-Options: DENY`, `Referrer-Policy`). The CSP's `connect-src`
  references `Nettle-Api`'s live `ServiceUrl` via a cross-stack import, so
  it's never out of sync with where the API actually is. Deliberately does
  NOT bundle `frontend/dist` into the stack as a CDK asset — same
  out-of-band-build shape as the backend (see `frontend-deploy.yml`) rather
  than requiring a CDK deploy for every frontend change. No custom
  domain/ACM certificate here — that needs a real domain and DNS control
  this sandbox doesn't have; the distribution's own `*.cloudfront.net`
  domain works as-is, or add a domain later (see that section below).
- **Nettle-CI** — a GitHub OIDC provider + a deploy role scoped to exactly
  what this repo's deploy workflows do: push images to the Nettle-Ecr repo,
  and sync/invalidate the Nettle-Frontend bucket/distribution. No AWS access
  keys are ever stored in GitHub.
- **Nettle-Database-Staging** / **Nettle-Api-Staging** — a second,
  independent environment: `NettleDatabaseStack`/`NettleApiStack` (the same
  classes as `Nettle-Database`/`Nettle-Api`) instantiated a second time with
  `stageName: "staging"`, sharing `Nettle-Network`'s VPC and `Nettle-Ecr`'s
  repository but with their own Secrets Manager secrets, App Runner service,
  and RDS instance — never production's. `Nettle-Api-Staging` tracks the
  ECR `:staging` tag rather than `:latest` (`imageTag: "staging"`), which is
  what `.github/workflows/backend-deploy-staging.yml` has been pushing on
  every merge to `develop` since before this pair existed to consume it —
  that workflow ran successfully the whole time with nowhere for its output
  to go; App Runner's `autoDeploymentsEnabled` on `Nettle-Api-Staging`
  closes that gap the same way it already does for production watching
  `:latest`. The staging database is `production: false` (1-day backups, no
  deletion protection, `RemovalPolicy.DESTROY`) — deliberately disposable,
  unlike `Nettle-Database`. See `lib/api-stack.ts`'s and
  `lib/database-stack.ts`'s `stageName` prop comments for exactly which
  physical resource names this affects; verified via `cdk synth` that
  `Nettle-Api`/`Nettle-Database`'s own templates are byte-for-byte unchanged
  by this addition (diffed directly against `cdk synth` from before these
  props existed) — deploying this cannot rename or replace any resource
  CloudFormation already manages for production.

## What's validated vs. what isn't

| Checked | How |
|---|---|
| All eight stacks synthesize to valid CloudFormation | `cdk synth` |
| Adding the staging stacks left `Nettle-Api`/`Nettle-Database`'s own templates completely unchanged | Diffed `cdk synth`'s output for both stacks directly against a synth from before the staging stacks/props existed — zero-byte diff |
| Adding `Nettle-Frontend` left `Nettle-Database` unchanged and added exactly one thing to `Nettle-Api` — a new CloudFormation `Export` of the App Runner service's `ServiceUrl`, for `Nettle-Frontend`'s cross-stack CSP reference | Diffed both templates directly against a synth from before `Nettle-Frontend` existed — `Nettle-Database` zero-byte diff; `Nettle-Api`'s diff is purely additive (a new `Outputs` entry), no existing resource modified or replaced |
| `Nettle-Frontend`'s bucket has all public access blocked, is reachable only via the one CloudFront distribution (Origin Access Control, `AWS:SourceArn` condition scoped to that exact distribution id), and denies any non-HTTPS request | Inspected the synthesized bucket policy directly — confirmed `PublicAccessBlockConfiguration` blocks all four dimensions, the `s3:GetObject` grant's principal is `cloudfront.amazonaws.com` conditioned on this distribution's ARN specifically (not any CloudFront distribution), and a separate statement denies `s3:*` account-wide when `aws:SecureTransport` is false |
| `Nettle-Frontend`'s CSP has no `unsafe-inline`/`unsafe-eval` | Inspected `frontend/dist/index.html` directly — the Vite build emits zero inline `<script>`/`<style>`, every asset is external, same-origin, and hashed |
| Nettle-Api correctly imports (not re-creates) the ECR repo cross-stack | Inspected the synthesized template's `Fn::ImportValue` reference directly |
| The database has no public ingress, encrypted, SG-scoped to the API connector only | Inspected the synthesized template's resource properties directly — confirmed `PubliclyAccessible: false`, `StorageEncrypted: true`, ingress rule is a security-group reference, never `0.0.0.0/0` |
| The RDS password never appears in App Runner's own runtime config, only resolved inside the container | Inspected the synthesized template directly — confirmed `RuntimeEnvironmentVariables` carries no `{{resolve:secretsmanager:...}}` value (previously it did: a composite `DATABASE_URL` built by joining `secretValueFromJson(...).unsafeUnwrap()` calls, which CloudFormation resolves before calling App Runner's API — so the plaintext password ended up stored in App Runner's own service configuration, visible via `DescribeService`/the console to anyone with that read permission, not just to principals with `secretsmanager:GetSecretValue` on the DB secret specifically. Fixed: `DB_USERNAME`/`DB_PASSWORD` now go through `RuntimeEnvironmentSecrets`, the same native ARN-reference mechanism already used correctly for the Stripe secrets, which App Runner resolves only inside the running container and never stores in its own config. `backend/src/db/index.ts`'s `resolveDatabaseUrl()` assembles the real connection string from that plus the plain `DB_HOST`/`DB_PORT`/`DB_NAME` values once the container is running) |
| Backend builds a working image, starts as non-root, applies its DB migration, serves `/health` and real requests against a real PostgreSQL server | Ran the built artifact directly as the unprivileged user against a local PostgreSQL 16.13 instance (not App Runner itself — see below) |
| Docker image build | **Not run** — no Docker daemon available in the sandbox this was built in |
| Actual `cdk deploy` / real AWS resources / App Runner networking / Stripe/SES connectivity | **Not run** — needs a real AWS account and credentials, which are never pasted into a chat session (see below) |

## Deploy order — read this before running anything

The stacks are not interchangeable in order. `cdk deploy --all` handles the
dependency graph correctly (CDK topologically sorts by cross-stack
references), but if you deploy stacks individually, this order matters:

```
Nettle-Network  →  Nettle-Database  →  Nettle-Ecr  →  [push an image]  →  Nettle-Api  →  Nettle-Frontend  →  Nettle-CI
                 →  Nettle-Database-Staging                            →  Nettle-Api-Staging
```

`Nettle-Frontend` depends on `Nettle-Api` (its CSP imports `Nettle-Api`'s
`ServiceUrl` — see that stack's own comment) but not on anything else;
`Nettle-CI` depends on `Nettle-Ecr` and `Nettle-Frontend` (it grants its
deploy role permissions scoped to both).

**Nettle-Ecr must be deployed, and a real image pushed into it, before
Nettle-Api (or Nettle-Api-Staging) is deployed for the first time.**
`AWS::AppRunner::Service` references an image tag (`:latest` for
`Nettle-Api`, `:staging` for `Nettle-Api-Staging`) and CloudFormation waits
for the service to reach `RUNNING` before the resource is considered
created. On a first-ever deploy there is no image at either tag yet — if the
ECR repo and the App Runner service were in the same stack (an earlier
version of this code had them together), the service would fail to pull,
CloudFormation would roll back the *entire* stack, and it would delete the
ECR repo it had just created moments earlier along with everything else.
Splitting them into separate stacks is what breaks that chicken-and-egg —
see `lib/ecr-stack.ts`.

**`cdk deploy --all` now deploys the staging pair too** (they're
unconditionally in `bin/app.ts`, same as every other stack) — this is a
real behavior change for anyone who has that command memorized from before
these two stacks existed. To deploy only staging (e.g. after `Nettle-Ecr`
already exists and a `:staging` image has been pushed):

```
npx cdk deploy Nettle-Database-Staging Nettle-Api-Staging
```

Staging is genuinely optional infrastructure — skip both if there's no need
for a separate pre-production environment yet; nothing else in this app
depends on them existing.

## First-time setup

**The fast path:** once prerequisites (below) are met, `infra/scripts/deploy-cloudshell.sh`
runs steps 1-4 below end to end — network, database, ECR, an `linux/amd64`
image build and push, and the API service — with the same safety checks a
human operator would apply by hand (safe recovery from a stack stuck in
`ROLLBACK_COMPLETE`, refusing to push an image that isn't `amd64`). It does
not touch Stripe secrets or GitHub wiring (steps 5, 7, 8 below) — those need
a human. Run it from AWS CloudShell (or any shell already configured against
the target account):

```bash
bash infra/scripts/deploy-cloudshell.sh
```

Safe to re-run — every step is idempotent. The manual walkthrough below
documents exactly what it does, for the first deploy or when diagnosing a
failure by hand.

**0. Prerequisites**

- An AWS account, with a payment method attached (this deploys billable
  resources — see Cost notes below).
- AWS credentials configured locally (`aws configure`, or SSO) for that
  account, with sufficient permissions to run `cdk bootstrap` and create
  VPCs, RDS instances, ECR repos, App Runner services, IAM roles, and
  Secrets Manager secrets. An account admin/power-user role is the
  simplest starting point for a first deploy; scope it down afterward if
  you want a narrower deploy identity.
- AWS CLI v2, Docker, and Node.js 20+ installed locally.
- Decide the AWS **region** up front. `CDK_DEFAULT_REGION` (or your AWS CLI
  profile's default region) is what `infra/bin/app.ts` reads; it falls back
  to `us-east-1` if neither is set.

Do all of this from your own machine, not inside a chat session — AWS
credentials should never be pasted into a conversation transcript.

**1. Bootstrap the account/region** (one-time per account+region — creates
the CDK toolkit stack: an S3 bucket and IAM roles CDK itself uses to publish
assets):

```bash
cd infra
npm install
npx cdk bootstrap
```

**2. Deploy the network and database:**

```bash
npx cdk deploy Nettle-Network Nettle-Database
```

This takes a while — RDS instance creation alone is typically 5–10 minutes.
Note the `Nettle-Database` stack's `DatabaseSecretArn` output; you don't need
its value (the API stack wires it automatically), just confirm it printed.

**3. Deploy the ECR repo and push a real image into it:**

```bash
npx cdk deploy Nettle-Ecr
```

Note the `RepositoryUri` output, then:

```bash
cd ../backend
docker build -t nettle-api .
aws ecr get-login-password --region <region> \
  | docker login --username AWS --password-stdin <account-id>.dkr.ecr.<region>.amazonaws.com
docker tag nettle-api:latest <account-id>.dkr.ecr.<region>.amazonaws.com/nettle-api:latest
docker push <account-id>.dkr.ecr.<region>.amazonaws.com/nettle-api:latest
cd ../infra
```

**4. Deploy the API:**

```bash
npx cdk deploy Nettle-Api
```

Note the `ServiceUrl` output — that's the live, public HTTPS endpoint. It
will start; the container's own persistence guard
(`assertProductionPersistence()` in `backend/src/index.ts`) refuses to boot
without `DATABASE_URL`, which this stack injects automatically, so if it
comes up at all, the database connection is real.

**5. Populate the Stripe secret** (the stack creates it with placeholder
`"unset"` values under the real key names — see `lib/api-stack.ts` for why
it needs real JSON structure from creation, not a truly empty secret):

```bash
aws secretsmanager put-secret-value \
  --secret-id nettle/application \
  --secret-string '{
    "STRIPE_SECRET_KEY": "sk_live_...",
    "STRIPE_WEBHOOK_SECRET": "whsec_...",
    "STRIPE_PRICE_BUILD": "price_...",
    "STRIPE_PRICE_PROTECT": "price_..."
  }'
```

App Runner picks up secret changes on the next deployment, not live — either
push a new image or use `aws apprunner start-deployment` to pick up the new
values without a code change.

**6. Verify it's actually live:**

```bash
curl https://<ServiceUrl>/health
# {"status":"ok","timestamp":"..."}
```

Then a real end-to-end check: sign up, confirm the session works, confirm
the paywall gate fires for an unpaid account:

```bash
curl -X POST https://<ServiceUrl>/api/auth/signup \
  -H 'Content-Type: application/json' \
  -d '{"email":"you@example.com","password":"a real passphrase here"}'
```

**7. Deploy the frontend bucket/distribution:**

```bash
npx cdk deploy Nettle-Frontend
```

Note the `BucketName` and `DistributionId` outputs — `frontend-deploy.yml`
needs both (step 9). This creates the distribution itself but does not put
anything in the bucket yet; until the first `frontend-deploy.yml` run, the
distribution serves an empty bucket (a 403→index.html fallback with nothing
at `/index.html` either — a blank error page, not a security problem,
just not useful yet).

**8. Deploy CI:**

```bash
npx cdk deploy Nettle-CI
```

**9. Wire GitHub Actions.** `backend-deploy.yml`/`frontend-deploy.yml` run
under the `production` GitHub Environment and `backend-deploy-staging.yml`
under `staging` — add these repository/environment variables (Settings →
Secrets and variables → Actions → Variables; set per-environment if you
want staging pushing with a narrower role, or as plain repository variables
to share one set — `Nettle-CI`'s deploy role is already scoped to any ref
in this repo, so sharing is fine):

| Variable | Used by | Value |
|---|---|---|
| `AWS_REGION` | all three workflows | the region you deployed to |
| `AWS_DEPLOY_ROLE_ARN` | all three workflows | `Nettle-CI` stack's `DeployRoleArn` output |
| `ECR_REPOSITORY_URI` | backend workflows | `Nettle-Ecr` stack's `RepositoryUri` output (same repo for both — only the image tag differs) |
| `FRONTEND_BUCKET_NAME` | `frontend-deploy.yml` | `Nettle-Frontend` stack's `BucketName` output |
| `FRONTEND_DISTRIBUTION_ID` | `frontend-deploy.yml` | `Nettle-Frontend` stack's `DistributionId` output |
| `API_BASE_URL` | `frontend-deploy.yml` | `Nettle-Api` stack's `ServiceUrl` output — baked into the Vite build at build time (`VITE_API_BASE_URL`), not read at runtime |

**10. (Recommended)** Add a `production` GitHub Environment with required
reviewers, so a push to `main` pauses for approval before it touches AWS —
`backend-deploy.yml`/`frontend-deploy.yml` already target the `production`
environment.

From here on, every push to `main` touching `backend/**` builds a new image
and pushes `:latest` — App Runner's `autoDeploymentsEnabled: true` picks it
up automatically, no separate deploy step needed. A push to `main` touching
`frontend/**` builds and syncs the SPA into the bucket, then invalidates
`/index.html`. Every push to `develop` does the backend's equivalent for
`:staging`, once step 11 below exists to consume it.

**11. (Optional) Deploy staging** — a second, independent environment (its
own database, its own App Runner service, its own Stripe-secret slot)
tracking the `:staging` tag `backend-deploy-staging.yml` already pushes on
every merge to `develop`:

```bash
npx cdk deploy Nettle-Database-Staging
# push a real image tagged :staging into the same ECR repo from step 3
# before deploying the service, same chicken-and-egg reasoning as step 4 —
# use the same docker build/tag/push sequence with :staging instead of :latest
npx cdk deploy Nettle-Api-Staging
```

Then populate `nettle/application-staging` (step 5's command, with
`--secret-id nettle/application-staging`) — with Stripe **test-mode** keys,
never the live keys from step 5. Skip this step entirely if there's no need
for a separate pre-production environment yet; nothing else here depends on
it existing. There is no separate staging frontend target — `Nettle-Frontend`
is a single production distribution; the frontend is a static SPA with no
server-side state, so a staging frontend build (pointed at
`Nettle-Api-Staging`'s URL via `VITE_API_BASE_URL`) can be served from any
static host (even just `npx serve dist` locally) without needing its own
CDK-managed S3/CloudFront stack.

## Cost notes (estimates, not sourced pricing — check AWS's current pricing page)

This is no longer a near-zero-cost deployment — RDS and the NAT gateway are
real recurring costs:

- **NAT gateway**: ~$32/month base, plus ~$0.045/GB processed. Required
  because App Runner's VPC egress has no route to Stripe/GitHub otherwise
  (see Nettle-Network above) — this is the largest single addition since the
  original zero-NAT design.
- **RDS `db.t4g.micro`, single-AZ**: roughly $12-15/month for the instance,
  plus storage (20 GB minimum, autoscales to 100 GB) and backup storage.
- **App Runner, 1 vCPU / 2 GB, running continuously**: roughly $35-50/month.
  Raised from the original 0.25 vCPU / 0.5 GB sizing — Semgrep is a Python
  process working over uploads up to 500 MB, and the smaller tier was below
  what one large scan needs.
- ECR image storage, Secrets Manager, the VPC endpoint, IAM, the OIDC
  provider: a few dollars/month combined at most.
- **S3 + CloudFront (`Nettle-Frontend`)**: at low/zero traffic, effectively
  a few cents to a dollar or two/month — S3 storage for a few MB of static
  assets, CloudFront's free tier (1 TB/month egress, 10M requests) covers
  most early usage entirely. Scales with actual visitor traffic, unlike the
  fixed NAT/App Runner/RDS costs above.

Rough total: **$90-130/month** at low/zero traffic. The two big line items
(NAT, App Runner sizing) are both direct consequences of real product
requirements (outbound calls to Stripe/git hosts; Semgrep's actual resource
needs) documented at the point they were added — see `lib/network-stack.ts`
and `lib/api-stack.ts`.

**If staging is also deployed**, add roughly another **$35-45/month**: a
second `db.t4g.micro` RDS instance (no NAT gateway or VPC endpoint
duplication — staging shares `Nettle-Network`) plus a second 1 vCPU/2 GB App
Runner service at the same sizing as production. Destroy the staging stacks
(see "Tearing it down") when not actively using them if that cost isn't
justified yet — unlike production's database, staging's has no retention
guard, so this is a clean, complete teardown.

## What's deliberately not here yet

- **Asynchronous scanning is now real, but in-process.** A project-tied
  `POST /api/scans`/`/api/scans/repo` (any request that identifies a
  project via its API key) returns immediately with a CREATED scan record;
  `scanner/scanQueue.ts` runs the actual scan afterward, off the request
  path — same in-process async-queue pattern as continuous monitoring's
  detection queue, and for the same reason (no SQS/Fargate/worker
  infrastructure added speculatively before there's real traffic to
  justify it). What this does and doesn't fix, stated honestly: no HTTP
  connection has to stay open for a scan's duration anymore, and a scan
  failure can no longer take an in-flight request down with it — but
  `runScan()` itself still blocks the Node event loop while it executes
  (it shells out to Semgrep via a synchronous, timeout-bounded
  `execFileSync`, unchanged), so this is not true multi-core parallelism.
  A separate worker process/task (ECS/Fargate) is still the next real step
  for that, and for surviving a process crash mid-scan — today's queue is
  memory-only, same disclosed limitation as the detection queue. Scans with
  no project attached (the anonymous try-it-without-an-account flow) are
  deliberately unchanged and stay synchronous.
- **Event retention.** The `events` table has no pruning yet; a scheduled
  cleanup job (EventBridge Scheduler → Lambda/ECS task, matching the
  reasoning in `../docs/DATABASE.md`'s rate-limit-table section, which
  explains why *that* table doesn't need one) is still open.
- **A custom domain for the frontend.** `Nettle-Frontend`'s distribution is
  real and serves over the default `*.cloudfront.net` domain, but there's no
  ACM certificate or Route 53/DNS wiring here — that needs a real domain
  this sandbox doesn't have. Add a `viewerCertificate`/`domainNames` on the
  `Distribution` construct and a validated ACM cert (must be in `us-east-1`
  regardless of the app's own region — a CloudFront requirement) once a
  domain exists.
- **A WAF in front of the frontend or the API.** Neither `Nettle-Frontend`
  nor `Nettle-Api` has AWS WAF attached — CloudFront and App Runner both
  support it, but it's a real ongoing cost/complexity with no concrete rule
  set justified yet at zero traffic. Revisit once there's actual abuse
  traffic to write rules against.
- **SES delivery is implemented but not live-verified.** Password-reset and
  organization-invitation emails both go through the shared
  `backend/src/notifications/email.ts` (SES v2 SDK) — real code, exercised
  in tests against a mocked SES client, IAM-role/credential-chain
  authenticated like every other AWS SDK client in this codebase. What
  cannot be verified from this sandbox: a real send, because that needs a
  **verified SES sending identity** (an address or domain) in the target
  AWS account/region — an unverified `EMAIL_FROM_ADDRESS` will have every
  send rejected by SES itself. Verify a sending identity (and, if the
  account is still in the SES sandbox, verify each recipient too, or
  request production access) before trusting this in production. Set
  `EMAIL_FROM_ADDRESS`, `APP_PASSWORD_RESET_URL`, and
  `APP_ORGANIZATION_INVITE_URL` to enable delivery — the API's own IAM
  instance role already grants `ses:SendEmail`/`ses:SendRawEmail`
  (`ApiInstanceRole` in `lib/api-stack.ts`), scoped to this account/region's
  identities.
- **Cognito.** Auth is real (email/password, scrypt-hashed, hashed opaque
  session tokens, rate-limited) but hand-rolled rather than Cognito-backed —
  revisit if there's a concrete reason (social login, enterprise SSO) to
  want a managed identity provider instead.
- **True per-scan sandboxing.** The whole API service is network-isolated,
  which is real but coarse: one large or malicious upload still runs in the
  same process as everything else. Per-job ephemeral isolation (a Fargate
  task per scan, or a service built for running untrusted code) is the next
  real hardening step once there's actual multi-tenant traffic to protect
  against.

## Tearing it down

```bash
npx cdk destroy Nettle-CI Nettle-Frontend Nettle-Api Nettle-Ecr Nettle-Database Nettle-Network
```

`Nettle-Frontend` must come after `Nettle-CI` (whose deploy role policy
references the frontend bucket/distribution ARNs) and before `Nettle-Api`
(whose `ServiceUrl` the frontend's CSP imports) — CloudFormation refuses to
delete a stack while another stack still imports one of its outputs, so
this order isn't optional. `Nettle-Frontend`'s bucket has
`autoDeleteObjects: true`, so this actually empties and deletes it, unlike
`Nettle-Database` below.

If the staging pair was deployed, tear it down first (no dependents, so
order relative to the above doesn't matter) — unlike `Nettle-Database`, it
has no `RemovalPolicy.RETAIN`/deletion protection, so this actually deletes
the staging database along with the stack, as intended for disposable
infrastructure:

```bash
npx cdk destroy Nettle-Api-Staging Nettle-Database-Staging
```

`Nettle-Database` has `RemovalPolicy.RETAIN` and deletion protection on in
production mode (`production: true` in `bin/app.ts`). These are two separate
guards, and they fail differently:

- `RemovalPolicy.RETAIN` means `cdk destroy Nettle-Database` will *appear to
  succeed* — CloudFormation deletes the stack but deliberately does not
  attempt to delete the RDS instance, leaving it running and orphaned
  outside CDK's management (and still billing). Check the RDS console
  afterward; do not assume the stack disappearing means the database is
  gone.
- RDS's own `deletionProtection: true` is a second, independent guard: even
  a direct `aws rds delete-db-instance` call against the orphaned instance
  above will be rejected until deletion protection is explicitly disabled
  first (`aws rds modify-db-instance --no-deletion-protection`).

Both exist so this one stack — the one holding real customer data — cannot
be deleted by a single mistaken command.
