# Nettle infra

Five stacks, each scoped to one concern:

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
- **Nettle-CI** — a GitHub OIDC provider + a deploy role scoped to exactly
  one permission set: push images to the Nettle-Ecr repo. No AWS access
  keys are ever stored in GitHub.

## What's validated vs. what isn't

| Checked | How |
|---|---|
| All five stacks synthesize to valid CloudFormation | `cdk synth` |
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
Nettle-Network  →  Nettle-Database  →  Nettle-Ecr  →  [push an image]  →  Nettle-Api  →  Nettle-CI
```

**Nettle-Ecr must be deployed, and a real image pushed into it, before
Nettle-Api is deployed for the first time.** `AWS::AppRunner::Service`
references the image at `:latest` and CloudFormation waits for the service
to reach `RUNNING` before the resource is considered created. On a first-ever
deploy there is no image yet — if the ECR repo and the App Runner service
were in the same stack (an earlier version of this code had them together),
the service would fail to pull, CloudFormation would roll back the *entire*
stack, and it would delete the ECR repo it had just created moments earlier
along with everything else. Splitting them into separate stacks is what
breaks that chicken-and-egg — see `lib/ecr-stack.ts`.

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

**7. Deploy CI:**

```bash
npx cdk deploy Nettle-CI
```

**8. Wire GitHub Actions.** Add these repository variables (Settings →
Secrets and variables → Actions → Variables):

| Variable | Value |
|---|---|
| `AWS_REGION` | the region you deployed to |
| `AWS_DEPLOY_ROLE_ARN` | `Nettle-CI` stack's `DeployRoleArn` output |
| `ECR_REPOSITORY_URI` | `Nettle-Ecr` stack's `RepositoryUri` output |

**9. (Recommended)** Add a `production` GitHub Environment with required
reviewers, so a push to `main` pauses for approval before it touches AWS —
`backend-deploy.yml` already targets the `production` environment.

From here on, every push to `main` touching `backend/**` builds a new image
and pushes `:latest` — App Runner's `autoDeploymentsEnabled: true` picks it
up automatically, no separate deploy step needed.

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

Rough total: **$90-130/month** at low/zero traffic. The two big line items
(NAT, App Runner sizing) are both direct consequences of real product
requirements (outbound calls to Stripe/git hosts; Semgrep's actual resource
needs) documented at the point they were added — see `lib/network-stack.ts`
and `lib/api-stack.ts`.

## What's deliberately not here yet

- **Asynchronous scanning.** `runScan` still runs on the request path inside
  the single App Runner service; a large scan can still block that
  instance's event loop. An SQS+worker (or ECS/Fargate task) architecture is
  designed but not implemented.
- **Event retention.** The `events` table has no pruning yet; a scheduled
  cleanup job (EventBridge Scheduler → Lambda/ECS task, matching the
  reasoning in `../docs/DATABASE.md`'s rate-limit-table section, which
  explains why *that* table doesn't need one) is still open.
- **A frontend deployment.** `frontend/` is real and browser-tested, but
  isn't part of this CDK app yet — needs its own static hosting
  (S3+CloudFront) and a `VITE_API_BASE_URL` pointed at the `ServiceUrl`
  above.
- **SES / real password-reset email delivery.** Reset tokens are generated
  and stored securely (see `backend/src/notifications/passwordResetDelivery.ts`)
  but nothing sends the email yet — `PASSWORD_RESET_FROM_ADDRESS` and
  `APP_PASSWORD_RESET_URL` mark where a real provider gets wired in.
  Requires a verified SES sending identity, which is itself a deployment
  prerequisite this CDK app doesn't set up.
- **A working staging deploy target.** `backend-deploy-staging.yml` pushes
  an image tagged `:staging` to the same ECR repo, but there's only one App
  Runner service (watching `:latest`) — nothing currently reads that tag. A
  second, smaller App Runner service (or a second environment's stacks
  entirely) is needed before that workflow does anything but push an unused
  image.
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
npx cdk destroy Nettle-CI Nettle-Api Nettle-Ecr Nettle-Database Nettle-Network
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
