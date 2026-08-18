# Nettle infra

Three stacks, deliberately scoped to what Tier 1 actually needs today — not
a copy of a bigger app's infrastructure:

- **Nettle-Network** — a VPC with isolated subnets only. No NAT gateway, no
  internet gateway at all. The API executes code from strangers; the network
  should make outbound calls impossible by construction, not by convention.
- **Nettle-Api** — an ECR repo + a single App Runner service running the
  API, with its egress routed through the isolated VPC (so: no internet
  access) via a VPC connector, and an `AutoScalingConfiguration` resource
  pinned to `minSize: 1, maxSize: 1`. Still no RDS/Cognito — accounts,
  sessions, projects, scans, and alerts are all real now, but persisted with
  `node:sqlite` on the single container App Runner runs, not a managed
  database, with no shared volume behind it. **`maxSize` is capped at 1 on
  purpose**: a second concurrent instance would boot its own empty SQLite
  file, and requests would silently see different data depending on which
  instance served them. The `AutoScalingConfiguration` resource exists so
  raising the cap later is a one-line CDK change, not a new resource to
  design — do that the same day a shared datastore (RDS, most likely)
  replaces the per-instance SQLite file, not before. That's the actual
  trigger to add RDS: the day this needs to run as more than one container
  for real.
- **Nettle-CI** — a GitHub OIDC provider + a deploy role scoped to exactly
  one permission set: push images to this one ECR repo. No AWS access keys
  are ever stored in GitHub.

## What's validated vs. what isn't

| Checked | How |
|---|---|
| All three stacks synthesize to valid CloudFormation | Ran `cdk synth` — caught and fixed one real issue this way (a security group description containing an em-dash, which CloudFormation's validation pattern rejects) |
| The `AutoScalingConfiguration` resource synthesizes and is wired to the service | Ran `cdk synth Nettle-Api` — confirmed `AWS::AppRunner::AutoScalingConfiguration` in the template and `ApiService.Properties.AutoScalingConfigurationArn` pointing at it |
| The VPC has no NAT gateway or internet gateway | Inspected the synthesized template's resource list directly — confirmed absent |
| Docker image build | **Not run** — no Docker daemon available in this sandbox, same limitation hit building RavelGo. Build it yourself once (`docker build -t nettle-api backend/`) before relying on the deploy workflow |
| Actual `cdk deploy` / real AWS resources | **Not run** — needs a real AWS account and credentials, which should never be pasted into a chat session |

## First-time setup

1. **Have an AWS account.** If you don't have one connected yet, this is the
   point to create it — everything above this was buildable and testable
   without one, deploying isn't.
2. From your own machine (not this chat): `aws configure` with credentials
   for that account, then from `infra/`:
   ```bash
   npm install
   npx cdk bootstrap
   npx cdk deploy --all
   ```
3. Manually build and push a first image so the App Runner service has
   something to run (`AutoDeploymentsEnabled` only triggers on *new* pushes
   to `:latest`, it needs one image to exist first):
   ```bash
   cd ../backend
   docker build -t nettle-api .
   aws ecr get-login-password --region <region> | docker login --username AWS --password-stdin <account-id>.dkr.ecr.<region>.amazonaws.com
   docker tag nettle-api:latest <account-id>.dkr.ecr.<region>.amazonaws.com/nettle-api:latest
   docker push <account-id>.dkr.ecr.<region>.amazonaws.com/nettle-api:latest
   ```
4. **Wire GitHub Actions.** Add these repository variables (Settings ->
   Secrets and variables -> Actions -> Variables), all from the `cdk deploy`
   output: `AWS_REGION`, `AWS_DEPLOY_ROLE_ARN` (the `Nettle-CI` stack's
   `DeployRoleArn` output), `ECR_REPOSITORY_URI` (the `Nettle-Api` stack's
   `RepositoryUri` output).
5. **(Recommended)** Add a `production` GitHub Environment with required
   reviewers, so a push to `main` pauses for approval before it touches AWS.
6. From here on, every push to `main` touching `backend/**` builds a new
   image and pushes it — App Runner picks up the new `:latest` tag
   automatically.

## Cost notes (estimates, not sourced pricing — check AWS's current pricing page)

- App Runner at the smallest tier (0.25 vCPU / 0.5 GB), running continuously:
  roughly $10-25/month. This is the main ongoing cost.
- No NAT gateway: this alone is typically $32-45/month saved compared to a
  VPC that has one — a deliberate choice, not an oversight.
- ECR image storage: a few cents/month at this scale.
- VPC, subnets, security groups, IAM, the OIDC provider: no charge.

Rough total: well under $30/month at zero traffic, before any database or
Tier 2 infrastructure gets added.

## What's deliberately not here yet

- **RDS / a database.** Accounts, projects, scans, and alerts are real and
  persisted, just on `node:sqlite` inside the one App Runner container —
  add RDS/Aurora the day this needs to run as more than one instance, not
  before.
- **Cognito.** Auth is real (email/password, scrypt-hashed, opaque session
  tokens) but hand-rolled rather than Cognito-backed — revisit if there's a
  concrete reason (social login, SSO for enterprise customers) to want a
  managed identity provider instead.
- **A queue between Tier 2 intake and detection** (Kinesis, per the earlier
  architecture notes) — `POST /api/events` runs detection inline on the
  request today. Fine at low volume; add the queue when there's real
  traffic to justify it.
- **A frontend deployment.** `frontend/` is real and browser-tested, but
  isn't part of this CDK app yet — needs its own static hosting
  (S3+CloudFront, or similar) and a `VITE_API_BASE_URL` pointed at wherever
  the API ends up deployed.
- **True per-scan sandboxing** — today the whole API service is network-
  isolated, which is real but coarse-grained: one large or malicious upload
  still runs in the same process as everything else. Per-job ephemeral
  isolation (a Fargate task per scan, or a service like e2b/Modal built for
  running untrusted code) is the next real hardening step once there's
  actual multi-tenant traffic to protect against.
