# Nettle infra

Three stacks, deliberately scoped to what Tier 1 actually needs today — not
a copy of a bigger app's infrastructure:

- **Nettle-Network** — a VPC with isolated subnets only. No NAT gateway, no
  internet gateway at all. The API executes code from strangers; the network
  should make outbound calls impossible by construction, not by convention.
- **Nettle-Api** — an ECR repo + a single App Runner service running the
  Tier 1 API, with its egress routed through the isolated VPC (so: no
  internet access) via a VPC connector. No RDS, no Cognito — there's no
  persistent data model yet, so there's nothing for a database to hold.
- **Nettle-CI** — a GitHub OIDC provider + a deploy role scoped to exactly
  one permission set: push images to this one ECR repo. No AWS access keys
  are ever stored in GitHub.

## What's validated vs. what isn't

| Checked | How |
|---|---|
| All three stacks synthesize to valid CloudFormation | Ran `cdk synth` — caught and fixed one real issue this way (a security group description containing an em-dash, which CloudFormation's validation pattern rejects) |
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

- **RDS / a database** — add it when there's an actual reason (accounts,
  saved scan history), not before.
- **Cognito / user accounts** — same reasoning.
- **Tier 2 infrastructure** (Kinesis, the detection worker, alerting) — add
  it when Tier 2 development starts, not speculatively now.
- **True per-scan sandboxing** — today the whole API service is network-
  isolated, which is real but coarse-grained: one large or malicious upload
  still runs in the same process as everything else. Per-job ephemeral
  isolation (a Fargate task per scan, or a service like e2b/Modal built for
  running untrusted code) is the next real hardening step once there's
  actual multi-tenant traffic to protect against.
