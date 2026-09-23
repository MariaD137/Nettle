#!/usr/bin/env bash
#
# Nettle — CloudShell deployment script.
#
# Runs the sequence documented in infra/README.md ("First-time setup" steps
# 1-6 and 9-11, and on later runs, the "picks up code changes" path), plus
# fixes this repo's actual deploys needed and a plain manual runbook does
# not enforce:
#
#   - Docker images are built with --platform linux/amd64 explicitly. App
#     Runner only runs amd64 images; CloudShell's host architecture is not
#     guaranteed (AWS has been rolling out Graviton/ARM CloudShell in some
#     regions), so a plain `docker build` can silently produce an arm64
#     image that App Runner then fails to deploy with no application-level
#     logs at all — the exact failure this script exists to prevent.
#   - A stack stuck in ROLLBACK_COMPLETE (a terminal state CloudFormation
#     will not update out of) is deleted and recreated automatically, rather
#     than requiring a human to notice a confusing "already exists" or
#     "NotStabilized" error and diagnose it from scratch. For Nettle-Api
#     specifically, this also clears the orphaned `nettle/application`
#     Secrets Manager secret — but ONLY when the stack that owns it is
#     itself being torn down as part of that same recovery, and only for a
#     secret confirmed empty. Once a deploy succeeds, the secret is
#     RemovalPolicy.RETAIN and this script never touches it again — that
#     secret goes on to hold real Stripe credentials, and deleting it after
#     that point would be a real incident, not a convenience.
#   - Nettle-Waf-CloudFront is a CLOUDFRONT-scope WAF, which AWS requires to
#     live in us-east-1 regardless of which region everything else deploys
#     to (see lib/waf-stack.ts). This script bootstraps us-east-1
#     separately when the primary region differs, so that deploy doesn't
#     fail on a missing CDK toolkit stack.
#
# What this script does NOT do, on purpose:
#   - Populate the Stripe application secret (needs real values only a human
#     should type, and never into a script committed to source control).
#   - Build or sync the frontend's static assets into the S3 bucket
#     Nettle-Frontend creates. This script deploys the bucket/distribution
#     infrastructure only — actually populating it is frontend-deploy.yml's
#     job (a GitHub Actions workflow), by design (see frontend-stack.ts's
#     own doc comment for why the frontend is deliberately NOT a CDK asset).
#     Until that workflow runs once, the distribution serves an empty
#     bucket.
#   - Request or validate an ACM certificate for a custom frontend domain.
#     That's a manual, external-DNS-provider-dependent process — see
#     infra/README.md's "Custom domain" section. This script deploys
#     Nettle-Frontend either way; set FRONTEND_DOMAIN and
#     FRONTEND_CERTIFICATE_ARN in the environment before running this
#     script if a certificate is already issued and ready.
#   - Wire GitHub Actions repository variables, or add a `production`
#     GitHub Environment with required reviewers (steps 12-13 in
#     infra/README.md). Deploying Nettle-CI creates the IAM role those
#     workflows assume, but pointing GitHub at it means pasting values into
#     GitHub's own UI, not this repo.
#   - Deploy the staging environment (Nettle-Database-Staging,
#     Nettle-Api-Staging) — genuinely optional infrastructure with no other
#     stack depending on it; see infra/README.md's "First-time setup" step
#     14 to add it later.
#   - Run any AWS credential setup. CloudShell already runs as your signed-in
#     IAM identity — this script never asks for, generates, or prints a key,
#     secret, or token.
#
# Usage: run from anywhere inside the repo, in AWS CloudShell (or any shell
# with the AWS CLI v2, Docker, and Node.js 20+ already configured against
# the target account):
#
#   bash infra/scripts/deploy-cloudshell.sh
#
# Safe to re-run. Each step is idempotent: `cdk deploy` on an unchanged stack
# is a no-op, `cdk bootstrap` on an already-bootstrapped account/region is a
# no-op, and the ROLLBACK_COMPLETE recovery only fires when a stack is
# actually stuck.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
INFRA_DIR="$REPO_ROOT/infra"
BACKEND_DIR="$REPO_ROOT/backend"

log() { printf '\n\033[1;36m==>\033[0m %s\n' "$1"; }
warn() { printf '\033[1;33m!!\033[0m %s\n' "$1" >&2; }
die() { printf '\033[1;31mERROR:\033[0m %s\n' "$1" >&2; exit 1; }

command -v aws >/dev/null 2>&1 || die "AWS CLI not found. This script must run somewhere the AWS CLI v2 is already configured (CloudShell has it by default)."
command -v docker >/dev/null 2>&1 || die "Docker not found."
command -v npx >/dev/null 2>&1 || die "Node.js/npx not found (need Node 20+)."

# ---------------------------------------------------------------------------
# 0. Resolve account/region. Never hardcoded: pulled live from the caller's
#    own AWS credentials, so nothing account-specific ever lives in this file.
# ---------------------------------------------------------------------------
log "Resolving AWS account and region"
ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text)"
REGION="${CDK_DEFAULT_REGION:-$(aws configure get region 2>/dev/null || true)}"
REGION="${REGION:-us-east-1}"
export CDK_DEFAULT_ACCOUNT="$ACCOUNT_ID"
export CDK_DEFAULT_REGION="$REGION"
echo "Account: $ACCOUNT_ID"
echo "Region:  $REGION"

REPO_URI="${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com/nettle-api"

# ---------------------------------------------------------------------------
# Helper: recover a stack stuck in ROLLBACK_COMPLETE, a terminal state that
# CloudFormation refuses to update out of — it must be deleted and
# recreated. Any other status (including "stack does not exist") is left
# alone; `cdk deploy` handles both of those cases correctly on its own.
# ---------------------------------------------------------------------------
recover_if_rollback_complete() {
  local stack="$1"
  local region="${2:-$REGION}"
  local status
  status="$(aws cloudformation describe-stacks --stack-name "$stack" --region "$region" \
    --query 'Stacks[0].StackStatus' --output text 2>/dev/null || echo "NOT_FOUND")"

  if [[ "$status" == "ROLLBACK_COMPLETE" ]]; then
    warn "$stack is stuck in ROLLBACK_COMPLETE — deleting so it can be recreated cleanly"
    aws cloudformation delete-stack --stack-name "$stack" --region "$region"
    aws cloudformation wait stack-delete-complete --stack-name "$stack" --region "$region"
    echo "$stack deleted."
    return 0
  fi
  return 1
}

# ---------------------------------------------------------------------------
# 1. Install deps and bootstrap
# ---------------------------------------------------------------------------
log "Installing infra dependencies"
cd "$INFRA_DIR"
npm install

log "Bootstrapping CDK toolkit (no-op if already bootstrapped)"
npx cdk bootstrap "aws://${ACCOUNT_ID}/${REGION}"

# Nettle-Waf-CloudFront is hardcoded to us-east-1 regardless of $REGION (a
# real AWS requirement for a CLOUDFRONT-scope WAF — see lib/waf-stack.ts).
# Bootstrap that region too, if different, or its deploy later fails on a
# missing CDK toolkit stack.
if [[ "$REGION" != "us-east-1" ]]; then
  log "Bootstrapping us-east-1 as well (required for Nettle-Waf-CloudFront's CLOUDFRONT-scope WAF)"
  npx cdk bootstrap "aws://${ACCOUNT_ID}/us-east-1"
fi

# ---------------------------------------------------------------------------
# 2. Network + Database
# ---------------------------------------------------------------------------
log "Deploying Nettle-Network and Nettle-Database"
recover_if_rollback_complete "Nettle-Network" || true
recover_if_rollback_complete "Nettle-Database" || true
npx cdk deploy Nettle-Network Nettle-Database --require-approval never

# ---------------------------------------------------------------------------
# 3. ECR repo, then a real image pushed into it — must happen before
#    Nettle-Api's or Nettle-ScanWorker's first-ever deploy (see README's
#    "Deploy order" section).
# ---------------------------------------------------------------------------
log "Deploying Nettle-Ecr"
recover_if_rollback_complete "Nettle-Ecr" || true
npx cdk deploy Nettle-Ecr --require-approval never

log "Building backend image for linux/amd64 (App Runner's only supported architecture)"
cd "$BACKEND_DIR"
docker build --platform linux/amd64 -t nettle-api .

BUILT_ARCH="$(docker image inspect nettle-api --format '{{.Architecture}}')"
[[ "$BUILT_ARCH" == "amd64" ]] || die "Built image reports architecture '$BUILT_ARCH', not amd64 — App Runner will fail to deploy this. Refusing to push."
echo "Image architecture confirmed: $BUILT_ARCH"

log "Pushing image to ECR"
aws ecr get-login-password --region "$REGION" \
  | docker login --username AWS --password-stdin "${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com"
docker tag nettle-api:latest "${REPO_URI}:latest"
docker push "${REPO_URI}:latest"

# ---------------------------------------------------------------------------
# 4. Scan worker (true scan sandboxing — an isolated ECS Fargate task the
#    API dispatches untrusted scan execution to). Reads the same image just
#    pushed, so must come after step 3; Nettle-Api imports its cluster/task
#    definition/bucket ARNs below, so it must come before Nettle-Api too.
# ---------------------------------------------------------------------------
cd "$INFRA_DIR"
log "Deploying Nettle-ScanWorker"
recover_if_rollback_complete "Nettle-ScanWorker" || true
npx cdk deploy Nettle-ScanWorker --require-approval never

# ---------------------------------------------------------------------------
# 5. API service
# ---------------------------------------------------------------------------
log "Deploying Nettle-Api"
if recover_if_rollback_complete "Nettle-Api"; then
  # Only reachable when Nettle-Api itself was just torn down above. The
  # application secret is RemovalPolicy.RETAIN, so a rolled-back attempt
  # leaves it orphaned under the name the new deploy needs. It is safe to
  # force-delete here specifically because we just confirmed (by finding the
  # stack in ROLLBACK_COMPLETE) that this stack never reached a completed
  # deploy — the secret was created empty and never populated with real
  # Stripe credentials. This branch never runs against a live, healthy
  # Nettle-Api stack.
  SECRET_STATUS="$(aws secretsmanager describe-secret --secret-id nettle/application \
    --query 'ARN' --output text 2>/dev/null || echo "NOT_FOUND")"
  if [[ "$SECRET_STATUS" != "NOT_FOUND" ]]; then
    warn "Deleting orphaned (never-populated) nettle/application secret left behind by the rolled-back deploy"
    aws secretsmanager delete-secret --secret-id nettle/application --force-delete-without-recovery >/dev/null
  fi
fi
npx cdk deploy Nettle-Api --require-approval never

SERVICE_URL="$(aws cloudformation describe-stacks --stack-name Nettle-Api \
  --query "Stacks[0].Outputs[?OutputKey=='ServiceUrl'].OutputValue" --output text)"

# ---------------------------------------------------------------------------
# 6. WAF for the API — associates directly with the App Runner service just
#    created, so must come after step 5.
# ---------------------------------------------------------------------------
log "Deploying Nettle-Waf-Api"
recover_if_rollback_complete "Nettle-Waf-Api" || true
npx cdk deploy Nettle-Waf-Api --require-approval never

# ---------------------------------------------------------------------------
# 7. WAF for CloudFront — no dependency on anything else in this app, but
#    must exist before Nettle-Frontend if the distribution should be
#    created with WAF already attached rather than attaching it with a
#    later update. Always in us-east-1, independent of $REGION.
# ---------------------------------------------------------------------------
log "Deploying Nettle-Waf-CloudFront (us-east-1)"
recover_if_rollback_complete "Nettle-Waf-CloudFront" "us-east-1" || true
npx cdk deploy Nettle-Waf-CloudFront --require-approval never

# ---------------------------------------------------------------------------
# 8. Frontend bucket/distribution — depends on Nettle-Api (CSP imports its
#    ServiceUrl) and Nettle-Waf-CloudFront (WAF attachment). Honors
#    FRONTEND_DOMAIN/FRONTEND_CERTIFICATE_ARN from the environment if
#    already set (see infra/README.md's "Custom domain" section); if unset,
#    the distribution serves only its own *.cloudfront.net domain.
# ---------------------------------------------------------------------------
log "Deploying Nettle-Frontend"
recover_if_rollback_complete "Nettle-Frontend" || true
npx cdk deploy Nettle-Frontend --require-approval never

FRONTEND_OUTPUTS="$(aws cloudformation describe-stacks --stack-name Nettle-Frontend --query "Stacks[0].Outputs")"
BUCKET_NAME="$(echo "$FRONTEND_OUTPUTS" | node -e 'const o=JSON.parse(require("fs").readFileSync(0,"utf8"));process.stdout.write((o.find(x=>x.OutputKey==="BucketName")||{}).OutputValue||"")')"
DISTRIBUTION_ID="$(echo "$FRONTEND_OUTPUTS" | node -e 'const o=JSON.parse(require("fs").readFileSync(0,"utf8"));process.stdout.write((o.find(x=>x.OutputKey==="DistributionId")||{}).OutputValue||"")')"
DISTRIBUTION_DOMAIN="$(echo "$FRONTEND_OUTPUTS" | node -e 'const o=JSON.parse(require("fs").readFileSync(0,"utf8"));process.stdout.write((o.find(x=>x.OutputKey==="DistributionDomainName")||{}).OutputValue||"")')"

# ---------------------------------------------------------------------------
# 9. CI — the IAM role backend-deploy.yml/frontend-deploy.yml/
#    backend-deploy-staging.yml assume. Depends on Nettle-Ecr and
#    Nettle-Frontend (scoped to both). No external secrets needed to
#    deploy the stack itself — only the later GitHub Actions variable
#    wiring (step 12 in infra/README.md) needs a human.
# ---------------------------------------------------------------------------
log "Deploying Nettle-CI"
recover_if_rollback_complete "Nettle-CI" || true
npx cdk deploy Nettle-CI --require-approval never

DEPLOY_ROLE_ARN="$(aws cloudformation describe-stacks --stack-name Nettle-CI \
  --query "Stacks[0].Outputs[?OutputKey=='DeployRoleArn'].OutputValue" --output text)"
REPOSITORY_URI="$(aws cloudformation describe-stacks --stack-name Nettle-Ecr \
  --query "Stacks[0].Outputs[?OutputKey=='RepositoryUri'].OutputValue" --output text)"

log "Deploy complete"
cat <<EOF
Service URL:          ${SERVICE_URL}
Frontend distribution: https://${DISTRIBUTION_DOMAIN}   (empty until frontend-deploy.yml runs — see below)

Next steps (manual — see infra/README.md for full details):

  1. Populate the Stripe secret:
       aws secretsmanager put-secret-value --secret-id nettle/application --secret-string '{
         "STRIPE_SECRET_KEY": "sk_live_...",
         "STRIPE_WEBHOOK_SECRET": "whsec_...",
         "STRIPE_PRICE_BUILD": "price_...",
         "STRIPE_PRICE_PROTECT": "price_..."
       }'
     App Runner picks this up on the next deployment, not live — push a new
     image or run: aws apprunner start-deployment --service-arn <arn>

  2. Verify the API is live:
       curl ${SERVICE_URL}/health

  3. Wire GitHub Actions repository/environment variables (Settings →
     Secrets and variables → Actions → Variables) so pushes to main/develop
     deploy automatically:
       AWS_REGION               = ${REGION}
       AWS_DEPLOY_ROLE_ARN       = ${DEPLOY_ROLE_ARN}
       ECR_REPOSITORY_URI        = ${REPOSITORY_URI}
       FRONTEND_BUCKET_NAME      = ${BUCKET_NAME}
       FRONTEND_DISTRIBUTION_ID  = ${DISTRIBUTION_ID}
       API_BASE_URL              = ${SERVICE_URL}

  4. Run frontend-deploy.yml once (or push to main touching frontend/**) to
     actually populate the frontend bucket — the distribution above serves
     an empty bucket until then.

  5. (Optional) Add a "production" GitHub Environment with required
     reviewers, and/or a custom frontend domain — see infra/README.md's
     "Custom domain" section (set FRONTEND_DOMAIN/FRONTEND_CERTIFICATE_ARN
     and re-run this script, or run "npx cdk deploy Nettle-Frontend" alone).

  6. (Optional) Deploy the staging environment — see infra/README.md's
     "First-time setup" step 14. Not run by this script.
EOF
