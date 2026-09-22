#!/usr/bin/env bash
#
# Nettle — CloudShell deployment script.
#
# Runs the exact sequence documented in infra/README.md ("First-time setup"
# and, on later runs, the "picks up code changes" path), plus two fixes this
# repo's actual deploys needed and a plain manual runbook does not enforce:
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
#
# What this script does NOT do, on purpose:
#   - Populate the Stripe application secret (needs real values only a human
#     should type, and never into a script committed to source control).
#   - Deploy Nettle-CI or wire GitHub Actions variables (one-time, and
#     involves pasting values into GitHub's own UI, not this repo).
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
  local status
  status="$(aws cloudformation describe-stacks --stack-name "$stack" \
    --query 'Stacks[0].StackStatus' --output text 2>/dev/null || echo "NOT_FOUND")"

  if [[ "$status" == "ROLLBACK_COMPLETE" ]]; then
    warn "$stack is stuck in ROLLBACK_COMPLETE — deleting so it can be recreated cleanly"
    aws cloudformation delete-stack --stack-name "$stack"
    aws cloudformation wait stack-delete-complete --stack-name "$stack"
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

# ---------------------------------------------------------------------------
# 2. Network + Database
# ---------------------------------------------------------------------------
log "Deploying Nettle-Network and Nettle-Database"
recover_if_rollback_complete "Nettle-Network" || true
recover_if_rollback_complete "Nettle-Database" || true
npx cdk deploy Nettle-Network Nettle-Database --require-approval never

# ---------------------------------------------------------------------------
# 3. ECR repo, then a real image pushed into it — must happen before
#    Nettle-Api's first-ever deploy (see README's "Deploy order" section).
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
# 4. API service
# ---------------------------------------------------------------------------
cd "$INFRA_DIR"
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

log "Deploy complete"
cat <<EOF
Service URL: ${SERVICE_URL}

Next steps (manual — see infra/README.md for details):
  1. Populate the Stripe secret:
       aws secretsmanager put-secret-value --secret-id nettle/application --secret-string '{...}'
  2. Verify: curl ${SERVICE_URL}/health
  3. Deploy CI, once, and wire GitHub Actions repo variables:
       npx cdk deploy Nettle-CI
EOF
