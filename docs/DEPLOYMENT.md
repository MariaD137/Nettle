# Deployment

## Architecture

```
feature/* / fix/* branch
        |
        v
   Pull Request
        |
        v
  GitHub Actions CI
  (lint, typecheck, test, build)
        |
        v
     develop
        |
        v
   Pull Request
        |
        v
      main
        |
        v
   GitHub Actions Deploy
   (Docker build -> ECR push)
        |
        v
   AWS App Runner
   (auto-deploys on :latest tag)
```

## Environments

| Environment | Branch | Trigger | Infrastructure |
|------------|--------|---------|---------------|
| Development | Any | Local `npm run dev` | localhost:8080 (backend), localhost:5173 (frontend) |
| CI | Any PR or push to main/develop | Automatic | GitHub Actions runners |
| Production | `main` | Push to main with backend/ changes | AWS App Runner via ECR |

There is currently no staging environment. See "Recommended Staging Setup" below.

## Backend Deployment

### How it works

1. Code is pushed to `main` (via merged PR)
2. `backend-deploy.yml` triggers if `backend/**` files changed
3. Workflow authenticates to AWS via OIDC (no stored credentials)
4. Docker image is built from `backend/Dockerfile`
5. Image is pushed to ECR with both `:latest` and `:<commit-sha>` tags
6. App Runner auto-deploys when it detects a new `:latest` image

### Required GitHub Settings

| Setting | Location | Value |
|---------|----------|-------|
| `AWS_DEPLOY_ROLE_ARN` | Repository Variables | ARN of the OIDC deployment role |
| `AWS_REGION` | Repository Variables | AWS region (e.g., `us-east-1`) |
| `ECR_REPOSITORY_URI` | Repository Variables | Full ECR repository URI |
| Environment: `production` | Repository Environments | Configured with required reviewers |

### Required Runtime Environment Variables

Set these in App Runner's service configuration:

| Variable | Required | Purpose |
|----------|----------|---------|
| `PORT` | No | Server port (default: 8080, App Runner expects 8080) |
| `NETTLE_DB_PATH` | No | SQLite file path (default: `./nettle.db`) |
| `STRIPE_SECRET_KEY` | For billing | Stripe secret key |
| `STRIPE_WEBHOOK_SECRET` | For billing | Stripe webhook signing secret |
| `BILLING_SUCCESS_URL` | No | Post-checkout redirect |
| `BILLING_CANCEL_URL` | No | Checkout cancel redirect |

### Build Command

```bash
cd backend && npm ci && npm run build
```

### Start Command

```bash
node dist/index.js
```

### Health Check

App Runner pings `GET /health` every 10 seconds. The endpoint returns `200 OK` with `{ status: "ok" }`.

## Frontend Deployment

The frontend is a static React SPA built with Vite. There is no automated deployment workflow yet.

### Build

```bash
cd frontend && npm ci && npm run build
```

Output goes to `frontend/dist/`. Deploy the contents to any static hosting (S3 + CloudFront, Vercel, Netlify, etc.).

### Required Build Environment

| Variable | Purpose |
|----------|---------|
| `VITE_API_BASE_URL` | Backend API URL (baked in at build time) |

## Database

SQLite runs embedded in the Node.js process. There is no separate database server.

- **File location**: Controlled by `NETTLE_DB_PATH`
- **Schema**: Created automatically on startup (`CREATE TABLE IF NOT EXISTS`)
- **Migrations**: None (additive schema only)
- **Backup**: Copy the `.db` file from the App Runner instance's ephemeral storage

### Important limitation

App Runner uses ephemeral storage. The SQLite database is lost on each deployment. For production persistence, migrate to RDS or mount an EFS volume.

## Rollback Process

### Quick rollback (redeploy previous image)

```bash
# Find the previous working image tag (commit SHA)
aws ecr describe-images --repository-name nettle-api --query 'sort_by(imageDetails,&imagePushedAt)[-2].imageTags'

# Tag that image as :latest
MANIFEST=$(aws ecr batch-get-image --repository-name nettle-api --image-ids imageTag=<previous-sha> --query 'images[].imageManifest' --output text)
aws ecr put-image --repository-name nettle-api --image-tag latest --image-manifest "$MANIFEST"
```

App Runner will auto-deploy the "new" `:latest`.

### Git rollback

```bash
git revert <bad-commit-sha>
git push origin main
```

This creates a new commit that undoes the change, triggering a normal deployment.

Never use `git push --force` on `main`.

## Recommended Staging Setup

To add a staging environment:

1. Create a second App Runner service (`nettle-api-staging`) pointing to a `:staging` ECR tag
2. Add a `backend-deploy-staging.yml` workflow triggered by pushes to `develop`
3. Use separate environment variables (different Stripe test keys, different DB path)
4. QA against staging before merging `develop` into `main`
