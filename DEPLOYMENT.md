# Nettle Deployment Guide

## Prerequisites

- Node.js 20+ 
- Docker and Docker Compose
- AWS account with CDK installed
- GitHub account for CI/CD

## Local Development

### 1. Setup Environment

```bash
# Clone and install dependencies
git clone https://github.com/MariaD137/Nettle.git
cd Nettle

# Backend setup
cd backend
npm install
cp .env.example .env.local

# Frontend setup
cd ../frontend
npm install
```

### 2. Environment Variables

Create `.env.local` in the backend directory:

```bash
# Database
NETTLE_DB_PATH=./nettle.db

# Authentication
NETTLE_WEBHOOK_SECRET=dev-webhook-secret

# Stripe (leave blank for testing)
STRIPE_SECRET_KEY=
STRIPE_WEBHOOK_SECRET=

# Server
PORT=8080
NODE_ENV=development
```

### 3. Run Locally

```bash
# Terminal 1: Backend
cd backend
npm run dev

# Terminal 2: Frontend
cd frontend
npm run dev
```

Backend runs on `http://localhost:8080`  
Frontend runs on `http://localhost:5173`

## Docker Deployment

### 1. Build Image

```bash
docker build -t nettle:latest .
```

### 2. Run Container

```bash
docker run -p 8080:8080 \
  -e NODE_ENV=production \
  -e NETTLE_DB_PATH=/data/nettle.db \
  -e STRIPE_SECRET_KEY=$STRIPE_SECRET_KEY \
  -v nettle-data:/data \
  nettle:latest
```

## AWS App Runner Deployment

### 1. Push to ECR

```bash
# Authenticate to ECR
aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin $ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com

# Tag and push
docker tag nettle:latest $ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com/nettle:latest
docker push $ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com/nettle:latest
```

### 2. Deploy with CDK

```bash
cd infra
npm install
cdk deploy --all
```

The CDK stack creates:
- VPC with no internet gateway (isolated)
- App Runner service
- GitHub OIDC role for CI/CD

### 3. Configure Production Secrets

After deployment, set secrets in App Runner:

```bash
aws apprunner update-service \
  --service-arn $SERVICE_ARN \
  --instance-configuration \
    Cpu=0.25,Memory=512,InstanceRoleArn=$ROLE_ARN \
  --source-configuration \
    ImageRepository={ImageIdentifier=$IMAGE_URI,ImageRepositoryType=ECR}
```

Environment variables to set:
- `NODE_ENV=production`
- `STRIPE_SECRET_KEY` (from Stripe dashboard)
- `STRIPE_WEBHOOK_SECRET` (from Stripe webhooks)

## Database (PostgreSQL, required)

The backend's code side of this is done: `backend/src/db/index.ts` is
PostgreSQL-only, with no SQLite fallback — it requires a real `DATABASE_URL`
(or `PGHOST`/`PGPORT`/`PGUSER`/`PGPASSWORD`/`PGDATABASE`) to start at all.
What's still a real, un-taken step is provisioning RDS in an actual AWS
account — nothing in this repository does that on its own.

### Provisioning RDS

This repo already has a real CDK stack for this — use it rather than
hand-running `aws rds create-db-instance`:

```bash
cd infra
npx cdk deploy Nettle-Database
```

This prints `DatabaseEndpoint` and `DatabaseSecretArn`. Fill both into
`infra/lib/api-stack.ts`'s `NettleApiStack` props (`databaseEndpointAddress`,
`databaseSecretArn` — see `infra/bin/app.ts`'s comment there) and redeploy
`Nettle-Api`; that's what actually wires `PGHOST`/`PGPORT`/`PGUSER`/
`PGPASSWORD`/`PGDATABASE` into the running App Runner service. See
`AWS_GITHUB_DEPLOYMENT.md` §6–7 for the full walkthrough.

### Applying the schema

```bash
cd backend
export DATABASE_URL="postgres://user:pass@<endpoint-from-above>:5432/nettle"
npm run db:migrate:postgres
```

Safe to run repeatedly — it only applies migrations under
`backend/src/db/postgres/migrations/` that haven't already run
(`schema_migrations` tracks what's applied). The server itself also runs
this automatically at startup before accepting requests.

## Monitoring & Observability

### Structured Logging

Enable CloudWatch Logs integration:

```bash
# Add to App Runner environment
export AWS_REGION=us-east-1
export LOG_GROUP=/aws/apprunner/nettle
```

### Metrics

CloudWatch automatically metrics:
- CPU and memory utilization
- Request count and latency
- Error rate

View in CloudWatch dashboard.

### Health Checks

App Runner automatically health-checks `/health` endpoint every 10 seconds.

## Backup & Disaster Recovery

### Database Backups

1. **Enable automated backups** (AWS RDS)
   ```bash
   aws rds modify-db-instance \
     --db-instance-identifier nettle-db \
     --backup-retention-period 30
   ```

2. **Test restore**
   ```bash
   aws rds restore-db-instance-from-db-snapshot \
     --db-instance-identifier nettle-db-restored \
     --db-snapshot-identifier nettle-db-backup-xyz
   ```

### Data Export

Export database weekly to S3:

```bash
aws s3 cp s3://nettle-backups/$(date +%Y-%m-%d).sql.gz .
```

## Scaling

### Horizontal Scaling

App Runner automatically scales based on CPU/memory. Adjust in CDK:

```typescript
const service = new apprunner.Service(this, 'NettleService', {
  source: apprunner.Source.fromEcrRepository({ ... }),
  cpu: apprunner.Cpu.ONE,           // 1 vCPU
  memory: apprunner.Memory.TWO_GB,  // 2 GB
  desiredCount: 3,                  // 3 instances
});
```

### Database Connection Pooling

With RDS, enable connection pooling:

```bash
# PgBouncer setup (or use RDS Proxy)
export DATABASE_POOL_MAX=20
export DATABASE_IDLE_TIMEOUT=300
```

## Troubleshooting

### App Runner Service Crashed

1. Check logs
   ```bash
   aws apprunner describe-service --service-arn $ARN
   aws logs tail /aws/apprunner/nettle --follow
   ```

2. Check security group
   ```bash
   aws ec2 describe-security-groups --group-ids sg-xxx
   ```

### High Latency

1. **Check database indexes**
   ```sql
   SELECT * FROM pg_stat_user_indexes ORDER BY idx_scan DESC;
   ```

2. **Enable query logging**
   ```bash
   ALTER SYSTEM SET log_min_duration_statement = 1000;
   ```

3. **Check CloudWatch metrics** for CPU/memory spikes

### Out of Disk Space (RDS)

RDS storage is provisioned separately from the app (`allocatedStorage` in
`infra/lib/database-stack.ts`) and doesn't grow unbounded from normal use.
If it does fill up, `backend/src/patrol/retention.ts`'s cleanup (triggered
via `POST /api/internal/retention/cleanup`, see `RETENTION_*_DAYS` env
vars) already prunes old events/alerts/scans/webhook_events on whatever
schedule you point a cron trigger at — that's the mechanism to use, not a
manual `DELETE`/`VACUUM` against the database directly.

## Production Checklist

- [ ] RDS database configured and tested
- [ ] Automated backups enabled (30-day retention)
- [ ] App Runner HTTPS certificate configured
- [ ] Environment secrets set (Stripe keys, etc.)
- [ ] CloudWatch Logs enabled
- [ ] Health checks passing
- [ ] Rate limiting active on scan endpoints
- [ ] Webhook retry logic verified
- [ ] CORS policy configured for production domain
- [ ] SSL/TLS certificate installed
- [ ] Disaster recovery tested (restore from snapshot)
- [ ] Monitoring alerts configured
- [ ] Load testing completed
- [ ] Security audit passed

## CI/CD Pipeline

### GitHub Actions Workflow

Automatically runs on every commit:

1. **Lint** — TypeScript, ESLint
2. **Test** — Full test suite
3. **Build** — Docker image
4. **Push** — to ECR on `main` branch
5. **Deploy** — App Runner updates automatically

Workflows in `.github/workflows/`:
- `ci.yml` — lint + test
- `deploy.yml` — build + push
