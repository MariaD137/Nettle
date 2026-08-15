# Troubleshooting

## Standard Repair Workflow

1. **Identify the affected component** — which part of the app is broken? (auth, scanner, billing, patrol, frontend, infra)
2. **Create a fix branch from develop**:
   ```bash
   git checkout develop
   git pull --ff-only origin develop
   git checkout -b fix/<component>-<problem>
   ```
3. **Reproduce the problem** — write a failing test if possible
4. **Identify root cause** — read the relevant source files, check logs
5. **Make the smallest safe change** — fix only the broken behavior
6. **Run component tests**:
   ```bash
   cd backend
   NETTLE_DB_PATH=:memory: node --import tsx --test test/<relevant>.test.ts
   ```
7. **Run the full test suite**:
   ```bash
   cd backend && npm test
   ```
8. **Run the build**:
   ```bash
   cd backend && npm run build
   cd frontend && npm run build
   ```
9. **Commit and push**:
   ```bash
   git add <specific-files>
   git commit -m "fix: <description>"
   git push -u origin fix/<component>-<problem>
   ```
10. **Open a pull request** to `develop`
11. **Review CI results** — all checks must pass
12. **Merge into develop** — QA the fix
13. **Open a PR from develop to main**
14. **Merge into main** — triggers production deployment
15. **Verify production** — check the `/health` endpoint, test the fixed behavior

## Emergency Hotfix Workflow

For critical production issues that can't wait for the develop flow:

```bash
git checkout main
git pull --ff-only origin main
git checkout -b hotfix/<problem>

# Make the fix
# Test locally
cd backend && npm test && npm run build

git add <specific-files>
git commit -m "fix: <description>"
git push -u origin hotfix/<problem>
```

Open a PR directly to `main`. After merging:

```bash
# Bring the fix into develop
git checkout develop
git pull --ff-only origin develop
git merge --no-ff main
git push origin develop
```

## Component-Specific Troubleshooting

### Authentication issues

- **Files**: `backend/src/auth/`, `backend/src/routes/auth.routes.ts`
- **Tests**: `backend/test/auth.test.ts`
- **Common issues**:
  - Session token not being sent: Check `Authorization: Bearer <token>` header
  - Password validation failing: Check `passwords.ts` scrypt parameters
  - Session expired: Check `sessions.ts` expiry window

### Scanner not detecting issues

- **Files**: `backend/src/scanner/`
- **Tests**: `backend/test/scanner.test.ts`
- **Common issues**:
  - Semgrep not installed: 5 tests will fail — install with `pip install semgrep`
  - New patterns not matching: Test regex against sample input before adding
  - File not being scanned: Check `walk.ts` extension filter and skip patterns

### Billing / Stripe issues

- **Files**: `backend/src/billing/`, `backend/src/routes/billing.routes.ts`
- **Tests**: `backend/test/billing.test.ts`
- **Common issues**:
  - Webhook signature verification failing: Ensure `STRIPE_WEBHOOK_SECRET` is correct
  - Checkout session failing: Ensure `STRIPE_SECRET_KEY` is set
  - Webhook must be mounted before `express.json()` (raw body needed for signature)

### Badge not updating

- **Files**: `backend/src/patrol/badge.ts`, `backend/src/routes/badge.routes.ts`
- **Tests**: `backend/test/badge.test.ts`
- **Common issues**:
  - Badge shows "unknown": No scan has been recorded for the project
  - Badge shows "caution" for clean app: Check if any medium+ findings exist
  - SVG not rendering: Check `renderBadgeSVG` width calculations

### Database errors

- **Files**: `backend/src/db/index.ts`
- **Common issues**:
  - "database is locked": Multiple processes accessing the same SQLite file
  - "UNIQUE constraint failed": Duplicate email or API key
  - "no such table": Application didn't start cleanly (schema creation failed)

### Frontend not connecting to backend

- **Files**: `frontend/src/api.ts`
- **Common issues**:
  - CORS errors: Backend CORS is open, check if the backend is running
  - 404s: Check that the API route path matches
  - Auth failures: Check that the token is being sent in the Authorization header

### CI failures

- Backend CI installs Semgrep via pip — if the pip install fails, all Semgrep-dependent tests fail
- Frontend CI runs `tsc --noEmit` as the lint step — any type error fails the build
- Tests use in-memory SQLite — no database setup needed in CI

## Checking Production Health

```bash
curl https://<your-app-runner-url>/health
# Expected: {"status":"ok"}
```

## Viewing Recent Deployments

Check the `backend-deploy.yml` workflow runs in GitHub Actions, or check the App Runner service in the AWS Console for deployment history.
