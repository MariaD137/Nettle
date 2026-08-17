# Nettle Architecture

## Application Overview

Nettle is a security scanning platform for AI-built ("vibe-coded") applications. It scans uploaded application source code for security gaps, dependency vulnerabilities, legal compliance issues, and AI disclosure requirements, producing a scored report and trust badge.

The platform has two tiers:
- **Tier 1 (Static Scan)**: Upload source code, receive a security report with findings, pass/fail checks, and a 0-100 score.
- **Tier 2 (Continuous Monitoring)**: Customer apps embed a middleware SDK that streams request events to Nettle. A detection engine watches for anomalies (brute-force, credential stuffing, unusual traffic) and raises alerts.

## Technology Stack

| Layer | Technology |
|-------|-----------|
| Backend | Node.js 22, Express 4, TypeScript |
| Frontend | React 18, Vite 8, TypeScript |
| Database | Node.js built-in `node:sqlite` (SQLite, single-file) |
| Infrastructure | AWS CDK (TypeScript), App Runner, ECR, VPC |
| Payments | Stripe (Checkout Sessions, Webhooks) |
| Static Analysis | Semgrep (shelled out), custom regex-based scanners |
| Vulnerability DB | Bundled OSV database (offline, no external API calls) |
| CI/CD | GitHub Actions |

## Frontend

- **Location**: `frontend/`
- **Framework**: React 18 + React Router 7 + Vite 8
- **Entry point**: `frontend/src/main.tsx`
- **Pages**: Dashboard, scan results, billing, auth (login/signup), badge embed
- **API communication**: `frontend/src/api.ts` — fetches from `VITE_API_BASE_URL` (defaults to `http://localhost:8080`)
- **Auth**: `frontend/src/AuthContext.tsx` — session token stored in React context, passed as Bearer token

## Backend / API

- **Location**: `backend/`
- **Entry point**: `backend/src/index.ts`
- **Framework**: Express.js with TypeScript
- **Port**: `PORT` env var, defaults to 8080

### Route modules (`backend/src/routes/`)
| Route file | Prefix | Purpose |
|-----------|--------|---------|
| `health.routes.ts` | `/health` | Health check for App Runner |
| `auth.routes.ts` | `/api/auth/*` | Signup, login, logout, password reset |
| `scans.routes.ts` | `/api/scans` | Upload zip, run scan, retrieve results |
| `projects.routes.ts` | `/api/projects` | CRUD for monitored projects (Tier 2) |
| `events.routes.ts` | `/api/events` | Ingest request events from customer middleware |
| `badge.routes.ts` | `/api/badge/*` | Trust badge SVG and state endpoint |
| `billing.routes.ts` | `/api/billing/*` | Stripe checkout sessions and webhook receiver |

## Database

- **Technology**: `node:sqlite` (Node.js 22 built-in SQLite)
- **Location**: `backend/src/db/index.ts`
- **Storage**: Single file at `NETTLE_DB_PATH` (defaults to `./nettle.db`)
- **Schema**: Created inline via `CREATE TABLE IF NOT EXISTS` on startup (no migration framework)
- **Tables**: `users`, `sessions`, `projects`, `events`, `alerts`, `password_resets`, `scans`
- **Tests**: Use `:memory:` SQLite via `NETTLE_DB_PATH=:memory:`

There is no migration framework. Schema changes are additive (`IF NOT EXISTS`). Destructive changes require manual migration.

## Authentication

- **Location**: `backend/src/auth/`
- **Strategy**: Email/password with session tokens
- **Password hashing**: Node.js `crypto.scrypt` (not bcrypt — zero native dependencies)
- **Sessions**: Random 32-byte hex tokens stored in `sessions` table with expiry
- **Middleware**: `backend/src/auth/middleware.ts` — `requireAuth` extracts Bearer token

## Payments

- **Location**: `backend/src/billing/`
- **Provider**: Stripe
- **Integration**: Checkout Sessions for subscription creation, webhook for fulfillment
- **Environment variables**: `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`, `BILLING_SUCCESS_URL`, `BILLING_CANCEL_URL`
- **Plans**: free, pro, team (defined in billing routes)

## Scanner Engine

- **Location**: `backend/src/scanner/`
- **Orchestrator**: `backend/src/scanner/index.ts` — calls all scanner modules, merges findings
- **File walker**: `backend/src/scanner/walk.ts` — collects `.js/.ts/.jsx/.tsx/.env/.json` files, skips `node_modules/.git/dist/build/.next`

### Scanner modules (15 total)
| Module | Category | What it checks |
|--------|----------|---------------|
| `secrets.ts` | Security | Hardcoded API keys, tokens, credentials (25 patterns) |
| `dependencies.ts` | Dependencies | Lockfile presence, vulnerable dependencies |
| `osvVulnerabilities.ts` | Dependencies | Known CVEs via bundled OSV database |
| `legalPolicy.ts` | Legal & Policy | Privacy policy, terms of service |
| `aiDisclosure.ts` | AI Disclosure | AI-generated content labeling compliance |
| `authHeuristic.ts` | Authentication | Routes missing auth middleware |
| `semgrepScanner.ts` | Security | SQL injection, command injection, TLS, CORS, JWT (via Semgrep) |
| `securityHeaders.ts` | Security | Helmet, CSP, HSTS, X-Frame-Options |
| `codeQuality.ts` | Code Quality | Console.log, debug flags, stack traces, .env files |
| `cryptoSecurity.ts` | Cryptography | Weak algorithms (MD5/SHA1/DES/RC4/ECB), hardcoded keys |
| `databaseSecurity.ts` | Database | SQL injection patterns, hardcoded DB URLs |
| `apiSecurity.ts` | API Security | Rate limiting, CORS, CSRF, cookies, input validation, file uploads |
| `frontendSecurity.ts` | Frontend Security | localStorage secrets, innerHTML, eval, source maps |
| `aiSecurity.ts` | AI Disclosure | AI API keys, prompt injection, token limits, tool execution |
| `sessionJwt.ts` | Session Management | JWT expiry, algorithm, refresh tokens, session stores |

## Tier 2 Monitoring

- **Location**: `backend/src/patrol/`
- **Components**: Projects, events, alerts, detection rules, badge computation
- **Customer middleware**: `backend/src/middleware/nettleMonitor.ts` — Express middleware customers embed
- **Detection**: `backend/src/patrol/detection.ts` — rule-based anomaly detection on ingested events

## Infrastructure

- **Location**: `infra/`
- **Framework**: AWS CDK (TypeScript)
- **Stacks**:
  - `network-stack.ts` — VPC with isolated subnets
  - `api-stack.ts` — ECR repository + App Runner service
  - `ci-stack.ts` — OIDC provider for GitHub Actions deployments
- **Deployment**: Docker image pushed to ECR, App Runner auto-deploys on `:latest` tag update

## Deployment

- **Backend**: Push to `main` triggers `backend-deploy.yml` which builds Docker image and pushes to ECR. App Runner auto-deploys.
- **Frontend**: No automated deployment workflow yet (CI only does lint + build check).
- **Trigger**: Push to `main` branch with changes in `backend/` or `frontend/` paths.

## Testing

- **Location**: `backend/test/`
- **Runner**: Node.js built-in test runner (`node --test`)
- **Test database**: In-memory SQLite (`NETTLE_DB_PATH=:memory:`)
- **Test fixtures**: `backend/test/fixtures/sample-app/` (insecure app) and `backend/test/fixtures/clean-app/` (secure app)
- **Coverage**: Auth, billing, badges, scans, scanner, patrol, monitoring, scan root resolution (8 test files, 63 tests)
- **Frontend tests**: None currently

## Environment Configuration

| Variable | Required | Used by | Purpose |
|----------|----------|---------|---------|
| `PORT` | No | Backend | Server port (default: 8080) |
| `NETTLE_DB_PATH` | No | Backend | SQLite database path (default: `./nettle.db`) |
| `STRIPE_SECRET_KEY` | For billing | Backend | Stripe API key |
| `STRIPE_WEBHOOK_SECRET` | For billing | Backend | Stripe webhook signature verification |
| `BILLING_SUCCESS_URL` | No | Backend | Post-checkout redirect URL |
| `BILLING_CANCEL_URL` | No | Backend | Checkout cancellation redirect URL |
| `VITE_API_BASE_URL` | No | Frontend | API base URL (default: `http://localhost:8080`) |

## Dependencies Between Components

### Tightly coupled
- All backend modules share the same SQLite database via `backend/src/db/index.ts`
- Route handlers depend on auth middleware for protected endpoints
- Scanner modules share `Finding` and `Pass` types from `backend/src/scanner/types.ts`
- Badge computation depends on both scan results and alert data

### Loosely coupled
- Frontend and backend communicate only via HTTP API
- Scanner engine is stateless — can run independently via CLI (`bin/nettle.js`)
- Infrastructure (CDK) is independent of application code
- Each scanner module is independently testable

## Known Risks

1. **Single SQLite file** — no concurrent write safety across processes; suitable for single-instance only
2. **No migration framework** — schema changes require careful manual coordination
3. **Semgrep dependency** — scanner tests that exercise Semgrep fail when the binary isn't installed
4. **No frontend tests** — UI changes have no automated verification
5. **No staging environment** — changes go directly from CI to production on `main` push
6. **CORS is fully open** — acceptable only because auth uses Bearer tokens, not cookies
