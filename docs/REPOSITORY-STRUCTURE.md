# Repository Structure

```
Nettle/
├── .github/
│   └── workflows/
│       ├── backend-ci.yml          # Lint + test on PRs and main pushes (backend/)
│       ├── backend-deploy.yml      # Docker build + ECR push on main push (backend/)
│       └── frontend-ci.yml         # Lint + build on PRs and main pushes (frontend/)
│
├── backend/                        # Express.js API and scanner engine
│   ├── bin/
│   │   └── nettle.js               # CLI entry point for standalone scanning
│   ├── src/
│   │   ├── auth/                   # Authentication: users, passwords, sessions, middleware
│   │   │   ├── middleware.ts       # requireAuth Express middleware
│   │   │   ├── passwords.ts       # scrypt hashing and verification
│   │   │   ├── sessions.ts        # Session token CRUD
│   │   │   └── users.ts           # User creation and lookup
│   │   ├── billing/
│   │   │   └── stripeClient.ts    # Stripe SDK initialization
│   │   ├── db/
│   │   │   └── index.ts           # SQLite database connection and schema
│   │   ├── middleware/
│   │   │   ├── nettleMonitor.ts   # Customer-facing SDK middleware (Tier 2)
│   │   │   └── rateLimit.ts       # In-memory rate limiting middleware
│   │   ├── patrol/                # Tier 2: continuous monitoring
│   │   │   ├── alerts.ts          # Alert creation and queries
│   │   │   ├── badge.ts           # Trust badge state computation and SVG rendering
│   │   │   ├── detection.ts       # Rule-based anomaly detection
│   │   │   ├── events.ts          # Event ingestion and queries
│   │   │   ├── projects.ts        # Project CRUD
│   │   │   ├── scans.ts           # Scan result persistence
│   │   │   └── types.ts           # Patrol type definitions
│   │   ├── routes/                # Express route handlers
│   │   │   ├── auth.routes.ts
│   │   │   ├── badge.routes.ts
│   │   │   ├── billing.routes.ts
│   │   │   ├── events.routes.ts
│   │   │   ├── health.routes.ts
│   │   │   ├── projects.routes.ts
│   │   │   └── scans.routes.ts
│   │   ├── scanner/               # Tier 1: static analysis engine (15 modules)
│   │   │   ├── index.ts           # Scanner orchestrator
│   │   │   ├── types.ts           # Finding, Pass, ScanReport types
│   │   │   ├── walk.ts            # File system walker
│   │   │   ├── secrets.ts         # Hardcoded secrets detection (25 patterns)
│   │   │   ├── dependencies.ts    # Lockfile and dependency checks
│   │   │   ├── osvVulnerabilities.ts # CVE scanning via bundled OSV DB
│   │   │   ├── legalPolicy.ts     # Privacy policy and terms detection
│   │   │   ├── aiDisclosure.ts    # AI content labeling compliance
│   │   │   ├── authHeuristic.ts   # Missing auth middleware detection
│   │   │   ├── semgrepScanner.ts  # Semgrep integration (SQL/command injection, TLS, CORS)
│   │   │   ├── securityHeaders.ts # HTTP security headers
│   │   │   ├── codeQuality.ts     # Debug code, stack traces, .env files
│   │   │   ├── cryptoSecurity.ts  # Weak crypto algorithms
│   │   │   ├── databaseSecurity.ts # SQL injection, hardcoded DB URLs
│   │   │   ├── apiSecurity.ts     # Rate limiting, CORS, CSRF, cookies, input validation
│   │   │   ├── frontendSecurity.ts # localStorage, innerHTML, eval
│   │   │   ├── aiSecurity.ts      # AI API keys, prompt injection, token limits
│   │   │   ├── sessionJwt.ts      # JWT and session management
│   │   │   ├── resolveScanRoot.ts # Upload extraction and root detection
│   │   │   ├── semgrep-rules/     # Semgrep YAML rule files
│   │   │   └── osv-data/          # Bundled vulnerability database
│   │   └── index.ts               # Express app entry point
│   ├── test/
│   │   ├── fixtures/
│   │   │   ├── sample-app/        # Intentionally insecure app (for scanner tests)
│   │   │   └── clean-app/         # Secure app (for scanner tests)
│   │   ├── auth.test.ts
│   │   ├── badge.test.ts
│   │   ├── billing.test.ts
│   │   ├── nettleMonitor.test.ts
│   │   ├── patrol.test.ts
│   │   ├── resolveScanRoot.test.ts
│   │   ├── scanner.test.ts
│   │   └── scans.test.ts
│   ├── scripts/
│   │   └── build-osv-db.js        # Script to rebuild the bundled OSV database
│   ├── Dockerfile                 # Multi-stage Docker build
│   ├── .dockerignore
│   ├── .gitignore
│   ├── package.json
│   ├── package-lock.json
│   └── tsconfig.json
│
├── frontend/                      # React SPA (Vite)
│   ├── src/
│   │   ├── App.tsx                # Main app with routing
│   │   ├── AuthContext.tsx        # Auth state management
│   │   ├── api.ts                 # API client
│   │   ├── main.tsx               # React DOM entry point
│   │   ├── styles.css             # Global styles
│   │   └── vite-env.d.ts          # Vite type declarations
│   ├── index.html
│   ├── package.json
│   ├── package-lock.json
│   ├── tsconfig.json
│   └── vite.config.ts
│
├── infra/                         # AWS CDK infrastructure
│   ├── bin/
│   │   └── app.ts                 # CDK app entry point
│   ├── lib/
│   │   ├── api-stack.ts           # ECR + App Runner service
│   │   ├── ci-stack.ts            # GitHub OIDC for deployments
│   │   └── network-stack.ts       # VPC with isolated subnets
│   ├── cdk.json
│   ├── package.json
│   ├── package-lock.json
│   └── tsconfig.json
│
├── docs/                          # Project documentation
│   ├── ARCHITECTURE.md
│   └── REPOSITORY-STRUCTURE.md
│
└── README.md
```
