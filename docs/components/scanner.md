# Scanner Component

## Purpose

Static analysis engine that scans uploaded application source code for security gaps, producing a scored report with findings and pass/fail checks.

## Location

- `backend/src/scanner/` — All scanner modules
- `backend/src/routes/scans.routes.ts` — Upload and scan endpoint

## Architecture

The scanner orchestrator (`index.ts`) calls 15 independent scanner modules, each returning `{ findings: Finding[]; passed: Pass[] }`. Results are merged, deduplicated, and scored (0-100 scale, penalties by severity).

## Scanner Modules

| Module | Category | Checks |
|--------|----------|--------|
| `secrets.ts` | Security | 25 hardcoded secret patterns (AWS, Stripe, GitHub, etc.) |
| `dependencies.ts` | Dependencies | Lockfile presence, dependency versions |
| `osvVulnerabilities.ts` | Dependencies | Known CVEs from bundled OSV database |
| `legalPolicy.ts` | Legal & Policy | Privacy policy, terms of service files |
| `aiDisclosure.ts` | AI Disclosure | AI content labeling compliance |
| `authHeuristic.ts` | Authentication | Routes missing auth middleware |
| `semgrepScanner.ts` | Security | SQL/command injection, TLS, CORS, JWT (via Semgrep binary) |
| `securityHeaders.ts` | Security | Helmet, CSP, HSTS, X-Frame-Options, etc. |
| `codeQuality.ts` | Code Quality | Console.log, debug flags, stack traces |
| `cryptoSecurity.ts` | Cryptography | MD5, SHA-1, DES, ECB, Math.random |
| `databaseSecurity.ts` | Database | SQL injection, hardcoded DB URLs |
| `apiSecurity.ts` | API Security | Rate limiting, CORS, cookies, input validation |
| `frontendSecurity.ts` | Frontend Security | localStorage secrets, innerHTML, eval |
| `aiSecurity.ts` | AI Disclosure | AI API keys, prompt injection, token limits |
| `sessionJwt.ts` | Session Management | JWT expiry, algorithm, session stores |

## Scoring

| Severity | Penalty |
|----------|---------|
| Critical | -16 |
| High | -10 |
| Medium | -5 |
| Low | -2 |
| Info | 0 |

Score is clamped to 0-100.

## Dependencies

- `semgrepScanner.ts` requires the `semgrep` binary installed
- `osvVulnerabilities.ts` uses a bundled SQLite database at `src/scanner/osv-data/`
- All other modules are pure TypeScript with no external dependencies

## Tests

- `backend/test/scanner.test.ts` — 25 tests against fixture apps
- Fixtures: `test/fixtures/sample-app/` (insecure) and `test/fixtures/clean-app/` (secure)
- 5 tests require Semgrep binary (fail gracefully when not installed)

## How to Add a New Scanner Module

1. Create `backend/src/scanner/<name>.ts`
2. Export a function: `(files: string[], targetRoot: string) => { findings: Finding[]; passed: Pass[] }`
3. Import and add to the `results` array in `backend/src/scanner/index.ts`
4. Add test assertions to `backend/test/scanner.test.ts`
5. Update fixture apps if needed

## Common Failures

- Semgrep tests failing: Install `pip install semgrep`
- Regex not matching: Test pattern in isolation before adding
- Clean app failing: Update `test/fixtures/clean-app/` to demonstrate the good practice
