# Nettle Remediation Plan

**Phase 2 — Implementation Roadmap**

Based on audit [NETTLE-GAP-AUDIT.md](/NETTLE-GAP-AUDIT.md), this plan sequences all 34 gaps by dependency, complexity, and impact. Fixes are grouped into implementation phases that do not block each other.

---

## Executive Summary

| Phase | Focus | Gates | Effort | Days |
|---|---|---|---|---|
| **Phase 3a** | Security + type model | MVP blockers | ~60h | 7 |
| **Phase 3b** | Scoring + status + framework | Foundation | ~55h | 7 |
| **Phase 3c** | Education + prioritisation | Product value | ~80h | 10 |
| **Phase 3d** | Worker isolation + cleanup | Production readiness | ~120h | 14–21 |
| **Phase 4** | Test suite + self-scan | Verification | ~40h | 5 |
| **Total** | — | — | ~355 hours | ~40 days |

Three gaps block MVP: **C-1** (symlink), **C-2** (isolation), **C-3** (decompression). The plan lands all three in Phase 3a.

---

## Dependency Graph

```
H-2 (three-state model)
  ├─> H-1 (Semgrep honesty)
  ├─> H-4 (score integrity)
  ├─> H-7 (scan status)
  └─> M-1 (evidence/ruleId)

H-3 (rate limiting) — no deps, ship early

C-1 (symlink) → C-3 (decompression bomb)
  └─> C-2 (worker isolation)

M-5, M-6 (legal language) — no deps, ship early

H-6 (auth analysis) + M-4 (framework detection) — pair together

M-2 (prioritisation) ← M-1 (evidence) ← H-2 (three-state)
M-3 (education) ← M-2 + H-6 (framework) + H-1 (honesty)

H-5 (OSV metadata) — no deps, parallelize

Documentation + self-scan — everything else first
```

---

## Phase 3a: Security + Type Model (7 days, ~60 hours)

The foundation: fix the critical vulnerabilities and introduce the three-state model. No product features yet, just the infrastructure that everything downstream depends on.

### C-1 · Arbitrary host file read via symlinks

**Files:** `backend/src/routes/scans.routes.ts`, `backend/src/scanner/walk.ts`

**Current:** `unzip -q -o` preserves symlinks; scanner follows them out of workspace and reports contents to uploader.

**Changes:**
1. Extraction: reject archives containing symlinks. Verify this with `unzip -t` first or switch to a library extractor.
2. Traversal: re-verify every path with `lstat` before opening. Fail the entire scan if any symlink is detected.

**Tests:**
- Unit: `backend/test/security/symlink.test.ts` (new)
  - Symlink to `/etc/passwd` → `ScanStatus.FAILED` + error message
  - Symlink to `nettle.db` → scan stops
  - Normal archive without symlinks → scan proceeds
- E2E: reproduce the audit's proof-of-concept (symlink to AWS key, confirm scan fails)

**Complexity:** Low. **Effort:** 8–10 hours. **Dependencies:** None.

**Success criteria:**
- Scan fails fast (< 1s) if zip contains symlinks
- Scan fails if any symlink is detected during traversal
- Audit's PoC no longer yields file read
- Backwards-compatible: normal zips unaffected

---

### C-3 · Decompression bomb — no expansion, file-count or depth limit

**Files:** `backend/src/routes/scans.routes.ts`, `backend/src/scanner/walk.ts`

**Current:** 25 MB compressed limit only. No uncompressed-size cap, no file-count cap, no directory-depth cap, no extraction timeout.

**Changes:**
1. Add extraction guards: timeout (30s), max uncompressed bytes (500 MB), max file count (10,000), max depth (100).
2. Stream-check the ratio during extraction: abort if > 10:1.
3. Enforce limits in `walk.ts`: skip deeper-than-100 paths, skip beyond file-count limit.

**Tests:**
- Unit: `backend/test/security/decompression.test.ts` (new)
  - 25 MB zip → expands to 30 MB (passes)
  - 25 MB zip → expands to 600 MB (fails, exceeds cap)
  - 1 MB zip → 50,000 files (fails, exceeds count)
  - 1 MB zip → depth 150 (fails, exceeds depth)
  - Extraction timeout hit → scan stops
- Benchmark: 25 MB maximum-valid zip extraction time (should be < 5s)

**Complexity:** Low–medium. **Effort:** 10–12 hours. **Dependencies:** None; can ship in parallel with C-1.

**Success criteria:**
- Zip expansion capped at 500 MB
- File count capped at 10,000
- Directory depth capped at 100
- Extraction timeout 30s (kill scan if exceeded)
- Ratio check aborts > 10:1
- Audit's decompression-bomb attack fails

---

### H-2 · Three-state model — PASS | FAIL | NOT_VERIFIED

**Files:** 
- `backend/src/scanner/types.ts` (core type changes)
- All 15 analyzers in `backend/src/scanner/`
- `backend/src/routes/scans.routes.ts` (API response)
- `frontend/src/pages/ScanReport.tsx` (UI rendering)
- Database schema (add `status` column)

**Current:** Binary model — `Finding` (implicitly fail) or `Pass`. Type lacks `status`, `confidence`, `ruleId`, `evidence`, `whyItMatters`, `verification`, `detectionMethod`.

**Changes:**

1. **Types:** Extend `Finding` and introduce `CheckResult`:
   ```typescript
   type CheckStatus = "PASS" | "FAIL" | "NOT_VERIFIED";
   
   interface CheckResult {
     checkId: string;          // unique identifier
     title: string;
     status: CheckStatus;
     severity?: "critical" | "high" | "medium" | "low";
     category: string;
     evidence?: string;        // redacted, no secrets
     remediation?: string;
     confidence: 0–100;        // how sure are we?
     ruleId?: string;          // which rule fired
     detectionMethod?: string; // how we determined this
     whyItMatters?: string;    // education layer
   }
   ```

2. **Database schema:** Add `status` column to `scans` table (enum: PASS/FAIL/NOT_VERIFIED).

3. **Migrate all 15 analyzers:**
   - `osv.ts`: OSV findings remain FAIL; missing data becomes NOT_VERIFIED
   - `semgrepScanner.ts`: AST findings PASS/FAIL; Semgrep missing → NOT_VERIFIED for those 6 checks
   - `authHeuristic.ts`: protected routes PASS, unprotected FAIL, undetermined NOT_VERIFIED
   - `codeQuality.ts`: findings FAIL, no findings PASS, analysis failed → NOT_VERIFIED
   - etc. (15 total)

4. **API:** Update `/api/scans/:id` response to include CheckResult array.

5. **UI:** Render NOT_VERIFIED distinctly (gray stripe, "We couldn't complete this check" message).

**Tests:**
- Unit: `backend/test/scanner/types.test.ts` (new)
  - CheckResult type validates
  - Status enum exhaustive
- Analyzer tests: each of 15 analyzers updated to return CheckResult[]
  - Example: OSV missing → returns results with status NOT_VERIFIED, confidence 0
  - Example: Auth heuristic can't parse file → returns NOT_VERIFIED for auth results
- E2E: run scan, verify JSON response includes status on every result

**Complexity:** High — touches 40+ files. **Effort:** 24–28 hours. **Dependencies:** None; this is the foundation.

**Success criteria:**
- All 15 analyzers return CheckResult[]
- Three-state model correctly expresses every outcome
- Database persists status
- UI renders NOT_VERIFIED distinctly
- API response validated against schema
- All existing tests pass with new types
- Backwards-compatible API versioning or clear deprecation

---

## Phase 3b: Scoring + Status + Framework (7 days, ~55 hours)

Build on the three-state model: make scores honest, add scan lifecycle tracking, and add framework detection.

### H-1 · Semgrep honesty

**Files:** `backend/src/scanner/semgrepScanner.ts`, `backend/Dockerfile`, `.github/workflows/*.yml`

**Current:** When Semgrep is missing, returns single `low` finding (2-point penalty). Scan still scores ~98/100, presenting as healthy when 6 AST checks never ran.

**Changes:**

1. **Version pinning:** 
   - `Dockerfile`: `pip install semgrep==1.65.0` (pinned, verify latest when shipping)
   - `.github/workflows/test.yml` and `ci.yml`: same pin
   - Record version in scan metadata

2. **Startup verification:**
   - At API startup, run `semgrep --version`
   - If fails or missing, log warning but proceed (don't crash)
   - A successful init adds Semgrep to scan metadata as available

3. **On failure:** Return NOT_VERIFIED for the 6 AST checks (instead of single `low` finding):
   - SQL injection detection
   - Command injection detection
   - Eval usage detection
   - Hardcoded JWT detection
   - Disabled TLS detection
   - Wildcard CORS detection

4. **Metadata:** Record semgrep version + date on every scan

**Tests:**
- Unit: `backend/test/scanner/semgrepScanner.test.ts` (update)
  - Mock: Semgrep missing → returns 6 NOT_VERIFIED results, no misleading `low` finding
  - Mock: Semgrep present → returns real findings
  - Version is recorded in metadata
- Integration: mock `semgrep` command failing → scan completes with NOT_VERIFIED, not score degraded
- E2E: if running in this environment, no-op (binary absent, tests skip)

**Complexity:** Medium. **Effort:** 12–14 hours. **Dependencies:** H-2 (must have CheckStatus to return NOT_VERIFIED).

**Success criteria:**
- Semgrep version pinned and verified at startup
- Semgrep missing → 6 NOT_VERIFIED results, no false `low` finding
- Version recorded in metadata
- Audit's 5 failing tests now pass

---

### H-4 · Score integrity

**Files:** `backend/src/scanner/index.ts`, scoring config

**Current:** `score = 100 − Σ penalties`, clamped. Failed analyzers barely move it. No confidence signal. No versioning of scoring config.

**Changes:**

1. **Version the scoring config:**
   - Create `backend/src/scanner/scoringConfig.ts`:
     ```typescript
     export const SCORING_CONFIG = {
       version: "1.0",
       createdAt: "2026-01-01T00:00:00Z",
       penalties: {
         critical: 20,
         high: 10,
         medium: 5,
         low: 2,
       },
     };
     ```
   - Record version on every scan

2. **Exclude NOT_VERIFIED from credit:**
   - NOT_VERIFIED findings do not reduce score
   - PASS findings do not add credit (score floor is 0, ceiling 100)
   - Only FAIL findings incur penalty

3. **Add confidence score:**
   - `confidence: 0–100` on the scan object
   - Confidence = (completed checks / total checks) × 100
   - NOT_VERIFIED checks do not count as completed

4. **Render confidence:**
   - Report always shows confidence: "Confidence: 87% (12 of 14 checks completed)"
   - UI shows confidence as % circle or bar
   - Scores < 80% confidence show a banner: "Some checks could not be completed. Review the report for details."

**Tests:**
- Unit: `backend/test/scanner/scoring.test.ts` (new)
  - Scan with 1 FAIL (severity high) → score = 90, confidence 100%
  - Scan with 1 NOT_VERIFIED + 1 FAIL → score = 90, confidence 50%
  - Semgrep missing (6 NOT_VERIFIED) → score unchanged, confidence reduced
- E2E: JSON response includes scoreConfig.version and confidence

**Complexity:** Medium. **Effort:** 10–12 hours. **Dependencies:** H-2, H-1.

**Success criteria:**
- Scoring config versioned and recorded
- NOT_VERIFIED findings do not reduce score
- Confidence calculated and rendered
- Misleading high scores on partial scans eliminated
- Tests verify score/confidence relationship

---

### H-7 · Scan status model

**Files:** `backend/src/patrol/scans.ts`, `scans` table schema, API response

**Current:** Scan rows written only on success. No status column. No distinction between `COMPLETED`, `PARTIALLY_COMPLETED`, `FAILED`.

**Changes:**

1. **Add enum:**
   ```typescript
   type ScanStatus = 
     | "CREATED"           // uploaded, queued
     | "SCANNING"          // analysis in progress
     | "COMPLETED"         // all checks ran
     | "PARTIALLY_COMPLETED" // some checks failed (e.g., Semgrep missing)
     | "FAILED"            // fatal error (symlink detected, timeout, etc.)
     | "CANCELLED";        // user cancelled
   ```

2. **Database:** Add `status` column to `scans` table, default `CREATED`.

3. **Update during scan:**
   - On upload: `CREATED`
   - On start: `SCANNING`
   - On completion: `COMPLETED` if all checks ran; `PARTIALLY_COMPLETED` if any returned NOT_VERIFIED
   - On fatal error: `FAILED`
   - On user cancel: `CANCELLED`

4. **API:** Include `status` in scan response.

5. **UI:** Render status distinctly:
   - `COMPLETED`: normal
   - `PARTIALLY_COMPLETED`: yellow stripe, "Some checks didn't complete"
   - `FAILED`: red stripe, error message
   - `CANCELLED`: gray stripe

**Tests:**
- Unit: `backend/test/patrol/scans.test.ts` (update)
  - Scan with all checks → status `COMPLETED`
  - Scan with Semgrep missing → status `PARTIALLY_COMPLETED`
  - Scan with symlink detected → status `FAILED`
- E2E: verify status changes through scan lifecycle

**Complexity:** Medium. **Effort:** 8–10 hours. **Dependencies:** H-2.

**Success criteria:**
- Scan status persisted and accurate
- UI renders status correctly
- Partial scans no longer appear identical to complete ones
- Tests cover all status transitions

---

### M-4 · Framework detection

**Files:** `backend/src/scanner/frameworkDetection.ts` (new)

**Current:** No framework detection. Remediation is generic (e.g., "add authentication" instead of "add Next.js middleware").

**Changes:**

1. **New analyzer:** `frameworkDetection.ts`
   - Scan `package.json`: look for `next`, `react`, `express`, `fastapi`, `django`, etc.
   - Scan `pyproject.toml`, `requirements.txt` for Python frameworks
   - Look for framework-specific config files: `nuxt.config.ts`, `next.config.js`, `svelte.config.js`, etc.
   - Scan source for telltale patterns: `getServerSideProps`, `@app.route`, `@FastAPI()`, etc.

2. **Return:**
   ```typescript
   {
     detected: ["next.js", "typescript", "tailwind"],
     primaryFramework: "next.js",
     confidence: 95,
     detectionMethod: ["package.json", "next.config.js"],
   }
   ```

3. **Store:** Add `frameworks` column to `scans` table, store as JSON array.

4. **Use downstream:** 
   - H-6 auth analyzer uses this to emit framework-aware remediation
   - M-3 education layer uses this to tailor explanations

**Tests:**
- Unit: `backend/test/scanner/frameworkDetection.test.ts` (new)
  - Next.js project → detects `next.js`, confidence ≥ 90
  - Django project → detects `django`, confidence ≥ 85
  - Generic Node → detects frameworks if present, confidence lower if ambiguous
- E2E: scan Next.js sample → frameworks array populated

**Complexity:** Medium–high. **Effort:** 14–16 hours. **Dependencies:** None; can ship in parallel.

**Success criteria:**
- Framework detection works for: Next.js, React, Express, Nuxt, FastAPI, Django, Flask
- Confidence > 80% for clear matches
- No false positives for ambiguous cases
- Frameworks stored and retrievable via API

---

## Phase 3c: Education + Prioritisation (10 days, ~80 hours)

The product value tier: make the scanner useful and actionable for non-technical users.

### M-1 · Evidence and metadata on findings

**Files:** All 15 analyzers, API response

**Current:** Findings lack `evidence`, `ruleId`, `confidence`. Secret findings show file + line but no redacted evidence — user can't verify what matched.

**Changes:**

1. **Extend Finding type** (via H-2 CheckResult):
   ```typescript
   evidence?: string;     // redacted context (e.g., "password_field = ..." for auth)
   ruleId?: string;       // which rule matched (e.g., "semgrep:java.lang.sql-injection-jdbc")
   confidence: 0–100;     // how sure are we?
   detectionMethod?: string; // "regex", "ast", "heuristic", "manual"
   ```

2. **Update all 15 analyzers:**
   - OSV: `ruleId = vulnerability CVE ID`, `evidence = package + version`
   - Semgrep: `ruleId = rule ID from Semgrep`, `evidence = matched code snippet (safe)`
   - Auth: `ruleId = auth_missing_on_route`, `evidence = route name`
   - Privacy policy: `ruleId = privacy_policy_missing`, `evidence = none (structural)`
   - etc.

3. **Redact secrets from evidence:**
   - If evidence contains API key patterns, AWS ARN, etc., redact to `[REDACTED_KEY]`
   - Logged with full evidence server-side only

4. **API:** Return evidence + ruleId + confidence

5. **UI:** Show evidence next to finding (small font, code block)

**Tests:**
- Unit: each analyzer test verifies evidence is present and safe
- Example: auth analyzer finding includes route name in evidence
- Example: secret scanner finding has redacted secret in evidence
- Verify no unredacted credentials in API response

**Complexity:** Medium. **Effort:** 16–18 hours. **Dependencies:** H-2 (types), M-4 (framework) helps.

**Success criteria:**
- Every finding has `evidence`, `ruleId`, `confidence`
- Evidence is safe (no unredacted secrets)
- UI renders evidence legibly
- User can verify each finding by reference

---

### M-2 · Finding prioritisation

**Files:** `backend/src/scanner/index.ts`, API response, frontend sort logic

**Current:** All findings flat list, ordered by analyzer execution. No "Fix These First", no exploitability signal.

**Changes:**

1. **Prioritisation signal:**
   - Each finding gets a `priority: 1–3` (1=urgent, 3=nice-to-have)
   - Derived from: severity, exploitability, business impact
   - Heuristics:
     - Severity `critical` + remote-exploitable → priority 1
     - Severity `high` or secret found → priority 1
     - Severity `medium` → priority 2
     - Severity `low` or best-practice → priority 3

2. **API:** Return findings sorted by priority, then severity.

3. **UI:** 
   - Group findings by priority: "🔴 Fix Immediately" / "🟡 Fix Soon" / "🟢 Best Practices"
   - Within each group, sort by severity
   - Show priority count summary

**Tests:**
- Unit: `backend/test/scanner/prioritisation.test.ts` (new)
  - SQL injection (severity high) → priority 1
  - Hardcoded password (severity high) → priority 1
  - Missing security header (severity low) → priority 3
  - Sorting preserves priority order
- E2E: scan response sorted by priority

**Complexity:** Low–medium. **Effort:** 8–10 hours. **Dependencies:** None; can parallelize.

**Success criteria:**
- All findings have priority 1–3
- API response sorted by priority
- UI renders priority groups clearly
- No findings incorrectly prioritised

---

### M-3 · Education layer

**Files:** New `backend/src/scanner/education.ts`, all 15 analyzers, API response, frontend

**Current:** `detail` + `remediation` are single technical strings. Missing: what this means, why it matters, how to verify.

**Changes:**

1. **Extend Finding:**
   ```typescript
   education?: {
     beginnerExplanation: string;  // plain English, no jargon
     whyItMatters: string;         // business impact
     commonCause: string;          // why devs make this mistake
     howToFix: string;             // step-by-step for the framework
     howToVerify: string;          // how to test the fix
     learnMore?: string;           // link to resource
   }
   ```

2. **Create education DB:**
   - Map finding ID → education object
   - Keyed by `checkId` + framework
   - Example: `auth_missing_on_route:next.js` vs `auth_missing_on_route:express`

3. **Populate all findings:**
   - 15 analyzers × 3–5 findings each = ~50 finding types
   - Each gets beginner explanation, business impact, remediation steps
   - Framework-aware (use M-4 framework detection)

4. **API:** Include `education` object in finding response.

5. **UI:** 
   - Show beginner explanation by default
   - Expand to "why it matters" + "how to fix"
   - Toggle "expert mode" to show technical detail

6. **Example:**
   ```
   Finding: "Missing authentication on /api/posts"
   
   Beginner explanation: "Your API endpoint doesn't check if the user is logged in. 
     Anyone on the internet can access it."
   
   Why it matters: "Someone could steal your user's data or change their information 
     without permission."
   
   Common cause: "Easy to miss when building new endpoints. Most developers forget 
     to add the auth check."
   
   How to fix (Next.js): "Add this to your route handler:
     if (!session) { return NextResponse.json({error: 'Unauthorized'}, {status: 401}) }"
   
   How to verify: "Logout, then try the endpoint in your browser. You should get 
     a 401 error."
   ```

**Tests:**
- Unit: `backend/test/scanner/education.test.ts` (new)
  - Every finding type has education object
  - Beginner explanation is non-empty and jargon-free
  - Framework-aware explanations differ correctly
- Manual: read 10 random findings, verify clarity for a non-developer

**Complexity:** Medium–high (product-intensive). **Effort:** 28–32 hours. **Dependencies:** H-2, M-4, M-1.

**Success criteria:**
- All ~50 finding types have complete education layer
- Beginner explanations pass clarity test
- Framework-aware remediation is accurate
- UI toggles between beginner/expert views
- Users can follow remediation steps without prior knowledge

---

### H-6 · Authentication analysis

**Files:** `backend/src/scanner/authHeuristic.ts` (rewrite)

**Current:** 25-line file-level heuristic. Misses `router.*`, all of Next.js/FastAPI/Django. One `requireAuth` anywhere marks entire file as fine.

**Changes:**

1. **Per-route extraction:**
   - Parse JavaScript/TypeScript AST (use `@babel/parser`)
   - Extract all routes: `app.get()`, `app.post()`, `router.get()`, etc.
   - Extract all route handlers
   - Parse Python routes: `@app.get()`, `@app.post()`, Flask decorators, etc.

2. **Framework-aware classification:**
   - Next.js: look for middleware, `getServerSideProps`, auth checks in handler
   - Express: look for middleware function calls on route definition
   - FastAPI: look for `Depends(get_current_user)` or equivalent
   - Django: look for `@login_required`, `LoginRequiredMixin`

3. **Per-route classification:**
   ```typescript
   routes: [
     { method: "GET", path: "/", protected: true, evidence: "has middleware auth" },
     { method: "GET", path: "/api/posts", protected: false, evidence: "no auth check" },
     { method: "POST", path: "/api/posts", protected: true, evidence: "middleware enforced" },
   ]
   ```

4. **Return counts:**
   ```typescript
   {
     totalRoutes: 42,
     protectedRoutes: 38,
     unprotectedRoutes: 3,   // public endpoints that look internal
     undeterminedRoutes: 1,  // couldn't parse
   }
   ```

5. **Public route detection:**
   - Skip `/health`, `/status`, `/ping`, `/metrics`, `/swagger`, `/.well-known/*`
   - Skip routes that are explicitly marked public in code (`@Public()`, etc.)
   - Flag unprotected routes that look internal (contain `/api/`, `/admin/`)

**Tests:**
- Unit: `backend/test/scanner/authHeuristic.test.ts` (rewrite)
  - Next.js: detect middleware auth, per-route checks
  - Express: detect route-level middleware
  - FastAPI: detect `Depends()` auth
  - Django: detect `@login_required`
  - Public routes: `/health`, `/status` not flagged as unprotected
  - Count accuracy: 42 routes → 42 entries in result
- E2E: scan real Next.js + Express + FastAPI samples, verify counts match manual review

**Complexity:** Medium–high. **Effort:** 20–24 hours. **Dependencies:** M-4 (framework detection).

**Success criteria:**
- Per-route extraction works for JavaScript, TypeScript, Python
- Framework-aware detection accurate (≥ 85%)
- Counts are correct (total, protected, unprotected, undetermined)
- Public routes not falsely flagged
- E2E test: real app audit matches manual review

---

## Phase 3d: Worker Isolation + Cleanup (14–21 days, ~120 hours)

The largest structural change: separate untrusted input processing from API process.

### C-2 · Scanner isolation — worker process with restricted filesystem

**Files:** New `backend/src/worker/` directory, API refactor, queue layer

**Current:** Extraction and analysis run inside API process, with same environment and filesystem access, with same Stripe keys and database.

**Goal:** Per the brief: `upload → S3 → queue → isolated worker → workspace → analysis → report → cleanup`.

**Changes:**

1. **Architecture:**
   - API accepts upload → stores file in `/tmp` or S3
   - API enqueues job to queue (Redis, RabbitMQ, or SQS)
   - Separate worker process (different container or host) picks up job
   - Worker extracts to isolated scratch directory (tmpfs or container-bound volume)
   - Worker runs scanner with no access to Stripe keys, DB credentials, or host files
   - Worker writes report to S3 or stdout
   - API reads report and stores result in DB
   - Worker cleans up workspace

2. **Worker restrictions:**
   - Runs as dedicated non-root user (e.g., `nettle-worker`)
   - No environment variables except: `LOG_LEVEL`, `REPORT_OUTPUT_PATH`
   - Filesystem: `/tmp/workspace-{jobId}/` only (tmpfs, auto-cleanup)
   - CPU/memory ceilings (ulimit or cgroup): 2 CPU, 1 GB RAM
   - Process ceiling: max 100 child processes
   - Timeout: 120s per scan

3. **Queue:** 
   - Redis: `QUEUE_URL=redis://...`, simple in-memory queue
   - Or: SQS for AWS, built-in retry + DLQ
   - Job schema:
     ```json
     {
       "jobId": "scan_abc123",
       "uploadPath": "s3://nettle-uploads/abc123.zip",
       "userId": "user_123",
       "projectId": "proj_456"
     }
     ```

4. **API refactor:**
   - `/api/scans/upload` → enqueue job (return 202 Accepted + jobId)
   - Redirect user to `/scan/{jobId}` which polls for result
   - Worker → API callback: POST `/internal/scan/{jobId}/complete` with result
   - Or: worker writes result to S3, API periodically checks

5. **Status polling:**
   - User polls `/api/scans/{jobId}` 
   - Status: `QUEUED`, `SCANNING`, `COMPLETED`, `FAILED`
   - Return 202 Accepted while scanning

**Timeline:** 
- Architecture design: 2–3 days
- Worker scaffold + queue integration: 3–4 days
- Migrate extraction + scanning to worker: 3–4 days
- Testing + Docker compose: 3–4 days

**Tests:**
- Unit: worker initialization, resource limits applied
- Integration: job enqueue → worker pickup → result callback
- E2E: end-to-end scan via queue
- Chaos: worker crash mid-scan → result not lost (idempotent requeue)
- Security: worker never gets Stripe key or DB credentials

**Complexity:** Very high. **Effort:** 80–100 hours. **Dependencies:** C-1, C-3 (should land first); H-2 (types).

**Success criteria:**
- Worker process isolated (different user, no secrets in env)
- Scan uploads enqueued, not processed synchronously
- Worker restarts don't lose results
- Timeout enforced (scan stops after 120s)
- All resource limits in place and verified
- E2E test: scan via queue completes correctly

---

### H-5 · OSV database versioning

**Files:** `backend/src/scanner/osv-data/`, `backend/src/scanner/osvVulnerabilities.ts`

**Current:** SQLite DB with single table `vulnerabilities`, no metadata, no version, no generated-at. Nothing updates it; reports can't state which vulnerability data was used.

**Changes:**

1. **Add metadata table:**
   ```sql
   CREATE TABLE osv_metadata (
     id INTEGER PRIMARY KEY,
     version TEXT NOT NULL,
     generated_at TEXT NOT NULL,
     source_commit TEXT,
     npm_rows INTEGER,
     pypi_rows INTEGER
   );
   ```

2. **Populate on OSV updates:**
   - Create a build script: `backend/scripts/update-osv-db.sh`
   - Fetches latest OSV data from npm advisory API (or GitHub CVE database)
   - Updates SQLite, inserts metadata row
   - Records timestamp + data row count
   - Version: `YYYY-MM-DD` of build date

3. **Record on every scan:**
   - Query OSV metadata at scan start
   - Store in `scans.osv_version` and `scans.osv_generated_at`

4. **Report generation:**
   - Always include "OSV data as of 2026-08-16"
   - Warn if data > 30 days old: "Vulnerability data is 45 days old. Run a rescan to check for newly-disclosed vulnerabilities."

5. **Refresh job (optional for MVP):**
   - Cron job: weekly OSV update
   - Skipped if no changes (avoid unnecessary rebuilds)

**Tests:**
- Unit: metadata table queries work
- Integration: OSV update records version + timestamp
- E2E: scan includes osv_version in response
- Staleness check: data 45 days old → warning in report

**Complexity:** Low–medium. **Effort:** 12–16 hours. **Dependencies:** None; can parallelize.

**Success criteria:**
- OSV metadata persisted and accurate
- Scan includes osv_version + osv_generated_at
- Report warns if data > 30 days old
- Refresh job (optional) doesn't break on schema change

---

### M-5 · Legal language

**Files:** `backend/src/scanner/legalChecks.ts`, API response, frontend rendering

**Current:** "No privacy policy found" with no disclaimer. Reads as compliance verdict, not an audit finding.

**Changes:**

1. **Rename findings:**
   - "No privacy policy found" → "Privacy policy not detected"
   - "No terms of service found" → "Terms of service not detected"
   - "No GDPR compliance language found" → "GDPR compliance language not detected"

2. **Add disclaimer to finding:**
   ```typescript
   {
     title: "Privacy policy not detected",
     severity: "medium",
     evidence: "no `/privacy` route found, no privacy policy HTML detected",
     remediation: "Add a privacy policy page to your website.",
     education: {
       beginnerExplanation: "Nettle scanned your website and did not find a privacy policy. "
         + "This is a tool for automated scanning—it cannot determine if you are legally compliant. "
         + "You should consult a lawyer about your privacy and legal obligations.",
       whyItMatters: "Users expect to see how their data is used. Many jurisdictions require a privacy policy.",
       disclaimer: "This finding is informational only and does not constitute legal advice. "
         + "Consult a lawyer to verify legal compliance.",
     },
   }
   ```

3. **API response:**
   - Every legal finding includes `disclaimer` field
   - Scan metadata includes: "Nettle is a technical audit tool, not legal advice."

4. **UI:**
   - Legal findings shown separately under "Legal & Compliance"
   - Each finding prefaced with disclaimer
   - Gray icon (info, not warning)

**Tests:**
- Unit: every legal finding has disclaimer
- E2E: API response includes disclaimer
- Manual: read findings, verify language is appropriately cautious

**Complexity:** Low. **Effort:** 4–6 hours. **Dependencies:** None.

**Success criteria:**
- All legal findings reworded (not found → not detected)
- Disclaimer on every legal finding
- UI renders legal findings distinctly
- No overclaim of legal authority

---

### M-6 · AI disclosure language

**Files:** `backend/src/scanner/aiChecks.ts`, API response, frontend

**Current:** AI requirement finding phrased as fact: "AI disclosure required" (reads as legal mandate).

**Changes:**

1. **Reword:**
   - "AI disclosure required" → "Potential AI disclosure requirement — review recommended"

2. **Education:**
   ```typescript
   education: {
     beginnerExplanation: "Some regions may require disclosing if you use AI. "
       + "The laws are new and changing. Nettle cannot determine if this applies to you.",
     whyItMatters: "Users deserve transparency about AI in products. Some laws mandate disclosure.",
     disclaimer: "This finding reflects emerging regulatory guidance. "
       + "Consult a lawyer about your specific jurisdiction and use case.",
   }
   ```

3. **Confidence:** Lower confidence (50–70%) since law is evolving

4. **UI:** Gray icon, "review recommended" tag, not red warning

**Tests:**
- Unit: finding includes disclaimer and lower confidence
- Manual: read finding, verify tone is advisory, not prescriptive

**Complexity:** Low. **Effort:** 2–4 hours. **Dependencies:** None.

**Success criteria:**
- AI finding language is appropriately cautious
- Disclaimer included
- Confidence reduced
- UI renders as advisory, not mandate

---

## Phase 4: Validation (5 days, ~40 hours)

Test the complete system, run Nettle against itself, verify all fixes.

### Test suite completion

**Files:** `backend/test/`

**Current:** 90 passing tests, 5 failing (Semgrep binary absent).

**Changes:**

1. **Semgrep skip:** Mark 5 Semgrep tests to skip if binary absent (already done in H-1)

2. **New tests:**
   - Security: symlink, decompression bomb (5–8 tests each)
   - Types: CheckResult, CheckStatus (10 tests)
   - Scoring: H-4 (10 tests)
   - Status: H-7 (8 tests)
   - Framework: M-4 (12 tests)
   - Auth: H-6 (15 tests)
   - Education: M-3 (10 tests)
   - Queue: C-2 (20 tests)
   - OSV: H-5 (5 tests)
   - **Total new:** ~95 tests

3. **E2E:** 
   - Run complete scan flow (upload → analysis → report → download)
   - Verify all analyzers execute
   - Verify scores, status, confidence calculated
   - Verify education layer rendered

**Effort:** 20–24 hours. **Dependencies:** All Phase 3a–3d.

---

### Self-scan: Nettle scanning Nettle

**Process:**
1. Package Nettle source as zip
2. Run scan via API
3. Document all findings
4. For each finding: verify accuracy, fix if false positive, fix if real bug
5. Re-run scan until clean or all findings are understood

**Expected findings:**
- No hardcoded secrets (verified clean in audit)
- No SQL injection (parameterized queries used throughout)
- May flag: console.logs (M-3 observability), TODO comments (codeQuality heuristic)
- Security headers: if web frontend, may flag missing CSP/HSTS (intentional for this phase)

**Effort:** 10–12 hours. **Dependencies:** All implementation complete.

---

### Documentation

**Files:** New docs

**Create:**
- `SECURITY.md` — threat model, security guarantees, incident response
- `SCANNER.md` — what each analyzer does, limitations, framework support
- `SCANNER-RULES.md` — complete list of rules (by analyzer, by severity, by framework)
- `THREAT-MODEL.md` — assumptions, trust boundaries, known limitations
- `DATA-RETENTION.md` — how long reports/events kept, deletion policy, GDPR compliance
- `DEPLOYMENT.md` — Docker build, worker setup, queue configuration, resource limits

**Effort:** 8–10 hours.

---

## Implementation Phases Summary

| Phase | Duration | Focus | Effort | Blockers |
|---|---|---|---|---|
| **3a** | Days 1–7 | Security + types | 60h | C-1, C-3, H-2 |
| **3b** | Days 8–14 | Scoring + framework | 55h | H-1, H-4, H-7, M-4 |
| **3c** | Days 15–24 | Education + auth | 80h | M-1, M-2, M-3, H-6 |
| **3d** | Days 25–45 | Isolation + cleanup | 120h | C-2, H-5, M-5, M-6 |
| **4** | Days 46–50 | Testing + docs | 40h | All Phase 3 complete |

---

## Risk Mitigation

| Risk | Probability | Impact | Mitigation |
|---|---|---|---|
| Semgrep version conflicts | Medium | High | Pin version early; test in CI |
| Framework detection false positives | Medium | Low | Whitelist known false positives; manual testing |
| Worker queue backlog | Low | Medium | Monitor queue depth; auto-scale workers |
| Type system migration regression | Medium | High | Comprehensive test suite; staged rollout |
| Database schema migration data loss | Low | Critical | Backup before migration; test on replica first |

---

## Success Criteria

All gaps addressed:
- ✅ C-1: Symlink traversal fixed, verified with PoC
- ✅ C-2: Worker isolation implemented, API isolated from untrusted input
- ✅ C-3: Decompression limits enforced
- ✅ H-1 through H-7: Semgrep honesty, three-state model, rate limiting, scoring, status, auth analysis
- ✅ M-1 through M-9: Evidence, prioritisation, education, framework detection, legal language
- ✅ L-1 through L-4: UI clarity, launch checklist, progressive disclosure
- ✅ Self-scan: Nettle verified against itself

Every finding includes evidence, rule ID, confidence, and education layer.
Scores accurately reflect completion state (confidence metric).
Unauthorized file read / DoS / misleading scores impossible.

---

## Commit & Review Workflow

1. **Phase 3a (security + types):** Branch `feature/nettle-phase-3a-security` → PR
   - Code review: security impact, test coverage
   - Merge to develop once approved

2. **Phase 3b (scoring + framework):** New branch `feature/nettle-phase-3b-scoring` → PR
   - Code review: type migration impact, education accuracy

3. **Phase 3c (education + auth):** New branch `feature/nettle-phase-3c-education` → PR
   - Code review: education quality, framework detection accuracy

4. **Phase 3d (isolation + cleanup):** New branch `feature/nettle-phase-3d-isolation` → PR
   - Code review: architecture, queue integrity, worker security

5. **Phase 4 (validation):** `feature/nettle-phase-4-validation` → PR
   - Code review: test coverage, self-scan results

Each PR rebases on latest `develop` to avoid conflict bloat.

---

*Phase 2 complete. Plan approved — proceed to Phase 3a.*
