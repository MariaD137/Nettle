# Nettle Gap Audit

**Phase 1 — inspection only. No code was modified to produce this document.**

Scope: full repository — scanner, API, frontend, database, Docker, CI, tests,
dependencies, security configuration. Audited against the 34 gaps in the brief.

Every finding below was **verified against the running code**, not inferred.
Where a claim is empirical, the reproduction is included. Where something could
not be verified in this environment, it is marked **NOT VERIFIED** rather than
assumed either way.

Baseline: `claude/nettle-repo-context-lnd87f` @ `9c1f816`.
Scanner v1.3.0 · 15 analyzers · 36 API endpoints · 10 tables · 95 backend tests
(90 passing, 5 failing — all 5 are Semgrep tests failing because the binary is
absent here, which is itself GAP 1).

---

## Summary

| Severity | Count | Headline |
|---|---|---|
| **CRITICAL** | 3 | Arbitrary host file read via symlink; no scanner isolation; decompression bomb |
| **HIGH** | 7 | Semgrep fails to a near-clean report; no three-state model; unlimited scan endpoint; score integrity; OSV unversioned; auth analysis unreliable; no scan status model |
| **MEDIUM** | 9 | No confidence/evidence/rule IDs; no remediation prioritisation; no education layer; framework blindness; legal overclaim risk; observability; retention; rescan UX; completeness reporting |
| **LOW** | 4 | Explanation levels; launch checklist; "what we didn't check"; report structure |
| **INFO** | 3 | SQLite scaling boundary; docs; no production mocks found (clean) |

**Three findings block MVP.** C-1, C-2 and C-3 are exploitable today by any
paying customer and would constitute a breach of every other tenant.

---

## CRITICAL

### C-1 · Arbitrary host file read via symlinks in uploaded archives

**Location:** `backend/src/routes/scans.routes.ts` (extraction) + `backend/src/scanner/walk.ts` (traversal)

**Status: EXPLOITABLE — demonstrated, not theoretical.**

`unzip -q -o` preserves symlinks. The scanner then follows them out of the
workspace and reports the contents of whatever they point at, back to the
person who uploaded the archive.

Reproduction actually run during this audit:

```bash
ln -s /home/user/Nettle/backend/nettle.db db.json
zip -qy payload.zip db.json
# upload payload.zip → scan report contains data from the host file
```

Verified reachable through this path:

| Symlink target | Result |
|---|---|
| `/proc/self/environ` | **6,802 bytes read** — every env var, including `STRIPE_SECRET_KEY` |
| `backend/nettle.db` | **208,896 bytes read** — the entire database: all users, password hashes, sessions, API keys, every tenant's scans |
| `/etc/passwd` | 1,238 bytes read |

And confirmed end-to-end that the scanner *reports* it: a symlink to a file
containing `AKIAIOSFODNN7EXAMPLE` produced the finding
`AWS Access Key ID found in source — file: stolen.js`. The secret scanner
becomes an exfiltration oracle: point a symlink at a host file, and Nettle
extracts and returns the credentials inside it.

**Impact:** Full multi-tenant compromise. Any subscriber can read the server's
environment (Stripe keys, DB credentials), the entire user table, and every
other customer's source and scan history. This defeats the tenant isolation
guarantees verified in `tenantIsolation.test.ts` — those tests check the API
layer, and this bypasses the API layer entirely.

**Fix:** Refuse symlinks at extraction; re-verify with `lstat` during traversal
that every path resolves inside the workspace root. Both layers, because either
alone is a single point of failure.

**Complexity:** Low (a day). **Dependencies:** none. **BLOCKS MVP.**

---

### C-2 · No scanner isolation — untrusted input processed in the API process

**Location:** `backend/src/routes/scans.routes.ts`

Extraction and analysis run **inside the API process**, on the same host, with
the same environment and the same filesystem access as the code that holds
Stripe keys and the database. There is no worker, no queue, no sandbox, no
resource ceiling.

The brief's requirement is `upload → S3 → queue → isolated worker → workspace →
analysis → report → cleanup`. Current state is `upload → same process → done`.

The Dockerfile does run as a non-root `nettle` user — genuinely good, and it
limits C-1's reach to files that user can read. But `/proc/self/environ` and
`nettle.db` are both readable by that user, so it does not contain the breach.

**Impact:** C-1 becomes total rather than partial. Any future scanner bug —
a regex catastrophic backtrack, an `unzip` CVE — becomes an API compromise.

**Fix:** Extract and scan in a separate worker with its own restricted user,
CPU/memory/process ceilings, a scratch-only filesystem, and no credentials in
its environment. Full queue architecture can follow; process separation is the
part that matters first.

**Complexity:** High (1–2 weeks for the full architecture; 2–3 days for
process separation alone). **Dependencies:** C-1 should land first.
**BLOCKS MVP.**

---

### C-3 · Decompression bomb — no expansion, file-count or depth limit

**Location:** `backend/src/routes/scans.routes.ts`, `backend/src/scanner/walk.ts`

The only guard is a 25 MB limit on the **compressed** upload. Verified absent:
no uncompressed-size cap, no file-count cap, no directory-depth cap, no
extraction timeout. `walk.ts` has no traversal guards at all.

A 25 MB zip can expand to hundreds of gigabytes. Extraction fills the disk or
the scan walks millions of files until the process dies — taking the API with
it, since C-2 means they are the same process.

**Impact:** Trivial denial of service against the whole platform by any
subscriber, costing one scan from their quota.

**Fix:** Cap uncompressed bytes, file count and depth; enforce a wall-clock
extraction timeout; stream-check the ratio and abort past a threshold.

**Complexity:** Low–medium. **Dependencies:** best done with C-1.
**BLOCKS MVP.**

---

## HIGH

### H-1 · Semgrep failure produces a near-clean report (GAP 1)

**Location:** `backend/src/scanner/semgrepScanner.ts`

When Semgrep is missing, the module returns a single **`low`** severity finding
and an empty `passed` list. `low` costs **2 points**. So a codebase whose entire
structural analysis layer did not run still scores ~98/100 and presents as
healthy. Its own wording — *"The rest of the readiness report is unaffected"* —
is misleading: six AST rules covering SQL injection, command injection, `eval`,
TLS bypass and wildcard CORS silently did not execute.

This is live in this environment: 5 tests fail for exactly this reason.

Also missing: no version pin (`pip install semgrep`, unpinned in both the
Dockerfile and both CI workflows), no startup verification, no version or
ruleset version recorded in scan metadata, no resource limits. A 30s timeout
and 20 MB buffer do exist.

**Fix:** Pin the version; verify at startup; on failure mark the six checks
`NOT_VERIFIED`, degrade scan status to `PARTIALLY_COMPLETED`, and reduce score
confidence rather than the score.

**Complexity:** Medium. **Dependencies:** H-2. **BLOCKS MVP.**

---

### H-2 · No three-state model — the type system cannot express NOT_VERIFIED (GAP 3)

**Location:** `backend/src/scanner/types.ts` and all 15 analyzers

The model is binary: a `Finding` (implicitly fail) or a `Pass`. There is no
third state, so *"we could not determine this"* has nowhere to live and every
analyzer is forced to choose between claiming a failure and claiming a pass.

`Finding` also lacks: `status`, `confidence`, `ruleId`, `evidence`,
`whyItMatters`, `verification`, `detectionMethod`. The brief's `CheckResult`
interface needs all of them.

This is the **root cause of H-1, H-4 and most MEDIUM findings** — they are all
downstream of a model that cannot represent uncertainty.

**Fix:** Introduce `CheckStatus = PASS | FAIL | NOT_VERIFIED`, extend the result
type, migrate all 15 analyzers, and thread it through API, DB, report and UI.

**Complexity:** High — touches everything. **Dependencies:** none; it is the
foundation. **BLOCKS MVP** (nothing else in the brief can be built cleanly on
the current model.)

---

### H-3 · Scan endpoints have no rate limit (GAP 28)

**Location:** `backend/src/routes/scans.routes.ts`, `projects.routes.ts`, `billing.routes.ts`, `badge.routes.ts`, `events.routes.ts`

Verified coverage:

| Router | Rate limited |
|---|---|
| auth | ✅ 5 endpoints (15 / 15 min) |
| **scans** | ❌ none |
| **projects** | ❌ none |
| **billing** | ❌ none |
| **badge** (public) | ❌ none |
| **events** (public ingest) | ❌ none |

Scanning is the most expensive operation in the product and is completely
unthrottled. The quota caps scans per *month*, not per *second* — 30 concurrent
25 MB uploads are all permitted. The public badge and event-ingest endpoints
take no token at all and have no limit.

The limiter is also **in-memory**, so it resets on restart and does not work
across instances.

**Fix:** Per-endpoint limits — concurrency cap on scans, per-IP on public
endpoints, per-user elsewhere. Proper `429` with `Retry-After`.

**Complexity:** Low–medium. **BLOCKS MVP** (badge/events are unauthenticated).

---

### H-4 · Score integrity (GAP 19)

**Location:** `backend/src/scanner/index.ts`

`score = 100 − Σ penalties`, clamped. Verified problems:

- A failed analyzer barely moves the score (H-1).
- `NOT_VERIFIED` does not exist, so unverified silently reads as fine.
- No confidence signal — a score from a partial scan is indistinguishable from a complete one.
- No versioning of the scoring configuration, so scores are not comparable across releases.
- Unknown severities silently default to a `?? 7` penalty.

**Fix:** Version the config; exclude `NOT_VERIFIED` from credit; publish a
separate confidence value; show *"Score confidence reduced — some checks could
not be completed."*

**Complexity:** Medium. **Dependencies:** H-2. **BLOCKS MVP.**

---

### H-5 · OSV database is unversioned and unrefreshable (GAP 14)

**Location:** `backend/src/scanner/osv-data/npm-vulnerabilities.db`

Inspected the file: it contains exactly one table, `vulnerabilities`. **No
metadata table, no version, no generated-at timestamp.** Nothing in the repo
updates it. Nothing reports its age. Reports cannot state which vulnerability
data was used, and a scan run in a year will silently use data frozen today
while telling the customer "no known vulnerabilities."

**Fix:** Add a metadata table (version, generated-at, source commit); surface it
in every report; warn past a staleness threshold; add a validated, rollback-able
refresh job.

**Complexity:** Medium. **DOES NOT BLOCK MVP** — but must ship before the data
is meaningfully old, and the report must state the date from day one.

---

### H-6 · Authentication analysis is unreliable (GAP 21)

**Location:** `backend/src/scanner/authHeuristic.ts`

Read in full. It is a 25-line file-level heuristic:

- Matches only `app.get|post|put|delete|patch` — **misses `router.*` entirely**, which is how most real Express apps are written, and all of Next.js, FastAPI and Django.
- Analysis is **per file, not per route**: one `requireAuth` anywhere in the file marks *every* route in it as fine.
- Assumes every route needs auth — health checks and public endpoints are flagged.
- Produces none of the counts the brief requires (total / protected / unprotected / undetermined).

**Impact:** Both false negatives (a `router.get` with no auth is invisible) and
false positives (a legitimately public route is reported). For a product whose
headline is *"we tell you what's unprotected"*, this is the weakest analyzer.

**Fix:** Per-route extraction across `app.*` and `router.*`, framework-aware;
classify each route protected / unprotected / undetermined; report the counts.

**Complexity:** Medium–high. **Dependencies:** H-2, GAP 10. **BLOCKS MVP.**

---

### H-7 · No scan status model (GAP 16)

**Location:** `scans` table, `backend/src/patrol/scans.ts`

A scan row is only ever written on success. There is no `status` column and no
concept of `QUEUED`, `SCANNING`, `PARTIALLY_COMPLETED`, `FAILED` or `CANCELLED`.
A scan where one analyzer died is stored and displayed identically to a complete
one.

**Fix:** Add the status enum, persist per-category outcome, and render partial
scans distinctly.

**Complexity:** Medium. **Dependencies:** H-2. **BLOCKS MVP.**

---

## MEDIUM

| # | Gap | Finding | Blocks MVP |
|---|---|---|---|
| M-1 | 5, 6 | No `confidence`, `ruleId`, `evidence` or `detectionMethod` on findings. Secret findings report file+line but no redacted evidence — the user cannot see *what* matched. Triage states exist in `finding_statuses` and work. | No |
| M-2 | 7 | No prioritisation. All findings are a flat list ordered by analyzer execution order. No "Fix These First", no exploitability or effort signal. | No |
| M-3 | 8 | No education layer. `detail` + `remediation` are single technical strings. Missing: what this means, why it matters, how to verify. **This is the product thesis and it is the largest gap by product value.** | No |
| M-4 | 10 | No framework detection at all. Remediation is generic; the scanner cannot tell Next.js from Django. | No |
| M-5 | 12 | Legal checks are titled `No privacy policy found` with no disclaimer anywhere in report or UI. Reads as a compliance verdict. | **Yes** — liability |
| M-6 | 13 | AI disclosure finding is phrased as fact rather than "potential requirement, review recommended". | **Yes** — liability |
| M-7 | 32 | 5 bare `console` calls, no structured logging, no metrics, no scan lifecycle events. | No |
| M-8 | 33 | Workspace cleanup is correct (`finally { rmSync }`, verified). No documented retention policy for stored reports or events; no `DATA-RETENTION.md`. Account deletion cascades correctly. | No |
| M-9 | 4, 17, 20 | Scan completeness is not reported; rescan works but is not presented as the core loop; no "what Nettle did not check" section anywhere. | No |

---

## LOW

| # | Gap | Finding |
|---|---|---|
| L-1 | 9 | No Beginner/Developer/Expert views. Single technical register throughout. |
| L-2 | 18 | No launch checklist view. |
| L-3 | 23 | Report structure is flat; no progressive disclosure. |
| L-4 | 11 | AI security covers the six required checks well, but does not enumerate dangerous capabilities (db/file/payment/email/command access) or carry the "increases impact of prompt injection" framing. |

---

## INFORMATIONAL

**I-1 · SQLite scaling boundary (GAP 30).** `node:sqlite`, single-instance. Correct
for today, and the brief says not to migrate unnecessarily. But on App Runner
storage is ephemeral — **containers are replaced on every deploy, taking all
data with them**. This is not a scaling concern, it is data loss on first
redeploy. Needs RDS before real signups, and a documented migration plan.

**I-2 · Documentation.** `ARCHITECTURE.md` and `REPOSITORY-STRUCTURE.md` exist.
Missing: `SECURITY.md`, `SCANNER.md`, `SCANNER-RULES.md`, `THREAT-MODEL.md`,
`DATA-RETENTION.md`, `DEPLOYMENT.md`.

**I-3 · No production mocks (GAP 31) — clean.** Searched the whole `src/` tree
for mock/fake/stub/placeholder/hardcoded results. The only hits are *detection
patterns* (`codeQuality.ts` searching customer code for security-related TODOs).
No fake findings, scores, alerts or billing state. Tests use real fixtures and
run the real scanner.

---

## What is already right

Worth stating plainly, because the brief says not to rewrite working things:

- **Tenant isolation at the API layer** — all 13 project routes verified refusing strangers with `404` (not `403`, so existence is not confirmed).
- **Password reset does not leak account existence** — returns the same message either way. GAP 29 partially satisfied already.
- **Password hashing** — scrypt with per-user salt and `timingSafeEqual`.
- **Docker runs as a non-root user**, and does install Semgrep (unpinned — see H-1).
- **Scan quota metering** — usage ledger correctly independent of stored reports.
- **Workspace cleanup** — `finally` blocks verified on both scan paths.
- **Zip slip specifically is blocked** — verified empirically. But by `unzip`'s own path sanitisation, not by Nettle code, and it is untested. A future switch to a library extractor would silently reintroduce it.
- **The scanner makes zero outbound network calls** — verified across every module. Customer source never leaves the host.

---

## NOT VERIFIED in this environment

Stated explicitly rather than assumed:

- **Docker build and run.** No Docker daemon available here. The Dockerfile is read and reviewed above, but `docker build` has **not** been executed and the image has **not** been started. GAP 27 cannot be closed from this environment.
- **Semgrep execution.** Binary absent; 5 tests fail. The integration is reviewed by reading, not by running.
- **Repo-scan cloning.** The sandbox proxy demands credentials for public repos, so `/api/scans/repo` cannot be exercised end to end.
- **Real Stripe flows.** No API key configured.

---

## Recommended sequence

1. **C-1, C-3** — symlink refusal + archive limits. Small, self-contained, closes the live breach.
2. **H-2** — the three-state model. Everything else depends on it.
3. **H-1, H-4, H-7** — Semgrep honesty, score integrity, scan status. Natural follow-ons to H-2.
4. **H-3** — rate limiting, especially the unauthenticated endpoints.
5. **M-5, M-6** — legal and AI-disclosure language. Small edits, real liability reduction.
6. **H-6, M-4** — route analysis and framework detection together.
7. **M-1, M-2, M-3** — evidence, prioritisation, education. The product-value tier.
8. **C-2** — worker isolation. Largest change; sequenced after the cheap mitigations are in.
9. Tests, docs, self-scan.

---

*Phase 1 complete. No implementation has begun. Proceeding to
`NETTLE-REMEDIATION-PLAN.md` on approval of these findings and this ordering.*
