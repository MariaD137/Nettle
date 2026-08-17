# Nettle Security Policy

## Reporting Security Vulnerabilities

**Do not open public GitHub issues for security vulnerabilities.**

Please report security issues to: `security@nettle.app`

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Any proof-of-concept

We will acknowledge receipt within 24 hours and provide updates every 5 days.

## Security Practices

### Authentication & Authorization

- ✅ Passwords hashed with scrypt + per-user salt
- ✅ Timing-safe comparison (`timingSafeEqual`)
- ✅ Session tokens as cryptographic random bytes
- ✅ Project isolation — API refuses cross-tenant access
- ✅ Bearer token authentication on all protected endpoints

### Data Protection

- ✅ Encrypted in transit (HTTPS only)
- ⚠️ Database encryption at rest — **not yet true**. Production currently runs on `node:sqlite`, a single file on the App Runner container's ephemeral disk. No RDS, S3, or Secrets Manager resource is provisioned in `infra/` today. See "SQLite in Production" under Known Issues.
- ✅ API keys never logged
- ✅ Credentials in environment variables, not files
- ✅ Scanner never sends customer code to external services

### API Security

- ✅ CORS enabled for dashboard origin only
- ✅ Rate limiting on all public endpoints
- ✅ Rate limiting on scan endpoints (prevent abuse)
- ✅ HMAC-SHA256 signatures on webhooks (customer can verify)
- ✅ Input validation on all endpoints

### Secrets & Credentials

**Environment Variables (never committed):**
- `STRIPE_SECRET_KEY`
- `STRIPE_WEBHOOK_SECRET`
- `NETTLE_WEBHOOK_SECRET`
- `DATABASE_URL` (when using RDS)

**Rotation:**
- Stripe keys: rotate in Stripe dashboard
- Webhook secret: update and restart service
- Database credentials: rotate in RDS console

### Dependency Management

- ✅ No hardcoded secrets in code
- ✅ Dependencies pinned in `package-lock.json`
- ✅ GitHub Dependabot monitors for vulnerabilities
- ✅ Manual audit of major updates

**Current high-severity vulnerabilities:**
- [ ] None identified

### Logging & Monitoring

- ✅ Errors logged with context (no PII)
- ✅ Authentication failures logged
- ✅ Rate limit violations logged
- ✅ All admin actions logged

**What is logged:**
- Request method and path (not response body)
- HTTP status code
- User ID (not email)
- Timestamp

**What is NOT logged:**
- Request bodies (contain customer source)
- Response bodies (contain findings/secrets)
- Authorization tokens
- API keys or passwords

### File Upload Security

- ✅ Zip files extracted to isolated workspace
- ✅ Symlinks rejected during extraction
- ✅ Decompression bomb prevention (500 MB uncompressed limit)
- ✅ File traversal checks (`../` path normalization)
- ✅ Workspace cleaned up after scan
- ✅ 25 MB compressed file size limit

### Scanner Isolation (Roadmap)

Current state: Scanner runs in same process as API.

**Planned (Phase 3d):**
- Process-level isolation (separate worker)
- Resource limits (CPU, memory, processes)
- Scratch-only filesystem
- No environment variables in worker

### Multi-Tenancy

- ✅ Database queries filtered by `user_id` and `project_id`
- ✅ Cannot list other users' projects
- ✅ Cannot access other users' scans
- ✅ Cannot modify other users' rules
- ✅ Tenant isolation tests verify all boundaries

**Test coverage:** See `tenantIsolation.test.ts`

### Third-Party Integrations

#### Stripe (Payment Processing)

- ✅ PCI DSS compliant
- ✅ Webhook signatures verified
- ✅ Customer ID stored locally
- ✅ Card details never stored or transmitted

#### GitHub (Repo Scanning)

- ✅ OAuth token stored encrypted
- ✅ Public repos accessed read-only
- ✅ No write access requested
- ✅ Token scoped to `public_repo` only

#### Slack / PagerDuty (Webhooks)

- ✅ Webhook URLs stored in database
- ✅ Payloads signed with HMAC-SHA256
- ✅ Customer can verify signatures
- ✅ Retry logic with exponential backoff

## Known Issues & Mitigations

### SQLite in Production

**Issue:** Single-file database on ephemeral storage.  
**Mitigation:** Migrate to RDS immediately (see `DEPLOYMENT.md`).  
**Status:** Will be enforced before production launch.

### Scanner in API Process

**Issue:** Untrusted input processed in API process.  
**Mitigation:** Separate worker process coming in Phase 3d.  
**Status:** Acceptable for MVP, blocks large-scale deployment.

### Rate Limiting (In-Memory)

**Issue:** Resets on server restart, doesn't work across instances.  
**Mitigation:** OK for single-instance deployment.  
**Upgrade:** Redis-backed rate limiter for multi-instance.

## Compliance

### GDPR

- ✅ User data export available (future: `/api/user/data`)
- ✅ Account deletion cascades to all data
- ✅ Data retention policy (see `DATA-RETENTION.md`)
- ✅ No data shared with third parties

### SOC 2

**In Scope (planned):**
- Access controls (authentication, authorization)
- Data security (encryption, secrets management)
- Monitoring (logging, alerting)
- Change management (deployments, CI/CD)

**Audit:** No SOC 2 audit has been performed or scheduled as of this revision. The Q2 2025 date in a previous version of this document has passed without one occurring — this section describes intended scope, not current certification status.

## Security Testing

### Manual Testing

- ✅ SQL injection attempts
- ✅ Cross-site scripting (XSS)
- ✅ Cross-site request forgery (CSRF)
- ✅ Authentication bypass
- ✅ Authorization bypass
- ✅ Symlink traversal (FIXED)
- ✅ Zip slip (FIXED)

### Automated Testing

- ✅ Semgrep rules for security patterns
- ✅ OSV database for known vulnerabilities
- ✅ SAST on custom code (TypeScript)
- ✅ Dependency scanning (npm audit)

### Penetration Testing

**Status:** Not yet performed. The Q1 2025 date in a previous version of this document has passed without a penetration test occurring; a new date has not been set.

## Security Roadmap

The Q4 2024 / Q1 2025 / Q2 2025 target dates in earlier versions of this
document have all passed without these items being completed. Removing the
stale dates rather than replacing them with new unverified ones — this list
reflects what's still outstanding as of this revision, not a committed
timeline.

- [ ] Process-level scanner isolation (scans currently run in the same
      process as the API server — see "Scanner Isolation" above)
- [ ] Redis-backed rate limiting (currently in-memory, single-instance only)
- [ ] Audit logging system (currently console-based application logging only)
- [ ] RDS migration (currently `node:sqlite` on ephemeral container disk)
- [ ] Penetration testing
- [ ] Security audit report
- [ ] SOC 2 Type II certification
- [ ] Real anomaly/threat detection beyond the current rule-based checks
      (brute force, request flood, known attack-probe paths, SQLi-shaped
      requests) — an ML-based scoring module exists in the codebase but is
      not connected to live detection
- [ ] Security incident response plan

## Contact

**Security Issues:** security@nettle.app  
**General Inquiries:** support@nettle.app  
**Blog:** https://nettle.app/blog

---

Last Updated: 2026-08-17
