/**
 * Education layer: beginner/developer/expert explanations for findings.
 * Helps non-technical users understand security without oversimplifying.
 */

import type { CheckResult } from "./types";

export type ExpertiseLevel = "beginner" | "developer" | "expert";

export interface EducationContent {
  beginner: string;
  developer: string;
  expert: string;
}

/**
 * Map finding categories to multi-level education content.
 */
const EDUCATION_MAP: Record<string, EducationContent> = {
  // Authentication & Access Control
  "no-authentication": {
    beginner:
      "This endpoint doesn't check if you're logged in. Anyone on the internet could use it, even if they shouldn't have access.",
    developer:
      "Route lacks authentication middleware. Add verify-jwt or similar auth checks before handling requests. Ensure all user-specific endpoints require valid tokens.",
    expert:
      "Mismatched auth semantics (app.use global vs route-specific middleware) are common. Check that auth applies recursively through nested routers. Verify token expiry, refresh flows, and session invalidation.",
  },
  "weak-authentication": {
    beginner:
      "This endpoint uses a weak way to check if you're logged in. Someone could potentially guess or forge their way in.",
    developer:
      "Auth uses weak patterns (hardcoded checks, client-side validation, weak token signing). Use strong JWT (HS256+ or RS256), short expiry, secure storage, and HttpOnly cookies.",
    expert:
      "JWT signing algorithm confusion (HS256 vs RS256 key leaks), lack of jti (JWT ID) for revocation, weak client secrets in OAuth flows, or missing PKCE in SPA auth flows.",
  },

  // Secrets & Credentials
  "hardcoded-secret": {
    beginner:
      "A password or API key is written directly in your code. Anyone who sees the code (or your git history) gets access to your accounts.",
    developer:
      "Secrets must never be in code. Use environment variables (process.env), .env files (loaded locally, never committed), or secret management (AWS Secrets Manager, HashiCorp Vault).",
    expert:
      "Rotation strategy: generate new secret, update code/config, wait for deployment, revoke old secret. Audit git history: git log -S 'secret_value' to find exposures. Use git-secrets pre-commit hook to prevent re-occurrence.",
  },

  // SQL Injection
  "sql-injection": {
    beginner:
      "User input is pasted directly into a database query. An attacker can trick your database into revealing or deleting data.",
    developer:
      "Always use parameterized queries (prepared statements). Example: db.query('SELECT * FROM users WHERE id = ?', [userId]). Never concatenate user input into SQL strings.",
    expert:
      "ORM limitations: Sequelize/TypeORM may auto-inject values unsafely in certain contexts (raw(), sequelize.literal()). Review query construction. Second-order injection: data from DB used in later query without re-escaping.",
  },

  // Command Injection
  "command-injection": {
    beginner:
      "Your code runs shell commands with user input. An attacker can inject extra commands to read files, steal data, or break your app.",
    developer:
      "Avoid shell execution with user input. Use library functions (fs.readFile, spawn with argv array) instead of exec(). If you must exec, use shell-escape library and avoid shell: true.",
    expert:
      "spawn() with shell:false is safe (no shell interpretation of argv). execFile() is safe. exec(), execSync() require shell escaping. Watch for second-order injection (database values used in shell commands).",
  },

  // XSS (Cross-Site Scripting)
  "xss": {
    beginner:
      "User input is displayed on a page without escaping. An attacker can inject code that runs in other people's browsers, stealing cookies or passwords.",
    developer:
      "Escape HTML when rendering user content. In React/Vue, use textContent or sanitize HTML with DOMPurify. Never use innerHTML with user data. Use CSP (Content-Security-Policy) header to block inline scripts.",
    expert:
      "Context matters: HTML escaping != URL escaping != JavaScript escaping. Dangling markup attacks (unclosed tags). DOM XSS from location.hash without sanitization. Check CSP directives: script-src, style-src, img-src. Review third-party scripts.",
  },

  // CSRF (Cross-Site Request Forgery)
  "csrf": {
    beginner:
      "Your app might execute unwanted actions when an attacker tricks a user into visiting a malicious site. Deleting data, changing passwords, transferring money.",
    developer:
      "Use CSRF tokens: generate unique token per session, embed in forms, verify on state-changing requests (POST/PUT/DELETE). Or use SameSite=Strict cookies (blocks cross-site sends). Express: use csurf middleware.",
    expert:
      "SameSite=Strict breaks some legitimate flows (cross-site sign-in links). SameSite=Lax is safer default. CSRF tokens alone don't help if XSS is present (attacker reads token). Double-submit cookies bypass session state.",
  },

  // CORS
  "cors-misconfiguration": {
    beginner:
      "Your API is open to requests from any website. Someone could build a site that tricks your users into making unwanted requests to your API.",
    developer:
      "Set CORS headers precisely. Use Access-Control-Allow-Origin: https://yourfrontend.com (not '*'). Whitelist origins, methods (GET, POST), headers. Use credentials: 'include' only for same-origin or specific trusted origins.",
    expert:
      "Wildcard origin ('*') + credentials = browser rejects. Null origin (file://) matches wildcard. Preflight requests (OPTIONS) are bypassed for simple requests (GET, POST with basic headers). Server-side origin validation for WebSocket upgrades.",
  },

  // Dependency Vulnerabilities
  "vulnerable-dependency": {
    beginner:
      "A library your app uses has a known security hole. Hackers might exploit it to break into your app.",
    developer:
      "Run npm audit to find vulnerabilities. Update to patched version (npm update library@latest). If no patch exists, find an alternative library or apply a temporary workaround. Lock versions in package-lock.json.",
    expert:
      "Transitive dependency hell: your code doesn't use library-X directly, but library-Y does (10 versions back). npm audit may show unfixable vulnerabilities until upstream updates. Use npm audit ignore for false positives (theoretically exploitable but no gadget chain).",
  },

  // Security Headers
  "missing-security-headers": {
    beginner:
      "Your website isn't telling browsers how to protect against common attacks. Without these headers, your site is more vulnerable to hacking.",
    developer:
      "Install helmet (npm install helmet). Add app.use(helmet()). Key headers: CSP (blocks XSS), HSTS (forces HTTPS), X-Frame-Options (prevents clickjacking), X-Content-Type-Options: nosniff.",
    expert:
      "CSP nonce management: regenerate nonce per request, embed in every <script>. HSTS preload: maxAge 31536000 (1 year), includeSubDomains, preload. Reporting: Content-Security-Policy-Report-Only first, then switch to enforcement.",
  },

  // HTTPS & TLS
  "missing-https": {
    beginner:
      "Your website isn't encrypted. Anyone on the same WiFi can read passwords, messages, and other data people send to your site.",
    developer:
      "Use HTTPS (TLS/SSL certificate). Free certs: Let's Encrypt. Set HSTS header (Strict-Transport-Security: max-age=31536000) to force HTTPS. Redirect HTTP → HTTPS.",
    expert:
      "TLS 1.2+ only (disable 1.0, 1.1). Disable weak ciphers. Check certificate pinning for APIs. OCSP stapling reduces client latency. Monitor certificate expiry (renewal 30 days before). CTLogs monitoring for certificate transparency.",
  },

  // Configuration & Defaults
  "default-credentials": {
    beginner:
      "Your app or server still has default usernames and passwords. Attackers always try these first.",
    developer:
      "Change all default credentials (database, admin panels, SSH, etc.) before deploying. Use strong passwords (16+ chars, random). Store in env vars, never in code.",
    expert:
      "Automated scanning for default creds (Shodan, Censys). Disable default user accounts entirely if possible. Use OAuth/OIDC instead of password auth. Implement rate limiting on login to slow brute-force.",
  },

  // Legal & Policy
  "missing-privacy-policy": {
    beginner:
      "Your app doesn't tell users what data you collect and how you use it. This may violate privacy laws.",
    developer:
      "Create PRIVACY_POLICY.md or /privacy route. Cover: what data collected (IPs, cookies, analytics), retention period, user rights (access, deletion, portability), third-party sharing, GDPR/CCPA compliance.",
    expert:
      "GDPR: document legal basis (consent, contract, legitimate interest). DPA (Data Processing Agreement) if you use processors. CCPA: opt-out mechanism. Retention: set deletion policy by data type. Test: verify DSAR (Data Subject Access Request) process.",
  },

  // Info & Best Practices
  "best-practice": {
    beginner:
      "This is a best practice recommendation to improve your security over time. It's not an immediate risk, but following it makes your app more resilient.",
    developer:
      "Best practices evolve as attacks do. Prioritize critical/high findings first. Best practices can usually be addressed in a separate sprint.",
    expert:
      "Use OWASP Top 10 as baseline. Layer defense: assume each layer will fail. Monitor logs and errors. Regular penetration testing. Security culture: train developers, encourage bug reports, automate security checks.",
  },
};

/**
 * Get multi-level education content for a finding.
 * Falls back to generic content if category not found.
 */
export function getEducation(finding: CheckResult): EducationContent {
  const category = finding.category?.toLowerCase() || "";
  const title = (finding.title || "").toLowerCase();

  // Try direct category match
  if (EDUCATION_MAP[category]) {
    return EDUCATION_MAP[category];
  }

  // Try keyword matching on title
  for (const [key, content] of Object.entries(EDUCATION_MAP)) {
    if (title.includes(key.replace(/-/g, " "))) {
      return content;
    }
  }

  // Fallback: generic education based on severity
  return {
    beginner: `This security finding was detected in your code. Review the remediation steps to address it.`,
    developer: `This finding indicates a potential security issue. Follow the provided remediation guidance to fix it. Consider adding automated tests to prevent regression.`,
    expert: `Security findings should be triaged by risk and exploitability. Implement compensating controls if immediate fixes aren't possible. Document assumptions and edge cases.`,
  };
}

/**
 * Enrich a finding with education content at all levels.
 */
export function enrichWithEducation(
  finding: CheckResult,
  level: ExpertiseLevel = "beginner"
): CheckResult & { education: EducationContent; educationLevel: ExpertiseLevel } {
  return {
    ...finding,
    education: getEducation(finding),
    educationLevel: level,
  };
}

/**
 * Get explanation at specific level.
 */
export function getExplanation(finding: CheckResult, level: ExpertiseLevel): string {
  const content = getEducation(finding);
  return content[level];
}

/**
 * Format finding with education content as markdown.
 */
export function formatFindingWithEducation(finding: CheckResult, level: ExpertiseLevel): string {
  const content = getEducation(finding);
  const explanation = content[level];

  return `## ${finding.title}

**Severity:** ${finding.severity}

${finding.detail}

### Explanation (${level} level)
${explanation}

### Remediation
${finding.remediation || "See details above."}
`;
}
