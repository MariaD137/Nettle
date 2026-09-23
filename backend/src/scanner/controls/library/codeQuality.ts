import type { Control } from "../types";
import { registerControl } from "../registry";

export const CQ_001: Control = {
  controlKey: "CQ-001",
  category: "Code Quality",
  subcategory: "Debug artifacts",
  name: "No excessive debug console output",
  description:
    "console.log/debug/trace calls left in production code can leak sensitive data (tokens, passwords, user " +
    "info) into browser consoles or server logs, and clutter output that matters. A file with three or more such " +
    "calls is flagged; occasional debug logging isn't.",
  question: "Is production code free of excessive debug console output?",
  defaultSeverity: "low",
  passCriteria: "No scanned file had three or more console.log/debug/trace calls.",
  failCriteria: "A scanned file had three or more console.log/debug/trace calls.",
  notVerifiedCriteria: "A file matched by the scan's inclusion rules could not be read, so debug output was not checked in it.",
  whyItMatters:
    "Debug logging that ships to production routinely captures exactly the data an attacker wants — request " +
    "bodies, tokens, internal identifiers — in a place (server logs, browser devtools) that's far less protected " +
    "than the application itself.",
  technologyFixes: [
    {
      technology: "generic",
      quickFix: "Remove leftover console.log/debug/trace calls before shipping.",
      developerFix: "Replace ad hoc console logging with a structured logger (pino, winston) that respects log levels and can redact sensitive fields, and gate verbose output behind a debug flag that defaults to off in production.",
    },
  ],
  verificationMethod: "Rescan and confirm no file has three or more debug console calls.",
  references: [],
  complianceMappings: [],
  releaseImpactBySeverity: { critical: "BLOCK_RELEASE", high: "REVIEW_BEFORE_RELEASE", medium: "FIX_RECOMMENDED", low: "IMPROVEMENT", info: "INFORMATIONAL" },
  enabled: true,
  version: "1.0.0",
};

export const CQ_002: Control = {
  controlKey: "CQ-002",
  category: "Code Quality",
  subcategory: "Debug artifacts",
  name: "No unresolved security TODO/FIXME items",
  description:
    "A TODO/FIXME/HACK/XXX comment that mentions a security-relevant term (auth, secret, token, encrypt, " +
    "sanitize, etc.) documents a known gap the author was aware of and didn't close before this code shipped.",
  question: "Are all security-relevant TODO/FIXME comments resolved?",
  defaultSeverity: "medium",
  passCriteria: "No scanned file contains a TODO/FIXME/HACK/XXX comment mentioning a security-relevant term.",
  failCriteria: "A scanned file contains a TODO/FIXME/HACK/XXX comment mentioning a security-relevant term.",
  notVerifiedCriteria: "A file matched by the scan's inclusion rules could not be read, so its comments were not checked.",
  whyItMatters:
    "Unlike a vulnerability nobody noticed, this is a gap someone flagged and then shipped anyway — it's the " +
    "highest-confidence, lowest-effort finding in the whole scan to act on, because the fix is already described " +
    "in the comment.",
  technologyFixes: [
    {
      technology: "generic",
      quickFix: "Address the security concern described in the comment before shipping to production.",
      developerFix: "Triage every security-flagged TODO: fix it now, or turn it into a tracked issue with an owner and a deadline rather than leaving it silently in the code.",
    },
  ],
  verificationMethod: "Rescan and confirm the flagged comment (and the gap it described) is gone.",
  references: [],
  complianceMappings: [],
  releaseImpactBySeverity: { critical: "BLOCK_RELEASE", high: "REVIEW_BEFORE_RELEASE", medium: "FIX_RECOMMENDED", low: "IMPROVEMENT", info: "INFORMATIONAL" },
  enabled: true,
  version: "1.0.0",
};

export const CQ_003: Control = {
  controlKey: "CQ-003",
  category: "Code Quality",
  subcategory: "Debug artifacts",
  name: "Debug mode not hardcoded on",
  description:
    "A hardcoded debug/development flag set to true can expose stack traces, internal state, and verbose error " +
    "messages to attackers if that code path reaches production.",
  question: "Is debug mode controlled by environment configuration rather than hardcoded on?",
  defaultSeverity: "medium",
  passCriteria: "No scanned file hardcodes a debug/DEBUG flag or NODE_ENV development check to true.",
  failCriteria: "A scanned file hardcodes a debug/DEBUG flag, or a NODE_ENV development-only branch, to true.",
  notVerifiedCriteria: "A file matched by the scan's inclusion rules could not be read, so debug configuration was not checked in it.",
  whyItMatters:
    "Debug mode is meant to be off by default in production. A hardcoded true bypasses whatever environment " +
    "configuration was supposed to control that — the value ships the same regardless of what environment it " +
    "actually runs in.",
  technologyFixes: [
    {
      technology: "generic",
      quickFix: "Drive the debug flag from an environment variable that defaults to false, not a hardcoded true.",
      developerFix: "Replace the hardcoded value with process.env.DEBUG === 'true' (or the framework's equivalent), and confirm the deployed environment doesn't set it.",
    },
  ],
  verificationMethod: "Rescan and confirm the debug flag now reads from environment configuration.",
  references: [],
  complianceMappings: [],
  releaseImpactBySeverity: { critical: "BLOCK_RELEASE", high: "REVIEW_BEFORE_RELEASE", medium: "FIX_RECOMMENDED", low: "IMPROVEMENT", info: "INFORMATIONAL" },
  enabled: true,
  version: "1.0.0",
};

export const CQ_004: Control = {
  controlKey: "CQ-004",
  category: "Code Quality",
  subcategory: "Error handling",
  name: "Stack traces not returned to clients",
  description:
    "Sending a stack trace in an HTTP response reveals internal file paths, library versions, and code structure " +
    "— a reconnaissance gift to an attacker probing the application.",
  question: "Are stack traces kept out of HTTP responses?",
  defaultSeverity: "high",
  passCriteria: "No scanned file passes a stack trace value (stack/stackTrace/err.stack/error.stack) to res.json()/res.send().",
  failCriteria: "A scanned file passes a stack trace value to res.json()/res.send().",
  notVerifiedCriteria: "A file matched by the scan's inclusion rules could not be read, so its error responses were not checked.",
  whyItMatters:
    "A stack trace tells an attacker exactly which framework, library versions, and internal file layout the " +
    "application uses — often enough to go straight to a known CVE for that exact version.",
  technologyFixes: [
    {
      technology: "generic",
      quickFix: "Return a generic error message to clients; log the full error (with stack) server-side only.",
      developerFix: "Catch the error, log it server-side with a correlation ID, and return only that ID plus a generic message: res.status(500).json({ error: 'Internal server error', id: correlationId }).",
      codeExample: "app.use((err, req, res, next) => {\n  const id = crypto.randomUUID();\n  logger.error({ id, err });\n  res.status(500).json({ error: 'Internal server error', id });\n});",
    },
  ],
  verificationMethod: "Rescan and confirm no response path returns a stack trace.",
  references: ["OWASP: Improper Error Handling"],
  complianceMappings: [],
  releaseImpactBySeverity: { critical: "BLOCK_RELEASE", high: "REVIEW_BEFORE_RELEASE", medium: "FIX_RECOMMENDED", low: "IMPROVEMENT", info: "INFORMATIONAL" },
  enabled: true,
  version: "1.0.0",
};

export const CQ_005: Control = {
  controlKey: "CQ-005",
  category: "Code Quality",
  subcategory: "Error handling",
  name: "Raw error objects not returned to clients",
  description:
    "Passing a caught error object directly to res.json()/res.send() can leak internal details — SQL errors, " +
    "file paths, service names — that a generic error message wouldn't.",
  question: "Are caught errors sanitized before being sent to clients?",
  defaultSeverity: "medium",
  passCriteria: "No scanned file passes a caught error object (err/error/e) directly to res.json()/res.send().",
  failCriteria: "A scanned file's catch block passes the caught error object directly to res.json()/res.send().",
  notVerifiedCriteria: "A file matched by the scan's inclusion rules could not be read, so its catch blocks were not checked.",
  whyItMatters:
    "Even without a full stack trace, a raw error object often carries the same kind of internal detail — a " +
    "database driver's own error message, an internal hostname, a file path — that an attacker can use to learn " +
    "about the system underneath the application.",
  technologyFixes: [
    {
      technology: "generic",
      quickFix: "Catch the error and return a generic message: res.status(500).json({ error: 'Internal server error' }).",
      developerFix: "Log the real error server-side with full detail, and construct a separate, deliberately generic response object for the client rather than forwarding the caught error.",
    },
  ],
  verificationMethod: "Rescan and confirm catch blocks no longer forward the raw error object to a response.",
  references: [],
  complianceMappings: [],
  releaseImpactBySeverity: { critical: "BLOCK_RELEASE", high: "REVIEW_BEFORE_RELEASE", medium: "FIX_RECOMMENDED", low: "IMPROVEMENT", info: "INFORMATIONAL" },
  enabled: true,
  version: "1.0.0",
};

export const CQ_006: Control = {
  controlKey: "CQ-006",
  category: "Code Quality",
  subcategory: "Debug artifacts",
  name: "No test/debug endpoints in production code",
  description:
    "A route under a path like /test, /debug, /dev, /internal, or a name like admin-bypass/backdoor, left in " +
    "production code can provide unauthenticated access to internal functionality that was never meant to ship.",
  question: "Are test/debug endpoints removed or gated before production?",
  defaultSeverity: "high",
  passCriteria: "No scanned file registers a route under a test/debug/dev/internal/admin-bypass/backdoor-shaped path.",
  failCriteria: "A scanned file registers a route under a test/debug/dev/internal/admin-bypass/backdoor-shaped path.",
  notVerifiedCriteria: "A file matched by the scan's inclusion rules could not be read, so its routes were not checked.",
  whyItMatters:
    "These routes are convenient during development precisely because they skip the checks a real endpoint has — " +
    "which is exactly what makes one left in production a direct path around authentication or authorization.",
  technologyFixes: [
    {
      technology: "generic",
      quickFix: "Remove the test/debug endpoint, or gate it behind authentication and a NODE_ENV !== 'production' check.",
      developerFix: "If the endpoint is genuinely needed in every environment, apply the same authentication/authorization middleware every other route uses — never leave it open by omission.",
    },
  ],
  verificationMethod: "Rescan and confirm the route no longer exists or is now gated.",
  references: [],
  complianceMappings: [],
  releaseImpactBySeverity: { critical: "BLOCK_RELEASE", high: "REVIEW_BEFORE_RELEASE", medium: "FIX_RECOMMENDED", low: "IMPROVEMENT", info: "INFORMATIONAL" },
  enabled: true,
  version: "1.0.0",
};

export const CQ_007: Control = {
  controlKey: "CQ-007",
  category: "Code Quality",
  subcategory: "Suppressed checks",
  name: "No disabled security/quality checks",
  description:
    "A disabled linting rule, suppressed type check, or a flag like --force/--insecure/verify: false can mask a " +
    "real problem the tool it disables was specifically there to catch.",
  question: "Are security/quality checks (linting, type checking, TLS verification) left enabled?",
  defaultSeverity: "low",
  passCriteria: "No scanned file contains an eslint-disable/@ts-ignore/@ts-nocheck/--force/--insecure/verify: false pattern.",
  failCriteria: "A scanned file contains one of these disable/suppress patterns.",
  notVerifiedCriteria: "A file matched by the scan's inclusion rules could not be read, so suppressed checks were not checked in it.",
  whyItMatters:
    "Each of these exists to catch a specific class of bug automatically. Suppressing the warning doesn't fix " +
    "what triggered it — it just makes the tool stop telling you about it.",
  technologyFixes: [
    {
      technology: "generic",
      quickFix: "Re-enable the check and fix the underlying issue rather than suppressing the warning.",
      developerFix: "If a suppression is genuinely necessary, scope it as narrowly as possible (a single line, not a whole file) and leave a comment explaining why, so it's reviewable rather than silent.",
    },
  ],
  verificationMethod: "Rescan and confirm the suppression is gone or the underlying issue is fixed.",
  references: [],
  complianceMappings: [],
  releaseImpactBySeverity: { critical: "BLOCK_RELEASE", high: "REVIEW_BEFORE_RELEASE", medium: "FIX_RECOMMENDED", low: "IMPROVEMENT", info: "INFORMATIONAL" },
  enabled: true,
  version: "1.0.0",
};

export const SECRET_002: Control = {
  controlKey: "SECRET-002",
  category: "Security",
  subcategory: "Secrets",
  name: "No .env files committed to source control",
  description:
    "An .env/.env.local/.env.production/.env.development file committed to the repository is a structural risk " +
    "independent of SECRET-001's content-pattern matching — it flags the presence of a file whose entire purpose " +
    "is usually to hold secrets, regardless of whether this scan's patterns happen to recognize what's in it.",
  question: "Are .env-shaped files kept out of source control?",
  defaultSeverity: "critical",
  passCriteria: "No file matched by the scan's inclusion rules has an .env/.env.local/.env.production/.env.development name.",
  failCriteria: "A file matched by the scan's inclusion rules has an .env/.env.local/.env.production/.env.development name.",
  notVerifiedCriteria: "Not applicable — this control checks filenames already present in the scanned file set, not file contents.",
  whyItMatters:
    "Environment files often contain every secret the application uses in one place — database credentials, API " +
    "keys, signing secrets. Once committed, that content is in the repository's history permanently, readable by " +
    "anyone with repo access, even after the file is later deleted.",
  technologyFixes: [
    {
      technology: "generic",
      quickFix: "Add .env* to .gitignore and remove the committed file from the working tree.",
      developerFix: "Remove the file from git history entirely (git filter-repo or BFG Repo-Cleaner, not just a new commit deleting it), and rotate every secret it contained — assume all of them are compromised.",
      architectureFix: "Load configuration from a secrets manager or the deployment platform's own environment configuration rather than a file at all, so there's no file that could be committed by mistake.",
    },
  ],
  verificationMethod: "Rescan and confirm no .env-shaped file remains in the scanned file set.",
  references: [],
  complianceMappings: ["SOC 2 CC6.1"],
  releaseImpactBySeverity: { critical: "BLOCK_RELEASE", high: "REVIEW_BEFORE_RELEASE", medium: "FIX_RECOMMENDED", low: "IMPROVEMENT", info: "INFORMATIONAL" },
  enabled: true,
  version: "1.0.0",
};

registerControl(CQ_001);
registerControl(CQ_002);
registerControl(CQ_003);
registerControl(CQ_004);
registerControl(CQ_005);
registerControl(CQ_006);
registerControl(CQ_007);
registerControl(SECRET_002);
