import type { Control } from "../types";
import { registerControl } from "../registry";

export const AUTHZ_001: Control = {
  controlKey: "AUTHZ-001",
  category: "Authorization",
  subcategory: "Role/permission enforcement",
  name: "Admin/privileged routes enforce authorization, not just authentication",
  description:
    "Authentication answers 'who are you?'; authorization answers 'what are you allowed to do?'. The AUTH-* " +
    "controls in this library check authentication mechanics only — password hashing, session/JWT handling, " +
    "login/logout. None of them, and nothing else in this library before this control, checked whether a route " +
    "that should be restricted to privileged users (an admin panel, an internal/ops endpoint) actually enforces a " +
    "role or permission check, as opposed to merely requiring *some* logged-in session. A regular authenticated " +
    "user reaching an admin route because it only checked 'is there a session' is a real, common vulnerability " +
    "class this control exists to catch — see MT-002 for the closely related but distinct object-level " +
    "(resource-ownership) authorization check.",
  question: "Do admin/privileged routes check the caller's role or permissions, not just that they're logged in?",
  defaultSeverity: "critical",
  passCriteria: "Every detected admin/privileged route shows a role, permission, or authorization-middleware check in its own handler or middleware chain.",
  failCriteria: "A detected admin/privileged route (its path contains admin/internal-style segments) shows no role/permission/authorization check anywhere in its handler or middleware chain — only that a session exists, if even that.",
  notVerifiedCriteria:
    "No admin-style route path was detected at all, so this control cannot confirm route-level authorization is enforced anywhere in the scanned code — but the presence of authentication (login/session/JWT) alone is never treated as evidence that authorization is also enforced. Also NOT_VERIFIED when a matched file could not be read, or when authorization could plausibly be enforced by a mechanism this regex-level scan cannot see (a database row-level-security policy, an API gateway's own auth layer, a framework's route-level decorator this control's patterns don't recognize).",
  whyItMatters:
    "Broken Function Level Authorization (OWASP API Security's #5) is one of the most common real-world API " +
    "vulnerabilities precisely because it's easy to get authentication right and stop there — a route protected " +
    "by 'requireLogin' alone is reachable by every registered user, not just the admins it was meant for. The gap " +
    "is invisible in normal testing (a logged-in QA account can reach the route just fine) and only shows up when " +
    "a regular customer account is deliberately pointed at the admin URL.",
  technologyFixes: [
    {
      technology: "generic",
      quickFix: "Add an explicit role/permission check to every admin or privileged route, separate from the authentication check that only confirms a session exists.",
      developerFix:
        "Use a dedicated authorization middleware (requireRole('admin'), a permission-check function, or a policy library) applied to every admin/internal route — never rely on the route simply living behind the same login-required gate as ordinary user routes. Deny by default: a route with no explicit role check should not be assumed safe because it's also authenticated.",
      codeExample:
        "// Instead of: router.get('/admin/users', requireAuth, handler)\n" +
        "router.get('/admin/users', requireAuth, requireRole('admin'), handler);",
    },
  ],
  longTermHardening:
    "Add a test that authenticates as a regular (non-admin) user and requests every admin/internal route directly, asserting a 403 rather than the privileged response. Consider a centralized route-permission registry so a new admin route can't be added without an explicit permission declaration.",
  verificationMethod: "Rescan and confirm the previously-unprotected admin route now shows a role/permission check, or manually confirm authorization is enforced by a mechanism outside this scan's visibility (an API gateway, a framework decorator) if the regex can't see it.",
  references: ["OWASP API Security Top 10: API5:2023 Broken Function Level Authorization"],
  complianceMappings: ["SOC 2 CC6.1"],
  releaseImpactBySeverity: { critical: "BLOCK_RELEASE", high: "REVIEW_BEFORE_RELEASE", medium: "FIX_RECOMMENDED", low: "IMPROVEMENT", info: "INFORMATIONAL" },
  enabled: true,
  version: "1.0.0",
};

registerControl(AUTHZ_001);
