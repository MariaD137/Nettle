import type { Control } from "../types";
import { registerControl } from "../registry";

export const API_003: Control = {
  controlKey: "API-003",
  category: "API Security",
  subcategory: "Cross-site request forgery",
  name: "CSRF protection for cookie-based authentication",
  description:
    "An application that authenticates requests using a cookie the browser attaches automatically needs an explicit " +
    "CSRF defense (a token, the double-submit pattern, or a strict SameSite cookie) — otherwise a malicious page can " +
    "trigger state-changing requests using the victim's own session.",
  question: "Does the application defend cookie-authenticated requests against CSRF?",
  defaultSeverity: "medium",

  passCriteria: "A CSRF token library/pattern (csrf, csurf, a csrfToken/xsrf reference) is present in the scanned source.",
  failCriteria: "The application sets cookies (from AUTH-004's detection) but no CSRF token or double-submit pattern was found anywhere in the scanned source.",
  notVerifiedCriteria:
    "Only applicable when cookie-based auth is in use; a strict SameSite cookie alone can also mitigate CSRF, which a " +
    "source scan cannot fully evaluate against every browser's current SameSite defaults.",

  whyItMatters:
    "Without CSRF protection, a page on any other site can submit a form or fetch() to this API and the browser will " +
    "attach the victim's cookie automatically — the request looks completely legitimate to a server that only checks " +
    "for a valid session.",

  technologyFixes: [
    {
      technology: "express",
      quickFix: "Set sameSite: 'strict' on the session cookie as an immediate mitigation, then add a CSRF token library.",
      developerFix: "Use a CSRF middleware (csrf-csrf, or the double-submit-cookie pattern) that issues a token the client must echo back on state-changing requests, verified server-side before the handler runs.",
      architectureFix: "Apply CSRF verification as router-level middleware on every route group that trusts cookies, so a new route can't skip it by omission.",
      codeExample: "import { doubleCsrf } from 'csrf-csrf';\nconst { doubleCsrfProtection } = doubleCsrf({ getSecret: () => process.env.CSRF_SECRET! });\napp.use(doubleCsrfProtection);",
    },
    {
      technology: "generic",
      quickFix: "Set the session cookie's SameSite attribute to 'strict' or 'lax' as an immediate mitigation.",
      developerFix: "Add CSRF token verification (or the double-submit-cookie pattern) to every state-changing endpoint that relies on a cookie for authentication.",
      architectureFix: "Verify the CSRF token in shared middleware applied to a whole route group, not per-handler.",
    },
  ],

  longTermHardening: "Add an integration test that submits a state-changing request with a valid session cookie but no CSRF token and asserts it is rejected.",
  verificationMethod: "Rescan and confirm a CSRF token pattern is now present in the source.",
  references: ["OWASP Cross-Site Request Forgery Prevention Cheat Sheet"],
  complianceMappings: ["SOC 2 CC6.1"],

  releaseImpactBySeverity: {
    critical: "BLOCK_RELEASE",
    high: "REVIEW_BEFORE_RELEASE",
    medium: "FIX_RECOMMENDED",
    low: "IMPROVEMENT",
    info: "INFORMATIONAL",
  },

  enabled: true,
  version: "1.0.0",
};

registerControl(API_003);
