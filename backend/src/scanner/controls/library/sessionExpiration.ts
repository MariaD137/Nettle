import type { Control } from "../types";
import { registerControl } from "../registry";

export const AUTH_007: Control = {
  controlKey: "AUTH-007",
  category: "Session Management",
  subcategory: "Token lifecycle",
  name: "Session expiration configured",
  description:
    "A session cookie without a maxAge persists for the lifetime of the browser session by default in most " +
    "configurations, or in some setups indefinitely — increasing how long a stolen or shared session cookie remains " +
    "usable.",
  question: "Is a session expiration (maxAge) configured?",
  defaultSeverity: "medium",

  passCriteria: "A maxAge value is configured on the session cookie.",
  failCriteria: "express-session is used with no maxAge configured on the session cookie.",
  notVerifiedCriteria: "A file matched by the scan's inclusion rules could not be read, so session expiration configuration was not checked.",

  whyItMatters:
    "Without an explicit expiration, a session persists far longer than most users expect — on a shared or public " +
    "computer, or after a cookie is stolen via XSS, the window during which it remains valid is unnecessarily long.",

  technologyFixes: [
    {
      technology: "express",
      quickFix: "Set cookie.maxAge on the session configuration: cookie: { maxAge: 24 * 60 * 60 * 1000 } for 24 hours.",
      developerFix: "Choose a maxAge appropriate to the application's sensitivity — shorter for anything handling payments or sensitive data, longer for a low-risk consumer app — and pair it with sliding-expiration (resetting on activity) if users shouldn't be logged out mid-session.",
      codeExample: "app.use(session({ secret: process.env.SESSION_SECRET, cookie: { maxAge: 24 * 60 * 60 * 1000, httpOnly: true, secure: true } }));",
    },
    {
      technology: "generic",
      quickFix: "Configure an explicit session/cookie expiration appropriate to the application's sensitivity.",
      developerFix: "Set a maxAge (or equivalent) on the session so it does not persist indefinitely, and consider sliding expiration for active users.",
    },
  ],

  longTermHardening: "Add server-side session expiration enforcement independent of the cookie's own maxAge, so a client that ignores cookie expiry still can't use a stale session.",
  verificationMethod: "Rescan and confirm a maxAge is now configured on the session.",
  references: ["OWASP Session Management Cheat Sheet: Session Expiration"],
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

registerControl(AUTH_007);
