import type { Control } from "../types";
import { registerControl } from "../registry";

export const AUTH_004: Control = {
  controlKey: "AUTH-004",
  category: "Session Management",
  subcategory: "Cookie security",
  name: "Secure cookie configuration",
  description:
    "A cookie carrying a session or auth token needs HttpOnly (unreachable from JavaScript), Secure (never sent over " +
    "plain HTTP), and SameSite (not sent with most cross-site requests) to resist the three most common ways a " +
    "cookie-based session gets stolen or replayed.",
  question: "Are cookies that carry session/auth state configured with HttpOnly, Secure, and SameSite?",
  defaultSeverity: "high",

  passCriteria: "Every cookie-setting call found in the scanned source sets httpOnly, secure, and a SameSite value.",
  failCriteria: "A cookie-setting call (e.g. res.cookie()) is present without one or more of HttpOnly, Secure, or SameSite.",
  notVerifiedCriteria: "A file matched by the scan's inclusion rules could not be read, so its cookie configuration was not checked.",

  whyItMatters:
    "Missing HttpOnly means a single XSS bug can read the cookie and exfiltrate the session directly. Missing Secure " +
    "means the cookie can be intercepted on an untrusted network (public wifi, a compromised router). Missing " +
    "SameSite means the cookie rides along on a cross-site request, which is the basis of CSRF.",

  technologyFixes: [
    {
      technology: "express",
      quickFix: "Add the missing flags to every res.cookie() call carrying session/auth state.",
      developerFix: "res.cookie('session', token, { httpOnly: true, secure: true, sameSite: 'strict' }). Use 'lax' instead of 'strict' only if the app needs the cookie sent on top-level cross-site navigation (e.g. an OAuth redirect landing).",
      architectureFix: "Centralize cookie issuance in one helper so every call site gets the same flags by construction, rather than each route remembering to set them.",
      codeExample: "res.cookie('session', token, { httpOnly: true, secure: true, sameSite: 'strict', maxAge: 24 * 60 * 60 * 1000 });",
    },
    {
      technology: "generic",
      quickFix: "Set HttpOnly, Secure, and SameSite on every cookie that carries session or authentication state.",
      developerFix: "Configure the cookie-issuing call in your framework to set all three flags — most frameworks default at least one of them off.",
      architectureFix: "Issue cookies from one centralized location so the flags can't be omitted by a new call site.",
    },
  ],

  longTermHardening: "Add an integration test that inspects the Set-Cookie header on login and asserts all three flags are present, so a future refactor can't silently drop one.",
  verificationMethod: "Rescan and confirm every cookie-setting call in the source now sets HttpOnly, Secure, and SameSite.",
  references: ["OWASP Session Management Cheat Sheet", "MDN: Set-Cookie — SameSite"],
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

registerControl(AUTH_004);
