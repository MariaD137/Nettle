import type { Control } from "../types";
import { registerControl } from "../registry";

export const AUTH_005: Control = {
  controlKey: "AUTH-005",
  category: "Session Management",
  subcategory: "Token lifecycle",
  name: "Refresh token rotation for JWT-based sessions",
  description:
    "An application issuing JWTs for session-like authentication needs a refresh-token mechanism — otherwise access " +
    "tokens are either long-lived (a leaked token stays valid for a long time) or users must re-authenticate " +
    "uncomfortably often to keep access tokens short-lived.",
  question: "Is a refresh-token pattern present alongside JWT issuance?",
  defaultSeverity: "medium",

  passCriteria: "A refresh-token pattern (refresh_token/refreshToken/token rotation) is present in the scanned source.",
  failCriteria: "The application issues JWTs but no refresh-token pattern was found anywhere in the scanned source.",
  notVerifiedCriteria: "A file matched by the scan's inclusion rules could not be read, so refresh-token usage was not checked.",

  whyItMatters:
    "Without refresh tokens, teams tend toward one of two bad defaults: a long-lived access token (a leak or theft " +
    "grants access for its whole lifetime), or forcing users to log in again frequently (which trains them to not " +
    "notice a real phishing prompt asking for credentials).",

  technologyFixes: [
    {
      technology: "express",
      quickFix: "Issue a short-lived access token (e.g. 15m) alongside a separate, longer-lived refresh token.",
      developerFix: "Store the refresh token server-side (or as an HttpOnly cookie), rotate it on each use (one-time-use), and issue a new access token from it via a dedicated /refresh endpoint.",
      architectureFix: "Track issued refresh tokens in a revocation-capable store (a database table or Redis) so a compromised refresh token can be invalidated immediately, not just left to expire.",
      codeExample: "const accessToken = jwt.sign(payload, secret, { expiresIn: '15m' });\nconst refreshToken = jwt.sign({ sub: payload.sub }, refreshSecret, { expiresIn: '30d' });",
    },
    {
      technology: "generic",
      quickFix: "Issue a short-lived access token alongside a separate, longer-lived, single-use refresh token.",
      developerFix: "Rotate the refresh token on every use and store it server-side so it can be revoked, rather than relying on client-side deletion alone.",
      architectureFix: "Track issued refresh tokens in a revocation-capable store so a compromised one can be invalidated before it expires naturally.",
    },
  ],

  longTermHardening: "Detect and respond to refresh-token reuse (a rotated-out token being presented again) as a signal of possible theft, revoking the whole token family.",
  verificationMethod: "Rescan and confirm a refresh-token pattern is now present alongside JWT issuance.",
  references: ["OWASP ASVS V3: Session Management Verification Requirements"],
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

registerControl(AUTH_005);
