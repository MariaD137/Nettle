import type { Control } from "../types";
import { registerControl } from "../registry";

export const AUTH_008: Control = {
  controlKey: "AUTH-008",
  category: "Session Management",
  subcategory: "Token lifecycle",
  name: "Session/token invalidation on logout",
  description:
    "Logging out should actually end the session or token, not just tell the client to forget it. Without explicit " +
    "server-side invalidation (session destruction, or a token blacklist/revocation list for JWTs), a token or " +
    "session that the user believes is over remains valid until it happens to expire naturally.",
  question: "Does logout explicitly invalidate the session or token server-side?",
  defaultSeverity: "medium",

  passCriteria: "A session-destruction call or a token blacklist/revocation pattern is present in the scanned source.",
  failCriteria: "The application uses JWTs or sessions but no server-side invalidation pattern was found anywhere in the scanned source.",
  notVerifiedCriteria: "A file matched by the scan's inclusion rules could not be read, so logout invalidation was not checked.",

  whyItMatters:
    "A JWT is valid by design until it expires or is explicitly revoked — deleting it client-side (e.g. clearing " +
    "localStorage) does nothing server-side. If that token is intercepted before \"logout,\" it remains fully usable " +
    "afterward. A session-based app that doesn't call session.destroy() has the same problem: the cookie is gone " +
    "client-side, but the session data — and therefore any copy of that cookie — is still live server-side.",

  technologyFixes: [
    {
      technology: "express",
      quickFix: "Call req.session.destroy() in the logout handler for sessions, or check a token blacklist on every JWT verification.",
      developerFix: "For sessions: req.session.destroy(callback) in the /logout route. For JWTs: maintain a revocation list (a database table or Redis set of revoked token IDs) checked on every request, since a JWT itself can't be invalidated without one.",
      architectureFix: "For JWT-heavy architectures where a revocation list defeats the point of being stateless, keep access-token lifetimes very short and revoke via the refresh token instead — logout invalidates the refresh token, and the access token simply expires shortly after.",
      codeExample: "app.post('/logout', (req, res) => {\n  req.session.destroy((err) => {\n    res.clearCookie('connect.sid');\n    res.status(204).end();\n  });\n});",
    },
    {
      technology: "generic",
      quickFix: "Destroy the session server-side on logout, or check a revocation list before honoring a JWT.",
      developerFix: "Never rely on the client discarding a credential as the only invalidation mechanism — the server must have a way to reject a token/session it has explicitly ended.",
    },
  ],

  longTermHardening: "Add a test that calls logout, then replays the old session cookie or JWT against a protected route and asserts it is now rejected.",
  verificationMethod: "Rescan and confirm a session-destruction or token-revocation pattern is now present in the source.",
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

registerControl(AUTH_008);
