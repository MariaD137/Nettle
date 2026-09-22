import type { Control } from "../types";
import { registerControl } from "../registry";

export const AUTH_003: Control = {
  controlKey: "AUTH-003",
  category: "Session Management",
  subcategory: "Token lifecycle",
  name: "JWT tokens issued with an expiration",
  description:
    "A JWT issued without an expiration claim never becomes invalid on its own — it remains a valid credential " +
    "until the signing key itself is rotated, which most applications never do.",
  question: "Are the application's JWTs issued with an expiration (expiresIn / exp)?",
  defaultSeverity: "high",

  passCriteria: "A JWT sign call in the scanned source sets an expiration (expiresIn, exp, or maxAge).",
  failCriteria: "The application signs JWTs but no expiration pattern was found anywhere in the scanned source.",
  notVerifiedCriteria:
    "A file matched by the scan's inclusion rules could not be read, so Nettle cannot confirm whether it or another " +
    "unreadable file set the expiration.",

  whyItMatters:
    "A leaked or stolen token without an expiration grants the holder permanent access, identical to the original " +
    "user's, with no way to revoke it short of rotating the signing secret for every user at once.",

  technologyFixes: [
    {
      technology: "express",
      quickFix: "Add expiresIn to the sign call: jwt.sign(payload, secret, { expiresIn: '15m' }).",
      developerFix: "Set a short expiration on access tokens (minutes, not days) and pair it with a refresh token for longer sessions.",
      architectureFix: "Centralize token issuance in one function so every call site gets the same expiration policy, rather than each route configuring it independently.",
      codeExample: "jwt.sign(payload, secret, { expiresIn: '15m' });",
    },
    {
      technology: "fastapi",
      quickFix: "Set an 'exp' claim on the payload before encoding: payload['exp'] = datetime.utcnow() + timedelta(minutes=15).",
      developerFix: "Use PyJWT or python-jose's exp support, setting a short-lived access token expiration paired with a longer-lived refresh token.",
      architectureFix: "Wrap token creation in a single helper function so the expiration policy is enforced consistently across the app.",
      codeExample: "payload = {'sub': user_id, 'exp': datetime.utcnow() + timedelta(minutes=15)}\njwt.encode(payload, secret, algorithm='HS256')",
    },
    {
      technology: "generic",
      quickFix: "Set a short expiration claim on every issued JWT before it is signed.",
      developerFix: "Issue short-lived access tokens (minutes) with a separate refresh-token mechanism for longer sessions, rather than a single long-lived token.",
      architectureFix: "Centralize token issuance behind one function or service so the expiration policy can't be omitted by a new call site.",
    },
  ],

  longTermHardening: "Add an integration test that decodes a freshly issued token and asserts its exp claim is within the expected window, so a future change can't silently drop it.",
  verificationMethod: "Rescan and confirm an expiration pattern is now present alongside every JWT sign call in the source.",
  references: ["OWASP ASVS V3: Session Management Verification Requirements", "RFC 7519: JSON Web Token (JWT), Section 4.1.4"],
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

registerControl(AUTH_003);
