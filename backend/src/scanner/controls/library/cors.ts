import type { Control } from "../types";
import { registerControl } from "../registry";

export const API_002: Control = {
  controlKey: "API-002",
  category: "API Security",
  subcategory: "Cross-origin policy",
  name: "CORS restricted to specific origins",
  description:
    "A CORS policy that allows any origin lets any website make cross-origin requests to this API on a visitor's " +
    "behalf, using that visitor's own cookies or credentials.",
  question: "Is the application's CORS policy restricted to specific, known origins?",
  defaultSeverity: "high",

  passCriteria: "A CORS configuration in the scanned source sets an explicit origin (not a wildcard).",
  failCriteria: "A CORS configuration in the scanned source allows a wildcard origin ('*'), optionally combined with credentials.",
  notVerifiedCriteria:
    "No CORS configuration was found in the scanned application-layer source — CORS may be configured at the " +
    "infrastructure layer (a reverse proxy, API gateway, or CDN), which a source-code scan cannot see.",

  whyItMatters:
    "A wildcard CORS policy, especially combined with credentials, lets a malicious website silently make " +
    "authenticated requests to this API using a logged-in victim's session and read the response.",

  technologyFixes: [
    {
      technology: "express",
      quickFix: "Replace a wildcard origin with your actual frontend domain: cors({ origin: 'https://yourapp.com', credentials: true }).",
      developerFix: "Configure the cors middleware with an explicit origin (or an allowlist function for multiple known domains), never '*' when credentials are involved.",
      architectureFix: "Read the allowed origin(s) from environment configuration per deployment (staging vs. production) rather than hardcoding or defaulting to permissive.",
      codeExample: "app.use(cors({ origin: 'https://yourapp.com', credentials: true }));",
    },
    {
      technology: "fastapi",
      quickFix: "Set allow_origins to your actual frontend domain(s) instead of ['*'].",
      developerFix: "Configure CORSMiddleware with an explicit allow_origins list; avoid combining allow_origins=['*'] with allow_credentials=True (FastAPI/Starlette rejects this combination, but check for it in older wildcard configurations).",
      architectureFix: "Load allowed origins from environment configuration per deployment rather than hardcoding a wildcard.",
      codeExample: "app.add_middleware(CORSMiddleware, allow_origins=['https://yourapp.com'], allow_credentials=True)",
    },
    {
      technology: "generic",
      quickFix: "Replace a wildcard CORS origin with the specific domain(s) that should be allowed to call this API.",
      developerFix: "Configure CORS with an explicit origin allowlist rather than a wildcard, especially on any endpoint that relies on cookies or credentials.",
      architectureFix: "Source the allowed origin(s) from per-environment configuration so staging and production each get the correct, narrow policy.",
    },
  ],

  longTermHardening: "Add an integration test asserting a request from an unlisted Origin does not receive an Access-Control-Allow-Origin header matching it.",
  verificationMethod: "Rescan and confirm the CORS configuration in the source specifies explicit origins rather than a wildcard.",
  references: ["OWASP: CORS Misconfiguration", "OWASP API Security Top 10: API8:2023 – Security Misconfiguration"],
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

registerControl(API_002);
