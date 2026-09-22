import type { Control } from "../types";
import { registerControl } from "../registry";

export const BROWSER_001: Control = {
  controlKey: "BROWSER-001",
  category: "Configuration",
  subcategory: "Security response headers",
  name: "Security response headers",
  description:
    "Server responses should set the standard set of browser-security headers (CSP, HSTS, X-Frame-Options, " +
    "X-Content-Type-Options, Referrer-Policy, Permissions-Policy) that tell the browser to enforce protections " +
    "the app itself cannot guarantee at the application layer.",
  question: "Does the application set the standard security response headers, directly or via a middleware like Helmet?",
  defaultSeverity: "medium",

  passCriteria: "A recognized pattern for the header (or a headers middleware like Helmet, which sets all of them) is present in the scanned source.",
  failCriteria: "No recognized pattern for the header, and no headers middleware, was found in the scanned source.",
  notVerifiedCriteria: "A header can legitimately be set at a layer this scan can't see — a reverse proxy, CDN, or static hosting config — so a FAIL here means \"not set in application code,\" not \"definitely absent from the response.\"",

  whyItMatters:
    "These headers are the browser's own defense against attacks the server can't fully prevent on its own: CSP and " +
    "X-Frame-Options blunt XSS and clickjacking even if a script does get injected; HSTS prevents a downgrade to plain " +
    "HTTP; X-Content-Type-Options stops MIME-sniffing an upload into something executable. Missing them doesn't create " +
    "a vulnerability by itself, but it removes a layer that limits how bad one gets.",

  technologyFixes: [
    {
      technology: "express",
      quickFix: "npm install helmet, then app.use(helmet()) before your routes — it sets all of these at once with sane defaults.",
      developerFix: "Use Helmet for the baseline, then tune the specific directives that need a non-default value (CSP's script-src, HSTS's includeSubDomains, etc.) via its options object.",
      architectureFix: "Apply helmet() at the top of the middleware chain, before any route registration, so a new route can't be added without inheriting the headers.",
      codeExample: "const helmet = require('helmet');\napp.use(helmet());",
    },
    {
      technology: "nextjs",
      quickFix: "Add a headers() function in next.config.js returning the security headers for every route.",
      developerFix: "Define async headers() in next.config.js, returning an array of { source: '/(.*)', headers: [...] } — Next.js applies it to matching routes automatically.",
      architectureFix: "Use source: '/(.*)' to cover the whole app by default, adding narrower overrides only for routes that need a different policy (e.g. an embed page that needs a looser frame-ancestors).",
      codeExample: "module.exports = {\n  async headers() {\n    return [{ source: '/(.*)', headers: [{ key: 'X-Content-Type-Options', value: 'nosniff' }] }];\n  },\n};",
    },
    {
      technology: "generic",
      quickFix: "Set the missing header(s) explicitly on every response, or add a headers middleware/library equivalent to Helmet for your framework.",
      developerFix: "Apply the header at the framework's middleware/response layer so it's set on every response by default, not per-route.",
      architectureFix: "Centralize header configuration in one place (middleware, a reverse proxy config, or a platform-level setting) rather than setting headers ad hoc per handler.",
    },
  ],

  longTermHardening: "Test header presence with a tool like Mozilla Observatory or securityheaders.com against the deployed app, not just the source — this control can only see what application code sets, not the final response.",
  verificationMethod: "Rescan and confirm the previously-missing header pattern (or a headers middleware) is now present in the source.",
  references: ["OWASP Secure Headers Project", "MDN: HTTP security headers"],
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

registerControl(BROWSER_001);
