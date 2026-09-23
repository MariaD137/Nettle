import type { Control } from "../types";
import { registerControl } from "../registry";

export const API_005: Control = {
  controlKey: "API-005",
  category: "API Security",
  subcategory: "Resource limits",
  name: "Request body size limit",
  description:
    "A body parser without a size cap will buffer whatever the caller sends into memory before the handler ever " +
    "runs — an attacker can send an arbitrarily large payload to exhaust memory and take the process down, with no " +
    "authentication or exploit required beyond a single large POST.",
  question: "Is a request body size limit configured on the application's body parser?",
  defaultSeverity: "medium",

  passCriteria: "The body parser (express.json, express.urlencoded, bodyParser) is configured with an explicit limit option.",
  failCriteria: "A body parser is used in the scanned source with no limit option configured.",
  notVerifiedCriteria: "No body parser was found in the scanned source, so there is nothing this control applies to.",

  whyItMatters:
    "Without a limit, the default is often measured in megabytes but still unbounded enough that a handful of " +
    "concurrent large requests can exhaust available memory — a trivial, pre-authentication denial-of-service " +
    "against the whole application, not just one endpoint.",

  technologyFixes: [
    {
      technology: "express",
      quickFix: "Add a limit option to the body parser: app.use(express.json({ limit: '1mb' })).",
      developerFix: "Set limit on every body-parsing middleware (json, urlencoded, raw) to the largest payload the endpoint actually needs — a general API rarely needs more than 1-5mb; a dedicated upload endpoint should use its own, separately-limited parser.",
      codeExample: "app.use(express.json({ limit: '1mb' }));\napp.use(express.urlencoded({ extended: true, limit: '1mb' }));",
    },
    {
      technology: "generic",
      quickFix: "Configure an explicit request body size limit on the framework's body parser.",
      developerFix: "Set the limit to match the largest legitimate payload for that route, and use a separate, purpose-sized limit for any dedicated upload endpoint rather than raising the global limit.",
    },
  ],

  longTermHardening: "Enforce the limit again at the reverse proxy / load balancer layer as defense in depth, independent of the application-level setting.",
  verificationMethod: "Rescan and confirm the body parser now has an explicit limit configured.",
  references: ["OWASP: Denial of Service Cheat Sheet"],
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

registerControl(API_005);
