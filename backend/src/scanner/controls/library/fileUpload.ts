import type { Control } from "../types";
import { registerControl } from "../registry";

export const API_006: Control = {
  controlKey: "API-006",
  category: "API Security",
  subcategory: "File upload",
  name: "File upload size and type restrictions",
  description:
    "A file-upload endpoint without a size limit is a disk/memory exhaustion vector, and one without MIME/extension " +
    "validation lets a caller upload anything — including an executable — that may later be served back or run.",
  question: "Are file uploads restricted by size and by type?",
  defaultSeverity: "high",

  passCriteria: "The upload middleware (multer, formidable, busboy) is configured with both a file size limit and a MIME/extension check.",
  failCriteria: "File upload handling is present in the scanned source without a size limit, a type check, or both.",
  notVerifiedCriteria: "No file upload handling (multer, formidable, busboy, or an equivalent) was found in the scanned source, so there is nothing this control applies to.",

  whyItMatters:
    "An unbounded upload endpoint lets one caller fill available disk or memory with a single request. An untyped " +
    "one lets a caller upload an executable, a script, or a polyglot file — if it's later served from the same " +
    "origin or processed by another tool, that upload becomes code execution, not just storage abuse.",

  technologyFixes: [
    {
      technology: "express",
      quickFix: "Add limits.fileSize and a fileFilter to the multer (or equivalent) configuration.",
      developerFix: "Configure both a size cap and an allowlist-based fileFilter checking MIME type and extension — reject anything not on the allowlist rather than blocking a denylist.",
      architectureFix: "Store uploads outside the web root under randomly generated filenames, and serve them through a signed URL or an endpoint that re-checks type before responding — never trust the client-declared filename or MIME type for storage or serving decisions.",
      codeExample: "const upload = multer({\n  limits: { fileSize: 5 * 1024 * 1024 },\n  fileFilter: (req, file, cb) => {\n    const allowed = ['image/png', 'image/jpeg'];\n    cb(null, allowed.includes(file.mimetype));\n  },\n});",
    },
    {
      technology: "generic",
      quickFix: "Configure a file size limit and an allowlist-based type check on the upload handler.",
      developerFix: "Reject uploads outside an explicit allowlist of MIME types/extensions, and cap file size to what the feature actually needs.",
      architectureFix: "Store uploaded files outside the served web root with randomized names, and never execute or directly serve an uploaded file by its original name/path.",
    },
  ],

  longTermHardening: "Add antivirus/malware scanning on uploaded files before they are made available to other users, and quarantine anything flagged rather than deleting it outright.",
  verificationMethod: "Rescan and confirm the upload handler now configures both a size limit and a type check.",
  references: ["OWASP File Upload Cheat Sheet"],
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

registerControl(API_006);
