import type { Control } from "../types";
import { registerControl } from "../registry";

export const INPUT_001: Control = {
  controlKey: "INPUT-001",
  category: "Security",
  subcategory: "Path traversal",
  name: "No unsanitized user input in file-system paths",
  description:
    "Request-derived content (params, query, or body) must never be passed directly into a file-system operation " +
    "(path.join, readFile, createReadStream) without first resolving and verifying the resulting path stays inside " +
    "the intended directory.",
  question: "Is user-supplied input sanitized before it's used in a file-system path or read operation?",
  defaultSeverity: "critical",

  passCriteria: "No request-derived value (req.params/query/body) was found flowing directly into a file-system path operation.",
  failCriteria: "A file-system path operation (path.join, readFile, createReadStream) was found taking a request-derived value with no visible resolution/verification step.",
  notVerifiedCriteria: "A file matched by the scan's inclusion rules could not be read, so its file-system operations were not checked.",

  whyItMatters:
    "A path built from unsanitized user input lets an attacker supply ../ sequences to escape the intended " +
    "directory — reading arbitrary files the process has access to (source code, credentials, other users' " +
    "uploads) or, if the operation writes rather than reads, overwriting files outside the intended location.",

  technologyFixes: [
    {
      technology: "node",
      quickFix: "Resolve the path and verify it stays under the intended base directory before using it: const safe = path.resolve(baseDir, userInput); if (!safe.startsWith(baseDir)) throw new Error('Invalid path').",
      developerFix: "Never build a file-system path by directly joining request input. Resolve it against a known base directory and check the resolved path is still inside that directory before touching the file system.",
      architectureFix: "Where practical, avoid taking a caller-supplied path at all — use an opaque ID that maps to a stored location server-side, so there is no path string to sanitize in the first place.",
      codeExample: "const requested = path.resolve(uploadsDir, req.params.filename);\nif (!requested.startsWith(uploadsDir + path.sep)) return res.status(400).end();",
    },
    {
      technology: "generic",
      quickFix: "Resolve the requested path against a known base directory and verify it's still inside that directory before using it, in whatever path-resolution function your platform provides.",
      developerFix: "Reject the request (rather than silently truncating or stripping ../) if the resolved path escapes the intended base directory.",
      architectureFix: "Prefer an opaque, server-generated identifier over a caller-supplied path or filename wherever the design allows it.",
    },
  ],

  longTermHardening: "Add a test that requests a path containing ../ sequences targeting a file outside the intended directory and asserts it's rejected, not served.",
  verificationMethod: "Rescan and confirm no request-derived value reaches a file-system path operation without a visible resolve-and-verify step.",
  references: ["OWASP Top 10: A01:2021 – Broken Access Control", "CWE-22: Path Traversal"],
  complianceMappings: ["SOC 2 CC6.1"],

  releaseImpactBySeverity: {
    critical: "BLOCK_RELEASE",
    high: "BLOCK_RELEASE",
    medium: "REVIEW_BEFORE_RELEASE",
    low: "FIX_RECOMMENDED",
    info: "INFORMATIONAL",
  },

  enabled: true,
  version: "1.0.0",
};

registerControl(INPUT_001);
