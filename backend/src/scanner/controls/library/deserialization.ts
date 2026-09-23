import type { Control } from "../types";
import { registerControl } from "../registry";

export const INPUT_002: Control = {
  controlKey: "INPUT-002",
  category: "Security",
  subcategory: "Unsafe deserialization",
  name: "No unsafe deserialization of untrusted input",
  description:
    "Deserializing untrusted input with a library or function that can construct arbitrary objects (or execute code " +
    "as part of parsing) turns a data-parsing bug into remote code execution — this covers patterns like eval()-based " +
    "parsing, node-serialize, and non-safe YAML loading applied to request data.",
  question: "Does the application avoid unsafe deserialization of untrusted (request) input?",
  defaultSeverity: "high",

  passCriteria: "No unsafe deserialization pattern (eval-based parsing, node-serialize, yaml.load on request data, unserialize()) was found applied to request input in the scanned source.",
  failCriteria: "A request body/query/params value flows into eval(), node-serialize, unserialize(), or an unsafe YAML load in the scanned source.",
  notVerifiedCriteria: "A file matched by the scan's inclusion rules could not be read, so its deserialization patterns were not checked.",

  whyItMatters:
    "Unlike most injection classes, an unsafe deserializer can construct arbitrary objects or invoke arbitrary code " +
    "as a side effect of parsing — before any application logic runs at all. This is a well-documented source of " +
    "real-world remote code execution across many languages' serialization libraries.",

  technologyFixes: [
    {
      technology: "generic",
      quickFix: "Remove eval()/unserialize()-based parsing of request data immediately, and switch YAML loading to its library's explicit safe-load function.",
      developerFix: "Use JSON.parse (never eval) for JSON, and a YAML library's safe-load variant (e.g. js-yaml's load() with the default schema, or explicitly the safe schema on older versions) for YAML — never a variant that can construct arbitrary types or invoke code.",
      architectureFix: "If the application needs to exchange complex object graphs with a client, define an explicit, versioned schema and validate against it rather than deserializing directly into live objects.",
      codeExample: "// Instead of: eval('(' + req.body.data + ')')\nconst data = JSON.parse(req.body.data); // then validate against a schema",
    },
  ],

  longTermHardening: "Add a Semgrep or equivalent static-analysis rule that fails CI on eval()/unserialize() usage anywhere in the codebase, not just at request-input sites, so a new instance is caught before it reaches a request path at all.",
  verificationMethod: "Rescan and confirm no unsafe deserialization pattern is present in the source.",
  references: ["OWASP Deserialization Cheat Sheet", "CWE-502: Deserialization of Untrusted Data"],
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

registerControl(INPUT_002);
