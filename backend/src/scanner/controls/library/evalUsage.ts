import type { Control } from "../types";
import { registerControl } from "../registry";

export const INPUT_003: Control = {
  controlKey: "INPUT-003",
  category: "Security",
  subcategory: "Dangerous code execution",
  name: "No eval() usage",
  description:
    "eval() executes an arbitrary string as code. If any part of that string is influenced by user input, this is " +
    "a direct remote-code-execution path — but even without a known-tainted input, eval() usage is a standing " +
    "liability: it defeats static analysis of what the application can actually do, and a future change that adds " +
    "user input to the evaluated string introduces the vulnerability silently.",
  question: "Does the application avoid calling eval()?",
  defaultSeverity: "critical",

  passCriteria: "No call to eval() was found anywhere in the scanned source (verified via AST, not a text match).",
  failCriteria: "A call to eval() was found in the scanned source.",
  notVerifiedCriteria: "Semgrep (the AST analysis engine this check depends on) was not available, so eval() usage was not checked.",

  whyItMatters:
    "This is detected via AST analysis (Semgrep), not a text/regex match — it identifies an actual eval() call " +
    "site in the parsed source, not just the substring \"eval\" appearing in a comment or string.",

  technologyFixes: [
    {
      technology: "generic",
      quickFix: "Replace eval() with a safer alternative: JSON.parse() for data, or a proper template engine for dynamic content.",
      developerFix: "Identify what eval() is actually being used for and replace it with the narrowest tool that does that one thing — JSON.parse for data, Function constructor with no closure access only if truly unavoidable, or a sandboxed expression evaluator library if arbitrary expression evaluation is a genuine product requirement.",
      architectureFix: "If dynamic code execution is a real product requirement (a plugin system, a formula engine), isolate it in a sandboxed process or a purpose-built, restricted evaluator rather than the application's own eval().",
      codeExample: "// Instead of: eval('(' + jsonString + ')')\nconst data = JSON.parse(jsonString);",
    },
  ],

  longTermHardening: "Add an ESLint no-eval rule (or equivalent) so a new eval() call fails CI before it ever reaches this scan.",
  verificationMethod: "Rescan and confirm no eval() call remains in the source.",
  references: ["OWASP: Code Injection", "MDN: eval() — Never use eval()!"],
  complianceMappings: [],

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

registerControl(INPUT_003);
