import type { Control } from "../types";
import { registerControl } from "../registry";

export const AI_004: Control = {
  controlKey: "AI-004",
  category: "AI Disclosure",
  subcategory: "Output handling",
  name: "AI model output is validated before use",
  description:
    "AI model output is not guaranteed to be well-formed, complete, or safe — a model can hallucinate fields, " +
    "return malformed JSON, or produce content that wasn't expected. Using that output directly, with no schema " +
    "validation, lets a bad or unexpected response propagate into the rest of the application.",
  question: "Is AI model output validated (e.g. against a schema) before it's used?",
  defaultSeverity: "medium",

  passCriteria: "A schema-validation or output-parsing pattern (e.g. a .parse() call, or an explicit output/response schema) is present in source that also uses an AI SDK.",
  failCriteria: "The application calls an AI provider SDK but no output-validation pattern was found anywhere in the scanned source.",
  notVerifiedCriteria: "A file matched by the scan's inclusion rules could not be read, so output validation was not checked.",

  whyItMatters:
    "Model output is best treated as untrusted input to the rest of the system, the same as any other user- or " +
    "external-controlled data. A hallucinated field, wrong type, or malformed structure that reaches downstream " +
    "logic unvalidated can cause anything from a crash to, in the worst case, that output being used somewhere " +
    "sensitive (a query, a file path, a rendered template) without the checks that path would normally require.",

  technologyFixes: [
    {
      technology: "generic",
      quickFix: "Validate AI output against a schema before using it, e.g. with Zod: const result = responseSchema.parse(aiOutput).",
      developerFix: "Define an explicit schema for whatever structure the application expects back from the model (via structured/JSON-mode output where the provider supports it), and parse every response through it before use — reject or retry on a validation failure rather than passing the raw response through.",
      architectureFix: "Treat AI output the same as any other external input at a trust boundary: validate at the point it enters the rest of the system, not deep inside whatever consumes it.",
      codeExample: "const responseSchema = z.object({ answer: z.string(), confidence: z.number() });\nconst result = responseSchema.parse(JSON.parse(aiOutput));",
    },
  ],

  longTermHardening: "Add tests that feed malformed or unexpected model output through the validation path and assert it's rejected rather than silently accepted.",
  verificationMethod: "Rescan and confirm an output-validation pattern is now present alongside the AI SDK usage.",
  references: ["OWASP Top 10 for LLM Applications: LLM05 – Improper Output Handling"],
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

registerControl(AI_004);
