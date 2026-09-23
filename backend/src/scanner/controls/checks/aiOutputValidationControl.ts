import fs from "fs";
import type { CheckResult } from "../../types";
import { generateCheckId } from "../../threeStateModel";

const AI_SDK_PATTERNS = [
  /openai/i, /anthropic/i, /langchain/i, /llamaindex/i, /cohere/i,
  /replicate/i, /huggingface/i, /google.*generative/i, /vertex.*ai/i,
  /bedrock/i, /ai\.generate/i, /chat\.completions/i, /createCompletion/i,
  /createChatCompletion/i,
];

const OUTPUT_VALIDATION_PATTERNS = [
  /\.parse\s*\(/, /validate.*(?:output|response|result)/i,
  /schema.*(?:output|response)/i, /output.*schema/i, /structured.*output/i,
];

/**
 * AI-004, wired to the control library. Extracted from aiSecurity.ts's
 * former inline output-validation block -- same detection logic and
 * title/detail/remediation text, restructured to emit CheckResult with a
 * controlKey and to survive an unreadable file. Aggregate, like AI-002:
 * whether output validation is used anywhere is a whole-codebase signal.
 */
export function scanAiOutputValidationControl(files: string[], targetRoot: string): CheckResult[] {
  const jsFiles = files.filter((f) => /\.(js|ts|jsx|tsx)$/.test(f));

  let allSource = "";
  let anyUnreadable = false;
  for (const file of jsFiles) {
    try {
      allSource += fs.readFileSync(file, "utf8") + "\n";
    } catch {
      anyUnreadable = true;
    }
  }

  const usesAi = AI_SDK_PATTERNS.some((p) => p.test(allSource));
  if (!usesAi) {
    if (anyUnreadable) {
      return [
        {
          checkId: generateCheckId("AI Disclosure", "AI-004:unreadable"),
          status: "NOT_VERIFIED",
          category: "AI Disclosure",
          title: "Some files could not be read for AI output-validation analysis",
          detail: "No AI SDK usage was found in the files that could be read, but at least one file was unreadable and may have used one.",
          confidence: 0,
          detectionMethod: "heuristic",
          controlKey: "AI-004",
        },
      ];
    }
    return []; // app doesn't call an AI provider at all — nothing to check
  }

  const hasOutputValidation = OUTPUT_VALIDATION_PATTERNS.some((p) => p.test(allSource));
  if (hasOutputValidation) {
    return [
      {
        checkId: generateCheckId("AI Disclosure", "AI-004:pass"),
        status: "PASS",
        category: "AI Disclosure",
        title: "AI output validation is configured",
        confidence: 65,
        detectionMethod: "heuristic",
        controlKey: "AI-004",
      },
    ];
  }

  if (anyUnreadable) {
    return [
      {
        checkId: generateCheckId("AI Disclosure", "AI-004:unreadable"),
        status: "NOT_VERIFIED",
        category: "AI Disclosure",
        title: "AI SDKs are used but not every file could be read for output-validation analysis",
        detail: "No schema-validation pattern was found in the files that could be read, but at least one file was unreadable and may have configured one.",
        confidence: 0,
        detectionMethod: "heuristic",
        controlKey: "AI-004",
      },
    ];
  }

  return [
    {
      checkId: generateCheckId("AI Disclosure", "AI-004:fail"),
      status: "FAIL",
      category: "AI Disclosure",
      title: "No output validation for AI responses",
      detail: "AI model output is used without schema validation. Hallucinated or malformed responses can cause downstream errors or security issues.",
      severity: "medium",
      confidence: 65,
      detectionMethod: "heuristic",
      remediation: "Validate AI output against a schema (e.g. with Zod) before using it: const result = responseSchema.parse(aiOutput).",
      controlKey: "AI-004",
    },
  ];
}
