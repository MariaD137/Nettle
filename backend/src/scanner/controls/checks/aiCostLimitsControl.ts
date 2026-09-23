import fs from "fs";
import type { CheckResult } from "../../types";
import { generateCheckId } from "../../threeStateModel";

const AI_SDK_PATTERNS = [
  /openai/i, /anthropic/i, /langchain/i, /llamaindex/i, /cohere/i,
  /replicate/i, /huggingface/i, /google.*generative/i, /vertex.*ai/i,
  /bedrock/i, /ai\.generate/i, /chat\.completions/i, /createCompletion/i,
  /createChatCompletion/i,
];

const TOKEN_LIMIT_PATTERNS = [/max_tokens/i, /maxTokens/i, /token.*limit/i, /max.*length/i];

/**
 * AI-002, wired to the control library. Extracted from aiSecurity.ts's
 * former inline token-limit block -- same detection logic and
 * title/detail/remediation text, restructured to emit CheckResult with a
 * controlKey and to survive an unreadable file. Aggregate, like AUTH-003:
 * token-limit configuration is normally set once per call site but the
 * overall "is a limit used anywhere" signal is a whole-codebase one.
 */
export function scanAiCostLimitsControl(files: string[], targetRoot: string): CheckResult[] {
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
          checkId: generateCheckId("AI Disclosure", "AI-002:unreadable"),
          status: "NOT_VERIFIED",
          category: "AI Disclosure",
          title: "Some files could not be read for AI token-limit analysis",
          detail: "No AI SDK usage was found in the files that could be read, but at least one file was unreadable and may have used one.",
          confidence: 0,
          detectionMethod: "heuristic",
          controlKey: "AI-002",
        },
      ];
    }
    return []; // app doesn't call an AI provider at all — nothing to check
  }

  const hasTokenLimits = TOKEN_LIMIT_PATTERNS.some((p) => p.test(allSource));
  if (hasTokenLimits) {
    return [
      {
        checkId: generateCheckId("AI Disclosure", "AI-002:pass"),
        status: "PASS",
        category: "AI Disclosure",
        title: "Token limits are configured for AI API calls",
        confidence: 70,
        detectionMethod: "heuristic",
        controlKey: "AI-002",
      },
    ];
  }

  if (anyUnreadable) {
    return [
      {
        checkId: generateCheckId("AI Disclosure", "AI-002:unreadable"),
        status: "NOT_VERIFIED",
        category: "AI Disclosure",
        title: "AI SDKs are used but not every file could be read for token-limit analysis",
        detail: "No token/length limit was found in the files that could be read, but at least one file was unreadable and may have configured one.",
        confidence: 0,
        detectionMethod: "heuristic",
        controlKey: "AI-002",
      },
    ];
  }

  return [
    {
      checkId: generateCheckId("AI Disclosure", "AI-002:fail"),
      status: "FAIL",
      category: "AI Disclosure",
      title: "No token limits configured for AI API calls",
      detail: "Without max_tokens limits, a single request could consume a large number of tokens, leading to unexpected costs (denial-of-wallet attacks).",
      severity: "medium",
      confidence: 70,
      detectionMethod: "heuristic",
      remediation: "Set max_tokens on every AI API call to cap costs: { max_tokens: 1024 }. Also set per-user rate limits.",
      controlKey: "AI-002",
    },
  ];
}
