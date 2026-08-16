import fs from "fs";
import path from "path";
import type { Finding, Pass } from "./types";

const AI_SDK_PATTERNS = [
  /openai/i,
  /anthropic/i,
  /langchain/i,
  /llamaindex/i,
  /cohere/i,
  /replicate/i,
  /huggingface/i,
  /google.*generative/i,
  /vertex.*ai/i,
  /bedrock/i,
  /ai\.generate/i,
  /chat\.completions/i,
  /createCompletion/i,
  /createChatCompletion/i,
];

const PROMPT_INJECTION_GUARDS = [
  /prompt.*inject/i,
  /sanitize.*prompt/i,
  /input.*filter/i,
  /system.*prompt.*\+/i,
  /guardrail/i,
  /content.*filter/i,
  /moderat/i,
  /validate.*input.*before.*(?:ai|llm|model|prompt)/i,
];

const TOOL_EXECUTION_PATTERNS = [
  /function_call/i,
  /tool_use/i,
  /tools\s*:/,
  /functions\s*:/,
  /tool_choice/i,
  /exec\s*\(/,
  /spawn\s*\(/,
  /execSync\s*\(/,
];

const TOKEN_LIMIT_PATTERNS = [
  /max_tokens/i,
  /maxTokens/i,
  /token.*limit/i,
  /max.*length/i,
];

const OUTPUT_VALIDATION_PATTERNS = [
  /\.parse\s*\(/,
  /validate.*(?:output|response|result)/i,
  /schema.*(?:output|response)/i,
  /output.*schema/i,
  /structured.*output/i,
];

const AI_KEY_PATTERNS = [
  /OPENAI_API_KEY\s*=\s*['"]sk-[^'"]+['"]/,
  /ANTHROPIC_API_KEY\s*=\s*['"]sk-ant-[^'"]+['"]/,
  /api[_-]?key\s*[:=]\s*['"]sk-[^'"]+['"]/i,
];

export function scanAiSecurity(files: string[], targetRoot: string): { findings: Finding[]; passed: Pass[] } {
  const findings: Finding[] = [];
  const passed: Pass[] = [];

  const jsFiles = files.filter((f) => /\.(js|ts|jsx|tsx)$/.test(f));
  let usesAi = false;
  let hasPromptGuards = false;
  let hasToolExecution = false;
  let hasTokenLimits = false;
  let hasOutputValidation = false;
  let hasAiKeyExposed = false;

  for (const file of jsFiles) {
    const text = fs.readFileSync(file, "utf8");
    const rel = path.relative(targetRoot, file);

    if (AI_SDK_PATTERNS.some((p) => p.test(text))) usesAi = true;
    if (PROMPT_INJECTION_GUARDS.some((p) => p.test(text))) hasPromptGuards = true;
    if (TOOL_EXECUTION_PATTERNS.some((p) => p.test(text))) hasToolExecution = true;
    if (TOKEN_LIMIT_PATTERNS.some((p) => p.test(text))) hasTokenLimits = true;
    if (OUTPUT_VALIDATION_PATTERNS.some((p) => p.test(text))) hasOutputValidation = true;

    for (const pattern of AI_KEY_PATTERNS) {
      if (pattern.test(text)) {
        hasAiKeyExposed = true;
        findings.push({
          severity: "critical",
          category: "AI Disclosure",
          title: "AI model API key hardcoded in source",
          detail: "An OpenAI, Anthropic, or other AI provider API key is hardcoded. These keys can be used to generate content at your expense or access your account.",
          file: rel,
        line: null,
          remediation: "Move the API key to an environment variable (process.env.OPENAI_API_KEY) and rotate the exposed key immediately.",
        });
        break;
      }
    }

    const userInputToPrompt = /(?:req\.body|req\.query|req\.params|user_?input|user_?message)\b[^;]*(?:prompt|message|content)\s*[:=+]/gi;
    if (userInputToPrompt.test(text) && !hasPromptGuards) {
      findings.push({
        severity: "high",
        category: "AI Disclosure",
        title: "User input passed directly to AI prompt without sanitization",
        detail: "User-supplied content is concatenated into AI prompts without visible input filtering. This enables prompt injection attacks that can override system instructions.",
        file: rel,
        line: null,
        remediation: "Validate and sanitize user input before including it in prompts. Use structured message formats (separate system/user roles) and consider input/output guardrails.",
      });
    }
  }

  if (!usesAi) return { findings, passed };

  if (!hasTokenLimits) {
    findings.push({
      severity: "medium",
      category: "AI Disclosure",
      title: "No token limits configured for AI API calls",
      detail: "Without max_tokens limits, a single request could consume a large number of tokens, leading to unexpected costs (denial-of-wallet attacks).",
      file: null,
        line: null,
      remediation: "Set max_tokens on every AI API call to cap costs: { max_tokens: 1024 }. Also set per-user rate limits.",
    });
  } else {
    passed.push({ category: "AI Disclosure", title: "Token limits are configured for AI API calls" });
  }

  if (hasToolExecution) {
    findings.push({
      severity: "high",
      category: "AI Disclosure",
      title: "AI model has tool/function execution capability",
      detail: "The app gives the AI model access to tools or functions. Without an allowlist and approval flow, a prompt injection could cause the model to execute unintended actions.",
      file: null,
        line: null,
      remediation: "Implement a tool allowlist, sandbox tool execution, and require human approval for destructive actions (delete, send, pay).",
    });
  }

  if (!hasOutputValidation) {
    findings.push({
      severity: "medium",
      category: "AI Disclosure",
      title: "No output validation for AI responses",
      detail: "AI model output is used without schema validation. Hallucinated or malformed responses can cause downstream errors or security issues.",
      file: null,
        line: null,
      remediation: "Validate AI output against a schema (e.g. with Zod) before using it: const result = responseSchema.parse(aiOutput).",
    });
  } else {
    passed.push({ category: "AI Disclosure", title: "AI output validation is configured" });
  }

  if (hasPromptGuards) {
    passed.push({ category: "AI Disclosure", title: "Prompt injection guards or content filtering detected" });
  }

  return { findings, passed };
}
