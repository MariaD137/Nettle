import type { Control } from "../types";
import { registerControl } from "../registry";

export const AI_002: Control = {
  controlKey: "AI-002",
  category: "AI Disclosure",
  subcategory: "Cost abuse / denial-of-wallet",
  name: "Token limits configured for AI API calls",
  description:
    "AI provider API calls (OpenAI, Anthropic, and similar) are billed per token. A call made with no maximum " +
    "output-token limit lets a single request — whether from a legitimate user or an attacker deliberately " +
    "provoking long completions — consume an unbounded number of tokens, turning what should be a bounded cost " +
    "per request into an open-ended one.",
  question: "Is a maximum token/output length configured on AI API calls?",
  defaultSeverity: "medium",

  passCriteria: "A max_tokens/maxTokens option or an equivalent token/length limit pattern is present in source that also uses an AI SDK.",
  failCriteria: "The application calls an AI provider SDK but no token/length limit pattern was found anywhere in the scanned source.",
  notVerifiedCriteria: "A file matched by the scan's inclusion rules could not be read, so token-limit configuration was not checked.",

  whyItMatters:
    "Without a per-call cap, cost scales with whatever the model is willing to generate — and a model can be " +
    "prompted (accidentally or via prompt injection) into very long completions. Combined with no per-user rate " +
    "limiting, this is a direct denial-of-wallet vector: an attacker doesn't need to breach anything, they only " +
    "need to send requests that are individually unbounded in cost.",

  technologyFixes: [
    {
      technology: "generic",
      quickFix: "Set max_tokens (or the provider's equivalent) on every AI API call, e.g. { max_tokens: 1024 }.",
      developerFix: "Cap output length on every call site that invokes an AI provider, and add a per-user or per-API-key rate limit alongside it so the number of calls is bounded too, not just the size of each one.",
      architectureFix: "Track token usage per tenant/user and enforce a budget (daily/monthly cap) at the application layer, independent of any per-call limit, so a burst of otherwise-capped calls still can't run up an unbounded bill.",
      codeExample: "await openai.chat.completions.create({ model: 'gpt-4', messages, max_tokens: 1024 });",
    },
  ],

  longTermHardening: "Alert on anomalous token-spend spikes per user/tenant, and consider a circuit breaker that pauses AI calls for an account whose usage crosses a hard budget threshold.",
  verificationMethod: "Rescan and confirm a token/length limit is now present alongside the AI SDK usage.",
  references: ["OWASP Top 10 for LLM Applications: LLM10 – Unbounded Consumption"],
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

registerControl(AI_002);
