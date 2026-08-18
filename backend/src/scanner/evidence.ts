/**
 * Evidence generation: safe, redacted proof of findings.
 * Shows the user *what* triggered a finding without exposing secrets.
 */

import fs from "fs";
import path from "path";
import type { Finding } from "./types";
import { generateCheckId } from "./threeStateModel";

const SECRET_PATTERNS = [
  /[Aa]pi[_-]?key|apikey|api_secret/i,
  /[Pp]assword|passwd|pwd/i,
  /[Ss]ecret[_-]?key|secretkey/i,
  /[Aa]ccess[_-]?token|accesstoken|auth[_-]?token/i,
  /aws[_-]?secret|aws[_-]?key|AKIA/i,
  /stripe[_-]?key|stripe[_-]?secret/i,
  /github[_-]?token|ghp_/i,
  /private[_-]?key|rsa[_-]?private/i,
  /jwt|bearer/i,
  /oauth[_-]?token/i,
];

/**
 * Check if text contains secret-like patterns.
 */
function looksLikeSecret(text: string): boolean {
  return SECRET_PATTERNS.some((pattern) => pattern.test(text));
}

/**
 * Redact sensitive parts of a string, replacing with [REDACTED_TYPE].
 */
export function redactSecrets(text: string): string {
  if (!text) return text;
  if (looksLikeSecret(text)) return "[REDACTED]";

  // Redact common secret formats: long hex, base64, API keys
  return (
    text
      // Long hex strings (likely tokens)
      .replace(/\b[a-f0-9]{32,}\b/gi, "[REDACTED_HEX]")
      // Base64-ish strings (32+ chars of alphanumeric+/+=)
      .replace(/\b[A-Za-z0-9/+]{32,}={0,2}\b/g, "[REDACTED_BASE64]")
      // AWS key format (AKIA followed by 16 alphanumeric)
      .replace(/AKIA[0-9A-Z]{16}/g, "[REDACTED_AWS_KEY]")
      // Generic API key format
      .replace(/\b(api[_-]?key|secret)[_=:\s]+\S+/gi, (match) => "[REDACTED]")
  );
}

/**
 * Generate safe evidence from code snippet, redacting secrets.
 */
export function createEvidence(codeSnippet: string, maxLength = 200): string | undefined {
  if (!codeSnippet) return undefined;

  const redacted = redactSecrets(codeSnippet);
  if (redacted.length > maxLength) {
    return redacted.substring(0, maxLength) + "…";
  }
  return redacted;
}

/**
 * Extract evidence from a line of code.
 * Used by analyzers to show what triggered a finding.
 */
export function extractLineEvidence(line: string, maxLength = 150): string | undefined {
  if (!line) return undefined;

  // Trim whitespace
  const trimmed = line.trim();

  // Clean up the line (remove comments, normalize whitespace)
  const cleaned = trimmed
    .replace(/^\s*\/\/.*$/gm, "") // Remove comments
    .replace(/\s+/g, " ") // Normalize whitespace
    .trim();

  return createEvidence(cleaned, maxLength);
}

/**
 * Generate evidence for a finding type (generic, pattern-based).
 */
export function generateEvidenceForFinding(
  findingType: string,
  context?: {
    file?: string;
    line?: string;
    variable?: string;
    value?: string;
  }
): string | undefined {
  if (!context) return undefined;

  let evidence = "";

  if (context.variable) {
    evidence = `variable: ${context.variable}`;
    if (context.value) {
      evidence += ` = ${redactSecrets(context.value)}`;
    }
  } else if (context.value) {
    evidence = redactSecrets(context.value);
  } else if (context.line) {
    evidence = extractLineEvidence(context.line) ?? "";
  }

  return evidence || undefined;
}

/**
 * Reads the given line out of a file on disk and returns a redacted,
 * truncated snippet of it (via extractLineEvidence) — or undefined if the
 * file can't be read, the line number is out of range, or the resolved
 * path would escape targetRoot.
 *
 * `relativeFile` may carry a Semgrep-style trailing ":<line>" (see
 * semgrepScanner.ts's scanWithSemgrep, which bakes the line into `file`
 * for historical/hash-stability reasons) — that suffix is stripped before
 * resolving the path so those findings still get real context.
 */
export function extractCodeContext(targetRoot: string, relativeFile: string, line: number): string | undefined {
  try {
    const cleanFile = relativeFile.replace(/:\d+$/, "");
    const root = path.resolve(targetRoot);
    const resolved = path.resolve(root, cleanFile);
    if (resolved !== root && !resolved.startsWith(root + path.sep)) return undefined;
    const lines = fs.readFileSync(resolved, "utf8").split("\n");
    if (line < 1 || line > lines.length) return undefined;
    return extractLineEvidence(lines[line - 1]);
  } catch {
    return undefined;
  }
}

/**
 * Backfills `ruleId` and `codeContext` on findings that don't already have
 * them. Mutates and returns the same array — Semgrep findings already set
 * their own real `ruleId` (the actual Semgrep check_id) before this runs,
 * so this only fills in a stable generated one for everyone else. Code
 * context is only attempted when `targetRoot` is supplied (a URL scan has
 * no filesystem to read from) and the finding has both `file` and `line`.
 */
export function enrichFindings(findings: Finding[], targetRoot?: string): Finding[] {
  for (const f of findings) {
    if (!f.ruleId) f.ruleId = generateCheckId(f.category, f.title);
    if (!f.codeContext && targetRoot && f.file && f.line) {
      f.codeContext = extractCodeContext(targetRoot, f.file, f.line) ?? null;
    }
  }
  return findings;
}
