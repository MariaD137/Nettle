/**
 * Evidence generation: safe, redacted proof of findings.
 * Shows the user *what* triggered a finding without exposing secrets.
 */

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
  // `undefined` is the meaningful "no evidence available" signal here, matching
  // createEvidence/extractLineEvidence above and the optional `evidence?` field
  // on Finding. The declared `string` was simply wrong: both the no-context and
  // the empty-evidence paths below already returned undefined at runtime, and
  // M-1's own tests assert that.
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
    // extractLineEvidence yields undefined for a line it cannot make usable
    // (blank, comment-only). Collapse that to "" so the return below reports
    // it the same way as any other absent evidence.
    evidence = extractLineEvidence(context.line) ?? "";
  }

  return evidence || undefined;
}
