import fs from "fs";
import path from "path";
import type { CheckResult } from "../../types";
import { generateCheckId } from "../../threeStateModel";

const CRED_VAR_ASSIGNMENT = /(api[_-]?key|secret|token|password|access[_-]?key)\s*[:=]\s*["'`]([^"'`]{3,80})["'`]/gi;
const PLACEHOLDER_VALUE_PATTERN = /^(your[_-]?[a-z_]*(key|secret|token)[a-z_]*|insert[_-]?[a-z_]*here|change[_-]?me|replace[_-]?(me|with)[a-z_]*|xxx+x*|api[_-]?key[_-]?here|<[a-z_-]*(key|token|secret)[a-z_-]*>|sk-xxxx+x*|placeholder[a-z_]*|your[_-]?key[_-]?here)$/i;

const USER_ID_TOKEN_PATTERN = /\b(userId|user\.id|req\.user\.id|ADMIN_ID|MASTER_ID|SUPER_USER_ID|TEST_USER_ID|DEBUG_USER_ID|BACKDOOR_ID)\b/i;
const HARDCODED_ID_BYPASS_PATTERN = /\b(userId|user\.id|req\.user\.id)\s*(===|==)\s*['"]?\d+['"]?|['"]?\d+['"]?\s*(===|==)\s*\b(userId|user\.id|req\.user\.id)\b|\b(ADMIN_ID|MASTER_ID|SUPER_USER_ID|TEST_USER_ID|DEBUG_USER_ID|BACKDOOR_ID)\s*=\s*['"]?\d+/i;

/**
 * AICODE-001/002, wired to the control library. Fifth Phase B category
 * (master spec §25: AI-generated code review) -- entirely new. Several
 * items from the spec's own list (hidden debug routes, suspicious
 * TODO/FIXME, unsafe eval, disabled security checks) are already covered
 * by CQ-002/006/007 and INPUT-003 from the codeQuality.ts migration,
 * confirmed via grep, so this round covers only the genuinely uncovered
 * ones: placeholder credentials and hardcoded-ID authorization bypasses.
 * ("Hallucinated package" detection would require an npm registry lookup
 * per scan -- a different kind of feature, out of scope here.) Category is
 * "Code Quality", the same one CQ-* uses, rather than a new FindingCategory
 * -- these are the same kind of finding (AI-assisted development risk
 * indicators), not a distinct taxonomy dimension.
 *
 * Both gated on their own applicability: AICODE-001 only when a
 * credential-shaped variable is assigned any string literal at all (not
 * just a placeholder one); AICODE-002 only when the file references a
 * user-ID token or one of the suspiciously-named ID constants at all.
 */
export function scanAiCodeReviewControl(files: string[], targetRoot: string): CheckResult[] {
  const jsFiles = files.filter((f) => /\.(js|ts|jsx|tsx)$/.test(f));

  let anyUnreadable = false;
  const results: CheckResult[] = [];

  let hasCredAssignment = false;
  let placeholderFailed = false;
  let hasUserIdToken = false;
  let bypassFailed = false;

  for (const file of jsFiles) {
    const rel = path.relative(targetRoot, file);
    let text: string;
    try {
      text = fs.readFileSync(file, "utf8");
    } catch {
      anyUnreadable = true;
      continue;
    }

    CRED_VAR_ASSIGNMENT.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = CRED_VAR_ASSIGNMENT.exec(text))) {
      hasCredAssignment = true;
      if (PLACEHOLDER_VALUE_PATTERN.test(match[2].trim())) {
        placeholderFailed = true;
        results.push({
          checkId: generateCheckId("Code Quality", "AICODE-001:fail", `${rel}:${match.index}`),
          status: "FAIL",
          category: "Code Quality",
          title: "Placeholder credential left in source",
          detail: `A credential-shaped variable is assigned an obvious placeholder value: ${match[0]}`,
          severity: "medium",
          file: rel,
          confidence: 85,
          detectionMethod: "regex",
          remediation: "Replace the placeholder with a read from environment configuration, and fail loudly at startup if it's not set.",
          controlKey: "AICODE-001",
        });
      }
    }

    if (USER_ID_TOKEN_PATTERN.test(text)) {
      hasUserIdToken = true;
      if (HARDCODED_ID_BYPASS_PATTERN.test(text)) {
        bypassFailed = true;
        results.push({
          checkId: generateCheckId("Code Quality", "AICODE-002:fail", rel),
          status: "FAIL",
          category: "Code Quality",
          title: "Hardcoded user ID used as an authorization bypass",
          detail: "A user ID is compared directly against a hardcoded literal, or a suspiciously-named ID constant (ADMIN_ID, BACKDOOR_ID, etc.) is assigned a literal value.",
          severity: "critical",
          file: rel,
          confidence: 60,
          detectionMethod: "regex",
          remediation: "Replace the hardcoded ID comparison with a real role/permission check driven by the database, not a literal ID.",
          controlKey: "AICODE-002",
        });
      }
    }
  }

  if (hasCredAssignment && !placeholderFailed) {
    results.push(anyUnreadable ? notVerified("AICODE-001", "placeholder credentials") : pass("AICODE-001", "No placeholder credential detected"));
  }
  if (hasUserIdToken && !bypassFailed) {
    results.push(anyUnreadable ? notVerified("AICODE-002", "hardcoded ID bypasses") : pass("AICODE-002", "No hardcoded user ID authorization bypass detected"));
  }

  return results;
}

function pass(controlKey: string, title: string): CheckResult {
  return {
    checkId: generateCheckId("Code Quality", `${controlKey}:pass`),
    status: "PASS",
    category: "Code Quality",
    title,
    confidence: 80,
    detectionMethod: "regex",
    controlKey,
  };
}

function notVerified(controlKey: string, what: string): CheckResult {
  return {
    checkId: generateCheckId("Code Quality", `${controlKey}:unreadable`),
    status: "NOT_VERIFIED",
    category: "Code Quality",
    title: `Some files could not be read for ${what} analysis`,
    confidence: 0,
    detectionMethod: "regex",
    controlKey,
  };
}
