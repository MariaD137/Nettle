import type { Control } from "../types";
import { registerControl } from "../registry";

export const AICODE_001: Control = {
  controlKey: "AICODE-001",
  category: "Code Quality",
  subcategory: "AI-assisted development risk indicators",
  name: "No placeholder credential left in source",
  description:
    "A credential-shaped variable (api key, secret, token, password) assigned an obvious placeholder value " +
    "(\"your_api_key_here\", \"CHANGE_ME\", \"INSERT_KEY_HERE\") is a common artifact of AI-assisted code " +
    "generation, where a scaffold or example value gets left in place rather than replaced with a real " +
    "environment-variable read. Left in place, the application either fails obviously at the call site, or — " +
    "worse — the placeholder is silently sent as if it were a real credential.",
  question: "Are credential-shaped variables free of placeholder/example values?",
  defaultSeverity: "medium",
  passCriteria: "No scanned file assigns an obviously-placeholder value (your_*_key_here, CHANGE_ME, INSERT_*_HERE, xxx-shaped, angle-bracket placeholder) to a credential-shaped variable.",
  failCriteria: "A scanned file assigns an obviously-placeholder value to a credential-shaped variable (api key, secret, token, password).",
  notVerifiedCriteria: "A file matched by the scan's inclusion rules could not be read, so placeholder credentials were not checked in it.",
  whyItMatters:
    "This is distinct from SECRET-001 (which matches real-looking secret formats): a placeholder value is " +
    "obviously fake, not a leaked real credential. The risk here is different — it's a sign the integration was " +
    "never actually wired up to a real credential source, which either breaks at runtime in an unexpected way, or " +
    "worse, silently no-ops or falls back to some default the developer never intended to ship.",
  technologyFixes: [
    {
      technology: "generic",
      quickFix: "Replace the placeholder with a read from environment configuration: process.env.API_KEY.",
      developerFix: "Load every credential from environment variables (or a secrets manager) at startup, and fail loudly — not silently — if a required one is missing, so a forgotten placeholder is caught in development, not discovered in production.",
      codeExample: "const apiKey = process.env.OPENAI_API_KEY;\nif (!apiKey) throw new Error('OPENAI_API_KEY is not set');",
    },
  ],
  longTermHardening: "Add a startup-time check that validates every required environment variable is set and doesn't match a known placeholder pattern, failing fast instead of allowing the app to start misconfigured.",
  verificationMethod: "Rescan and confirm the placeholder value has been replaced with a real credential source.",
  references: [],
  complianceMappings: [],
  releaseImpactBySeverity: { critical: "BLOCK_RELEASE", high: "REVIEW_BEFORE_RELEASE", medium: "FIX_RECOMMENDED", low: "IMPROVEMENT", info: "INFORMATIONAL" },
  enabled: true,
  version: "1.0.0",
};

export const AICODE_002: Control = {
  controlKey: "AICODE-002",
  category: "Code Quality",
  subcategory: "AI-assisted development risk indicators",
  name: "No hardcoded user ID used as an authorization bypass",
  description:
    "A conditional that grants access by comparing a user ID directly against a hardcoded numeric or string " +
    "literal (if (userId === 1) grantAdminAccess()), or a constant named like ADMIN_ID/TEST_USER_ID/BACKDOOR_ID " +
    "assigned a literal value, is a hardcoded backdoor — whether left in deliberately during development or " +
    "generated as a scaffold that was never removed, it grants elevated access to one specific, guessable account " +
    "with no actual authorization check behind it.",
  question: "Is authorization free of hardcoded-user-ID bypass logic?",
  defaultSeverity: "critical",
  passCriteria: "No scanned file compares a user ID directly against a hardcoded literal to grant access, and no ADMIN_ID/MASTER_ID/SUPER_USER_ID/TEST_USER_ID/DEBUG_USER_ID/BACKDOOR_ID-named constant is assigned a literal value.",
  failCriteria: "A scanned file compares a user ID directly against a hardcoded literal, or declares one of those suspiciously-named ID constants with a literal value.",
  notVerifiedCriteria: "This is a regex-level heuristic over source text, not a data-flow analysis — it can't confirm the comparison actually gates something privileged (vs. an unrelated feature flag using the same shape), only that the shape is present. A FAIL here is worth a manual look, not an automatic conclusion.",
  whyItMatters:
    "Unlike a role/permission check, a hardcoded user ID comparison isn't tied to any actual authorization model — " +
    "it's tied to one specific account ID, which is trivial to guess (sequential IDs), enumerate, or simply " +
    "happens to already be known to whoever wrote the scaffold. It also bypasses any audit trail a real permission " +
    "system would provide.",
  technologyFixes: [
    {
      technology: "generic",
      quickFix: "Replace the hardcoded ID comparison with a real role/permission check (user.role === 'admin', driven by the database, not a literal ID).",
      developerFix: "If the intent was a genuine admin/test account, model it as a role or permission flag stored on the user record, checked the same way every other authorization decision in the app is checked — never as a literal ID comparison scattered in application logic.",
      codeExample: "// Instead of: if (userId === 1) { ... }\nif (user.role === 'admin') { ... }",
    },
  ],
  longTermHardening: "Add a Semgrep or equivalent static-analysis rule that fails CI on a direct user-ID-to-literal comparison anywhere near an authorization decision.",
  verificationMethod: "Rescan and confirm the hardcoded ID comparison has been replaced with a real authorization check.",
  references: ["OWASP: Insecure Design"],
  complianceMappings: [],
  releaseImpactBySeverity: { critical: "BLOCK_RELEASE", high: "REVIEW_BEFORE_RELEASE", medium: "FIX_RECOMMENDED", low: "IMPROVEMENT", info: "INFORMATIONAL" },
  enabled: true,
  version: "1.0.0",
};

registerControl(AICODE_001);
registerControl(AICODE_002);
