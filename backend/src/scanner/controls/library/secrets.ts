import type { Control } from "../types";
import { registerControl } from "../registry";

/**
 * SECRET-001 — hardcoded credential detection. The recommendedSolution text
 * below is the product spec's own worked example (§6) almost verbatim; the
 * "browser" technology fix is the spec's own §7 example of why the same
 * remediation can't apply everywhere (a secret in browser-delivered code
 * can't be fixed by "move it to an env var" the way a backend secret can,
 * because the browser bundle is inspectable by definition).
 */
export const SECRET_001: Control = {
  controlKey: "SECRET-001",
  category: "Security",
  subcategory: "Secrets",
  name: "No hardcoded credentials in source",
  description:
    "Cloud keys, database credentials, API keys, signing secrets and private keys must never appear as literal " +
    "values in source code — they must be loaded at runtime from environment configuration or a secret manager.",
  question: "Does the scanned source contain a hardcoded credential, key, or secret?",
  defaultSeverity: "critical",

  passCriteria: "No credential-shaped pattern (cloud key, API key, private key block, connection string with embedded credentials, etc.) was found in any scanned file.",
  failCriteria: "A credential-shaped pattern was matched in a scanned file.",
  notVerifiedCriteria: "A file matched by the scan's inclusion rules could not be read (permissions, encoding, or size), so its contents were not checked.",

  whyItMatters:
    "A credential committed to source is readable by anyone with repository access, persists in git history even after deletion, and is " +
    "routinely indexed by code-search tools, CI logs, and AI coding assistants that read the codebase. An exposed credential is not a " +
    "theoretical risk once committed — treat it as compromised.",

  technologyFixes: [
    {
      technology: "browser",
      quickFix: "Remove the secret from the frontend bundle immediately — it is already exposed to every visitor who opens dev tools or views source.",
      developerFix:
        "Browser-delivered code cannot contain a secret, because the user can always inspect it — minifying or obfuscating it is not a fix. " +
        "Move the privileged operation (the one this key authorizes) to a backend endpoint the browser calls instead, and keep the real key server-side only.",
      architectureFix: "Introduce a thin backend proxy endpoint for the privileged operation, authenticated by the app's own session/API-key mechanism rather than the third-party key directly.",
    },
    {
      technology: "aws",
      quickFix: "Rotate the exposed AWS key in the IAM console immediately, then remove it from source.",
      developerFix: "Load AWS credentials from the environment (AWS SDK's default credential chain) rather than hardcoding them — never construct a credentials object with a literal key/secret pair.",
      architectureFix: "Use IAM roles / workload identity (an EC2/ECS/Lambda execution role, or IAM Roles Anywhere) so the running process gets short-lived credentials automatically, with no static key to leak in the first place.",
    },
    {
      technology: "generic",
      quickFix: "Remove the credential from source and rotate it at its provider immediately — assume it is already compromised once committed.",
      developerFix:
        "Load the credential from an environment variable (process.env.X) or a secret manager (AWS Secrets Manager, HashiCorp Vault, etc.) at runtime, never as a literal in code. " +
        "Check git history for prior exposure (git log -S '<value>') even after removing the current copy.",
      architectureFix: "Use short-lived, workload-scoped credentials where the platform supports them (OIDC federation, IAM roles) instead of a long-lived static secret at all.",
    },
  ],

  longTermHardening:
    "Add a pre-commit secret-scanning hook (e.g. gitleaks, git-secrets) so a credential can't be committed in the first place, and enable your git " +
    "host's own secret-scanning/push-protection feature as a second layer.",
  verificationMethod: "Rescan the repository and confirm the credential pattern is no longer present in any scanned file — a rotated-but-still-present key still fails this control.",
  references: ["OWASP Top 10: A02:2021 – Cryptographic Failures", "CWE-798: Use of Hard-coded Credentials"],
  complianceMappings: ["SOC 2 CC6.1", "PCI DSS Req. 3 (where cardholder data is involved)"],

  releaseImpactBySeverity: {
    critical: "BLOCK_RELEASE",
    high: "BLOCK_RELEASE",
    medium: "REVIEW_BEFORE_RELEASE",
    low: "FIX_RECOMMENDED",
    info: "INFORMATIONAL",
  },

  enabled: true,
  version: "1.0.0",
};

registerControl(SECRET_001);
