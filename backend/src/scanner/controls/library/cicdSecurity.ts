import type { Control } from "../types";
import { registerControl } from "../registry";

export const CICD_001: Control = {
  controlKey: "CICD-001",
  category: "CI/CD Security",
  subcategory: "Workflow triggers",
  name: "No pull_request_target workflow checks out the PR's own head",
  description:
    "pull_request_target runs with the base repository's full permissions and secrets, unlike pull_request (which " +
    "runs sandboxed, with no secrets, for exactly this reason). Checking out the PR's own head commit inside a " +
    "pull_request_target workflow then runs an external contributor's code with that same privileged access — the " +
    "combination this control checks for.",
  question: "Does any pull_request_target workflow avoid checking out the PR's own (untrusted) head commit?",
  defaultSeverity: "critical",
  passCriteria: "No workflow file both triggers on pull_request_target and checks out the PR's head ref (github.event.pull_request.head.*).",
  failCriteria: "A workflow file triggers on pull_request_target and also checks out the PR's head ref.",
  notVerifiedCriteria: "A workflow file matched by the scan's inclusion rules could not be read, so its trigger/checkout configuration was not checked.",
  whyItMatters:
    "This exact combination is the most common real-world path to a GitHub Actions supply-chain compromise: a " +
    "malicious PR modifies a test script or build step, the pull_request_target-triggered workflow checks that " +
    "code out and runs it with access to repository secrets (npm tokens, deploy keys, cloud credentials) that a " +
    "sandboxed pull_request workflow would never have had.",
  technologyFixes: [
    {
      technology: "generic",
      quickFix: "Switch the trigger to pull_request (sandboxed, no secrets) unless privileged access is genuinely required.",
      developerFix: "If pull_request_target is genuinely needed (e.g. to comment on the PR with a privileged token), never check out and execute the PR's own head commit inside it. Split the workflow: run untrusted code (tests, builds) under pull_request with no secrets, and do only the privileged, no-untrusted-code-execution part (posting a comment, applying a label) under pull_request_target.",
      architectureFix: "Use workflow_run triggered by the completion of a pull_request workflow when a privileged step genuinely needs the result of running untrusted code — it lets the privileged workflow act on already-computed output without ever executing the PR's code itself.",
    },
  ],
  longTermHardening: "Enable GitHub's own Actions security hardening recommendations (restrict which actions can run, require approval for first-time contributors) at the repository or organization level.",
  verificationMethod: "Rescan and confirm no pull_request_target workflow checks out the PR's head commit.",
  references: ["GitHub Security Lab: Keeping your GitHub Actions and workflows secure — pull_request_target"],
  complianceMappings: [],
  releaseImpactBySeverity: { critical: "BLOCK_RELEASE", high: "REVIEW_BEFORE_RELEASE", medium: "FIX_RECOMMENDED", low: "IMPROVEMENT", info: "INFORMATIONAL" },
  enabled: true,
  version: "1.0.0",
};

export const CICD_002: Control = {
  controlKey: "CICD-002",
  category: "CI/CD Security",
  subcategory: "Supply chain",
  name: "GitHub Actions pinned to a commit SHA",
  description:
    "A workflow step referencing an action by a mutable tag (@v4, @main) — first-party or third-party alike — " +
    "runs whatever code that tag currently points to. The action's publisher (or anyone who compromises their " +
    "account or the tag itself) can change what runs in every workflow using that tag, retroactively, with no " +
    "change to the workflow file itself.",
  question: "Are GitHub Actions pinned to an immutable commit SHA rather than a mutable tag?",
  defaultSeverity: "medium",
  passCriteria: "Every action reference in scanned workflow files is pinned to a 40-character commit SHA.",
  failCriteria: "A workflow file references an action by a mutable tag or branch name instead of a commit SHA.",
  notVerifiedCriteria: "A workflow file matched by the scan's inclusion rules could not be read, so its action references were not checked.",
  whyItMatters:
    "A tag is just a pointer the publisher can move. Pinning to a commit SHA is the only way a workflow actually " +
    "runs the exact code that was reviewed when the dependency was added — this is the same principle a lockfile " +
    "enforces for npm packages, applied to CI.",
  technologyFixes: [
    {
      technology: "generic",
      quickFix: "Replace the tag with the commit SHA it currently resolves to: uses: owner/repo@<40-char-sha>.",
      developerFix: "Use a tool like Dependabot (which supports GitHub Actions updates) or GitHub's own \"pin actions to a full length commit SHA\" guidance to pin every third-party action, keeping the human-readable version as a trailing comment: uses: actions/checkout@8f4b7f84864484a7bde6ceaf20ad2debeafb5a5c # v4.1.1.",
      architectureFix: "Prefer actions published and maintained by GitHub itself or the tool's own vendor where possible, and review the diff whenever a pinned SHA is updated, the same way a dependency version bump would be reviewed.",
    },
  ],
  longTermHardening: "Enable Dependabot's github-actions ecosystem updates so pinned SHAs get proposed updates automatically, with the diff visible for review.",
  verificationMethod: "Rescan and confirm every third-party action reference is now pinned to a commit SHA.",
  references: ["GitHub Docs: Security hardening for GitHub Actions — Using third-party actions"],
  complianceMappings: [],
  releaseImpactBySeverity: { critical: "BLOCK_RELEASE", high: "REVIEW_BEFORE_RELEASE", medium: "FIX_RECOMMENDED", low: "IMPROVEMENT", info: "INFORMATIONAL" },
  enabled: true,
  version: "1.0.0",
};

export const CICD_003: Control = {
  controlKey: "CICD-003",
  category: "CI/CD Security",
  subcategory: "Least privilege",
  name: "Workflow does not grant write-all permissions",
  description:
    "The default GITHUB_TOKEN a workflow run gets is scoped by its permissions: block. Setting permissions: " +
    "write-all grants that token write access to every resource the repository has (contents, issues, packages, " +
    "deployments, and more) for the entire run, regardless of what the workflow actually needs to do.",
  question: "Does the workflow avoid granting write-all permissions to its GITHUB_TOKEN?",
  defaultSeverity: "high",
  passCriteria: "No workflow file sets permissions: write-all.",
  failCriteria: "A workflow file sets permissions: write-all.",
  notVerifiedCriteria: "A workflow file matched by the scan's inclusion rules could not be read, so its permissions configuration was not checked.",
  whyItMatters:
    "If any step in the workflow is compromised — a malicious dependency pulled in during npm install, a " +
    "poisoned action, an injected script — write-all means that compromise has write access to the entire " +
    "repository and more, not just the narrow scope (e.g. contents: read) the workflow's own steps actually " +
    "require.",
  technologyFixes: [
    {
      technology: "generic",
      quickFix: "Replace write-all with the specific scopes the workflow actually needs, e.g. contents: read.",
      developerFix: "Set permissions: { contents: read } at the workflow (or job) level as the default, and grant a broader scope (e.g. pull-requests: write) only on the specific job that needs it, not the whole workflow.",
      codeExample: "permissions:\n  contents: read\n\njobs:\n  comment-on-pr:\n    permissions:\n      pull-requests: write\n    runs-on: ubuntu-latest",
    },
  ],
  longTermHardening: "Set the organization-wide default workflow permissions to read-only, so a new workflow must opt into any write scope explicitly rather than inheriting a broad default.",
  verificationMethod: "Rescan and confirm the workflow no longer grants write-all permissions.",
  references: ["GitHub Docs: Security hardening for GitHub Actions — Permissions for GITHUB_TOKEN"],
  complianceMappings: [],
  releaseImpactBySeverity: { critical: "BLOCK_RELEASE", high: "REVIEW_BEFORE_RELEASE", medium: "FIX_RECOMMENDED", low: "IMPROVEMENT", info: "INFORMATIONAL" },
  enabled: true,
  version: "1.0.0",
};

registerControl(CICD_001);
registerControl(CICD_002);
registerControl(CICD_003);
