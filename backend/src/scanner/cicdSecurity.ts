import fs from "fs";
import path from "path";
import type { Finding, Pass } from "./types";

/**
 * Static analysis over GitHub Actions workflow files (.github/workflows/*.yml).
 * GitLab CI and other pipeline formats aren't covered — most repos Nettle
 * scans are GitHub-hosted, and adding another pipeline dialect is future
 * work rather than something silently half-supported here.
 */

const PULL_REQUEST_TARGET = /^\s*pull_request_target\s*:/m;
const CHECKOUT_PR_HEAD = /uses\s*:\s*actions\/checkout@[^\s]+[\s\S]{0,200}?ref\s*:\s*.*(pull_request\.head|github\.head_ref)/i;
const WRITE_ALL_PERMISSION = /permissions\s*:\s*write-all/i;
const CONTENTS_WRITE = /permissions\s*:[\s\S]{0,200}?contents\s*:\s*write/i;
const HAS_TOP_LEVEL_PERMISSIONS = /^permissions\s*:/m;
const CURL_PIPE_SHELL = /(curl|wget)\s+[^\n|]*\|\s*(sudo\s+)?(bash|sh)\b/i;
const UNPINNED_ACTION = /uses\s*:\s*([\w.-]+\/[\w.-]+)@([\w.\/-]+)/g;
const PINNED_SHA = /^[a-f0-9]{40}$/i;
const MUTABLE_REF_NAMES = new Set(["main", "master", "latest", "head"]);

export function scanCicdSecurity(files: string[], targetRoot: string): { findings: Finding[]; passed: Pass[] } {
  const findings: Finding[] = [];
  const workflowFiles = files.filter((f) => {
    const norm = f.replace(/\\/g, "/");
    return norm.includes("/.github/workflows/") && /\.ya?ml$/i.test(f);
  });
  if (workflowFiles.length === 0) return { findings, passed: [] };

  let anyPrTargetRisk = false;
  let anyBroadPermissions = false;
  let anyMissingPermissions = false;
  let anyDangerousShell = false;
  let anyUnpinnedAction = false;

  for (const file of workflowFiles) {
    const text = fs.readFileSync(file, "utf8");
    const rel = path.relative(targetRoot, file);

    const usesPrTarget = PULL_REQUEST_TARGET.test(text);
    const checksOutPrHead = CHECKOUT_PR_HEAD.test(text);
    if (usesPrTarget && checksOutPrHead) {
      anyPrTargetRisk = true;
      findings.push({
        severity: "critical",
        category: "CI/CD",
        title: "pull_request_target workflow checks out the PR's own head ref",
        detail: "pull_request_target runs with access to repo secrets even for forked-PR contributions, but normally checks out the base branch. This workflow checks out the pull request's own head commit instead, which means an external contributor's code runs with access to those secrets.",
        file: rel,
        line: null,
        remediation: "Switch the trigger to `pull_request` (no secret access for fork PRs), or if pull_request_target is required, never check out or execute the PR's own head ref/code with it.",
      });
    }

    if (WRITE_ALL_PERMISSION.test(text) || CONTENTS_WRITE.test(text)) {
      anyBroadPermissions = true;
      findings.push({
        severity: usesPrTarget ? "high" : "medium",
        category: "CI/CD",
        title: "Workflow grants broad GITHUB_TOKEN permissions",
        detail: "This workflow sets permissions: write-all or contents: write. The default GITHUB_TOKEN should be scoped to only what each job actually needs.",
        file: rel,
        line: null,
        remediation: "Set the minimum required permissions per job (e.g. `contents: read`, and only the specific write scope a job needs, like `pull-requests: write` for commenting).",
      });
    } else if (!HAS_TOP_LEVEL_PERMISSIONS.test(text) && !/^\s*permissions\s*:/m.test(text)) {
      anyMissingPermissions = true;
      findings.push({
        severity: "low",
        category: "CI/CD",
        title: "Workflow has no explicit permissions block",
        detail: "Without an explicit `permissions:` block, the GITHUB_TOKEN's scope depends on the repository/organization default, which may be broader than this workflow needs.",
        file: rel,
        line: null,
        remediation: "Add an explicit permissions block (e.g. `permissions: { contents: read }`) so the token's scope is intentional and visible in the workflow file.",
      });
    }

    if (CURL_PIPE_SHELL.test(text)) {
      anyDangerousShell = true;
      findings.push({
        severity: "medium",
        category: "CI/CD",
        title: "Workflow pipes a downloaded script directly into a shell",
        detail: "A `curl | bash` / `wget | sh` style pattern executes remote content without any integrity check.",
        file: rel,
        line: null,
        remediation: "Download the script, verify its checksum/signature, then execute it — or use a pinned, checksummed release asset instead of piping directly to a shell.",
      });
    }

    let match;
    UNPINNED_ACTION.lastIndex = 0;
    while ((match = UNPINNED_ACTION.exec(text)) !== null) {
      const [, actionName, ref] = match;
      if (PINNED_SHA.test(ref)) continue;
      if (MUTABLE_REF_NAMES.has(ref.toLowerCase()) || /^v?\d+(\.\d+)?$/.test(ref)) {
        anyUnpinnedAction = true;
        findings.push({
          severity: "medium",
          category: "CI/CD",
          title: `Action "${actionName}" is not pinned to a commit SHA`,
          detail: `Referenced as @${ref}, which is a mutable ref — the action's maintainer (or anyone who compromises their account) can change what code runs under this tag without the workflow changing.`,
          file: rel,
          line: null,
          remediation: `Pin to a full commit SHA instead: uses: ${actionName}@<40-character-sha> # ${ref}`,
        });
      }
    }
  }

  const passed: Pass[] = [];
  if (!anyPrTargetRisk) passed.push({ category: "CI/CD", title: "No pull_request_target workflow checks out untrusted PR code" });
  if (!anyBroadPermissions) passed.push({ category: "CI/CD", title: "No workflow grants write-all or contents:write permissions" });
  if (!anyMissingPermissions) passed.push({ category: "CI/CD", title: "Workflows declare an explicit permissions block" });
  if (!anyDangerousShell) passed.push({ category: "CI/CD", title: "No curl/wget-piped-to-shell pattern detected" });
  if (!anyUnpinnedAction) passed.push({ category: "CI/CD", title: "Third-party actions are pinned to a commit SHA" });

  return { findings, passed };
}
