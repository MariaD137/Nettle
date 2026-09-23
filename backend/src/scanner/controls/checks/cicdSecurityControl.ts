import fs from "fs";
import path from "path";
import type { CheckResult } from "../../types";
import { generateCheckId } from "../../threeStateModel";

const WORKFLOW_FILE_PATTERN = /\.github[\/\\]workflows[\/\\][^\/\\]+\.ya?ml$/;

const PR_TARGET_PATTERN = /\bon\s*:[\s\S]{0,200}?pull_request_target\b/;
const PR_HEAD_CHECKOUT_PATTERN = /uses:\s*actions\/checkout@[^\n]*\n(?:[^\n]*\n){0,5}?[^\n]*ref:\s*\$\{\{\s*github\.event\.pull_request\.head/;

const ACTION_REFERENCE_PATTERN = /uses:\s*([\w.-]+\/[\w.-]+)@([\w./-]+)/g;
const SHA_PATTERN = /^[0-9a-f]{40}$/i;

const WRITE_ALL_PATTERN = /permissions\s*:\s*write-all\b/;

/**
 * CICD-001..003, wired to the control library. Second Phase B category
 * (master spec §23) — entirely new, no legacy module to migrate from.
 * Requires SCANNED_EXTENSIONS to include .yml/.yaml (added in
 * scanner/index.ts alongside this control) since GitHub Actions workflow
 * files were never in the scanned file set before.
 *
 * Scoped to .github/workflows/*.yml(|.yaml) specifically, not every YAML
 * file in the repo — a docker-compose.yml or tool config wouldn't have any
 * of these patterns anyway, but scoping avoids the confusion of a
 * CI/CD-specific title attached to an unrelated config file.
 *
 * Gated like PAY-*: if there are no workflow files at all, none of the 3
 * controls produce a result.
 */
export function scanCicdSecurityControl(files: string[], targetRoot: string): CheckResult[] {
  const workflowFiles = files.filter((f) => WORKFLOW_FILE_PATTERN.test(f));
  if (workflowFiles.length === 0) return [];

  const results: CheckResult[] = [];
  let anyUnreadable = false;
  let prTargetFailed = false;
  let unpinnedActionFailed = false;
  let writeAllFailed = false;

  for (const file of workflowFiles) {
    const rel = path.relative(targetRoot, file);
    let text: string;
    try {
      text = fs.readFileSync(file, "utf8");
    } catch {
      anyUnreadable = true;
      continue;
    }

    if (PR_TARGET_PATTERN.test(text) && PR_HEAD_CHECKOUT_PATTERN.test(text)) {
      prTargetFailed = true;
      results.push({
        checkId: generateCheckId("CI/CD Security", "CICD-001:fail", rel),
        status: "FAIL",
        category: "CI/CD Security",
        title: "pull_request_target workflow checks out the PR's own head commit",
        detail: "This workflow triggers on pull_request_target (which runs with full repository permissions and secrets) and also checks out the pull request's own head commit — running untrusted, attacker-controlled code with privileged access.",
        severity: "critical",
        file: rel,
        confidence: 80,
        detectionMethod: "regex",
        remediation: "Switch to pull_request (sandboxed, no secrets) unless privileged access is genuinely required, and never check out the PR's own head commit inside a pull_request_target workflow.",
        controlKey: "CICD-001",
      });
    }

    ACTION_REFERENCE_PATTERN.lastIndex = 0;
    let match: RegExpExecArray | null;
    const unpinnedRefs = new Set<string>();
    while ((match = ACTION_REFERENCE_PATTERN.exec(text))) {
      const [, actionName, ref] = match;
      if (!SHA_PATTERN.test(ref)) {
        unpinnedRefs.add(`${actionName}@${ref}`);
      }
    }
    if (unpinnedRefs.size > 0) {
      unpinnedActionFailed = true;
      results.push({
        checkId: generateCheckId("CI/CD Security", "CICD-002:fail", rel),
        status: "FAIL",
        category: "CI/CD Security",
        title: "GitHub Action referenced by a mutable tag, not a commit SHA",
        detail: `Found ${unpinnedRefs.size} action reference(s) not pinned to a commit SHA: ${[...unpinnedRefs].join(", ")}.`,
        severity: "medium",
        file: rel,
        confidence: 90,
        detectionMethod: "regex",
        remediation: "Pin each action to the full 40-character commit SHA it currently resolves to, keeping the version as a trailing comment.",
        controlKey: "CICD-002",
      });
    }

    if (WRITE_ALL_PATTERN.test(text)) {
      writeAllFailed = true;
      results.push({
        checkId: generateCheckId("CI/CD Security", "CICD-003:fail", rel),
        status: "FAIL",
        category: "CI/CD Security",
        title: "Workflow grants write-all permissions",
        detail: "This workflow sets permissions: write-all, granting its GITHUB_TOKEN write access to every repository resource for the entire run.",
        severity: "high",
        file: rel,
        confidence: 95,
        detectionMethod: "regex",
        remediation: "Replace write-all with the specific scopes the workflow actually needs, e.g. contents: read.",
        controlKey: "CICD-003",
      });
    }
  }

  for (const [controlKey, failed, title] of [
    ["CICD-001", prTargetFailed, "No pull_request_target workflow checks out the PR's own head commit"],
    ["CICD-002", unpinnedActionFailed, "All GitHub Actions are pinned to a commit SHA"],
    ["CICD-003", writeAllFailed, "No workflow grants write-all permissions"],
  ] as const) {
    if (failed) continue;
    if (anyUnreadable) {
      results.push({
        checkId: generateCheckId("CI/CD Security", `${controlKey}:unreadable`),
        status: "NOT_VERIFIED",
        category: "CI/CD Security",
        title: `Some workflow files could not be read for "${title}" analysis`,
        confidence: 0,
        detectionMethod: "regex",
        controlKey,
      });
      continue;
    }
    results.push({
      checkId: generateCheckId("CI/CD Security", `${controlKey}:pass`),
      status: "PASS",
      category: "CI/CD Security",
      title,
      confidence: 85,
      detectionMethod: "regex",
      controlKey,
    });
  }

  return results;
}
