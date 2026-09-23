import fs from "fs";
import path from "path";
import type { CheckResult } from "../../types";
import { generateCheckId } from "../../threeStateModel";

const DOCKERFILE_PATTERN = /(^|[\/\\])dockerfile$/i;
const TERRAFORM_FILE_PATTERN = /\.tf$/i;

const USER_DIRECTIVE_PATTERN = /^\s*USER\s+(\S+)/gim;

const S3_BUCKET_RESOURCE_PATTERN = /resource\s+"aws_s3_bucket"/;
const PUBLIC_ACL_PATTERN = /acl\s*=\s*"public-read(-write)?"/;

const SENSITIVE_PORTS = [22, 3389, 3306, 5432, 6379, 27017, 9200, 5601];
const OPEN_CIDR_PATTERN = /cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0\/0"\s*\]/;
const SENSITIVE_PORT_PATTERN = new RegExp(`(from_port|to_port)\\s*=\\s*(${SENSITIVE_PORTS.join("|")})\\b`);

/**
 * CLOUD-001..003, wired to the control library. Fourth Phase B category
 * (master spec §24) — entirely new, no legacy module to migrate from.
 * Confirmed via grep before writing anything that no existing control
 * covers Dockerfile or Terraform configuration.
 *
 * Requires SCANNED_EXTENSIONS to include ".tf" and the literal "dockerfile"
 * (added in scanner/index.ts alongside this control) — walk()'s extension
 * matcher does a plain endsWith(), so "dockerfile" as an entry matches a
 * file literally named Dockerfile (case-insensitively) via the same
 * mechanism a real extension does; it does not match suffixed variants
 * like Dockerfile.prod, a known, documented limitation for this round.
 *
 * Each control gated on its own file-type applicability, matching the
 * pattern established for the other Phase B categories: CLOUD-001 only
 * runs when a Dockerfile exists; CLOUD-002 only when a Terraform ingress
 * block exists; CLOUD-003 only when a Terraform aws_s3_bucket resource
 * exists.
 */
export function scanCloudSecurityControl(files: string[], targetRoot: string): CheckResult[] {
  const results: CheckResult[] = [];
  let anyUnreadable = false;

  // --- CLOUD-001: Dockerfile running as root ---
  const dockerfiles = files.filter((f) => DOCKERFILE_PATTERN.test(f));
  let dockerRootFailed = false;
  for (const file of dockerfiles) {
    const rel = path.relative(targetRoot, file);
    let text: string;
    try {
      text = fs.readFileSync(file, "utf8");
    } catch {
      anyUnreadable = true;
      continue;
    }

    USER_DIRECTIVE_PATTERN.lastIndex = 0;
    const matches = [...text.matchAll(USER_DIRECTIVE_PATTERN)];
    const lastUser = matches.length > 0 ? matches[matches.length - 1][1] : null;
    const runsAsRoot = lastUser === null || lastUser === "root" || lastUser === "0";

    if (runsAsRoot) {
      dockerRootFailed = true;
      results.push({
        checkId: generateCheckId("Cloud Security", "CLOUD-001:fail", rel),
        status: "FAIL",
        category: "Cloud Security",
        title: "Docker container runs as root",
        detail: lastUser === null ? "No USER instruction found in this Dockerfile — the container runs as root by default." : "The last USER instruction in this Dockerfile sets root.",
        severity: "medium",
        file: rel,
        confidence: 75,
        detectionMethod: "regex",
        remediation: "Add a USER instruction after installing dependencies to run the container as a non-root user.",
        controlKey: "CLOUD-001",
      });
    }
  }
  if (dockerfiles.length > 0 && !dockerRootFailed) {
    results.push(anyUnreadable ? notVerified("CLOUD-001", "container user configuration") : pass("CLOUD-001", "Docker container runs as a non-root user"));
  }

  // --- CLOUD-002/003: Terraform ---
  const terraformFiles = files.filter((f) => TERRAFORM_FILE_PATTERN.test(f));
  let hasIngressBlock = false;
  let openSgFailed = false;
  let hasS3BucketResource = false;
  let publicBucketFailed = false;

  for (const file of terraformFiles) {
    const rel = path.relative(targetRoot, file);
    let text: string;
    try {
      text = fs.readFileSync(file, "utf8");
    } catch {
      anyUnreadable = true;
      continue;
    }

    const ingressBlocks = text.split(/ingress\s*\{/).slice(1);
    for (const raw of ingressBlocks) {
      hasIngressBlock = true;
      const block = raw.split(/\n\s*\}/)[0];
      if (OPEN_CIDR_PATTERN.test(block) && SENSITIVE_PORT_PATTERN.test(block)) {
        openSgFailed = true;
        results.push({
          checkId: generateCheckId("Cloud Security", "CLOUD-002:fail", `${rel}:${raw.length}`),
          status: "FAIL",
          category: "Cloud Security",
          title: "Security group rule opens a sensitive port to the world",
          detail: "An ingress rule allows 0.0.0.0/0 on a sensitive port (SSH, RDP, or a database port).",
          severity: "critical",
          file: rel,
          confidence: 80,
          detectionMethod: "regex",
          remediation: "Restrict cidr_blocks to the specific IP range that needs access, not 0.0.0.0/0.",
          controlKey: "CLOUD-002",
        });
      }
    }

    if (S3_BUCKET_RESOURCE_PATTERN.test(text)) {
      hasS3BucketResource = true;
      if (PUBLIC_ACL_PATTERN.test(text)) {
        publicBucketFailed = true;
        results.push({
          checkId: generateCheckId("Cloud Security", "CLOUD-003:fail", rel),
          status: "FAIL",
          category: "Cloud Security",
          title: "Storage bucket is publicly readable or writable",
          detail: "An aws_s3_bucket resource sets acl to public-read or public-read-write.",
          severity: "critical",
          file: rel,
          confidence: 85,
          detectionMethod: "regex",
          remediation: "Set acl to \"private\" and enable the bucket's public access block.",
          controlKey: "CLOUD-003",
        });
      }
    }
  }

  if (hasIngressBlock && !openSgFailed) {
    results.push(anyUnreadable ? notVerified("CLOUD-002", "security group rules") : pass("CLOUD-002", "No security group rule opens a sensitive port to the world"));
  }
  if (hasS3BucketResource && !publicBucketFailed) {
    results.push(anyUnreadable ? notVerified("CLOUD-003", "storage bucket ACL configuration") : pass("CLOUD-003", "Storage bucket is not publicly readable or writable"));
  }

  return results;
}

function pass(controlKey: string, title: string): CheckResult {
  return {
    checkId: generateCheckId("Cloud Security", `${controlKey}:pass`),
    status: "PASS",
    category: "Cloud Security",
    title,
    confidence: 80,
    detectionMethod: "regex",
    controlKey,
  };
}

function notVerified(controlKey: string, what: string): CheckResult {
  return {
    checkId: generateCheckId("Cloud Security", `${controlKey}:unreadable`),
    status: "NOT_VERIFIED",
    category: "Cloud Security",
    title: `Some files could not be read for ${what} analysis`,
    confidence: 0,
    detectionMethod: "regex",
    controlKey,
  };
}
