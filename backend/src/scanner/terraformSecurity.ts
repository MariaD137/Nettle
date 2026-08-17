import fs from "fs";
import path from "path";
import type { Finding, Pass } from "./types";

/**
 * Static analysis over raw Terraform (.tf) text — the same pattern-matching
 * approach the rest of the scanner uses, not a full HCL parser. This means
 * it can miss constructs split across variables/modules, and can't confirm
 * a value at plan/apply time (e.g. a variable defaulting to something safe
 * that a caller overrides unsafely elsewhere). Findings describe what the
 * static text says, not a confirmed deployed state.
 */

const PUBLIC_S3_ACL = /acl\s*=\s*["'](public-read|public-read-write)["']/gi;
const S3_PUBLIC_ACCESS_DISABLED = /block_public_acls\s*=\s*false|block_public_policy\s*=\s*false|ignore_public_acls\s*=\s*false|restrict_public_buckets\s*=\s*false/gi;

const IAM_WILDCARD_ACTION = /"Action"\s*:\s*"\*"|Action\s*=\s*\[\s*"\*"\s*\]|Action\s*=\s*"\*"/gi;
const IAM_WILDCARD_RESOURCE = /"Resource"\s*:\s*"\*"|Resource\s*=\s*\[\s*"\*"\s*\]|Resource\s*=\s*"\*"/gi;

const PUBLICLY_ACCESSIBLE_DB = /resource\s+"aws_db_instance"[^}]*?publicly_accessible\s*=\s*true/gis;

const OPEN_INGRESS_CIDR = /cidr_blocks\s*=\s*\[[^\]]*"0\.0\.0\.0\/0"[^\]]*\]/gi;
const SENSITIVE_PORTS = ["22", "3389", "3306", "5432", "27017", "6379", "9200", "5601"];

function extractResourceBlocks(text: string, resourceType: string): string[] {
  const blocks: string[] = [];
  const re = new RegExp(`resource\\s+"${resourceType}"\\s+"[^"]*"\\s*\\{`, "g");
  let match;
  while ((match = re.exec(text)) !== null) {
    // Naive brace matching from the opening brace of this resource block.
    let depth = 1;
    let i = match.index + match[0].length;
    const start = i;
    while (i < text.length && depth > 0) {
      if (text[i] === "{") depth++;
      else if (text[i] === "}") depth--;
      i++;
    }
    blocks.push(text.slice(start, i - 1));
  }
  return blocks;
}

export function scanTerraformSecurity(files: string[], targetRoot: string): { findings: Finding[]; passed: Pass[] } {
  const findings: Finding[] = [];
  const tfFiles = files.filter((f) => f.endsWith(".tf"));
  if (tfFiles.length === 0) return { findings, passed: [] };

  let anyS3 = false;
  let anyPublicS3 = false;
  let anyIamPolicy = false;
  let anyWildcardIam = false;
  let anySecurityGroup = false;
  let anyOpenIngress = false;
  let anyRds = false;
  let anyEncryptionGap = false;

  for (const file of tfFiles) {
    const text = fs.readFileSync(file, "utf8");
    const rel = path.relative(targetRoot, file);

    if (/resource\s+"aws_s3_bucket"/.test(text)) {
      anyS3 = true;
      if (PUBLIC_S3_ACL.test(text) || S3_PUBLIC_ACCESS_DISABLED.test(text)) {
        anyPublicS3 = true;
        findings.push({
          severity: "critical",
          category: "Infrastructure",
          title: "S3 bucket may be publicly accessible",
          detail: "This file sets a public ACL (public-read/public-read-write) or disables one of the S3 public-access-block settings on a bucket resource.",
          file: rel,
          line: null,
          remediation: 'Set acl = "private" and enable all four aws_s3_bucket_public_access_block settings (block_public_acls, block_public_policy, ignore_public_acls, restrict_public_buckets = true) unless the bucket is intentionally public (e.g. static site hosting).',
        });
      }
      if (!/server_side_encryption_configuration/.test(text)) {
        anyEncryptionGap = true;
        findings.push({
          severity: "medium",
          category: "Infrastructure",
          title: "S3 bucket has no server-side encryption configuration",
          detail: "No server_side_encryption_configuration block was found for this bucket resource.",
          file: rel,
          line: null,
          remediation: "Add a server_side_encryption_configuration block (SSE-S3 or SSE-KMS) to encrypt objects at rest.",
        });
      }
    }

    for (const block of [...extractResourceBlocks(text, "aws_iam_policy"), ...extractResourceBlocks(text, "aws_iam_role_policy")]) {
      anyIamPolicy = true;
      IAM_WILDCARD_ACTION.lastIndex = 0;
      IAM_WILDCARD_RESOURCE.lastIndex = 0;
      if (IAM_WILDCARD_ACTION.test(block) && IAM_WILDCARD_RESOURCE.test(block)) {
        anyWildcardIam = true;
        findings.push({
          severity: "critical",
          category: "Infrastructure",
          title: "IAM policy grants wildcard action on wildcard resource (*:*)",
          detail: 'This policy statement combines Action = "*" with Resource = "*", granting unrestricted access to every action on every resource.',
          file: rel,
          line: null,
          remediation: "Scope the policy to the specific actions and resource ARNs the role actually needs.",
        });
      }
    }

    if (/resource\s+"aws_db_instance"/.test(text)) {
      anyRds = true;
      PUBLICLY_ACCESSIBLE_DB.lastIndex = 0;
      if (PUBLICLY_ACCESSIBLE_DB.test(text)) {
        findings.push({
          severity: "critical",
          category: "Infrastructure",
          title: "RDS instance is configured as publicly accessible",
          detail: "publicly_accessible = true was found on an aws_db_instance resource, exposing the database to the internet rather than only the VPC.",
          file: rel,
          line: null,
          remediation: "Set publicly_accessible = false and reach the database through a VPC (bastion host, VPN, or app-tier security group) instead.",
        });
      }
      if (!/storage_encrypted\s*=\s*true/.test(text)) {
        anyEncryptionGap = true;
        findings.push({
          severity: "medium",
          category: "Infrastructure",
          title: "RDS instance does not set storage_encrypted = true",
          detail: "No storage_encrypted = true was found for this database instance.",
          file: rel,
          line: null,
          remediation: "Set storage_encrypted = true (this can only be enabled at creation time, not via a later update, for most engines).",
        });
      }
    }

    if (/resource\s+"aws_security_group"/.test(text)) {
      anySecurityGroup = true;
      const ingressBlocks = extractResourceBlocks(text, "aws_security_group");
      for (const block of ingressBlocks) {
        OPEN_INGRESS_CIDR.lastIndex = 0;
        if (OPEN_INGRESS_CIDR.test(block)) {
          const portMentioned = SENSITIVE_PORTS.find((p) => new RegExp(`from_port\\s*=\\s*${p}\\b`).test(block));
          anyOpenIngress = true;
          findings.push({
            severity: portMentioned ? "critical" : "high",
            category: "Infrastructure",
            title: portMentioned
              ? `Security group allows unrestricted ingress (0.0.0.0/0) on a sensitive port (${portMentioned})`
              : "Security group allows unrestricted ingress (0.0.0.0/0)",
            detail: "An ingress rule allows traffic from 0.0.0.0/0 (any IPv4 address).",
            file: rel,
            line: null,
            remediation: "Restrict cidr_blocks to known IP ranges (office VPN, load balancer, etc.) instead of 0.0.0.0/0.",
          });
        }
      }
    }
  }

  const passed: Pass[] = [];
  if (anyS3 && !anyPublicS3) passed.push({ category: "Infrastructure", title: "No publicly-writable S3 bucket ACLs detected" });
  if (anyIamPolicy && !anyWildcardIam) passed.push({ category: "Infrastructure", title: "No wildcard (*:*) IAM policy statements detected" });
  if (anyRds && !anyOpenIngress) passed.push({ category: "Infrastructure", title: "No publicly-accessible RDS instance detected" });
  if (anySecurityGroup && !anyOpenIngress) passed.push({ category: "Infrastructure", title: "No unrestricted (0.0.0.0/0) security group ingress detected" });
  if ((anyS3 || anyRds) && !anyEncryptionGap) passed.push({ category: "Infrastructure", title: "Encryption at rest configured for scanned S3/RDS resources" });

  return { findings, passed };
}
