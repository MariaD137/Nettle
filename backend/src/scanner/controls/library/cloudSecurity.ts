import type { Control } from "../types";
import { registerControl } from "../registry";

export const CLOUD_001: Control = {
  controlKey: "CLOUD-001",
  category: "Cloud Security",
  subcategory: "Container hardening",
  name: "Docker container does not run as root",
  description:
    "A Dockerfile with no USER instruction (or one that explicitly sets USER root) runs its process as root " +
    "inside the container. Container isolation is not a security boundary strong enough to treat that as " +
    "harmless — a container escape or a misconfigured volume mount hands an attacker root on the host, not just " +
    "root in the container.",
  question: "Does the container run as a non-root user?",
  defaultSeverity: "medium",
  passCriteria: "The Dockerfile's last USER instruction sets a non-root user.",
  failCriteria: "The Dockerfile has no USER instruction, or its last USER instruction sets root (or UID 0).",
  notVerifiedCriteria: "A Dockerfile matched by the scan's inclusion rules could not be read, so its user configuration was not checked. This is also a text-level heuristic across the whole file, not a per-stage analysis — in a multi-stage build, it assumes the last USER instruction in the file applies to the final (runtime) stage, which holds for the common case but not every possible stage ordering.",
  whyItMatters:
    "Running as root inside a container removes one of the few defense-in-depth layers a compromise has to cross " +
    "— a root process inside the container can write to any bind-mounted host path it can reach, and a kernel or " +
    "runtime vulnerability that allows container breakout hands the attacker root on the host directly instead of " +
    "an unprivileged user.",
  technologyFixes: [
    {
      technology: "generic",
      quickFix: "Add a USER instruction after installing dependencies: USER node (or create and switch to a dedicated non-root user).",
      developerFix: "Create a dedicated user early in the Dockerfile (many base images, like node:20, already ship one — node), switch to it with USER after any step that needs root (installing packages, chown-ing files), and keep every RUN/CMD after that running as that user.",
      codeExample: "FROM node:20\nWORKDIR /app\nCOPY --chown=node:node . .\nRUN npm ci\nUSER node\nCMD [\"node\", \"server.js\"]",
    },
  ],
  longTermHardening: "Add a CI check that fails the build if the final image's default user is root (docker inspect --format='{{.Config.User}}').",
  verificationMethod: "Rescan and confirm the Dockerfile's last USER instruction sets a non-root user.",
  references: ["Docker docs: Dockerfile best practices — USER"],
  complianceMappings: ["SOC 2 CC6.1"],
  releaseImpactBySeverity: { critical: "BLOCK_RELEASE", high: "REVIEW_BEFORE_RELEASE", medium: "FIX_RECOMMENDED", low: "IMPROVEMENT", info: "INFORMATIONAL" },
  enabled: true,
  version: "1.0.0",
};

export const CLOUD_002: Control = {
  controlKey: "CLOUD-002",
  category: "Cloud Security",
  subcategory: "Network exposure",
  name: "No security group rule opens a sensitive port to the world",
  description:
    "A Terraform ingress rule with cidr_blocks = [\"0.0.0.0/0\"] on a sensitive port (SSH, RDP, or a database's " +
    "own port) exposes that service to every host on the internet, not just the application's own network or an " +
    "administrator's known IP range.",
  question: "Are sensitive ports (SSH, RDP, database ports) restricted from 0.0.0.0/0 in security group rules?",
  defaultSeverity: "critical",
  passCriteria: "No Terraform ingress block both allows 0.0.0.0/0 and covers a sensitive port (22, 3389, 3306, 5432, 6379, 27017, 9200, 5601).",
  failCriteria: "A Terraform ingress block allows 0.0.0.0/0 on a sensitive port.",
  notVerifiedCriteria: "A Terraform file matched by the scan's inclusion rules could not be read, so its security group rules were not checked. This is a text-level heuristic scoped to an ingress { ... } block's own text — a rule split across variables/modules the regex can't resolve won't be seen.",
  whyItMatters:
    "SSH/RDP/database ports open to 0.0.0.0/0 are a mainstay of automated internet-wide scanning — these ports " +
    "get probed and brute-forced within minutes of being exposed, not eventually. Access to them should be " +
    "restricted to a known IP range (an office, a VPN, a bastion host), never the entire internet.",
  technologyFixes: [
    {
      technology: "generic",
      quickFix: "Restrict cidr_blocks to the specific IP range that needs access, not 0.0.0.0/0.",
      developerFix: "Replace cidr_blocks = [\"0.0.0.0/0\"] with the actual range that needs this port — a VPN's CIDR, an office IP, or (for a database) the application's own security group via security_groups instead of cidr_blocks entirely.",
      architectureFix: "Put SSH access behind a bastion host or Session Manager (no inbound SSH port open at all), and keep databases in a private subnet with no route to the internet, reachable only from the application's own security group.",
      codeExample: "ingress {\n  from_port   = 22\n  to_port     = 22\n  protocol    = \"tcp\"\n  cidr_blocks = [\"10.0.0.0/16\"] # VPN range, not 0.0.0.0/0\n}",
    },
  ],
  longTermHardening: "Add a policy-as-code check (tfsec, Checkov, OPA) to CI that fails the plan on any 0.0.0.0/0 ingress rule for a sensitive port.",
  verificationMethod: "Rescan and confirm the ingress rule's cidr_blocks no longer include 0.0.0.0/0 for this port.",
  references: ["CIS AWS Foundations Benchmark: Ensure no security groups allow ingress from 0.0.0.0/0 to port 22/3389"],
  complianceMappings: ["SOC 2 CC6.1", "PCI DSS"],
  releaseImpactBySeverity: { critical: "BLOCK_RELEASE", high: "REVIEW_BEFORE_RELEASE", medium: "FIX_RECOMMENDED", low: "IMPROVEMENT", info: "INFORMATIONAL" },
  enabled: true,
  version: "1.0.0",
};

export const CLOUD_003: Control = {
  controlKey: "CLOUD-003",
  category: "Cloud Security",
  subcategory: "Data exposure",
  name: "Cloud storage bucket not publicly readable/writable",
  description:
    "A Terraform S3 bucket resource with acl = \"public-read\" or \"public-read-write\" makes every object in that " +
    "bucket readable (or writable) by anyone on the internet with the bucket's name — no credentials, no " +
    "authentication, just the URL.",
  question: "Is the storage bucket's ACL set to private rather than public-read/public-read-write?",
  defaultSeverity: "critical",
  passCriteria: "No Terraform storage bucket resource sets acl to public-read or public-read-write.",
  failCriteria: "A Terraform storage bucket resource sets acl to public-read or public-read-write.",
  notVerifiedCriteria: "A Terraform file matched by the scan's inclusion rules could not be read, so its bucket ACL configuration was not checked. Bucket access can also be granted via a separate bucket policy resource this regex-level check doesn't parse — a PASS here doesn't rule out public access granted that way.",
  whyItMatters:
    "Publicly-readable storage buckets are one of the most common real-world sources of large-scale data " +
    "breaches — backups, user uploads, database dumps, and log files have all ended up publicly indexed and " +
    "scraped after being placed in a bucket that was public by configuration, not by any attack.",
  technologyFixes: [
    {
      technology: "generic",
      quickFix: "Set acl to \"private\" and enable the account/bucket-level public access block.",
      developerFix: "Set acl = \"private\" on the bucket resource, and add an aws_s3_bucket_public_access_block resource with all four settings (block_public_acls, block_public_policy, ignore_public_acls, restrict_public_buckets) set to true — this blocks public access even if a future policy change would otherwise grant it.",
      architectureFix: "For content that genuinely needs public access (static assets, public downloads), serve it through a CDN (CloudFront) with origin access control, rather than making the bucket itself public — the bucket stays private and only the CDN can read from it.",
      codeExample: "resource \"aws_s3_bucket\" \"data\" {\n  bucket = \"my-data\"\n  acl    = \"private\"\n}\n\nresource \"aws_s3_bucket_public_access_block\" \"data\" {\n  bucket                  = aws_s3_bucket.data.id\n  block_public_acls       = true\n  block_public_policy     = true\n  ignore_public_acls      = true\n  restrict_public_buckets = true\n}",
    },
  ],
  longTermHardening: "Enable AWS Config's s3-bucket-public-read-prohibited and s3-bucket-public-write-prohibited managed rules to catch a bucket made public outside of Terraform (the console, a different IaC tool) too.",
  verificationMethod: "Rescan and confirm the bucket's ACL is now private, and separately confirm (outside Nettle) that no bucket policy grants public access instead.",
  references: ["AWS: Blocking public access to your Amazon S3 storage"],
  complianceMappings: ["SOC 2 CC6.1", "PCI DSS"],
  releaseImpactBySeverity: { critical: "BLOCK_RELEASE", high: "REVIEW_BEFORE_RELEASE", medium: "FIX_RECOMMENDED", low: "IMPROVEMENT", info: "INFORMATIONAL" },
  enabled: true,
  version: "1.0.0",
};

registerControl(CLOUD_001);
registerControl(CLOUD_002);
registerControl(CLOUD_003);
