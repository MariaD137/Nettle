import fs from "fs";
import path from "path";
import type { Finding, Pass } from "./types";

interface SecretPattern {
  name: string;
  regex: RegExp;
  remediation: string;
}

const SECRET_PATTERNS: SecretPattern[] = [
  {
    name: "AWS Access Key ID",
    regex: /AKIA[0-9A-Z]{16}/g,
    remediation: "Remove the key from source code, rotate it in the AWS IAM console, and use environment variables or AWS Secrets Manager instead.",
  },
  {
    name: "AWS Secret Access Key",
    regex: /(aws_secret_access_key|awsSecretAccessKey)\s*[:=]\s*["'][A-Za-z0-9/+=]{40}["']/gi,
    remediation: "Remove the secret from source code, rotate the key pair in AWS IAM, and load it from an environment variable at runtime.",
  },
  {
    name: "Stripe live secret key",
    regex: /sk_live_[0-9a-zA-Z]{10,}/g,
    remediation: "Remove the key from source code, roll it in the Stripe dashboard, and set it as an environment variable (e.g. STRIPE_SECRET_KEY).",
  },
  {
    name: "GitHub personal access token",
    regex: /ghp_[0-9a-zA-Z]{30,}/g,
    remediation: "Delete the token in GitHub Settings > Developer settings > Personal access tokens and create a new one stored securely.",
  },
  {
    name: "Slack token",
    regex: /xox[baprs]-[0-9a-zA-Z-]{10,}/g,
    remediation: "Revoke the token in your Slack app settings and store the replacement in an environment variable.",
  },
  {
    name: "Hardcoded signing/JWT secret",
    regex: /(jwt[_-]?secret|signing[_-]?key|secret[_-]?key)\s*=\s*["'][^"']{6,}["']/gi,
    remediation: "Move the secret to an environment variable (e.g. JWT_SECRET) and load it at runtime with process.env.JWT_SECRET.",
  },
  {
    name: "Private key block",
    regex: /-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----/g,
    remediation: "Remove the private key from source code. Store it in a secrets manager or mount it from an encrypted volume at deploy time.",
  },
];

export function scanSecrets(files: string[], targetRoot: string): { findings: Finding[]; passed: Pass[] } {
  const findings: Finding[] = [];
  let secretsFound = 0;

  for (const file of files) {
    const text = fs.readFileSync(file, "utf8");
    for (const pattern of SECRET_PATTERNS) {
      const matches = text.match(pattern.regex);
      if (matches) {
        secretsFound += matches.length;
        findings.push({
          severity: "critical",
          category: "Security",
          title: `${pattern.name} found in source`,
          detail: `Matched ${matches.length} time(s). Secrets committed to source are readable by anyone with repo access and get indexed by any tool/AI assistant that reads the codebase.`,
          file: path.relative(targetRoot, file),
          remediation: pattern.remediation,
        });
      }
    }
  }

  const passed: Pass[] =
    secretsFound === 0 ? [{ category: "Security", title: "No hardcoded secrets detected in scanned files" }] : [];

  return { findings, passed };
}
