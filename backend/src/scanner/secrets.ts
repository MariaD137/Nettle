import fs from "fs";
import path from "path";
import type { Finding, Pass } from "./types";

interface SecretPattern {
  name: string;
  regex: RegExp;
}

// Patterns are intentionally conservative (favor missing an obscure one over
// flooding false positives) — this list grows as real scans surface gaps.
const SECRET_PATTERNS: SecretPattern[] = [
  { name: "AWS Access Key ID", regex: /AKIA[0-9A-Z]{16}/g },
  { name: "AWS Secret Access Key", regex: /(aws_secret_access_key|awsSecretAccessKey)\s*[:=]\s*["'][A-Za-z0-9/+=]{40}["']/gi },
  { name: "Stripe live secret key", regex: /sk_live_[0-9a-zA-Z]{10,}/g },
  { name: "GitHub personal access token", regex: /ghp_[0-9a-zA-Z]{30,}/g },
  { name: "Slack token", regex: /xox[baprs]-[0-9a-zA-Z-]{10,}/g },
  { name: "Hardcoded signing/JWT secret", regex: /(jwt[_-]?secret|signing[_-]?key|secret[_-]?key)\s*=\s*["'][^"']{6,}["']/gi },
  { name: "Private key block", regex: /-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----/g },
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
        });
      }
    }
  }

  const passed: Pass[] =
    secretsFound === 0 ? [{ category: "Security", title: "No hardcoded secrets detected in scanned files" }] : [];

  return { findings, passed };
}
