import fs from "fs";
import path from "path";
import type { CheckResult } from "./types";
import { generateCheckId } from "./threeStateModel";

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
  {
    name: "Google Cloud API key",
    regex: /AIza[0-9A-Za-z_-]{35}/g,
    remediation: "Delete the key in the Google Cloud Console, create a new one with domain/IP restrictions, and store it in an environment variable.",
  },
  {
    name: "Google OAuth client secret",
    regex: /GOCSPX-[0-9A-Za-z_-]{28}/g,
    remediation: "Rotate the client secret in the Google Cloud Console and store it in an environment variable.",
  },
  {
    name: "Firebase API key",
    regex: /FIREBASE[_-]?API[_-]?KEY\s*[:=]\s*["'][^"']+["']/gi,
    remediation: "Restrict the Firebase API key in the Google Cloud Console and store it in an environment variable.",
  },
  {
    name: "SendGrid API key",
    regex: /SG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}/g,
    remediation: "Revoke the key in the SendGrid dashboard and store the replacement in an environment variable.",
  },
  {
    name: "Twilio auth token",
    regex: /TWILIO[_-]?AUTH[_-]?TOKEN\s*[:=]\s*["'][0-9a-f]{32}["']/gi,
    remediation: "Rotate the auth token in the Twilio console and store it as an environment variable.",
  },
  {
    name: "Mailgun API key",
    regex: /key-[0-9a-zA-Z]{32}/g,
    remediation: "Rotate the Mailgun API key and store it as an environment variable.",
  },
  {
    name: "SMTP password",
    regex: /SMTP[_-]?PASS(WORD)?\s*[:=]\s*["'][^"']{4,}["']/gi,
    remediation: "Move the SMTP password to an environment variable. Consider using an API-based email service instead of raw SMTP.",
  },
  {
    name: "Database connection string with credentials",
    regex: /(mongodb(\+srv)?|postgres(ql)?|mysql|redis):\/\/[^:]+:[^@]+@[^"'\s]+/gi,
    remediation: "Move the database connection string to an environment variable (DATABASE_URL) and rotate the embedded credentials.",
  },
  {
    name: "Heroku API key",
    regex: /HEROKU[_-]?API[_-]?KEY\s*[:=]\s*["'][0-9a-f-]{36}["']/gi,
    remediation: "Regenerate the key via heroku authorizations and store it as an environment variable.",
  },
  {
    name: "Azure subscription key",
    regex: /(AZURE[_-]?(SUBSCRIPTION|API)[_-]?KEY)\s*[:=]\s*["'][0-9a-f]{32}["']/gi,
    remediation: "Rotate the Azure key in the Azure Portal and store it as an environment variable.",
  },
  {
    name: "Stripe publishable key in server code",
    regex: /pk_live_[0-9a-zA-Z]{10,}/g,
    remediation: "Publishable keys are safe on the frontend but should not be hardcoded in server-side code. Use an environment variable.",
  },
  {
    name: "PayPal client secret",
    regex: /PAYPAL[_-]?(CLIENT[_-]?)?SECRET\s*[:=]\s*["'][^"']{10,}["']/gi,
    remediation: "Rotate the PayPal client secret and store it as an environment variable.",
  },
  {
    name: "OpenAI API key",
    regex: /sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}/g,
    remediation: "Revoke the key at platform.openai.com/api-keys and store the replacement in an environment variable (OPENAI_API_KEY).",
  },
  {
    name: "Anthropic API key",
    regex: /sk-ant-[A-Za-z0-9_-]{20,}/g,
    remediation: "Revoke the key in the Anthropic Console and store the replacement in an environment variable (ANTHROPIC_API_KEY).",
  },
  {
    name: "Generic API key assignment",
    regex: /API[_-]?KEY\s*[:=]\s*["'][A-Za-z0-9_\-/.+=]{20,}["']/gi,
    remediation: "Move the API key to an environment variable and load it at runtime.",
  },
  {
    name: "Discord bot token",
    regex: /[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27,}/g,
    remediation: "Regenerate the bot token in the Discord Developer Portal and store it as an environment variable.",
  },
  {
    name: "npm access token",
    regex: /npm_[0-9a-zA-Z]{36}/g,
    remediation: "Revoke the token with `npm token revoke` and create a new one stored in CI secrets.",
  },
];

interface SecretMatch {
  pattern: SecretPattern;
  count: number;
  firstLine: number | null;
}

/** Shared detection core: every pattern match against one file's text, with no I/O. */
function detectSecrets(text: string): SecretMatch[] {
  const lines = text.split("\n");
  const results: SecretMatch[] = [];

  for (const pattern of SECRET_PATTERNS) {
    pattern.regex.lastIndex = 0;
    const matches = text.match(pattern.regex);
    if (!matches) continue;

    let firstLine: number | null = null;
    for (let i = 0; i < lines.length; i++) {
      const fresh = new RegExp(pattern.regex.source, pattern.regex.flags);
      if (fresh.test(lines[i])) { firstLine = i + 1; break; }
    }
    results.push({ pattern, count: matches.length, firstLine });
  }

  return results;
}

/**
 * SECRET-001, wired to the control library. This is the only exported scan
 * function in this module now — the legacy scanSecrets(files, targetRoot)
 * (same detectSecrets core, but returning Finding/Pass with no
 * NOT_VERIFIED path for an unreadable file, so one unreadable file would
 * throw and abort the entire scan rather than just this check) was never
 * called from scanner/index.ts's legacyResults array and had no test
 * coverage of its own — it was already fully superseded by this function
 * before this round, just left in place as dead code. Removed rather than
 * migrated.
 */
export function scanSecretsControl(files: string[], targetRoot: string): CheckResult[] {
  const results: CheckResult[] = [];
  let anyFailure = false;
  let anyFileRead = false;

  for (const file of files) {
    const relFile = path.relative(targetRoot, file);
    let text: string;
    try {
      text = fs.readFileSync(file, "utf8");
    } catch (err) {
      results.push({
        checkId: generateCheckId("Security", "SECRET-001:unreadable", relFile),
        status: "NOT_VERIFIED",
        category: "Security",
        title: "File could not be read for secret detection",
        detail: `${(err as Error).message}`,
        file: relFile,
        confidence: 0,
        detectionMethod: "regex",
        controlKey: "SECRET-001",
      });
      continue;
    }

    anyFileRead = true;
    for (const match of detectSecrets(text)) {
      anyFailure = true;
      results.push({
        checkId: generateCheckId("Security", `SECRET-001:${match.pattern.name}`, relFile),
        status: "FAIL",
        category: "Security",
        title: `${match.pattern.name} found in source`,
        detail: `Matched ${match.count} time(s). Secrets committed to source are readable by anyone with repo access and get indexed by any tool/AI assistant that reads the codebase.`,
        severity: "critical",
        file: relFile,
        line: match.firstLine,
        confidence: 95,
        detectionMethod: "regex",
        remediation: match.pattern.remediation,
        controlKey: "SECRET-001",
      });
    }
  }

  // A PASS asserts "checked, and found nothing" — only justified if at
  // least one file was actually read. If every file was unreadable, there's
  // nothing to report but the NOT_VERIFIED entries already pushed above.
  if (!anyFailure && anyFileRead) {
    results.push({
      checkId: generateCheckId("Security", "SECRET-001:pass"),
      status: "PASS",
      category: "Security",
      title: "No hardcoded secrets detected in scanned files",
      confidence: 95,
      detectionMethod: "regex",
      controlKey: "SECRET-001",
    });
  }

  return results;
}
