import type { Finding, AttackChain, Severity } from "./types";

/**
 * Attack-chain correlation groups already-detected findings that share a
 * file into a higher-level "this could plausibly connect" narrative,
 * instead of leaving a reader to notice the connection themselves.
 *
 * This is deliberately conservative: a chain only fires when an entry-point
 * finding and a target finding land in the *same file*, which is the only
 * signal the current scanner can support without real data-flow analysis.
 * That means false negatives (a real chain spanning multiple files won't be
 * caught) are expected and preferable to false positives. Every impact
 * description uses hedged language ("may be able to", "potential") — this
 * is correlation of static findings, not a confirmed, traced exploit.
 */
interface ChainRule {
  title: string;
  severity: Severity;
  entryCategory: string;
  entryKeywords: string[];
  targetCategory: string;
  targetKeywords: string[];
  entryPointLabel: string;
  componentLabel: string;
  impact: string;
  recommendation: string;
}

const CHAIN_RULES: ChainRule[] = [
  {
    title: "Unauthenticated route reaches a SQL query built from unsanitized input",
    severity: "critical",
    entryCategory: "Authentication",
    entryKeywords: ["no detected authentication", "no authentication check"],
    targetCategory: "Database",
    targetKeywords: ["string concatenation", "interpolation"],
    entryPointLabel: "Unauthenticated route",
    componentLabel: "SQL query without parameterization",
    impact:
      "This file contains both a route with no detected authentication check and a SQL query built by concatenating or interpolating a variable. If the route's parameters flow into that query, an unauthenticated caller may be able to manipulate the query — this is the shape of a SQL injection path, not a confirmed one.",
    recommendation:
      "Add authentication/authorization to the route, and independently parameterize the query so it stays safe even if the route is exposed elsewhere later.",
  },
  {
    title: "Unauthenticated route co-located with a hardcoded credential",
    severity: "high",
    entryCategory: "Authentication",
    entryKeywords: ["no detected authentication", "no authentication check"],
    targetCategory: "Security",
    targetKeywords: ["found in source"],
    entryPointLabel: "Unauthenticated route",
    componentLabel: "Hardcoded credential",
    impact:
      "A hardcoded secret sits in the same file as a route with no detected authentication check. If that route can be manipulated into reflecting file contents, stack traces, or debug output, the secret may become reachable without any authorization barrier.",
    recommendation:
      "Remove and rotate the hardcoded credential (see its own finding for specifics), and add authentication to the route independently — each is a real fix on its own regardless of the other.",
  },
  {
    title: "Unauthenticated route reaches unsafe deserialization",
    severity: "critical",
    entryCategory: "Authentication",
    entryKeywords: ["no detected authentication", "no authentication check"],
    targetCategory: "Security",
    targetKeywords: ["deserialization"],
    entryPointLabel: "Unauthenticated route",
    componentLabel: "Unsafe deserialization",
    impact:
      "An unauthenticated route and an unsafe-deserialization pattern (e.g. unvalidated JSON/YAML parsing) appear in the same file. Untrusted deserialization reachable without authentication is a common path toward remote code execution or object-injection attacks in the affected ecosystem.",
    recommendation:
      "Add authentication to the route, and replace the unsafe deserialization call with a safe parser (e.g. a schema-validated JSON parse, or `yaml.safeLoad` instead of `yaml.load`).",
  },
  {
    title: "Unauthenticated route reaches a shell/process-execution call",
    severity: "critical",
    entryCategory: "Authentication",
    entryKeywords: ["no detected authentication", "no authentication check"],
    targetCategory: "Security",
    targetKeywords: ["command injection", "exec", "child_process"],
    entryPointLabel: "Unauthenticated route",
    componentLabel: "Shell/process execution",
    impact:
      "This file contains both a route with no detected authentication check and code that executes a shell command or child process. If request data reaches that call, an unauthenticated caller may be able to influence what gets executed on the server.",
    recommendation:
      "Add authentication to the route, and avoid building shell commands from request input — use an argument array (not a shell string) or an allowlist of permitted operations.",
  },
];

function matches(f: Finding, category: string, keywords: string[]): boolean {
  if (f.category !== category) return false;
  const haystack = `${f.title} ${f.detail}`.toLowerCase();
  return keywords.some((k) => haystack.includes(k));
}

export function correlateAttackChains(findings: Finding[]): AttackChain[] {
  const chains: AttackChain[] = [];

  for (const rule of CHAIN_RULES) {
    const entryFindings = findings.filter((f) => f.file && matches(f, rule.entryCategory, rule.entryKeywords));
    const targetFindings = findings.filter((f) => f.file && matches(f, rule.targetCategory, rule.targetKeywords));
    if (entryFindings.length === 0 || targetFindings.length === 0) continue;

    const byFile = new Map<string, { entry: Finding[]; target: Finding[] }>();
    for (const f of entryFindings) {
      const g = byFile.get(f.file as string) ?? { entry: [], target: [] };
      g.entry.push(f);
      byFile.set(f.file as string, g);
    }
    for (const f of targetFindings) {
      const g = byFile.get(f.file as string);
      if (g) g.target.push(f);
    }

    for (const [file, group] of byFile) {
      if (group.entry.length === 0 || group.target.length === 0) continue;
      chains.push({
        severity: rule.severity,
        title: rule.title,
        entryPoint: `${rule.entryPointLabel} — ${file}`,
        component: rule.componentLabel,
        impact: rule.impact,
        recommendation: rule.recommendation,
        findings: [...group.entry, ...group.target],
      });
    }
  }

  return chains;
}
