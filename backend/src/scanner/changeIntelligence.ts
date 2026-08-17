import type { Finding, FindingCategory, Severity, ScanReport } from "./types";

/**
 * Change intelligence answers "what changed?" at the category level between
 * two scans, on top of the existing new/fixed/unchanged finding diff.
 *
 * Deliberately scoped: it rolls up the real per-finding diff by category —
 * it does NOT diff source files or claim "payment code changed" / "14 files
 * changed", because Nettle doesn't currently retain a per-scan file
 * manifest or have access to a git/PR diff (that requires the GitHub
 * integration work, not yet built). Everything here is computed from real
 * finding data already produced by two actual scans — nothing here is
 * inferred from file paths or fabricated.
 */
export interface CategoryChange {
  category: FindingCategory;
  new: number;
  fixed: number;
  unchanged: number;
  newHighestSeverity: Severity | null;
}

export interface ChangeIntelligence {
  categoryChanges: CategoryChange[];
  sensitiveCategoriesChanged: FindingCategory[];
  highRiskChange: boolean;
  summary: string;
}

// Categories where a new finding is treated as security-sensitive enough to
// call out specifically, mirroring the roadmap's "did auth/db/API surface
// change" framing using the categories the scanner actually produces.
const SENSITIVE_CATEGORIES: FindingCategory[] = [
  "Authentication",
  "Session Management",
  "Database",
  "API Security",
  "Security",
  "Cryptography",
  "AI Disclosure",
  "Infrastructure",
  "CI/CD",
];

const SEVERITY_RANK: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

function findingKey(f: Finding): string {
  return `${f.category}::${f.title}::${f.file}`;
}

function highestSeverity(findings: Finding[]): Severity | null {
  if (findings.length === 0) return null;
  return findings.reduce((worst, f) => (SEVERITY_RANK[f.severity] < SEVERITY_RANK[worst] ? f.severity : worst), findings[0].severity);
}

export function computeChangeIntelligence(older: ScanReport, newer: ScanReport): ChangeIntelligence {
  const olderKeys = new Set(older.findings.map(findingKey));
  const newerKeys = new Set(newer.findings.map(findingKey));

  const fixed = older.findings.filter((f) => !newerKeys.has(findingKey(f)));
  const newFindings = newer.findings.filter((f) => !olderKeys.has(findingKey(f)));
  const unchanged = newer.findings.filter((f) => olderKeys.has(findingKey(f)));

  const categories = new Set<FindingCategory>([
    ...fixed.map((f) => f.category),
    ...newFindings.map((f) => f.category),
    ...unchanged.map((f) => f.category),
  ]);

  const categoryChanges: CategoryChange[] = [...categories].map((category) => {
    const newInCategory = newFindings.filter((f) => f.category === category);
    return {
      category,
      new: newInCategory.length,
      fixed: fixed.filter((f) => f.category === category).length,
      unchanged: unchanged.filter((f) => f.category === category).length,
      newHighestSeverity: highestSeverity(newInCategory),
    };
  });

  const sensitiveCategoriesChanged = categoryChanges
    .filter((c) => SENSITIVE_CATEGORIES.includes(c.category) && c.new > 0)
    .map((c) => c.category);

  const highRiskChange = categoryChanges.some(
    (c) =>
      SENSITIVE_CATEGORIES.includes(c.category) &&
      c.new > 0 &&
      (c.newHighestSeverity === "critical" || c.newHighestSeverity === "high")
  );

  const summary =
    sensitiveCategoriesChanged.length === 0
      ? "No new findings in security-sensitive categories between these two scans."
      : `New findings appeared in: ${sensitiveCategoriesChanged.join(", ")}.${
          highRiskChange ? " At least one is critical or high severity." : ""
        }`;

  return { categoryChanges, sensitiveCategoriesChanged, highRiskChange, summary };
}
