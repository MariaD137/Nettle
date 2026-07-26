import { execFileSync } from "child_process";
import path from "path";
import type { Finding, Pass } from "./types";

const RULES_PATH = path.join(__dirname, "semgrep-rules", "nettle-js-rules.yaml");

interface SemgrepResult {
  check_id: string;
  path: string;
  start: { line: number };
  extra: { severity: "ERROR" | "WARNING" | "INFO"; message: string };
}

interface SemgrepOutput {
  results: SemgrepResult[];
  errors: unknown[];
}

function severityFor(semgrepSeverity: SemgrepResult["extra"]["severity"]): Finding["severity"] {
  return semgrepSeverity === "ERROR" ? "critical" : "caution";
}

function titleFor(checkId: string): string {
  // check_id comes through as a dotted path like
  // "src.scanner.semgrep-rules.nettle-sql-string-concat" — the last segment
  // is the actual rule id we wrote.
  const ruleId = checkId.split(".").pop() ?? checkId;
  return ruleId
    .replace(/^nettle-/, "")
    .split("-")
    .join(" ")
    .replace(/^\w/, (c) => c.toUpperCase());
}

/**
 * Wraps Semgrep (real, industry-standard static analysis) instead of hand-
 * rolling more regex patterns. Runs entirely offline against our own bundled
 * ruleset — no network call to Semgrep's registry, which matters twice over:
 * it works in this sandbox, and it works in production, where the API
 * deliberately has no internet egress at all.
 *
 * If Semgrep isn't installed or fails to run, this degrades to a caution
 * finding rather than crashing the whole scan — one check failing shouldn't
 * 500 the entire request.
 */
export function scanWithSemgrep(targetRoot: string): { findings: Finding[]; passed: Pass[] } {
  let output: SemgrepOutput;
  try {
    const raw = execFileSync(
      "semgrep",
      [
        "--config",
        RULES_PATH,
        "--no-git-ignore",
        "--x-ignore-semgrepignore-files",
        // The production API has no internet egress at all (by design — see
        // infra/README.md). Semgrep's default version-check phones home on
        // every run and blocks for ~90s waiting on that call before giving
        // up; --metrics=off avoids a second, separate telemetry call. Without
        // both flags this doesn't just fail, it silently adds ~90s to every
        // single scan request first.
        "--disable-version-check",
        "--metrics=off",
        "--json",
        "--quiet",
        targetRoot,
      ],
      { encoding: "utf8", timeout: 30_000, maxBuffer: 20 * 1024 * 1024 }
    );
    output = JSON.parse(raw);
  } catch (err) {
    return {
      findings: [
        {
          severity: "caution",
          category: "Security",
          title: "Semgrep static analysis did not run",
          detail: `Couldn't run the Semgrep-based checks (secrets/injection/TLS/CORS patterns) for this scan: ${(err as Error).message}. The rest of the readiness report is unaffected.`,
          file: null,
        },
      ],
      passed: [],
    };
  }

  if (output.results.length === 0) {
    return { findings: [], passed: [{ category: "Security", title: "No Semgrep findings (secrets, injection, TLS, CORS patterns)" }] };
  }

  const findings: Finding[] = output.results.map((r) => ({
    severity: severityFor(r.extra.severity),
    category: "Security",
    title: titleFor(r.check_id),
    detail: r.extra.message.trim(),
    file: `${path.relative(targetRoot, r.path)}:${r.start.line}`,
  }));

  return { findings, passed: [] };
}
