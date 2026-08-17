import fs from "fs";
import path from "path";
import type { Finding, Pass } from "./types";
import { analyzeAuth, getAuthSeverity, generateAuthRemediation } from "./authAnalysis";

/**
 * Per-route, framework-aware authentication analysis. Complements
 * authHeuristic.ts (which only checks "is there any auth hint anywhere in
 * this file") with per-route precision: each unprotected route gets its own
 * finding, severity depends on HTTP method, and remediation is tailored to
 * the detected framework.
 */
export function scanAuthAnalysis(files: string[], targetRoot: string): { findings: Finding[]; passed: Pass[] } {
  const findings: Finding[] = [];
  let anyRoutesAnalyzed = false;

  const relevant = files.filter((f) => f.endsWith(".js") || f.endsWith(".ts"));

  for (const file of relevant) {
    const code = fs.readFileSync(file, "utf8");
    const result = analyzeAuth(code);
    if (result.routesAnalyzed === 0) continue;
    anyRoutesAnalyzed = true;

    for (const route of result.unprotectedRoutes) {
      findings.push({
        severity: getAuthSeverity(route),
        category: "Authentication",
        title: `${route.method} ${route.path} has no detected authentication check`,
        detail: `Per-route analysis (framework: ${result.framework}) found no auth pattern for this specific handler.${
          route.evidence ? ` Nearby code: "${route.evidence.trim()}"` : ""
        }`,
        file: path.relative(targetRoot, file),
        line: null,
        remediation: generateAuthRemediation(route, result.framework),
      });
    }
  }

  const passed: Pass[] =
    findings.length === 0 && anyRoutesAnalyzed
      ? [{ category: "Authentication", title: "Per-route analysis found authentication checks on all detected routes" }]
      : [];

  return { findings, passed };
}
