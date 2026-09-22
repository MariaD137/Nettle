import fs from "fs";
import path from "path";
import type { CheckResult } from "../../types";
import { analyzeAuth, getAuthSeverity, generateAuthRemediation } from "../../authAnalysis";
import { generateCheckId } from "../../threeStateModel";

const RELEVANT_EXTENSIONS = new Set([".js", ".ts", ".jsx", ".tsx"]);

/**
 * AUTH-001, wired to the actual pipeline.
 *
 * This replaces authHeuristic.ts's whole-file, Express-only, single-pattern
 * check (previously the only auth check actually invoked by
 * scanner/index.ts — see the gap report). analyzeAuth/getAuthSeverity/
 * generateAuthRemediation in authAnalysis.ts are per-route, framework-aware,
 * and already unit-tested (test/h6-auth-analysis.test.ts) but were dead
 * code: nothing in the live pipeline called them. This module is the wiring,
 * not new detection logic.
 *
 * Genuine behavior change from the old heuristic: a file whose framework
 * can't be identified now reports NOT_VERIFIED instead of either being
 * silently skipped (the old authHeuristic path: no Express route pattern
 * matched, so it contributed nothing) or forced to PASS/FAIL on a guess.
 */
export function scanAuthControl(files: string[], targetRoot: string): CheckResult[] {
  const results: CheckResult[] = [];
  const relevant = files.filter((f) => RELEVANT_EXTENSIONS.has(path.extname(f)));

  for (const file of relevant) {
    let code: string;
    try {
      code = fs.readFileSync(file, "utf8");
    } catch (err) {
      const relFile = path.relative(targetRoot, file);
      results.push({
        checkId: generateCheckId("Authentication", "AUTH-001:unreadable", relFile),
        status: "NOT_VERIFIED",
        category: "Authentication",
        title: "File could not be read for authentication analysis",
        detail: `${(err as Error).message}`,
        file: relFile,
        confidence: 0,
        detectionMethod: "heuristic",
        controlKey: "AUTH-001",
      });
      continue;
    }

    const relFile = path.relative(targetRoot, file);
    const result = analyzeAuth(code);

    if (result.routesAnalyzed === 0) continue; // nothing to check in this file

    if (result.framework === "unknown") {
      results.push({
        checkId: generateCheckId("Authentication", "AUTH-001:unknown-framework", relFile),
        status: "NOT_VERIFIED",
        category: "Authentication",
        title: `${result.routesAnalyzed} route(s) found but the web framework could not be identified`,
        detail:
          "Nettle recognized route-like patterns in this file but could not identify the web framework in use, " +
          "so route-level authentication detection is not reliable enough to report as PASS or FAIL.",
        file: relFile,
        confidence: 0,
        detectionMethod: "heuristic",
        controlKey: "AUTH-001",
      });
      continue;
    }

    for (const route of result.unprotectedRoutes) {
      results.push({
        checkId: generateCheckId("Authentication", `AUTH-001:fail:${route.method}:${route.path}`, relFile),
        status: "FAIL",
        category: "Authentication",
        title: `${route.method} ${route.path} has no recognized authentication check`,
        detail: `No auth middleware, decorator, or session guard was found in this ${result.framework} route's handler.`,
        severity: getAuthSeverity(route),
        file: relFile,
        confidence: result.confidence,
        detectionMethod: "heuristic",
        remediation: generateAuthRemediation(route, result.framework),
        controlKey: "AUTH-001",
      });
    }

    const protectedCount = result.routesAnalyzed - result.unprotectedRoutes.length;
    if (protectedCount > 0) {
      results.push({
        checkId: generateCheckId("Authentication", "AUTH-001:pass", relFile),
        status: "PASS",
        category: "Authentication",
        title: `${protectedCount} route(s) in this file have a recognized authentication check`,
        file: relFile,
        confidence: result.confidence,
        detectionMethod: "heuristic",
        controlKey: "AUTH-001",
      });
    }
  }

  return results;
}
