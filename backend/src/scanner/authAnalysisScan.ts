import fs from "fs";
import path from "path";
import type { Finding, Pass } from "./types";
import { analyzeAuth, getAuthSeverity, generateAuthRemediation, generateRoleCheckRemediation, isAdminRoute } from "./authAnalysis";

/**
 * Per-route, framework-aware authentication analysis. Complements
 * authHeuristic.ts (which only checks "is there any auth hint anywhere in
 * this file") with per-route precision: each unprotected route gets its own
 * finding, severity depends on HTTP method, and remediation is tailored to
 * the detected framework.
 *
 * Two admin-route-specific checks layer on top of the generic per-route
 * ones: an unauthenticated route whose path looks administrative is
 * escalated to its own critical finding rather than the generic wording
 * (exposing admin surface to the public outright is worse than an ordinary
 * unprotected route), and an *authenticated* admin route with no role or
 * permission check gets a separate finding — "someone is logged in" is not
 * the same guarantee as "this someone is allowed to do this."
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
    const relFile = path.relative(targetRoot, file);

    for (const route of result.unprotectedRoutes) {
      const adminRoute = isAdminRoute(route.path);
      findings.push({
        severity: adminRoute ? "critical" : getAuthSeverity(route),
        category: "Authentication",
        title: adminRoute
          ? `Public admin route: ${route.method} ${route.path} has no authentication check`
          : `${route.method} ${route.path} has no detected authentication check`,
        detail: adminRoute
          ? `This route's path suggests administrative functionality, and per-route analysis (framework: ${result.framework}) found no auth pattern protecting it — meaning anyone, unauthenticated, may be able to reach it.${
              route.evidence ? ` Nearby code: "${route.evidence.trim()}"` : ""
            }`
          : `Per-route analysis (framework: ${result.framework}) found no auth pattern for this specific handler.${
              route.evidence ? ` Nearby code: "${route.evidence.trim()}"` : ""
            }`,
        file: relFile,
        line: null,
        remediation: generateAuthRemediation(route, result.framework),
      });
    }

    for (const route of result.allRoutes) {
      if (!route.isProtected || !isAdminRoute(route.path) || route.hasRoleCheck) continue;
      findings.push({
        severity: "high",
        category: "Authentication",
        title: `Admin route ${route.method} ${route.path} is authenticated but has no role or permission check`,
        detail: `This route requires login (framework: ${result.framework}), but nothing in the handler distinguishes an ordinary logged-in user from one actually authorized for administrative actions. Any authenticated account may be able to reach it.${
          route.evidence ? ` Nearby code: "${route.evidence.trim()}"` : ""
        }`,
        file: relFile,
        line: null,
        remediation: generateRoleCheckRemediation(route, result.framework),
      });
    }
  }

  const passed: Pass[] =
    findings.length === 0 && anyRoutesAnalyzed
      ? [{ category: "Authentication", title: "Per-route analysis found authentication and role checks on all detected routes" }]
      : [];

  return { findings, passed };
}
