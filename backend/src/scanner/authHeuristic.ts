import fs from "fs";
import path from "path";
import type { Finding, Pass } from "./types";

const AUTH_HINTS = /jwt\.verify|requireAuth|isAuthenticated|authMiddleware|passport\./;
const ROUTE_PATTERN = /app\.(get|post|put|delete|patch)\s*\(\s*["'`][^"'`]+["'`]/g;

// Deliberately simple: flags files that define routes but show no reference
// to an auth check anywhere in the same file. False positives are expected
// (auth enforced via a shared middleware file, for instance) — this is a
// prompt to double check, not a definitive verdict.
export function scanAuthHeuristic(files: string[], targetRoot: string): { findings: Finding[]; passed: Pass[] } {
  const findings: Finding[] = [];
  const relevant = files.filter((f) => f.endsWith(".js") || f.endsWith(".ts"));

  for (const file of relevant) {
    const text = fs.readFileSync(file, "utf8");
    const routes = text.match(ROUTE_PATTERN);
    if (routes && routes.length && !AUTH_HINTS.test(text)) {
      findings.push({
        severity: "caution",
        category: "Security",
        title: `${routes.length} route(s) in this file show no authentication check`,
        detail: "No reference to a JWT verification, auth middleware, or passport call was found in this file. If any of these routes return user-specific data, confirm access control is enforced elsewhere.",
        file: path.relative(targetRoot, file),
      });
    }
  }

  const passed: Pass[] =
    findings.length === 0 && relevant.length > 0
      ? [{ category: "Security", title: "Route handlers show references to an authentication check" }]
      : [];

  return { findings, passed };
}
