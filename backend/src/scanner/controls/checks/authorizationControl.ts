import fs from "fs";
import path from "path";
import type { CheckResult } from "../../types";
import { generateCheckId } from "../../threeStateModel";

// A route registration whose own path literal contains an admin/internal-
// style segment — deliberately narrow (a real admin path, not any path that
// happens to contain the substring "administrator" as part of a word) so
// this doesn't fire on unrelated routes like /administration-fee.
const ADMIN_ROUTE = /\.(get|post|put|patch|delete)\s*\(\s*["'`](\/[^"'`]*\/(admin|internal|ops)(\/[^"'`]*)?|\/(admin|internal|ops)(\/[^"'`]*)?)["'`]/gi;

// Evidence that SOME authorization check — as opposed to merely an
// authentication check — is present. Deliberately broad across common
// naming conventions (requireRole, hasPermission, isAdmin, a role
// comparison, well-known RBAC library calls) since this is heuristic
// evidence-of-presence, not a single framework's exact API.
const AUTHORIZATION_EVIDENCE =
  /\b(requireRole|requireAdmin|requirePermission|hasRole|hasPermission|checkPermission|isAdmin|can\s*\(|authorize\s*\(|\.can\s*\(|@Roles\s*\(|policy\s*\(|AccessControl|casl|rbac)\b/i;

// AUTH-001-style evidence that the app has authentication at all (session,
// JWT, login) — used only to decide whether "no admin routes found" should
// be NOT_VERIFIED (there IS authentication here, so authorization is a real
// question this scan just can't answer) versus no result at all (nothing in
// this file looks like a backend with routes/auth in the first place).
const AUTHENTICATION_EVIDENCE = /\b(req\.user|passport|jsonwebtoken|jwt\.verify|express-session|req\.session\.userId|requireAuth|isAuthenticated)\b/i;

/**
 * AUTHZ-001, wired to the control library. New category (Authorization),
 * distinct from every AUTH-* control (authentication mechanics only —
 * session/JWT/cookie handling) and from MT-002 (object-level/resource-
 * ownership authorization, not route-level/role-based). Confirmed via grep
 * before writing this that no existing control checks whether a
 * privileged/admin route enforces a role or permission check.
 *
 * Deliberately conservative, matching this library's own three-state
 * discipline: a route matching ADMIN_ROUTE with no AUTHORIZATION_EVIDENCE
 * anywhere in the same file is a FAIL, but this is a same-file, not same-
 * function-scope, heuristic — a large file with the check in a different
 * handler could produce a false FAIL. That imprecision is disclosed
 * honestly in the control's own notVerifiedCriteria/failCriteria rather
 * than hidden. When no admin-style route is found at all, this never
 * silently returns nothing the way MT-001/002 do for their own inapplicable
 * case — if the app shows authentication evidence, it gets an explicit
 * NOT_VERIFIED specifically to counter the "authentication implies
 * authorization" assumption; only an app with neither pattern (e.g. a
 * static frontend with no backend routes at all) gets no result.
 */
export function scanAuthorizationControl(files: string[], targetRoot: string): CheckResult[] {
  const jsFiles = files.filter((f) => /\.(js|ts|jsx|tsx)$/.test(f));

  const results: CheckResult[] = [];
  let anyAdminRouteFound = false;
  let anyAuthenticationEvidence = false;
  let anyUnreadable = false;

  for (const file of jsFiles) {
    const rel = path.relative(targetRoot, file);
    let text: string;
    try {
      text = fs.readFileSync(file, "utf8");
    } catch {
      anyUnreadable = true;
      continue;
    }

    if (AUTHENTICATION_EVIDENCE.test(text)) anyAuthenticationEvidence = true;

    ADMIN_ROUTE.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = ADMIN_ROUTE.exec(text))) {
      anyAdminRouteFound = true;
      const routePath = match[2] ?? match[5] ?? match[1];
      const hasAuthzEvidence = AUTHORIZATION_EVIDENCE.test(text);

      if (hasAuthzEvidence) {
        results.push({
          checkId: generateCheckId("Authorization", "AUTHZ-001:pass", `${rel}:${match.index}`),
          status: "PASS",
          category: "Authorization",
          title: `Admin/privileged route shows an authorization check: ${routePath}`,
          severity: "critical",
          file: rel,
          confidence: 60,
          detectionMethod: "regex",
          controlKey: "AUTHZ-001",
        });
      } else {
        results.push({
          checkId: generateCheckId("Authorization", "AUTHZ-001:fail", `${rel}:${match.index}`),
          status: "FAIL",
          category: "Authorization",
          title: `Admin/privileged route with no visible authorization check: ${routePath}`,
          detail:
            "This route's path looks admin/internal-only, but no role, permission, or authorization-middleware evidence " +
            "(requireRole, hasPermission, isAdmin, an RBAC library, etc.) was found anywhere in this file — only " +
            "authentication (a valid session) may be required, which any logged-in user satisfies, not just admins.",
          severity: "critical",
          file: rel,
          confidence: 60,
          detectionMethod: "regex",
          remediation: "Add an explicit role/permission check (e.g. requireRole('admin')) to this route, separate from any authentication check.",
          controlKey: "AUTHZ-001",
        });
      }
    }
  }

  if (!anyAdminRouteFound) {
    if (anyUnreadable) {
      results.push(notVerified("Some files could not be read, so admin/privileged routes could not be located."));
    } else if (anyAuthenticationEvidence) {
      // The point this branch exists to make, explicitly: authentication
      // evidence is not treated as authorization evidence, even though no
      // admin-style route was found to flag as a concrete FAIL.
      results.push(
        notVerified(
          "This scan found authentication (login/session/JWT) but no admin/internal-style route to check for a " +
            "role or permission requirement. Authentication alone is not evidence that authorization is enforced " +
            "anywhere in this application — confirm privileged routes (if any exist) check the caller's role, not " +
            "just that they're logged in."
        )
      );
    }
    // Neither admin routes nor authentication evidence at all: genuinely
    // inapplicable (e.g. a static frontend with no backend routes), so no
    // result — matching MT-001/002's own "no unearned result" precedent.
  }

  return results;
}

function notVerified(detail: string): CheckResult {
  return {
    checkId: generateCheckId("Authorization", "AUTHZ-001:not-verified"),
    status: "NOT_VERIFIED",
    category: "Authorization",
    title: "Route-level authorization could not be confirmed",
    detail,
    confidence: 0,
    detectionMethod: "regex",
    controlKey: "AUTHZ-001",
  };
}
