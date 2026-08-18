/**
 * Auth analysis: framework-aware, per-route authentication detection.
 * Identifies routes lacking proper authentication checks.
 */

export type FrameworkType = "express" | "django" | "flask" | "fastapi" | "rails" | "nextjs" | "nuxt" | "unknown";

export interface RouteInfo {
  path: string;
  method: "GET" | "POST" | "PUT" | "DELETE" | "PATCH" | "ALL";
  isProtected: boolean;
  detectionMethod: string;
  evidence?: string;
  // Whether a role/permission check (as opposed to plain "is someone logged
  // in") was found near the handler. Optional and only meaningful when
  // isProtected is true — an unauthenticated route has no identity to check
  // a role against in the first place. Undefined in any RouteInfo built
  // before this field existed (e.g. hand-built ones in older tests).
  hasRoleCheck?: boolean;
}

export interface AuthCheckResult {
  routesAnalyzed: number;
  unprotectedRoutes: RouteInfo[];
  // Every route this pass found, protected or not — unprotectedRoutes above
  // is a filtered view of this. Needed separately because the missing-
  // role-check check only makes sense against *protected* routes.
  allRoutes: RouteInfo[];
  framework: FrameworkType;
  confidence: number;
}

/**
 * Express.js authentication patterns.
 */
const EXPRESS_AUTH_PATTERNS = [
  /verify[_-]?jwt/i,
  /auth[_-]?middleware/i,
  /requireAuth/i,
  /passport\.(authenticate|session)/i,
  /jwt\.verify/i,
  /app\.use\(.*auth/i,
  /router\.use\(.*auth/i,
  /next\(\s*\)/i, // Middleware passing to next
];

/**
 * Django authentication patterns.
 */
const DJANGO_AUTH_PATTERNS = [
  /@login_required/i,
  /@permission_required/i,
  /LoginRequiredMixin/i,
  /from django\.contrib\.auth\.decorators import login_required/i,
  /request\.user\.is_authenticated/i,
  /check_permissions/i,
];

/**
 * Flask authentication patterns.
 */
const FLASK_AUTH_PATTERNS = [
  /@login_required/i,
  /@require_auth/i,
  /auth\.login_required/i,
  /current_user/i,
  /abort\(401\)/i,
];

/**
 * FastAPI authentication patterns.
 */
const FASTAPI_AUTH_PATTERNS = [
  /Depends\(.*auth/i,
  /oauth2_scheme/i,
  /jwt\.decode/i,
  /HTTPBearer/i,
  /HTTPAuthenticationCredentials/i,
];

/**
 * Rails authentication patterns.
 */
const RAILS_AUTH_PATTERNS = [
  /before_action :authenticate_user/i,
  /require_login/i,
  /authorize_user/i,
  /:authenticate_user/i,
];

/**
 * Next.js middleware auth patterns.
 */
const NEXTJS_AUTH_PATTERNS = [
  /middleware\.(ts|js)/i,
  /getSession/i,
  /useSession/i,
  /getServerSession/i,
  /redirectToLogin/i,
];

/**
 * Role/permission check patterns, per framework — deliberately distinct
 * from the *_AUTH_PATTERNS above. Those answer "is someone logged in";
 * these answer "is this specific someone allowed to do this specific
 * thing." A route can pass the first check and still fail the second
 * (any logged-in user reaching an admin action), which is a different,
 * commonly-missed vulnerability class (broken access control / vertical
 * privilege escalation) from missing authentication entirely.
 */
const EXPRESS_ROLE_PATTERNS = [
  /req\.user\.role/i,
  /requireRole/i,
  /checkRole/i,
  /hasRole/i,
  /hasPermission/i,
  /isAdmin\b/i,
  /authorize\s*\(/i,
];
const DJANGO_ROLE_PATTERNS = [
  /@permission_required/i,
  /user_passes_test/i,
  /is_staff/i,
  /is_superuser/i,
  /has_perm\s*\(/i,
];
const FLASK_ROLE_PATTERNS = [
  /@roles_required/i,
  /@admin_required/i,
  /current_user\.is_admin/i,
  /has_role\s*\(/i,
];
const FASTAPI_ROLE_PATTERNS = [
  /Depends\(.*(role|permission|admin)/i,
  /require_role/i,
  /require_permission/i,
];
const RAILS_ROLE_PATTERNS = [
  /before_action :require_admin/i,
  /:authorize\b/i,
  /can\?\s*\(/i,
  /\.admin\?/i,
];
const NEXTJS_ROLE_PATTERNS = [
  /role\s*===/i,
  /session\.user\.role/i,
  /isAdmin\b/i,
];

/**
 * A route whose path (or, for frameworks where extraction only yields a
 * function name, its name) marks it as administrative surface — the one
 * kind of route where "authenticated but not role-checked" and "not even
 * authenticated" both deserve a sharper, more specific finding than the
 * generic per-route ones above.
 */
const ADMIN_PATH_PATTERN = /(^|\/)(admin|administrator|internal|management|superuser|backoffice)(\/|$|_)/i;
export function isAdminRoute(routePath: string): boolean {
  return ADMIN_PATH_PATTERN.test(routePath);
}

function hasRoleCheck(code: string, framework: FrameworkType): boolean {
  const patterns: Record<FrameworkType, RegExp[]> = {
    express: EXPRESS_ROLE_PATTERNS,
    django: DJANGO_ROLE_PATTERNS,
    flask: FLASK_ROLE_PATTERNS,
    fastapi: FASTAPI_ROLE_PATTERNS,
    rails: RAILS_ROLE_PATTERNS,
    nextjs: NEXTJS_ROLE_PATTERNS,
    nuxt: NEXTJS_ROLE_PATTERNS,
    unknown: EXPRESS_ROLE_PATTERNS,
  };
  return patterns[framework].some((p) => p.test(code));
}

/**
 * Detect framework type from source code patterns.
 */
function detectFramework(code: string): FrameworkType {
  if (/import.*express|require\(['"]express['"]/.test(code)) return "express";
  if (/from django|import django/.test(code)) return "django";
  if (/from flask|import flask/.test(code)) return "flask";
  if (/from fastapi|import fastapi/.test(code)) return "fastapi";
  if (/before_action|rails/.test(code)) return "rails";
  if (/middleware\.ts|getServerSession|useSession/.test(code)) return "nextjs";
  return "unknown";
}

/**
 * Check if a route/function has authentication.
 */
function hasAuthentication(code: string, framework: FrameworkType): { protected: boolean; method: string } {
  const patterns: Record<FrameworkType, RegExp[]> = {
    express: EXPRESS_AUTH_PATTERNS,
    django: DJANGO_AUTH_PATTERNS,
    flask: FLASK_AUTH_PATTERNS,
    fastapi: FASTAPI_AUTH_PATTERNS,
    rails: RAILS_AUTH_PATTERNS,
    nextjs: NEXTJS_AUTH_PATTERNS,
    nuxt: NEXTJS_AUTH_PATTERNS,
    unknown: EXPRESS_AUTH_PATTERNS,
  };
  const patternList = patterns[framework];

  for (const pattern of patternList) {
    if (pattern.test(code)) {
      return { protected: true, method: pattern.source };
    }
  }

  return { protected: false, method: "" };
}

/**
 * Extract routes from Express code.
 * Looks for app.get, app.post, router.get, etc.
 */
function extractExpressRoutes(code: string): RouteInfo[] {
  const routes: RouteInfo[] = [];
  // More flexible pattern that handles various formatting
  const routePattern = /(app|router)\.(get|post|put|delete|patch|all)\s*\(\s*['"](\/[^'"]*)['"]\s*[,;]/gi;

  let match;
  while ((match = routePattern.exec(code)) !== null) {
    const [fullMatch, source, method, path] = match;

    // Look at the section after this match to find handler signature
    const matchIndex = match.index + fullMatch.length;
    const handlerSection = code.substring(matchIndex, Math.min(matchIndex + 500, code.length));

    const auth = hasAuthentication(handlerSection, "express");

    routes.push({
      path,
      method: method.toUpperCase() as any,
      isProtected: auth.protected,
      detectionMethod: auth.protected ? "middleware detection" : "no auth pattern",
      evidence: handlerSection.substring(0, 50),
      hasRoleCheck: hasRoleCheck(handlerSection, "express"),
    });
  }

  return routes;
}

/**
 * Extract routes from Django code.
 * Looks for function_name(request) or @login_required decorators
 */
function extractDjangoRoutes(code: string): RouteInfo[] {
  const routes: RouteInfo[] = [];
  // Look for function definitions that accept request
  const routePattern = /(?:@[\w.]+\s*\n)*def\s+(\w+)\s*\(\s*request[^)]*\)\s*:\s*([^\n]*(?:\n(?!def)[^\n]*)*)/g;

  let match;
  while ((match = routePattern.exec(code)) !== null) {
    const [_, funcName, funcBody] = match;
    // Gather context before function (decorators)
    const beforeMatch = code.substring(Math.max(0, match.index - 200), match.index);
    const fullContext = beforeMatch + funcBody;
    const auth = hasAuthentication(fullContext, "django");

    routes.push({
      path: funcName,
      method: "ALL",
      isProtected: auth.protected,
      detectionMethod: auth.protected ? "decorator/check detection" : "no auth pattern",
      evidence: funcBody.substring(0, 100),
      hasRoleCheck: hasRoleCheck(fullContext, "django"),
    });
  }

  return routes;
}

/**
 * Extract routes from Flask code.
 */
function extractFlaskRoutes(code: string): RouteInfo[] {
  const routes: RouteInfo[] = [];
  // Match @app.route decorator with function definition
  const routePattern = /@app\.route\s*\(\s*['"](\/[^'"]*)['"]\s*(?:,\s*methods\s*=\s*\[([^\]]*)\])?\s*\)\s*(?:@[\w.]+\s*\n)*def\s+(\w+)\s*\([^)]*\)\s*:([^\n]*(?:\n(?!@app\.route)[^\n]*)*)/g;

  let match;
  while ((match = routePattern.exec(code)) !== null) {
    const [_, path, methods, funcName, funcBody] = match;
    const methodList = methods ? methods.split(",").map((m) => m.trim().toUpperCase()) : ["GET"];
    // Check both decorators and body for auth
    const beforeMatch = code.substring(Math.max(0, match.index - 100), match.index);
    const fullContext = beforeMatch + funcBody;
    const auth = hasAuthentication(fullContext, "flask");
    const roleChecked = hasRoleCheck(fullContext, "flask");

    for (const method of methodList) {
      routes.push({
        path,
        method: method as any,
        isProtected: auth.protected,
        detectionMethod: auth.protected ? "decorator detection" : "no auth pattern",
        evidence: funcBody.substring(0, 100),
        hasRoleCheck: roleChecked,
      });
    }
  }

  return routes;
}

/**
 * Extract routes from FastAPI code.
 */
function extractFastAPIRoutes(code: string): RouteInfo[] {
  const routes: RouteInfo[] = [];
  const routePattern = /@app\.(get|post|put|delete|patch)\s*\(\s*['"](\/[^'"]*)['"]\s*(?:,([^)]*))?\)\s*def\s+(\w+)\s*\(([^)]*)\)\s*:([^}]*?)(?=\n@app\.\w+|\ndef|\Z)/gs;

  let match;
  while ((match = routePattern.exec(code)) !== null) {
    const [_, method, path, options, funcName, params, funcBody] = match;
    const auth = hasAuthentication(params + funcBody, "fastapi");

    routes.push({
      path,
      method: method.toUpperCase() as any,
      isProtected: auth.protected,
      detectionMethod: auth.protected ? "Depends/auth detection" : "no auth pattern",
      evidence: params.substring(0, 50),
      hasRoleCheck: hasRoleCheck(params + funcBody, "fastapi"),
    });
  }

  return routes;
}

/**
 * Analyze authentication in code for a specific framework.
 */
export function analyzeAuth(code: string, detectedFramework?: FrameworkType): AuthCheckResult {
  const framework = detectedFramework || detectFramework(code);

  let routes: RouteInfo[] = [];
  switch (framework) {
    case "express":
      routes = extractExpressRoutes(code);
      break;
    case "django":
      routes = extractDjangoRoutes(code);
      break;
    case "flask":
      routes = extractFlaskRoutes(code);
      break;
    case "fastapi":
      routes = extractFastAPIRoutes(code);
      break;
    default:
      // Try Express patterns as fallback for unknown frameworks
      routes = extractExpressRoutes(code);
  }

  const unprotectedRoutes = routes.filter((r) => !r.isProtected);
  const confidence = routes.length > 0 ? Math.min(100, Math.round((routes.length / (routes.length + 5)) * 100)) : 0;

  return {
    routesAnalyzed: routes.length,
    unprotectedRoutes,
    allRoutes: routes,
    framework,
    confidence,
  };
}

/**
 * Get human-readable auth issue severity.
 * POST/PUT/DELETE without auth is critical.
 * GET without auth might be acceptable (public APIs).
 */
export function getAuthSeverity(route: RouteInfo): "critical" | "high" | "medium" {
  if (["POST", "PUT", "DELETE", "PATCH"].includes(route.method)) {
    return "critical";
  }
  if (route.method === "GET") {
    return "medium"; // Public GET might be intentional
  }
  return "high";
}

/**
 * Generate remediation for unprotected route.
 */
export function generateAuthRemediation(route: RouteInfo, framework: FrameworkType): string {
  const unknownAdvice = `Add authentication checks before handling requests. Verify user identity and permissions.`;
  const paths: Record<FrameworkType, string> = {
    express: `Add auth middleware: \`app.get('${route.path}', verifyJWT, handler)\``,
    django: `Add @login_required decorator: \`@login_required\\ndef handler(request):\``,
    flask: `Add @login_required decorator: \`@app.route('${route.path}')\\n@login_required\\ndef handler():\``,
    fastapi: `Use Depends: \`@app.get('${route.path}')\\ndef handler(token: str = Depends(oauth2_scheme)):\``,
    rails: `Add before_action: \`before_action :authenticate_user, only: :action_name\``,
    nextjs: `Use middleware.ts: \`const response = NextResponse.next()\\nif (!token) redirect('/');\``,
    nuxt: `Use server middleware: \`export default defineEventHandler((event) => { if (!event.context.auth) throw createError({ statusCode: 401 }); })\``,
    unknown: unknownAdvice,
  };

  return paths[framework] || paths.unknown;
}

/**
 * Remediation for a route that's authenticated but not role-checked —
 * distinct from generateAuthRemediation above, which is entirely about
 * proving *someone* is logged in. This is about proving *this* someone is
 * allowed to do *this*.
 */
export function generateRoleCheckRemediation(route: RouteInfo, framework: FrameworkType): string {
  const unknownAdvice = `Add a role or permission check before performing this action. Being logged in is not the same as being authorized for it.`;
  const paths: Record<FrameworkType, string> = {
    express: `Add a role check after the auth middleware: \`app.get('${route.path}', requireAuth, requireRole('admin'), handler)\``,
    django: `Add @permission_required or a staff check: \`@permission_required('app.can_manage')\\ndef handler(request):\` or \`if not request.user.is_staff: raise PermissionDenied\``,
    flask: `Add a role decorator: \`@app.route('${route.path}')\\n@login_required\\n@roles_required('admin')\\ndef handler():\``,
    fastapi: `Add a role dependency: \`@app.get('${route.path}')\\ndef handler(user = Depends(require_role('admin'))):\``,
    rails: `Add an authorization check: \`before_action :require_admin, only: :action_name\` or \`authorize @resource\` (Pundit/CanCanCan)`,
    nextjs: `Check the role from the session before handling the request: \`if (session.user.role !== 'admin') return new Response('Forbidden', { status: 403 })\``,
    nuxt: `Check the role in server middleware: \`if (event.context.auth.role !== 'admin') throw createError({ statusCode: 403 })\``,
    unknown: unknownAdvice,
  };

  return paths[framework] || paths.unknown;
}
