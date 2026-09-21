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
}

export interface AuthCheckResult {
  routesAnalyzed: number;
  unprotectedRoutes: RouteInfo[];
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
 * Nuxt 3 / Nitro authentication patterns.
 *
 * Nuxt deliberately does NOT reuse the Express set. Its server routes are
 * Nitro event handlers, so Express idioms (`app.use(verifyJwt)`, `passport`)
 * simply do not appear in idiomatic Nuxt code — matching against them made
 * every authenticated Nuxt route look unprotected.
 */
const NUXT_AUTH_PATTERNS = [
  /requireUserSession/i,
  /getUserSession/i,
  /getServerSession/i,
  /serverSupabaseUser/i,
  /useSupabaseUser/i,
  /defineEventHandler\s*\(\s*auth/i,
  /server\/middleware/i,
  /definePageMeta\s*\(\s*\{[^}]*middleware/i,
];

/**
 * Framework-agnostic authentication indicators, used when the framework could
 * not be identified.
 *
 * This is the explicit default for "unknown" rather than an accidental
 * fallthrough to the Express set. It is a deliberately broad union of the
 * common idioms across the supported frameworks: when we do not know the
 * framework we bias towards recognising an auth check that is present, so an
 * unrecognised stack does not generate a page of false "unprotected route"
 * findings. `analyzeAuth` reports reduced confidence to match.
 */
const GENERIC_AUTH_PATTERNS = [
  /verify[_-]?jwt/i,
  /auth[_-]?middleware/i,
  /requireAuth/i,
  /isAuthenticated/i,
  /login_required/i,
  /authenticate/i,
  /current_user/i,
  /getSession/i,
  /getServerSession/i,
  /requireUserSession/i,
  /Depends\s*\(\s*\w*(oauth|auth|user|token)/i,
  /before_action\s*:authenticate/i,
];

/**
 * Every FrameworkType gets an intentional pattern set. Typing this as a
 * Record over the union means adding a framework to FrameworkType fails the
 * build until a strategy is chosen for it, instead of silently degrading to
 * whichever set happened to be the fallback.
 */
const AUTH_PATTERNS_BY_FRAMEWORK: Record<FrameworkType, readonly RegExp[]> = {
  express: EXPRESS_AUTH_PATTERNS,
  django: DJANGO_AUTH_PATTERNS,
  flask: FLASK_AUTH_PATTERNS,
  fastapi: FASTAPI_AUTH_PATTERNS,
  rails: RAILS_AUTH_PATTERNS,
  nextjs: NEXTJS_AUTH_PATTERNS,
  nuxt: NUXT_AUTH_PATTERNS,
  unknown: GENERIC_AUTH_PATTERNS,
};

/**
 * Detect framework type from source code patterns.
 */
function detectFramework(code: string): FrameworkType {
  if (/import.*express|require\(['"]express['"]/.test(code)) return "express";
  if (/from django|import django/.test(code)) return "django";
  if (/from flask|import flask/.test(code)) return "flask";
  if (/from fastapi|import fastapi/.test(code)) return "fastapi";
  if (/before_action|rails/.test(code)) return "rails";
  // Nuxt is tested before Next.js on purpose: both may reference
  // getServerSession, but only Nuxt/Nitro uses defineEventHandler, so the
  // narrower signal has to win or every Nuxt app is misreported as Next.js.
  if (/defineEventHandler|defineNuxtConfig|#imports|nuxt\.config/.test(code)) return "nuxt";
  if (/middleware\.ts|getServerSession|useSession/.test(code)) return "nextjs";
  return "unknown";
}

/**
 * Check if a route/function has authentication.
 */
function hasAuthentication(code: string, framework: FrameworkType): { protected: boolean; method: string } {
  const patterns = AUTH_PATTERNS_BY_FRAMEWORK[framework];

  for (const pattern of patterns) {
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
function extractExpressRoutes(code: string, framework: FrameworkType = "express"): RouteInfo[] {
  const routes: RouteInfo[] = [];
  // More flexible pattern that handles various formatting
  const routePattern = /(app|router)\.(get|post|put|delete|patch|all)\s*\(\s*['"](\/[^'"]*)['"]\s*[,;]/gi;

  let match;
  while ((match = routePattern.exec(code)) !== null) {
    const [fullMatch, source, method, path] = match;

    // Look at the section after this match to find handler signature
    const matchIndex = match.index + fullMatch.length;
    const handlerSection = code.substring(matchIndex, Math.min(matchIndex + 500, code.length));

    // Use the framework actually in play, not a hardcoded "express". This
    // extractor is shared by rails/nextjs/unknown, and pinning it to the
    // Express pattern set made ROUTE_EXTRACTORS and AUTH_PATTERNS_BY_FRAMEWORK
    // disagree: the route shape was generic but the auth check never was.
    const auth = hasAuthentication(handlerSection, framework);

    routes.push({
      path,
      method: method.toUpperCase() as any,
      isProtected: auth.protected,
      detectionMethod: auth.protected ? "middleware detection" : "no auth pattern",
      evidence: handlerSection.substring(0, 50),
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

    for (const method of methodList) {
      routes.push({
        path,
        method: method as any,
        isProtected: auth.protected,
        detectionMethod: auth.protected ? "decorator detection" : "no auth pattern",
        evidence: funcBody.substring(0, 100),
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
    });
  }

  return routes;
}

/**
 * Extract server routes from Nuxt 3 / Nitro code.
 *
 * Nuxt routes are file-based: the URL and HTTP method come from the file's
 * path and suffix (`server/api/users.post.ts`), neither of which is present
 * in the source text this function receives. Rather than invent a URL, each
 * handler is reported with a "(file-based route)" path and an ALL method,
 * which is enough to say "this handler has no auth check" without fabricating
 * routing information the scanner cannot see.
 */
function extractNuxtRoutes(code: string): RouteInfo[] {
  const routes: RouteInfo[] = [];
  const handlerPattern = /defineEventHandler\s*\(/g;

  let match;
  while ((match = handlerPattern.exec(code)) !== null) {
    const bodyStart = match.index + match[0].length;
    const body = code.substring(bodyStart, Math.min(bodyStart + 500, code.length));
    // Auth in Nuxt is commonly applied in server middleware rather than in
    // the handler, so the whole module is considered, not just the body.
    const auth = hasAuthentication(`${code.substring(0, match.index)}\n${body}`, "nuxt");

    routes.push({
      path: "(file-based route)",
      method: "ALL",
      isProtected: auth.protected,
      detectionMethod: auth.protected ? "Nitro session/middleware detection" : "no auth pattern",
      evidence: body.substring(0, 50),
    });
  }

  return routes;
}

/**
 * Route extraction strategy per framework. Exhaustive by construction, so a
 * new FrameworkType cannot be added without deciding how its routes are read.
 *
 * `rails`, `nextjs` and `unknown` intentionally share the Express extractor:
 * for Rails and Next.js no dedicated extractor has been written yet, and for
 * an unidentified framework the Express route shape is the most common one in
 * this codebase's target population. That choice is now explicit and
 * confidence-adjusted, rather than a `default:` branch.
 */
const ROUTE_EXTRACTORS: Record<
  FrameworkType,
  (code: string, framework: FrameworkType) => RouteInfo[]
> = {
  express: extractExpressRoutes,
  django: extractDjangoRoutes,
  flask: extractFlaskRoutes,
  fastapi: extractFastAPIRoutes,
  rails: extractExpressRoutes,
  nextjs: extractExpressRoutes,
  nuxt: extractNuxtRoutes,
  unknown: extractExpressRoutes,
};

/**
 * Analyze authentication in code for a specific framework.
 */
export function analyzeAuth(code: string, detectedFramework?: FrameworkType): AuthCheckResult {
  const framework = detectedFramework || detectFramework(code);

  const routes: RouteInfo[] = ROUTE_EXTRACTORS[framework](code, framework);

  const unprotectedRoutes = routes.filter((r) => !r.isProtected);
  let confidence = routes.length > 0 ? Math.min(100, Math.round((routes.length / (routes.length + 5)) * 100)) : 0;

  // An unidentified framework is scanned with the generic pattern set and an
  // Express-shaped route extractor, so any routes found are a best effort.
  // Say so in the confidence rather than reporting it as a firm result.
  if (framework === "unknown" && confidence > 0) {
    confidence = Math.round(confidence / 2);
  }

  return {
    routesAnalyzed: routes.length,
    unprotectedRoutes,
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
  const paths: Record<FrameworkType, string> = {
    express: `Add auth middleware: \`app.get('${route.path}', verifyJWT, handler)\``,
    django: `Add @login_required decorator: \`@login_required\\ndef handler(request):\``,
    flask: `Add @login_required decorator: \`@app.route('${route.path}')\\n@login_required\\ndef handler():\``,
    fastapi: `Use Depends: \`@app.get('${route.path}')\\ndef handler(token: str = Depends(oauth2_scheme)):\``,
    rails: `Add before_action: \`before_action :authenticate_user, only: :action_name\``,
    nextjs: `Use middleware.ts: \`const response = NextResponse.next()\\nif (!token) redirect('/');\``,
    nuxt: `Guard the Nitro handler: \`export default defineEventHandler(async (event) => {\\n  await requireUserSession(event)\\n})\``,
    unknown: `Add authentication checks before handling requests. Verify user identity and permissions.`,
  };

  return paths[framework];
}
