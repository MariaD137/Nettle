import type { Control } from "../types";
import { registerControl } from "../registry";

/**
 * AUTH-001 — the exact control from the product spec's own worked example
 * (§33), extended with technology-specific fixes pulled from the
 * framework-aware remediation strings already written in
 * scanner/authAnalysis.ts (generateAuthRemediation) rather than invented
 * fresh — that logic was tested (test/h6-auth-analysis.test.ts) but never
 * wired into the live scan pipeline; see controls/checks/authControl.ts.
 */
export const AUTH_001: Control = {
  controlKey: "AUTH-001",
  category: "Authentication",
  subcategory: "Server-side enforcement",
  name: "Server-side authentication enforcement",
  description:
    "Every protected application operation must verify the caller's identity on the server before it executes — " +
    "not merely hide a link or button on the client, which a direct request bypasses entirely.",
  question: "Are protected application operations authenticated server-side?",
  defaultSeverity: "high",

  passCriteria: "A recognized authentication check (framework-appropriate middleware, decorator, or session guard) is present for the route.",
  failCriteria: "A route accepting state-changing or user-specific requests has no recognized authentication check anywhere in its handler chain.",
  notVerifiedCriteria:
    "The application's framework could not be identified, so Nettle cannot reliably tell a real auth gap from an idiom it doesn't recognize yet.",

  whyItMatters:
    "An unauthenticated protected operation is reachable by anyone who can send it an HTTP request — no credentials, no session, " +
    "no prior access required. For a route that reads or changes user-specific data, that is a direct path to unauthorized access.",

  technologyFixes: [
    {
      technology: "express",
      quickFix: "Add an auth middleware argument to the route before shipping: app.get(path, verifyJWT, handler).",
      developerFix:
        "Add authentication middleware (verifyJWT, requireAuth, or passport.authenticate) as an explicit argument on the route, " +
        "or apply it via app.use()/router.use() on every router that mounts protected routes.",
      architectureFix:
        "Centralize auth as router-level middleware applied before route registration, so a new route can't be added without it by omission.",
      codeExample: "app.get('/api/admin/users', verifyJWT, (req, res) => { /* ... */ });",
    },
    {
      technology: "django",
      quickFix: "Add @login_required (or @permission_required for role-gated views) directly above the view function.",
      developerFix:
        "Decorate the view with @login_required, or for class-based views, mix in LoginRequiredMixin. Use @permission_required when the " +
        "operation needs more than \"any authenticated user\".",
      architectureFix: "Set a default LoginRequiredMixin-based generic view base class for the app, so a new view opts out of auth explicitly rather than opting in.",
      codeExample: "@login_required\ndef admin_view(request):\n    ...",
    },
    {
      technology: "flask",
      quickFix: "Add @login_required above the route function (Flask-Login), or explicit abort(401) at the top of the handler.",
      developerFix: "Use Flask-Login's @login_required decorator, or check current_user.is_authenticated and abort(401) before proceeding.",
      architectureFix: "Register a before_request hook on the relevant Blueprint so every route under it requires auth by default.",
      codeExample: "@app.route('/admin')\n@login_required\ndef admin():\n    ...",
    },
    {
      technology: "fastapi",
      quickFix: "Add a Depends(oauth2_scheme) (or your auth dependency) parameter to the path function.",
      developerFix: "Use FastAPI's Depends() with an OAuth2/HTTPBearer scheme, or a custom dependency that raises HTTPException(401) when the token is missing/invalid.",
      architectureFix: "Apply the auth dependency at the APIRouter level (dependencies=[Depends(...)]) so every route mounted under it is protected by default.",
      codeExample: "@app.get('/admin')\ndef admin(token: str = Depends(oauth2_scheme)):\n    ...",
    },
    {
      technology: "rails",
      quickFix: "Add before_action :authenticate_user to the controller, scoped with only:/except: as needed.",
      developerFix: "Use a before_action callback (Devise's authenticate_user!, or a custom equivalent) at the top of the controller.",
      architectureFix: "Set the authentication before_action in ApplicationController so a new controller is protected unless it explicitly skips it.",
      codeExample: "class AdminController < ApplicationController\n  before_action :authenticate_user!\nend",
    },
    {
      technology: "nextjs",
      quickFix: "Check the session in middleware.ts and redirect unauthenticated requests before they reach the route handler.",
      developerFix: "Use getServerSession()/auth() in the route handler or middleware.ts, and return a 401/redirect when no session is present.",
      architectureFix: "Define a matcher in middleware.ts covering every protected path prefix, so a new route under it is covered without a separate change.",
      codeExample: "export async function middleware(req) {\n  const session = await getServerSession();\n  if (!session) return NextResponse.redirect('/login');\n}",
    },
    {
      technology: "nuxt",
      quickFix: "Call await requireUserSession(event) at the top of the Nitro event handler.",
      developerFix: "Use requireUserSession(event) (or getUserSession + a manual 401) inside defineEventHandler, or a server middleware applied to the route's path prefix.",
      architectureFix: "Add a server/middleware guard for the protected path prefix so new handlers under it don't need to remember the check individually.",
      codeExample: "export default defineEventHandler(async (event) => {\n  const { user } = await requireUserSession(event);\n});",
    },
    {
      technology: "generic",
      quickFix: "Add an authentication check before the handler's business logic runs, using whatever session/token mechanism the app already has.",
      developerFix: "Implement server-side authentication before protected operations execute — verify the caller's identity from a session or token, not from client-side state.",
      architectureFix: "Centralize the check (middleware, decorator, or guard) so it applies to a whole group of routes at once rather than per-handler.",
    },
  ],

  longTermHardening:
    "Add an integration test per protected route asserting a 401/redirect with no credentials, so a future refactor can't silently drop the check.",
  verificationMethod: "Rescan the route; Nettle re-runs route/auth-pattern detection and confirms a recognized auth check is now present in the handler chain.",
  references: ["OWASP Top 10: A01:2021 – Broken Access Control", "OWASP ASVS V4: Access Control Verification Requirements"],
  complianceMappings: ["SOC 2 CC6.1", "ISO 27001 A.9"],

  releaseImpactBySeverity: {
    critical: "BLOCK_RELEASE",
    high: "REVIEW_BEFORE_RELEASE",
    medium: "FIX_RECOMMENDED",
    low: "IMPROVEMENT",
    info: "INFORMATIONAL",
  },

  enabled: true,
  version: "1.0.0",
};

registerControl(AUTH_001);
