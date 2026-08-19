import cors from "cors";
import express, { type NextFunction, type Request, type Response } from "express";
import { healthRouter } from "./routes/health.routes";
import { scansRouter } from "./routes/scans.routes";
import { scanJobsRouter } from "./routes/scanJobs.routes";
import { projectsRouter } from "./routes/projects.routes";
import { eventsRouter } from "./routes/events.routes";
import { authRouter } from "./routes/auth.routes";
import { badgeRouter } from "./routes/badge.routes";
import { billingRouter, billingWebhookRouter } from "./routes/billing.routes";
import customRulesRouter from "./routes/customRules.routes";
import analyticsRouter from "./routes/analytics.routes";
import integrationsRouter from "./routes/integrations.routes";
import { internalRouter } from "./routes/internal.routes";
import { apiRateLimit } from "./middleware/rateLimit";
import { optionalAuth } from "./auth/middleware";
import { initializeScanner } from "./scanner/initialization";
import { backfillFindingHistory } from "./patrol/findingHistory";
import { backfillApiKeys, backfillHashedApiKeys } from "./patrol/apiKeys";
import { adminRouter } from "./routes/admin.routes";
import { syncAdminEmails } from "./auth/users";
import { logger } from "./observability/logger";
import { incrementCounter, Metric } from "./observability/metrics";
import { getAllowedOrigins } from "./corsConfig";
import { sendOpsAlert } from "./observability/opsAlert";

const app = express();
const PORT = process.env.PORT || 8080;

// The dashboard is a separate origin from the API (see frontend/). Every
// route that returns account-specific data requires a bearer token, not a
// cookie, so a permissive origin policy was never a CSRF hole — but
// restricting it to the real frontend origin(s) is still real
// defense-in-depth (an XSS or malicious extension that got hold of a
// token benefits less from also being able to read cross-origin
// responses from any site), so it's no longer wide open.
//
// See corsConfig.ts — with neither CORS_ALLOWED_ORIGINS nor FRONTEND_URL
// set (local dev by default), this reflects whatever origin actually
// asks, same as the old cors() default, so no existing dev workflow breaks.
const allowedOrigins = getAllowedOrigins();

app.use(cors(allowedOrigins.length > 0 ? { origin: allowedOrigins } : undefined));

// Must be mounted BEFORE express.json(): Stripe signs the exact raw request
// bytes, and constructEvent() verifies against those same raw bytes. If
// express.json() parsed the body first, the signature check would fail on
// every real webhook delivery.
app.use(billingWebhookRouter);

app.use(express.json());

// Structured request logging + counters, mounted before everything else
// that isn't the webhook raw-body handler above, so every request is
// counted regardless of which router (or no router) ends up handling it.
app.use((req: Request, res: Response, next: NextFunction) => {
  const startedAt = Date.now();
  res.on("finish", () => {
    incrementCounter(Metric.HttpRequests);
    if (res.statusCode >= 500) incrementCounter(Metric.HttpErrors);
    logger.info("http_request", {
      method: req.method,
      path: req.path,
      status: res.statusCode,
      durationMs: Date.now() - startedAt,
    });
  });
  next();
});

// /health stays unrate-limited and ahead of everything else — it's polled
// frequently by whatever's checking liveness (App Runner's own health
// check once deployed), and rate-limiting it risks turning normal polling
// into false-negative failures that trigger unwanted restarts.
app.use(healthRouter);
// apiRateLimit is intentionally the only rate limiter mounted app-wide —
// scanRateLimit/publicRateLimit used to be mounted the same way
// (`app.use(scanRateLimit, scansRouter)`), but since that middleware form
// runs for every request that reaches this point in the stack regardless
// of which router ends up handling it, it meant EVERY API call — not just
// scan submissions — was consuming scanRateLimit's 30-requests-per-minute
// budget (and every call was also consuming publicRateLimit's, twice
// over). Both are now applied per-route, inside the routers that actually
// need them (see scans.routes.ts, scanJobs.routes.ts, events.routes.ts,
// badge.routes.ts), matching how auth.routes.ts already scopes its own
// stricter authLimiter to just signup/login/forgot-password/reset-password.
// Resolves req.userId (when a valid bearer token is present) before the
// rate limiter runs, without rejecting anyone — apiRateLimit's own keying
// (middleware/rateLimit.ts) needs req.userId to actually rate-limit
// per-account rather than silently falling back to per-IP for every
// request, since it previously ran before any route's own requireAuth had
// a chance to set it.
app.use(optionalAuth);
app.use(apiRateLimit);
// adminRouter is mounted here, after apiRateLimit, rather than up with
// healthRouter above — every admin route already requires an
// authenticated, admin-flagged session (requireAuth + requireAdmin, see
// admin.routes.ts), but nothing previously rate-limited it at all. This
// costs nothing (an admin session is no less real for arriving a few
// lines later in the middleware stack) and closes that gap for free.
app.use(adminRouter);
app.use(scansRouter);
app.use(scanJobsRouter);
app.use(projectsRouter);
app.use(eventsRouter);
app.use(authRouter);
app.use(badgeRouter);
app.use(billingRouter);
app.use('/api/custom-rules', customRulesRouter);
app.use('/api/analytics', analyticsRouter);
app.use('/api/projects', integrationsRouter);
app.use(internalRouter);

app.use((_req: Request, res: Response) => {
  res.status(404).json({ error: "Not found" });
});

app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
  logger.error("unhandled_route_error", { error: err.message, stack: err.stack });
  incrementCounter(Metric.HttpErrors);
  void sendOpsAlert({
    category: "unhandled_exception",
    message: `Unhandled error in a route handler: ${err.message}`,
    detail: err.stack,
  });
  res.status(500).json({ error: "Internal server error" });
});

// Catches anything that escapes Express's own request/response handling —
// a throw in a timer callback, a background job, or any other code path
// that isn't inside a request Express itself wraps. Node's own process
// state is unknown after an uncaught exception (a partially-unwound stack,
// possibly-corrupted in-memory state), so the documented safe move is to
// alert, then exit and let the orchestrator (App Runner) restart into a
// clean process — not to try to keep running.
//
// This cannot detect or throttle a *crash loop* across restarts: the
// in-memory alert state in observability/opsAlert.ts starts over every
// time this process starts, so a tight crash loop would alert on every
// single restart. Real crash-loop detection with its own backoff needs
// something that survives outside this process — see README's REQUIRES
// AWS CONFIGURATION note.
process.on("uncaughtException", (err) => {
  logger.error("uncaught_exception", { error: err.message, stack: err.stack });
  sendOpsAlert({
    category: "unhandled_exception",
    message: `Uncaught exception: ${err.message}`,
    detail: err.stack,
  })
    .catch(() => {})
    .finally(() => process.exit(1));
});

// An unhandled promise rejection doesn't necessarily corrupt process state
// the way an uncaught exception does, so this alerts without exiting —
// but it's still a real bug (a promise nothing ever awaited or caught) and
// worth knowing about rather than letting it vanish silently.
process.on("unhandledRejection", (reason) => {
  const message = reason instanceof Error ? reason.message : String(reason);
  const stack = reason instanceof Error ? reason.stack : undefined;
  logger.error("unhandled_rejection", { error: message, stack });
  void sendOpsAlert({ category: "unhandled_rejection", message: `Unhandled promise rejection: ${message}`, detail: stack });
});

async function start(): Promise<void> {
  // Initialize scanner at startup
  initializeScanner();

  // Declarative admin grants: NETTLE_ADMIN_EMAILS (comma-separated) is the
  // source of truth, re-read on every startup — removing an email from the
  // list actually revokes access on next restart rather than leaving a
  // stale is_admin flag in the database forever. See auth/users.ts.
  syncAdminEmails();

  // One-time seed of first/last-detected history for scans recorded before
  // this table existed — a no-op after the first successful run. Runs
  // before the server starts accepting requests so there's no window where
  // a fresh scan could race the backfill.
  backfillFindingHistory();

  // Same one-time-seed pattern: every project that predates the multi-key
  // api_keys table gets its existing projects.api_key mirrored in as its
  // default key, so revoke/scope/last-used tracking cover it too.
  backfillApiKeys();

  // Migrates any api_keys row created before key hashing existed — replaces
  // a non-default row's plaintext key with its hash and fills in every row's
  // precomputed masked display form. Runs after backfillApiKeys() so rows it
  // just seeded for pre-existing projects get covered in the same pass.
  backfillHashedApiKeys();

  app.listen(PORT, () => {
    logger.info("server_started", { port: PORT });
  });
}

start().catch((err: Error) => {
  // A fatal startup failure (e.g. a corrupt DB file, a missing required
  // migration precondition) means the service never comes up at all — this
  // is exactly the case where nobody would otherwise notice until a
  // customer or an uptime check does, so it's worth an immediate alert
  // rather than only a log line headed for an unread CloudWatch stream.
  logger.error("fatal_startup_failure", { error: err.message, stack: err.stack });
  sendOpsAlert({
    category: "startup_failure",
    message: `Nettle backend failed to start: ${err.message}`,
    detail: err.stack,
  })
    .catch(() => {})
    .finally(() => process.exit(1));
});
