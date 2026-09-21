import cors from "cors";
import helmet from "helmet";
import express, { type NextFunction, type Request, type Response } from "express";
import { healthRouter } from "./routes/health.routes";
import { scansRouter } from "./routes/scans.routes";
import { projectsRouter } from "./routes/projects.routes";
import { eventsRouter } from "./routes/events.routes";
import { authRouter } from "./routes/auth.routes";
import { badgeRouter } from "./routes/badge.routes";
import { billingRouter, billingWebhookRouter } from "./routes/billing.routes";
import { initializeScanner } from "./scanner/initialization";
import { initializeDatabase, assertProductionPersistence } from "./db";

const app = express();
const PORT = process.env.PORT || 8080;

// The dashboard is a separate origin from the API (see frontend/) — CORS is
// a real production need here, not just a dev convenience. Wide open for
// now since every route that returns account-specific data already requires
// a bearer token, not a cookie, so there's no CSRF surface from a permissive
// origin policy the way there would be with cookie-based auth.
// Nettle's own scanner flags apps that ship without these (see
// src/scanner/securityHeaders.ts), and the API previously set none of them.
//
// Tuned for a JSON API rather than left on defaults:
//  - CSP is locked to default-src 'none'. The API returns JSON and one SVG;
//    it never loads scripts, styles or frames, so nothing legitimate needs a
//    broader policy. frame-ancestors 'none' plus X-Frame-Options covers
//    clickjacking for the error pages Express renders.
//  - crossOriginResourcePolicy stays at helmet's same-origin default here and
//    is relaxed per-route on the badge, which exists to be embedded from
//    customer sites (see badge.routes.ts). Leaving the default in place
//    globally would have silently broken every embedded badge.
//  - HSTS is on: App Runner terminates TLS in front of this service.
app.use(
  helmet({
    contentSecurityPolicy: {
      useDefaults: false,
      directives: {
        "default-src": ["'none'"],
        "frame-ancestors": ["'none'"],
        "base-uri": ["'none'"],
        "form-action": ["'none'"],
      },
    },
    hsts: { maxAge: 31_536_000, includeSubDomains: true, preload: false },
    referrerPolicy: { policy: "no-referrer" },
  })
);

app.use(cors());

// Must be mounted BEFORE express.json(): Stripe signs the exact raw request
// bytes, and constructEvent() verifies against those same raw bytes. If
// express.json() parsed the body first, the signature check would fail on
// every real webhook delivery.
app.use(billingWebhookRouter);

app.use(express.json());
app.use(healthRouter);
app.use(scansRouter);
app.use(projectsRouter);
app.use(eventsRouter);
app.use(authRouter);
app.use(badgeRouter);
app.use(billingRouter);

app.use((_req: Request, res: Response) => {
  res.status(404).json({ error: "Not found" });
});

app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
  console.error(err);
  res.status(500).json({ error: "Internal server error" });
});

/**
 * Startup order matters.
 *
 * The persistence check runs first and throws rather than warning: booting a
 * production instance on SQLite would look healthy right up until the next
 * deployment discarded every account. Migrations run before the listener
 * opens, so a broken migration fails the deployment instead of the first
 * request that happens to touch the database.
 */
async function start(): Promise<void> {
  assertProductionPersistence();
  await initializeDatabase();
  initializeScanner();

  app.listen(PORT, () => {
    console.log(`Nettle backend listening on port ${PORT}`);
  });
}

start().catch((err) => {
  console.error(`Nettle failed to start: ${(err as Error).message}`);
  process.exit(1);
});
