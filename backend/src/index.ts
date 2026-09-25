import cors from "cors";
import helmet from "helmet";
import express, { type NextFunction, type Request, type Response } from "express";
import { healthRouter } from "./routes/health.routes";
import { scansRouter } from "./routes/scans.routes";
import { projectsRouter } from "./routes/projects.routes";
import { organizationsRouter } from "./routes/organizations.routes";
import { eventsRouter } from "./routes/events.routes";
import { authRouter } from "./routes/auth.routes";
import { badgeRouter } from "./routes/badge.routes";
import { billingRouter, billingWebhookRouter } from "./routes/billing.routes";
import { initializeScanner } from "./scanner/initialization";
import { startDurableQueueConsumer } from "./scanner/durableQueue";
import { initializeDatabase, assertProductionPersistence } from "./db";
import { startRateLimitCleanup } from "./middleware/rateLimit";
import { apiVersioning } from "./middleware/apiVersion";

const app = express();
const PORT = process.env.PORT || 8080;

/**
 * Exactly one hop sits between the internet and this process: App Runner's
 * own edge, which terminates TLS and forwards the request. Confirmed against
 * the actual infrastructure, not assumed — infra/lib/api-stack.ts sets no
 * ingressConfiguration, so App Runner uses its default public endpoint, and
 * no CloudFront/ALB/other proxy is layered in front of it anywhere in
 * infra/lib/.
 *
 * `trust proxy: 1` tells Express to trust exactly that one nearest hop. With
 * one proxy in the chain, that makes `req.ip` the address our one trusted hop
 * itself observed on the TCP connection — which is the real client, because
 * App Runner is the thing that actually accepted that connection. A client
 * cannot spoof this by sending its own X-Forwarded-For header: Express with
 * trust proxy=1 reads only the single entry closest to us (the one App
 * Runner appended from its own observation) and ignores anything further
 * left in the header that the client supplied before ever reaching App
 * Runner.
 *
 * `trust proxy: true` would be wrong here and is deliberately NOT used: it
 * trusts the entire X-Forwarded-For chain, including a value an attacker
 * prepends themselves — with `true`, a request carrying
 * `X-Forwarded-For: 9.9.9.9` would make Express report the client as
 * 9.9.9.9 regardless of what address actually connected, defeating every
 * IP-keyed rate limit and the brute-force/abuse detection in patrol/detection.ts.
 *
 * If a CDN or load balancer is ever added in front of App Runner, this must
 * become 2 (or however many hops are added) — leaving it at 1 in that case
 * would let anything behind the new hop spoof its origin again.
 */
app.set("trust proxy", 1);

// Rewrites /api/v1/<rest> to /api/<rest> before any router sees the
// request — see middleware/apiVersion.ts for why this is a rewrite rather
// than a second mount point for every router.
app.use(apiVersioning);

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
app.use(organizationsRouter);
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
  startRateLimitCleanup();
  // No-op when SCAN_QUEUE_URL isn't configured (every test, local dev, this
  // sandbox) — see durableQueue.ts's own doc comment.
  startDurableQueueConsumer();

  app.listen(PORT, () => {
    console.log(`Nettle backend listening on port ${PORT}`);
  });
}

start().catch((err) => {
  console.error(`Nettle failed to start: ${(err as Error).message}`);
  process.exit(1);
});
