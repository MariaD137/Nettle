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
import { scanRateLimit, publicRateLimit, apiRateLimit } from "./middleware/rateLimit";
import { initializeScanner } from "./scanner/initialization";
import { backfillFindingHistory } from "./patrol/findingHistory";
import { backfillApiKeys } from "./patrol/apiKeys";

const app = express();
const PORT = process.env.PORT || 8080;

// The dashboard is a separate origin from the API (see frontend/) — CORS is
// a real production need here, not just a dev convenience. Wide open for
// now since every route that returns account-specific data already requires
// a bearer token, not a cookie, so there's no CSRF surface from a permissive
// origin policy the way there would be with cookie-based auth.
app.use(cors());

// Must be mounted BEFORE express.json(): Stripe signs the exact raw request
// bytes, and constructEvent() verifies against those same raw bytes. If
// express.json() parsed the body first, the signature check would fail on
// every real webhook delivery.
app.use(billingWebhookRouter);

app.use(express.json());
app.use(healthRouter);
app.use(apiRateLimit);
app.use(scanRateLimit, scansRouter);
app.use(scanRateLimit, scanJobsRouter);
app.use(projectsRouter);
app.use(publicRateLimit, eventsRouter);
app.use(authRouter);
app.use(publicRateLimit, badgeRouter);
app.use(billingRouter);
app.use('/api/custom-rules', customRulesRouter);
app.use('/api/analytics', analyticsRouter);
app.use('/api/projects', integrationsRouter);
app.use(internalRouter);

app.use((_req: Request, res: Response) => {
  res.status(404).json({ error: "Not found" });
});

app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
  console.error(err);
  res.status(500).json({ error: "Internal server error" });
});

// Initialize scanner at startup
initializeScanner();

// One-time seed of first/last-detected history for scans recorded before
// this table existed — a no-op after the first successful run. Runs
// before the server starts accepting requests so there's no window where
// a fresh scan could race the backfill.
backfillFindingHistory();

// Same one-time-seed pattern: every project that predates the multi-key
// api_keys table gets its existing projects.api_key mirrored in as its
// default key, so revoke/scope/last-used tracking cover it too.
backfillApiKeys();

app.listen(PORT, () => {
  console.log(`Nettle backend listening on port ${PORT}`);
});
