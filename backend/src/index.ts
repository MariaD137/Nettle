import cors from "cors";
import express, { type NextFunction, type Request, type Response } from "express";
import { healthRouter } from "./routes/health.routes";
import { scansRouter } from "./routes/scans.routes";
import { projectsRouter } from "./routes/projects.routes";
import { eventsRouter } from "./routes/events.routes";
import { authRouter } from "./routes/auth.routes";
import { badgeRouter } from "./routes/badge.routes";
import { billingRouter, billingWebhookRouter } from "./routes/billing.routes";
import customRulesRouter from "./routes/customRules.routes";
import { initializeScanner } from "./scanner/initialization";

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
app.use(scansRouter);
app.use(projectsRouter);
app.use(eventsRouter);
app.use(authRouter);
app.use(badgeRouter);
app.use(billingRouter);
app.use('/api/custom-rules', customRulesRouter);

app.use((_req: Request, res: Response) => {
  res.status(404).json({ error: "Not found" });
});

app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
  console.error(err);
  res.status(500).json({ error: "Internal server error" });
});

// Initialize scanner at startup
initializeScanner();

app.listen(PORT, () => {
  console.log(`Nettle backend listening on port ${PORT}`);
});
