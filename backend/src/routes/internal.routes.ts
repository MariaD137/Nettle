import { Router, Request, Response } from "express";
import { sendDigests, type DigestPeriod } from "../patrol/digest";
import { runRetentionCleanup } from "../patrol/retention";

/**
 * Triggered by something outside this process on a schedule (a hosted cron,
 * an EventBridge rule, etc.) — this app has no in-process job scheduler,
 * and one wouldn't be safe here anyway once App Runner scales to multiple
 * instances, since each would independently fire the same digest. Gated by
 * a shared secret rather than a user session since the caller is a
 * scheduler, not a signed-in account.
 */
export const internalRouter = Router();

function requireCronSecret(req: Request, res: Response): boolean {
  const secret = process.env.CRON_SECRET;
  if (!secret) {
    res.status(503).json({ error: "Internal trigger is not configured (CRON_SECRET is unset)" });
    return false;
  }
  if (req.get("X-Nettle-Cron-Secret") !== secret) {
    res.status(401).json({ error: "Unauthorized" });
    return false;
  }
  return true;
}

internalRouter.post("/api/internal/digest/:period", (req: Request, res: Response) => {
  if (!requireCronSecret(req, res)) return;

  const period = req.params.period;
  if (period !== "daily" && period !== "weekly") {
    return res.status(400).json({ error: 'period must be "daily" or "weekly"' });
  }

  const results = sendDigests(period as DigestPeriod);
  res.json({ period, projectsNotified: results.length });
});

// Intended to be triggered on a schedule (daily is reasonable) once actual
// AWS scheduled execution exists — see AWS_GITHUB_DEPLOYMENT.md. Retention
// windows are configured via env (RETENTION_EVENTS_DAYS,
// RETENTION_ALERTS_DAYS, RETENTION_SCANS_DAYS,
// RETENTION_WEBHOOK_EVENTS_DAYS — see patrol/retention.ts for defaults);
// never deletes account/subscription/billing records.
internalRouter.post("/api/internal/retention/cleanup", (req: Request, res: Response) => {
  if (!requireCronSecret(req, res)) return;

  const result = runRetentionCleanup();
  res.json(result);
});
