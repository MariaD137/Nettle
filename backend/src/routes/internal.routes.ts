import { Router, Request, Response } from "express";
import { sendDigests, type DigestPeriod } from "../patrol/digest";

/**
 * Triggered by something outside this process on a schedule (a hosted cron,
 * an EventBridge rule, etc.) — this app has no in-process job scheduler,
 * and one wouldn't be safe here anyway once App Runner scales to multiple
 * instances, since each would independently fire the same digest. Gated by
 * a shared secret rather than a user session since the caller is a
 * scheduler, not a signed-in account.
 */
export const internalRouter = Router();

internalRouter.post("/api/internal/digest/:period", (req: Request, res: Response) => {
  const secret = process.env.CRON_SECRET;
  if (!secret) {
    return res.status(503).json({ error: "Digest trigger is not configured (CRON_SECRET is unset)" });
  }
  if (req.get("X-Nettle-Cron-Secret") !== secret) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  const period = req.params.period;
  if (period !== "daily" && period !== "weekly") {
    return res.status(400).json({ error: 'period must be "daily" or "weekly"' });
  }

  const results = sendDigests(period as DigestPeriod);
  res.json({ period, projectsNotified: results.length });
});
