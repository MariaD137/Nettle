import { Router, json, type Request, type Response } from "express";
import { resolvePendingScan, rejectPendingScan } from "../jobs/pendingScanRegistry";
import { asyncHandler } from "../middleware/asyncHandler";
import type { ScanReport } from "../scanner/types";

/**
 * Where an isolated Fargate scan task reports its result back (see
 * jobs/fargateScanner.ts, scanner/taskEntrypoint.ts, scanner/ISOLATION.md).
 * Mounted in index.ts with its OWN body parser, BEFORE the app-wide
 * express.json() — same reason the Stripe webhook router is mounted
 * before it (see index.ts's comment there): a real ScanReport for a large
 * repository can genuinely exceed the app-wide parser's default 100kb
 * limit, and by the time a request reaches a router mounted after
 * express.json() already ran, the body is already parsed (or already
 * rejected) — a second, bigger-limit parser on this router alone
 * wouldn't get a second chance to re-parse it.
 *
 * Authorization is the per-job callback token (X-Nettle-Scan-Callback-Token),
 * never CRON_SECRET or any other shared/application secret — see
 * jobs/pendingScanRegistry.ts for why it's scoped this way. A request for
 * an unknown job id or a wrong/missing token gets an identical 404,
 * regardless of which — this endpoint has no legitimate caller other than
 * the one task that was launched for that exact job, so there's nothing
 * useful (and something mildly leaky) in distinguishing "wrong token" from
 * "no such job."
 */
export const scanTaskCallbackRouter = Router();

const callbackBodyParser = json({ limit: "15mb" });

function isValidReportShape(report: unknown): report is ScanReport {
  if (!report || typeof report !== "object") return false;
  const r = report as Record<string, unknown>;
  return Array.isArray(r.findings) && Array.isArray(r.passed) && typeof r.summary === "object" && r.summary !== null;
}

scanTaskCallbackRouter.post(
  "/api/internal/scan-tasks/:jobId/result",
  callbackBodyParser,
  asyncHandler(async (req: Request, res: Response) => {
    const token = req.get("X-Nettle-Scan-Callback-Token");
    if (!token) return res.status(404).json({ error: "Not found" });

    const report = req.body?.report;
    if (!isValidReportShape(report)) {
      return res.status(400).json({ error: "Malformed scan report" });
    }

    const claimed = resolvePendingScan(req.params.jobId, token, report);
    if (!claimed) return res.status(404).json({ error: "Not found" });

    res.status(204).end();
  })
);

scanTaskCallbackRouter.post(
  "/api/internal/scan-tasks/:jobId/error",
  callbackBodyParser,
  asyncHandler(async (req: Request, res: Response) => {
    const token = req.get("X-Nettle-Scan-Callback-Token");
    if (!token) return res.status(404).json({ error: "Not found" });

    const message = typeof req.body?.message === "string" ? req.body.message : "Scan task reported an unspecified error";

    const claimed = rejectPendingScan(req.params.jobId, token, message);
    if (!claimed) return res.status(404).json({ error: "Not found" });

    res.status(204).end();
  })
);
