import { Router } from "express";
import { db } from "../db/index";
import { getQueueStats } from "../jobs/scanJobs";
import { asyncHandler } from "../middleware/asyncHandler";

export const healthRouter = Router();

const processStartedAt = Date.now();

// Deliberately public and deliberately minimal: real signal an
// uptime/orchestration check (App Runner health check, a status page)
// needs, and nothing an unauthenticated caller shouldn't see — no secret
// names, no env values, no counts scoped to a specific customer, no stack
// traces. Anything more detailed lives behind /api/admin/*.
healthRouter.get("/health", asyncHandler(async (_req, res) => {
  let dbOk = true;
  try {
    await db.prepare("SELECT 1").get();
  } catch {
    dbOk = false;
  }

  const status = dbOk ? "ok" : "degraded";
  res.status(dbOk ? 200 : 503).json({
    status,
    timestamp: new Date().toISOString(),
    uptimeSeconds: Math.round((Date.now() - processStartedAt) / 1000),
    database: dbOk ? "ok" : "unreachable",
    scanQueue: getQueueStats(),
  });
}));
