import { Router } from "express";
import { findProjectByApiKey } from "../patrol/projects";
import { recordEvent } from "../patrol/events";
import { enqueueDetection } from "../patrol/detectionQueue";
import type { IncomingEvent } from "../patrol/types";
import { rateLimit } from "../middleware/rateLimit";
import { getUserById } from "../auth/users";
import { entitledPlan } from "../billing/subscription";
import { canUseContinuousMonitoring } from "../billing/entitlements";

export const eventsRouter = Router();

/**
 * This endpoint is designed to receive a continuous stream — the Tier 2
 * monitoring middleware customers install calls it once per HTTP request
 * their own app serves, so a busy customer can legitimately generate many
 * requests per second. A tight per-minute cap here would break the product's
 * core feature, not just abuse.
 *
 * So this is a circuit breaker, not a precise throttle: generous enough
 * (10 req/s sustained) that no realistic legitimate integration should ever
 * approach it, but bounded so a misconfigured integration stuck in a retry
 * loop, or a leaked API key being flooded, cannot consume unbounded compute.
 *
 * Keyed by the API key itself where one is present — a customer's events can
 * legitimately originate from many servers/IPs behind a load balancer, all
 * sharing one project's key, so IP-keying would fragment (and under-protect)
 * a single customer's real traffic. An invalid or missing key falls back to
 * IP, since at that point there is no project identity to key on yet and the
 * request is about to be rejected by the 401 checks below anyway — this just
 * stops someone hammering the endpoint with garbage keys from consuming
 * unbounded lookups.
 */
const eventsLimiter = rateLimit({
  windowMs: 60 * 1000,
  maxRequests: 600,
  message: "Too many events submitted — try again shortly",
  scope: "events:ingest",
  keyFn: (req) => {
    const apiKey = req.header("x-nettle-api-key");
    return apiKey ? `key:${apiKey}` : `ip:${req.ip ?? "unknown"}`;
  },
});

function isValidEvent(body: unknown): body is IncomingEvent {
  if (!body || typeof body !== "object") return false;
  const b = body as Record<string, unknown>;
  return (
    typeof b.ip === "string" &&
    typeof b.method === "string" &&
    typeof b.path === "string" &&
    typeof b.statusCode === "number"
  );
}

eventsRouter.post("/api/events", eventsLimiter, async (req, res) => {
  const apiKey = req.header("x-nettle-api-key");
  if (!apiKey) {
    return res.status(401).json({ error: "Missing X-Nettle-Api-Key header" });
  }
  const project = await findProjectByApiKey(apiKey);
  if (!project) {
    return res.status(401).json({ error: "Invalid API key" });
  }

  // Continuous monitoring/event ingestion is PROTECT-only (§8). Gated on the
  // project owner's entitled plan, same as everything else per-project —
  // Phase D scoped MVP keeps billing per-user, not per-org.
  const owner = await getUserById(project.userId);
  const plan = entitledPlan(owner);
  if (!canUseContinuousMonitoring(plan)) {
    return res.status(402).json({
      error: "Continuous monitoring requires an active PROTECT subscription",
      subscriptionRequired: true,
      requiredPlan: "protect",
      plan,
    });
  }

  if (!isValidEvent(req.body)) {
    return res.status(400).json({ error: "Expected { ip, method, path, statusCode, userAgent? }" });
  }

  const stored = await recordEvent(project.id, req.body);

  // Detection runs off the request's critical path (see
  // patrol/detectionQueue.ts) — the response no longer waits on it, so it
  // can't report newAlerts synchronously here. The nettleMonitor SDK never
  // read that field anyway (it's fire-and-forget on the customer's side);
  // alerts are visible via GET /api/projects/:id/alerts once detection has
  // run.
  enqueueDetection(project.id, stored);

  res.status(202).json({ recorded: true });
});
