import { Router } from "express";
import { findProjectByApiKey } from "../patrol/projects";
import { recordEvent } from "../patrol/events";
import { runDetection } from "../patrol/detection";
import { rateLimit } from "../middleware/rateLimit";
import type { IncomingEvent } from "../patrol/types";

export const eventsRouter = Router();

// This is public-ingest, authenticated only by a project API key rather
// than a session — IP alone is the wrong unit to limit by (a customer's
// monitored app has one stable server IP shared across all its legitimate
// traffic, and a leaked/misbehaving key shouldn't cost every other
// customer sharing an egress IP their budget). Key by the API key instead,
// falling back to IP only when it's missing — which the handler below
// rejects anyway.
const eventsLimiter = rateLimit({
  windowMs: 60 * 1000,
  maxRequests: 120,
  message: "Too many events — slow down",
  keyGenerator: (req) => `${req.path}:${req.header("x-nettle-api-key") ?? req.ip}`,
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

eventsRouter.post("/api/events", eventsLimiter, (req, res) => {
  const apiKey = req.header("x-nettle-api-key");
  if (!apiKey) {
    return res.status(401).json({ error: "Missing X-Nettle-Api-Key header" });
  }
  const project = findProjectByApiKey(apiKey);
  if (!project) {
    return res.status(401).json({ error: "Invalid API key" });
  }
  if (!isValidEvent(req.body)) {
    return res.status(400).json({ error: "Expected { ip, method, path, statusCode, userAgent? }" });
  }

  const stored = recordEvent(project.id, req.body);
  const alerts = runDetection(project.id, stored);

  res.status(202).json({ recorded: true, newAlerts: alerts });
});
