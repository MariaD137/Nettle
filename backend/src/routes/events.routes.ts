import { Router } from "express";
import { findProjectByApiKey } from "../patrol/projects";
import { recordEvent } from "../patrol/events";
import { runDetection } from "../patrol/detection";
import type { IncomingEvent } from "../patrol/types";

export const eventsRouter = Router();

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

eventsRouter.post("/api/events", async (req, res) => {
  const apiKey = req.header("x-nettle-api-key");
  if (!apiKey) {
    return res.status(401).json({ error: "Missing X-Nettle-Api-Key header" });
  }
  const project = await findProjectByApiKey(apiKey);
  if (!project) {
    return res.status(401).json({ error: "Invalid API key" });
  }
  if (!isValidEvent(req.body)) {
    return res.status(400).json({ error: "Expected { ip, method, path, statusCode, userAgent? }" });
  }

  const stored = await recordEvent(project.id, req.body);
  const alerts = await runDetection(project.id, stored);

  res.status(202).json({ recorded: true, newAlerts: alerts });
});
