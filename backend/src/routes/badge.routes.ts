import { Router } from "express";
import { getProject } from "../patrol/projects";
import { computeBadgeState, renderBadgeSVG } from "../patrol/badge";
import { rateLimit } from "../middleware/rateLimit";

export const badgeRouter = Router();

/**
 * Keyed by IP, not by project id. The badge is embedded via a plain <img> on
 * customer sites and viewed by many different real visitors' browsers — a
 * popular page can legitimately generate many requests for the SAME project
 * from many DIFFERENT visitor IPs, and none of that should be throttled.
 * IP-keying only catches the actual abuse case (one scripted client hammering
 * the endpoint), not organic traffic to a well-embedded badge.
 *
 * 60/min per IP is generous for a real visitor (one page load = one badge
 * request; even someone repeatedly refreshing wouldn't get near this) while
 * still bounding a single scripted source.
 */
const badgeLimiter = rateLimit({
  windowMs: 60 * 1000,
  maxRequests: 60,
  message: "Too many badge requests — try again shortly",
  scope: "badge",
});

// Deliberately public, no auth — this is meant to be embedded with a plain
// <img> tag on a customer's own site, which can't attach an Authorization
// header. The project ID in the URL is not a secret (unlike the API key
// used for event ingestion); it only reveals a pass/fail badge state.

badgeRouter.get("/api/projects/:id/badge.svg", badgeLimiter, async (req, res) => {
  const project = await getProject(req.params.id);
  if (!project) return res.status(404).end();

  const state = await computeBadgeState(project.id);
  res.setHeader("Content-Type", "image/svg+xml");
  // The badge's whole purpose is to be embedded with a plain <img> on a
  // customer's own site, so it must opt out of the same-origin
  // Cross-Origin-Resource-Policy helmet applies to every other response.
  res.setHeader("Cross-Origin-Resource-Policy", "cross-origin");
  res.setHeader("Cache-Control", "no-cache, max-age=0"); // status can change any time an alert fires
  res.send(renderBadgeSVG(state));
});

badgeRouter.get("/api/projects/:id/badge.json", badgeLimiter, async (req, res) => {
  const project = await getProject(req.params.id);
  if (!project) return res.status(404).json({ error: "Project not found" });

  res.setHeader("Cache-Control", "no-cache, max-age=0");
  res.setHeader("Cross-Origin-Resource-Policy", "cross-origin");
  res.json(await computeBadgeState(project.id));
});
