import { Router } from "express";
import { getProject } from "../patrol/projects";
import { computeBadgeState, renderBadgeSVG } from "../patrol/badge";
import { rateLimit } from "../middleware/rateLimit";

export const badgeRouter = Router();

// Deliberately public, no auth — this is meant to be embedded with a plain
// <img> tag on a customer's own site, which can't attach an Authorization
// header. The project ID in the URL is not a secret (unlike the API key
// used for event ingestion); it only reveals a pass/fail badge state.
//
// Generous limit: real page views of a customer's site legitimately hit
// this (Cache-Control is no-cache, so every view is a fresh request), but
// it's still not unbounded — caps outright scripted abuse of one project's
// badge endpoint. The key includes the concrete path (project ID and all),
// so one popular project's traffic can't exhaust another project's budget.
badgeRouter.use(
  rateLimit({
    windowMs: 5 * 60 * 1000,
    maxRequests: 300,
    message: "Too many requests — try again shortly",
  })
);

badgeRouter.get("/api/projects/:id/badge.svg", (req, res) => {
  const project = getProject(req.params.id);
  if (!project) return res.status(404).end();

  const state = computeBadgeState(project.id);
  res.setHeader("Content-Type", "image/svg+xml");
  res.setHeader("Cache-Control", "no-cache, max-age=0"); // status can change any time an alert fires
  res.send(renderBadgeSVG(state));
});

badgeRouter.get("/api/projects/:id/badge.json", (req, res) => {
  const project = getProject(req.params.id);
  if (!project) return res.status(404).json({ error: "Project not found" });

  res.setHeader("Cache-Control", "no-cache, max-age=0");
  res.json(computeBadgeState(project.id));
});
