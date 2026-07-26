import { Router } from "express";
import { createProject, getProject } from "../patrol/projects";
import { listAlerts } from "../patrol/alerts";

export const projectsRouter = Router();

// No auth on project creation yet — there are no accounts/billing at all
// today (see backend/README.md). Fine for early testing, not fine once this
// is reachable by the public internet with real traffic.
projectsRouter.post("/api/projects", (req, res) => {
  const name = typeof req.body?.name === "string" ? req.body.name.trim() : "";
  if (!name) {
    return res.status(400).json({ error: "Provide a project 'name'" });
  }
  const project = createProject(name);
  res.status(201).json(project);
});

projectsRouter.get("/api/projects/:id/alerts", (req, res) => {
  const project = getProject(req.params.id);
  if (!project) {
    return res.status(404).json({ error: "Project not found" });
  }
  res.json({ project: { id: project.id, name: project.name }, alerts: listAlerts(project.id) });
});
