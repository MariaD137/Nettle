import { Router } from "express";
import { createProject, getProject, listProjectsByUser } from "../patrol/projects";
import { listAlerts } from "../patrol/alerts";
import { listScans } from "../patrol/scans";
import { requireAuth } from "../auth/middleware";

export const projectsRouter = Router();

projectsRouter.post("/api/projects", requireAuth, (req, res) => {
  const name = typeof req.body?.name === "string" ? req.body.name.trim() : "";
  if (!name) {
    return res.status(400).json({ error: "Provide a project 'name'" });
  }
  const project = createProject(req.userId!, name);
  res.status(201).json(project);
});

projectsRouter.get("/api/projects", requireAuth, (req, res) => {
  res.json({ projects: listProjectsByUser(req.userId!) });
});

function ownedProjectOr404(req: import("express").Request, res: import("express").Response) {
  const project = getProject(req.params.id);
  if (!project || project.userId !== req.userId) {
    res.status(404).json({ error: "Project not found" });
    return null;
  }
  return project;
}

projectsRouter.get("/api/projects/:id/alerts", requireAuth, (req, res) => {
  const project = ownedProjectOr404(req, res);
  if (!project) return;
  res.json({ project: { id: project.id, name: project.name }, alerts: listAlerts(project.id) });
});

projectsRouter.get("/api/projects/:id/scans", requireAuth, (req, res) => {
  const project = ownedProjectOr404(req, res);
  if (!project) return;
  res.json({ project: { id: project.id, name: project.name }, scans: listScans(project.id) });
});
