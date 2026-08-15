import { Router } from "express";
import { createProject, getProject, listProjectsByUser } from "../patrol/projects";
import { listAlerts, getAlert, updateAlertStatus, countAlertsByStatus } from "../patrol/alerts";
import { listScans, getLatestScan } from "../patrol/scans";
import { computeBadgeState } from "../patrol/badge";
import { requireAuth } from "../auth/middleware";
import type { AlertStatus } from "../patrol/types";

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

projectsRouter.get("/api/projects/:id", requireAuth, (req, res) => {
  const project = ownedProjectOr404(req, res);
  if (!project) return;
  const badge = computeBadgeState(project.id);
  const latestScan = getLatestScan(project.id);
  const alertCounts = countAlertsByStatus(project.id);
  res.json({ project, badge, latestScan, alertCounts });
});

projectsRouter.get("/api/projects/:id/alerts", requireAuth, (req, res) => {
  const project = ownedProjectOr404(req, res);
  if (!project) return;
  res.json({ project: { id: project.id, name: project.name }, alerts: listAlerts(project.id) });
});

projectsRouter.patch("/api/projects/:id/alerts/:alertId", requireAuth, (req, res) => {
  const project = ownedProjectOr404(req, res);
  if (!project) return;

  const alert = getAlert(req.params.alertId);
  if (!alert || alert.projectId !== project.id) {
    return res.status(404).json({ error: "Alert not found" });
  }

  const status = req.body?.status as AlertStatus;
  if (!status || !["new", "acknowledged", "resolved", "false_positive"].includes(status)) {
    return res.status(400).json({ error: 'status must be "new", "acknowledged", "resolved", or "false_positive"' });
  }

  const updated = updateAlertStatus(alert.id, status);
  res.json({ alert: updated });
});

projectsRouter.get("/api/projects/:id/scans", requireAuth, (req, res) => {
  const project = ownedProjectOr404(req, res);
  if (!project) return;
  res.json({ project: { id: project.id, name: project.name }, scans: listScans(project.id) });
});

projectsRouter.get("/api/overview", requireAuth, (req, res) => {
  const projects = listProjectsByUser(req.userId!);

  let totalCritical = 0;
  let totalHigh = 0;
  let totalNewAlerts = 0;
  let latestScore: number | null = null;
  let latestScanAt: string | null = null;

  const projectSummaries = projects.map((p) => {
    const badge = computeBadgeState(p.id);
    const latest = getLatestScan(p.id);
    const alertCounts = countAlertsByStatus(p.id);

    totalNewAlerts += alertCounts.new;

    if (latest) {
      totalCritical += latest.criticalCount;
      totalHigh += latest.cautionCount;
      if (!latestScanAt || latest.scannedAt > latestScanAt) {
        latestScanAt = latest.scannedAt;
        latestScore = latest.score;
      }
    }

    return {
      id: p.id,
      name: p.name,
      badge,
      latestScore: latest?.score ?? null,
      lastScannedAt: latest?.scannedAt ?? null,
      newAlerts: alertCounts.new,
    };
  });

  res.json({
    totalProjects: projects.length,
    totalCriticalFindings: totalCritical,
    totalHighFindings: totalHigh,
    totalNewAlerts,
    latestScore,
    latestScanAt,
    projects: projectSummaries,
  });
});
