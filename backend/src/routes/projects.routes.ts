import { Router } from "express";
import { createProject, getProject, listProjectsByUser, updateProject, deleteProject, archiveProject, restoreProject, rotateApiKey, countProjectsByUser } from "../patrol/projects";
import { listAlerts, getAlert, updateAlertStatus, countAlertsByStatus } from "../patrol/alerts";
import { listScans, getLatestScan } from "../patrol/scans";
import { computeBadgeState } from "../patrol/badge";
import { hashFinding, upsertFindingStatus, listFindingStatuses } from "../patrol/findingStatuses";
import { requireAuth } from "../auth/middleware";
import type { AlertStatus, FindingStatus } from "../patrol/types";

export const projectsRouter = Router();

const PLAN_LIMITS: Record<string, number> = { free: 3, tier1: 10, tier2: 50 };

projectsRouter.post("/api/projects", requireAuth, (req, res) => {
  const name = typeof req.body?.name === "string" ? req.body.name.trim() : "";
  if (!name) {
    return res.status(400).json({ error: "Provide a project 'name'" });
  }

  const user = req as any;
  const limit = PLAN_LIMITS[user.userPlan ?? "free"] ?? 3;
  const count = countProjectsByUser(req.userId!);
  if (count >= limit) {
    return res.status(403).json({ error: `Project limit reached (${limit}). Upgrade your plan to add more.` });
  }

  const project = createProject(req.userId!, name, {
    url: typeof req.body?.url === "string" ? req.body.url.trim() : undefined,
    description: typeof req.body?.description === "string" ? req.body.description.trim() : undefined,
    environment: typeof req.body?.environment === "string" ? req.body.environment : undefined,
  });
  res.status(201).json(project);
});

projectsRouter.get("/api/projects", requireAuth, (req, res) => {
  const includeArchived = req.query.includeArchived === "true";
  res.json({ projects: listProjectsByUser(req.userId!, includeArchived) });
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

projectsRouter.patch("/api/projects/:id", requireAuth, (req, res) => {
  const project = ownedProjectOr404(req, res);
  if (!project) return;
  const updates: Record<string, string | undefined> = {};
  if (typeof req.body?.name === "string") updates.name = req.body.name.trim();
  if (typeof req.body?.url === "string") updates.url = req.body.url.trim();
  if (typeof req.body?.description === "string") updates.description = req.body.description.trim();
  if (typeof req.body?.environment === "string") updates.environment = req.body.environment;
  const updated = updateProject(project.id, updates);
  res.json(updated);
});

projectsRouter.delete("/api/projects/:id", requireAuth, (req, res) => {
  const project = ownedProjectOr404(req, res);
  if (!project) return;
  deleteProject(project.id);
  res.status(204).end();
});

projectsRouter.post("/api/projects/:id/archive", requireAuth, (req, res) => {
  const project = ownedProjectOr404(req, res);
  if (!project) return;
  const archived = archiveProject(project.id);
  res.json(archived);
});

projectsRouter.post("/api/projects/:id/restore", requireAuth, (req, res) => {
  const project = ownedProjectOr404(req, res);
  if (!project) return;
  const restored = restoreProject(project.id);
  res.json(restored);
});

projectsRouter.post("/api/projects/:id/rotate-key", requireAuth, (req, res) => {
  const project = ownedProjectOr404(req, res);
  if (!project) return;
  const updated = rotateApiKey(project.id);
  res.json(updated);
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

projectsRouter.get("/api/projects/:id/scans/compare", requireAuth, (req, res) => {
  const project = ownedProjectOr404(req, res);
  if (!project) return;
  const scans = listScans(project.id);
  if (scans.length < 2) {
    return res.status(400).json({ error: "Need at least 2 scans to compare" });
  }
  const fromIdx = typeof req.query.from === "string" ? scans.findIndex((s) => s.id === req.query.from) : 1;
  const toIdx = typeof req.query.to === "string" ? scans.findIndex((s) => s.id === req.query.to) : 0;
  if (fromIdx < 0 || toIdx < 0) {
    return res.status(404).json({ error: "Scan not found" });
  }
  const older = scans[fromIdx].report;
  const newer = scans[toIdx].report;

  const olderSet = new Set(older.findings.map((f) => `${f.category}::${f.title}::${f.file}`));
  const newerSet = new Set(newer.findings.map((f) => `${f.category}::${f.title}::${f.file}`));
  const fixed = older.findings.filter((f) => !newerSet.has(`${f.category}::${f.title}::${f.file}`));
  const newFindings = newer.findings.filter((f) => !olderSet.has(`${f.category}::${f.title}::${f.file}`));
  const remaining = newer.findings.filter((f) => olderSet.has(`${f.category}::${f.title}::${f.file}`));

  res.json({
    from: { id: scans[fromIdx].id, score: scans[fromIdx].score, scannedAt: scans[fromIdx].scannedAt },
    to: { id: scans[toIdx].id, score: scans[toIdx].score, scannedAt: scans[toIdx].scannedAt },
    scoreDelta: scans[toIdx].score - scans[fromIdx].score,
    fixed: fixed.length,
    new: newFindings.length,
    remaining: remaining.length,
    fixedFindings: fixed,
    newFindings,
  });
});

projectsRouter.get("/api/projects/:id/findings", requireAuth, (req, res) => {
  const project = ownedProjectOr404(req, res);
  if (!project) return;
  const statuses = listFindingStatuses(project.id);
  res.json({ findingStatuses: statuses });
});

projectsRouter.patch("/api/projects/:id/findings/:findingHash", requireAuth, (req, res) => {
  const project = ownedProjectOr404(req, res);
  if (!project) return;
  const status = req.body?.status as FindingStatus;
  const validStatuses: FindingStatus[] = ["open", "in_progress", "resolved", "false_positive", "accepted_risk"];
  if (!status || !validStatuses.includes(status)) {
    return res.status(400).json({ error: 'status must be "open", "in_progress", "resolved", "false_positive", or "accepted_risk"' });
  }
  const notes = typeof req.body?.notes === "string" ? req.body.notes : undefined;
  const result = upsertFindingStatus(project.id, req.params.findingHash, status, notes);
  res.json({ findingStatus: result });
});

projectsRouter.get("/api/projects/:id/scans/:scanId/export", requireAuth, (req, res) => {
  const project = ownedProjectOr404(req, res);
  if (!project) return;
  const scans = listScans(project.id);
  const scan = scans.find((s) => s.id === req.params.scanId);
  if (!scan) return res.status(404).json({ error: "Scan not found" });
  res.setHeader("Content-Type", "application/json");
  res.setHeader("Content-Disposition", `attachment; filename="nettle-report-${scan.id}.json"`);
  res.json(scan.report);
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
