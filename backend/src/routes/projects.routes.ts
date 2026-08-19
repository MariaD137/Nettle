import { Router, Request, Response } from "express";
import { createProject, listProjectsByUser, updateProject, deleteProject, archiveProject, restoreProject, rotateApiKey, countProjectsByUser, setRepoAccessToken, setDefaultApiKeyValue } from "../patrol/projects";
import { getOwnedProject } from "../patrol/projectAccess";
import { MissingEncryptionKeyError } from "../security/tokenEncryption";
import { listAlerts, getAlert, updateAlertStatus, countAlertsByStatus } from "../patrol/alerts";
import { getAlertAnalytics } from "../patrol/alertAnalytics";
import { listScans, getLatestScan } from "../patrol/scans";
import { computeBadgeState } from "../patrol/badge";
import { hashFinding, upsertFindingStatus, listFindingStatuses } from "../patrol/findingStatuses";
import { listFindingHistory } from "../patrol/findingHistory";
import { createApiKey, listApiKeys, getApiKeyRecord, updateApiKey, revokeApiKey, rotateApiKeyById } from "../patrol/apiKeys";
import { getDetectionSettings, updateDetectionSettings, resetDetectionSettings } from "../patrol/detectionSettings";
import { requireAuth } from "../auth/middleware";
import { requireSubscription } from "../billing/subscription";
import { getQuotaState } from "../billing/scanQuota";
import type { AlertStatus, FindingStatus } from "../patrol/types";
import { computeChangeIntelligence } from "../scanner/changeIntelligence";
import { asyncHandler } from "../middleware/asyncHandler";

export const projectsRouter = Router();

// The paywall runs per-route rather than as router-level middleware. Two
// reasons it has to: this router is mounted at the app root, so a bare
// .use() would intercept every request in the app (signup included), and the
// public badge endpoints in badge.routes.ts share the /api/projects prefix,
// so even a path-scoped .use() would lock those embeds behind the paywall.
// Every route below therefore states the gate explicitly — new routes must
// too.
const paywalled = [requireAuth, requireSubscription];

const PLAN_LIMITS: Record<string, number> = { free: 3, tier1: 10, tier2: 50 };

projectsRouter.post("/api/projects", ...paywalled, asyncHandler(async (req, res) => {
  const name = typeof req.body?.name === "string" ? req.body.name.trim() : "";
  if (!name) {
    return res.status(400).json({ error: "Provide a project 'name'" });
  }

  const user = req as any;
  const limit = PLAN_LIMITS[user.userPlan ?? "free"] ?? 3;
  const count = await countProjectsByUser(req.userId!);
  if (count >= limit) {
    return res.status(403).json({ error: `Project limit reached (${limit}). Upgrade your plan to add more.` });
  }

  const project = await createProject(req.userId!, name, {
    url: typeof req.body?.url === "string" ? req.body.url.trim() : undefined,
    repoUrl: typeof req.body?.repoUrl === "string" ? req.body.repoUrl.trim() : undefined,
    repoBranch: typeof req.body?.repoBranch === "string" ? req.body.repoBranch.trim() : undefined,
    description: typeof req.body?.description === "string" ? req.body.description.trim() : undefined,
    environment: typeof req.body?.environment === "string" ? req.body.environment : undefined,
  });
  res.status(201).json(project);
}));

projectsRouter.get("/api/projects", ...paywalled, asyncHandler(async (req, res) => {
  const includeArchived = req.query.includeArchived === "true";
  res.json({ projects: await listProjectsByUser(req.userId!, includeArchived) });
}));

async function ownedProjectOr404(req: Request, res: Response) {
  const project = await getOwnedProject(req.params.id, req.userId);
  if (!project) {
    res.status(404).json({ error: "Project not found" });
    return null;
  }
  return project;
}

projectsRouter.get("/api/projects/:id", ...paywalled, asyncHandler(async (req, res) => {
  const project = await ownedProjectOr404(req, res);
  if (!project) return;
  const badge = await computeBadgeState(project.id);
  const latestScan = await getLatestScan(project.id);
  const alertCounts = await countAlertsByStatus(project.id);
  res.json({ project, badge, latestScan, alertCounts });
}));

projectsRouter.patch("/api/projects/:id", ...paywalled, asyncHandler(async (req, res) => {
  const project = await ownedProjectOr404(req, res);
  if (!project) return;
  const updates: Record<string, string | undefined> = {};
  if (typeof req.body?.name === "string") updates.name = req.body.name.trim();
  if (typeof req.body?.url === "string") updates.url = req.body.url.trim();
  if (typeof req.body?.repoUrl === "string") updates.repoUrl = req.body.repoUrl.trim();
  if (typeof req.body?.repoBranch === "string") updates.repoBranch = req.body.repoBranch.trim();
  if (typeof req.body?.description === "string") updates.description = req.body.description.trim();
  if (typeof req.body?.environment === "string") updates.environment = req.body.environment;
  let updated = await updateProject(project.id, updates);

  // Handled separately from the generic `updates` above so the encryption
  // step lives in exactly one place (patrol/projects.ts) — an empty string
  // clears a previously-stored token, a non-empty one replaces it, and
  // omitting the field entirely (the normal case: the user didn't touch
  // this field) leaves whatever is already stored untouched.
  if (typeof req.body?.repoAccessToken === "string") {
    try {
      updated = await setRepoAccessToken(project.id, req.body.repoAccessToken || null);
    } catch (err) {
      if (err instanceof MissingEncryptionKeyError) {
        return res.status(500).json({ error: err.message });
      }
      throw err;
    }
  }

  res.json(updated);
}));

projectsRouter.delete("/api/projects/:id", ...paywalled, asyncHandler(async (req, res) => {
  const project = await ownedProjectOr404(req, res);
  if (!project) return;
  await deleteProject(project.id);
  res.status(204).end();
}));

projectsRouter.post("/api/projects/:id/archive", ...paywalled, asyncHandler(async (req, res) => {
  const project = await ownedProjectOr404(req, res);
  if (!project) return;
  const archived = await archiveProject(project.id);
  res.json(archived);
}));

projectsRouter.post("/api/projects/:id/restore", ...paywalled, asyncHandler(async (req, res) => {
  const project = await ownedProjectOr404(req, res);
  if (!project) return;
  const restored = await restoreProject(project.id);
  res.json(restored);
}));

projectsRouter.post("/api/projects/:id/rotate-key", ...paywalled, asyncHandler(async (req, res) => {
  const project = await ownedProjectOr404(req, res);
  if (!project) return;
  const updated = await rotateApiKey(project.id);
  res.json(updated);
}));

// Fetches a key and verifies it actually belongs to the project in the
// URL — a valid keyId alone isn't sufficient to authorize access to it.
async function ownedApiKeyOr404(req: Request, res: Response, projectId: string) {
  const key = await getApiKeyRecord(req.params.keyId);
  if (!key || key.projectId !== projectId) {
    res.status(404).json({ error: "API key not found" });
    return null;
  }
  return key;
}

projectsRouter.post("/api/projects/:id/api-keys", ...paywalled, asyncHandler(async (req, res) => {
  const project = await ownedProjectOr404(req, res);
  if (!project) return;
  const name = typeof req.body?.name === "string" ? req.body.name.trim() : "";
  if (!name) {
    return res.status(400).json({ error: "Provide a key 'name'" });
  }
  const created = await createApiKey(project.id, name, req.body?.scopes);
  res.status(201).json({ apiKey: created });
}));

projectsRouter.get("/api/projects/:id/api-keys", ...paywalled, asyncHandler(async (req, res) => {
  const project = await ownedProjectOr404(req, res);
  if (!project) return;
  res.json({ apiKeys: await listApiKeys(project.id) });
}));

projectsRouter.patch("/api/projects/:id/api-keys/:keyId", ...paywalled, asyncHandler(async (req, res) => {
  const project = await ownedProjectOr404(req, res);
  if (!project) return;
  if (!(await ownedApiKeyOr404(req, res, project.id))) return;
  const updates: { name?: string; scopes?: unknown } = {};
  if (typeof req.body?.name === "string") updates.name = req.body.name;
  if (req.body?.scopes !== undefined) updates.scopes = req.body.scopes;
  const updated = await updateApiKey(req.params.keyId, updates);
  res.json({ apiKey: updated });
}));

projectsRouter.post("/api/projects/:id/api-keys/:keyId/rotate", ...paywalled, asyncHandler(async (req, res) => {
  const project = await ownedProjectOr404(req, res);
  if (!project) return;
  const existing = await ownedApiKeyOr404(req, res, project.id);
  if (!existing) return;
  const rotated = await rotateApiKeyById(req.params.keyId);
  // Keep the legacy single-key field in sync if this happened to be the
  // project's default key — same mirroring rotateApiKey() (the
  // project-level endpoint above) already does in the other direction.
  if (rotated && existing.isDefault) {
    await setDefaultApiKeyValue(project.id, rotated.key);
  }
  res.json({ apiKey: rotated });
}));

projectsRouter.post("/api/projects/:id/api-keys/:keyId/revoke", ...paywalled, asyncHandler(async (req, res) => {
  const project = await ownedProjectOr404(req, res);
  if (!project) return;
  if (!(await ownedApiKeyOr404(req, res, project.id))) return;
  const revoked = await revokeApiKey(req.params.keyId);
  res.json({ apiKey: revoked });
}));

projectsRouter.get("/api/projects/:id/alerts", ...paywalled, asyncHandler(async (req, res) => {
  const project = await ownedProjectOr404(req, res);
  if (!project) return;
  res.json({ project: { id: project.id, name: project.name }, alerts: await listAlerts(project.id) });
}));

projectsRouter.patch("/api/projects/:id/alerts/:alertId", ...paywalled, asyncHandler(async (req, res) => {
  const project = await ownedProjectOr404(req, res);
  if (!project) return;

  const alert = await getAlert(req.params.alertId);
  if (!alert || alert.projectId !== project.id) {
    return res.status(404).json({ error: "Alert not found" });
  }

  const status = req.body?.status as AlertStatus;
  if (!status || !["new", "acknowledged", "resolved", "false_positive"].includes(status)) {
    return res.status(400).json({ error: 'status must be "new", "acknowledged", "resolved", or "false_positive"' });
  }

  const updated = await updateAlertStatus(alert.id, status);
  res.json({ alert: updated });
}));

projectsRouter.get("/api/projects/:id/alerts/analytics", ...paywalled, asyncHandler(async (req, res) => {
  const project = await ownedProjectOr404(req, res);
  if (!project) return;
  const hours = Math.max(1, Math.min(720, parseInt(req.query.hours as string, 10) || 24));
  res.json({ analytics: await getAlertAnalytics(project.id, hours) });
}));

projectsRouter.get("/api/projects/:id/detection-settings", ...paywalled, asyncHandler(async (req, res) => {
  const project = await ownedProjectOr404(req, res);
  if (!project) return;
  res.json({ settings: await getDetectionSettings(project.id) });
}));

projectsRouter.patch("/api/projects/:id/detection-settings", ...paywalled, asyncHandler(async (req, res) => {
  const project = await ownedProjectOr404(req, res);
  if (!project) return;
  const updated = await updateDetectionSettings(project.id, {
    bruteForceThreshold: req.body?.bruteForceThreshold,
    highRequestRateThreshold: req.body?.highRequestRateThreshold,
    credentialStuffingMinIps: req.body?.credentialStuffingMinIps,
  });
  res.json({ settings: updated });
}));

projectsRouter.post("/api/projects/:id/detection-settings/reset", ...paywalled, asyncHandler(async (req, res) => {
  const project = await ownedProjectOr404(req, res);
  if (!project) return;
  res.json({ settings: await resetDetectionSettings(project.id) });
}));

projectsRouter.get("/api/projects/:id/scans", ...paywalled, asyncHandler(async (req, res) => {
  const project = await ownedProjectOr404(req, res);
  if (!project) return;
  res.json({ project: { id: project.id, name: project.name }, scans: await listScans(project.id) });
}));

projectsRouter.get("/api/projects/:id/scans/compare", ...paywalled, asyncHandler(async (req, res) => {
  const project = await ownedProjectOr404(req, res);
  if (!project) return;
  const scans = await listScans(project.id);
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
    remainingFindings: remaining,
    changeIntelligence: computeChangeIntelligence(older, newer),
  });
}));

projectsRouter.get("/api/projects/:id/findings", ...paywalled, asyncHandler(async (req, res) => {
  const project = await ownedProjectOr404(req, res);
  if (!project) return;
  const statuses = await listFindingStatuses(project.id);
  const history = await listFindingHistory(project.id);
  res.json({ findingStatuses: statuses, findingHistory: history });
}));

projectsRouter.patch("/api/projects/:id/findings/:findingHash", ...paywalled, asyncHandler(async (req, res) => {
  const project = await ownedProjectOr404(req, res);
  if (!project) return;
  const status = req.body?.status as FindingStatus;
  const validStatuses: FindingStatus[] = ["open", "in_progress", "resolved", "false_positive", "accepted_risk"];
  if (!status || !validStatuses.includes(status)) {
    return res.status(400).json({ error: 'status must be "open", "in_progress", "resolved", "false_positive", or "accepted_risk"' });
  }
  const notes = typeof req.body?.notes === "string" ? req.body.notes : undefined;
  const result = await upsertFindingStatus(project.id, req.params.findingHash, status, notes);
  res.json({ findingStatus: result });
}));

projectsRouter.get("/api/projects/:id/scans/:scanId/export", ...paywalled, asyncHandler(async (req, res) => {
  const project = await ownedProjectOr404(req, res);
  if (!project) return;
  const scans = await listScans(project.id);
  const scan = scans.find((s) => s.id === req.params.scanId);
  if (!scan) return res.status(404).json({ error: "Scan not found" });

  res.setHeader("Content-Type", "application/json");
  res.setHeader("Content-Disposition", `attachment; filename="nettle-report-${scan.id}.json"`);
  res.json(scan.report);
}));

projectsRouter.get("/api/overview", ...paywalled, asyncHandler(async (req, res) => {
  const projects = await listProjectsByUser(req.userId!);

  let totalCritical = 0;
  let totalHigh = 0;
  let totalNewAlerts = 0;
  let latestScore: number | null = null;
  let latestScanAt: string | null = null;

  const projectSummaries = await Promise.all(
    projects.map(async (p) => {
      const badge = await computeBadgeState(p.id);
      const latest = await getLatestScan(p.id);
      const alertCounts = await countAlertsByStatus(p.id);

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
        environment: p.environment,
        badge,
        latestScore: latest?.score ?? null,
        lastScannedAt: latest?.scannedAt ?? null,
        newAlerts: alertCounts.new,
      };
    })
  );

  res.json({
    quota: await getQuotaState(req.userId!),
    totalProjects: projects.length,
    totalCriticalFindings: totalCritical,
    totalHighFindings: totalHigh,
    totalNewAlerts,
    latestScore,
    latestScanAt,
    projects: projectSummaries,
  });
}));
