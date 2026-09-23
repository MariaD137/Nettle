import { Router } from "express";
import { createProject, getProject, listProjectsByUser, updateProject, deleteProject, archiveProject, restoreProject, rotateApiKey, countProjectsByUser } from "../patrol/projects";
import { listAlerts, getAlert, updateAlertStatus, countAlertsByStatus, createAlert, hasRecentAlert } from "../patrol/alerts";
import { listScans, getLatestScan, type StoredScan } from "../patrol/scans";
import { computeBadgeState } from "../patrol/badge";
import { hashFinding, upsertFindingStatus, listFindingStatuses } from "../patrol/findingStatuses";
import { requireAuth } from "../auth/middleware";
import { requireSubscription } from "../billing/subscription";
import { getQuotaState } from "../billing/scanQuota";
import { rateLimit } from "../middleware/rateLimit";
import { hydrateCheckResult, hydrateCheckResults } from "../scanner/controls";
import { compareScans, ScanComparisonError, type ComparisonFinding } from "../scanner/scanComparison";
import type { AlertStatus, AlertSeverity, FindingStatus } from "../patrol/types";

export const projectsRouter = Router();

// Dashboard CRUD had no rate limiting at all before this — scans, badge and
// event-ingestion did. Keyed by account (available here since this always
// runs after requireAuth), not IP: these are all authenticated routes, and
// account-keying keeps unrelated customers behind the same corporate NAT
// from throttling each other, matching the pattern scans.routes.ts already
// uses. Generous, since this covers ordinary dashboard usage (loading
// projects, scans, alerts), not an expensive operation like a scan.
const dashboardLimiter = rateLimit({
  windowMs: 60 * 1000,
  maxRequests: 120,
  message: "Too many requests — try again shortly",
  scope: "projects:dashboard",
  keyFn: (req) => (req.userId ? `user:${req.userId}` : null),
});

// The paywall (and now the dashboard rate limiter) runs per-route rather
// than as router-level middleware. Two reasons it has to: this router is
// mounted at the app root, so a bare .use() would intercept every request in
// the app (signup included, and it would run before requireAuth has even
// set req.userId), and the public badge endpoints in badge.routes.ts share
// the /api/projects prefix, so even a path-scoped .use() would lock those
// embeds behind the paywall. Every route below therefore states the gate
// explicitly — new routes must too.
const paywalled = [requireAuth, dashboardLimiter, requireSubscription];

const PLAN_LIMITS: Record<string, number> = { free: 3, tier1: 10, tier2: 50 };

/**
 * Every route here sits behind requireSubscription, so unlike
 * routes/scans.routes.ts's respondWithScan there's no free-tier trimming to
 * apply — a caller who reaches this route is already entitled to the full
 * report. What's still missing without this is hydration: a scan stored via
 * recordScan() carries the raw checkResults from the scan pipeline, with a
 * controlKey but no recommendation attached (hydration happens at the
 * response boundary, not before storage — see routes/scans.routes.ts). The
 * Fix Center needs that recommendation for stored/historical scans, not
 * just freshly-run ones, so it's added here the same way.
 */
function hydrateStoredScan(scan: StoredScan | null): StoredScan | null {
  if (!scan || !scan.report.checkResults) return scan;
  return {
    ...scan,
    report: {
      ...scan.report,
      checkResults: hydrateCheckResults(scan.report.checkResults, {
        detectedTechnology: scan.report.detectedTechnology ?? undefined,
      }),
    },
  };
}

projectsRouter.post("/api/projects", ...paywalled, async (req, res) => {
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
    description: typeof req.body?.description === "string" ? req.body.description.trim() : undefined,
    environment: typeof req.body?.environment === "string" ? req.body.environment : undefined,
  });
  res.status(201).json(project);
});

projectsRouter.get("/api/projects", ...paywalled, async (req, res) => {
  const includeArchived = req.query.includeArchived === "true";
  res.json({ projects: await listProjectsByUser(req.userId!, includeArchived) });
});

async function ownedProjectOr404(req: import("express").Request, res: import("express").Response) {
  const project = await getProject(req.params.id);
  if (!project || project.userId !== req.userId) {
    res.status(404).json({ error: "Project not found" });
    return null;
  }
  return project;
}

projectsRouter.get("/api/projects/:id", ...paywalled, async (req, res) => {
  const project = await ownedProjectOr404(req, res);
  if (!project) return;
  const badge = await computeBadgeState(project.id);
  const latestScan = hydrateStoredScan(await getLatestScan(project.id));
  const alertCounts = await countAlertsByStatus(project.id);
  res.json({ project, badge, latestScan, alertCounts });
});

projectsRouter.patch("/api/projects/:id", ...paywalled, async (req, res) => {
  const project = await ownedProjectOr404(req, res);
  if (!project) return;
  const updates: Record<string, string | undefined> = {};
  if (typeof req.body?.name === "string") updates.name = req.body.name.trim();
  if (typeof req.body?.url === "string") updates.url = req.body.url.trim();
  if (typeof req.body?.description === "string") updates.description = req.body.description.trim();
  if (typeof req.body?.environment === "string") updates.environment = req.body.environment;
  const updated = await updateProject(project.id, updates);
  res.json(updated);
});

projectsRouter.delete("/api/projects/:id", ...paywalled, async (req, res) => {
  const project = await ownedProjectOr404(req, res);
  if (!project) return;
  await deleteProject(project.id);
  res.status(204).end();
});

projectsRouter.post("/api/projects/:id/archive", ...paywalled, async (req, res) => {
  const project = await ownedProjectOr404(req, res);
  if (!project) return;
  const archived = await archiveProject(project.id);
  res.json(archived);
});

projectsRouter.post("/api/projects/:id/restore", ...paywalled, async (req, res) => {
  const project = await ownedProjectOr404(req, res);
  if (!project) return;
  const restored = await restoreProject(project.id);
  res.json(restored);
});

projectsRouter.post("/api/projects/:id/rotate-key", ...paywalled, async (req, res) => {
  const project = await ownedProjectOr404(req, res);
  if (!project) return;
  const updated = await rotateApiKey(project.id);
  res.json(updated);
});

projectsRouter.get("/api/projects/:id/alerts", ...paywalled, async (req, res) => {
  const project = await ownedProjectOr404(req, res);
  if (!project) return;
  res.json({ project: { id: project.id, name: project.name }, alerts: await listAlerts(project.id) });
});

projectsRouter.patch("/api/projects/:id/alerts/:alertId", ...paywalled, async (req, res) => {
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
});

projectsRouter.get("/api/projects/:id/scans", ...paywalled, async (req, res) => {
  const project = await ownedProjectOr404(req, res);
  if (!project) return;
  const scans = (await listScans(project.id)).map(hydrateStoredScan) as StoredScan[];
  res.json({ project: { id: project.id, name: project.name }, scans });
});

/**
 * Attaches the same technology-aware recommendation the Fix Center shows for
 * a live/stored scan (see hydrateStoredScan above) to every finding in a
 * comparison bucket — a FIXED or REGRESSED item keeps its original recommendation
 * available rather than only being useful while it was currently failing (§24).
 */
function hydrateComparisonList(list: ComparisonFinding[], detectedTechnology: string | undefined): ComparisonFinding[] {
  return list.map((item) => ({
    ...item,
    finding: hydrateCheckResult(item.finding, { detectedTechnology }),
    baseline: item.baseline ? hydrateCheckResult(item.baseline, { detectedTechnology }) : undefined,
    current: item.current ? hydrateCheckResult(item.current, { detectedTechnology }) : undefined,
  }));
}

projectsRouter.get("/api/projects/:id/scans/compare", ...paywalled, async (req, res) => {
  const project = await ownedProjectOr404(req, res);
  if (!project) return;
  // listScans is already project-scoped (§21): a from/to id belonging to
  // another project simply won't be found in this array, so compareScans
  // throws SCAN_NOT_FOUND below rather than ever comparing across tenants.
  const scans = await listScans(project.id);
  if (scans.length < 2) {
    return res.status(400).json({ error: "Need at least 2 scans to compare" });
  }
  // scans is newest-first; index 1/0 preserves this endpoint's previous
  // default of "baseline = second-most-recent, current = most recent".
  const baselineId = typeof req.query.from === "string" ? req.query.from : scans[1].id;
  const currentId = typeof req.query.to === "string" ? req.query.to : scans[0].id;

  let comparison;
  try {
    comparison = compareScans(scans, baselineId, currentId);
  } catch (err) {
    if (err instanceof ScanComparisonError) {
      return res.status(err.code === "SCAN_NOT_FOUND" ? 404 : 400).json({ error: err.message });
    }
    throw err;
  }

  const currentScan = scans.find((s) => s.id === comparison.currentScanId);
  const detectedTechnology = currentScan?.report.detectedTechnology ?? undefined;

  // Extend the existing alerts mechanism rather than build a separate audit
  // log (§25): a regression is exactly the kind of event the Alerts tab
  // already exists to surface. Deduped per fingerprint over an hour so
  // reloading this comparison repeatedly doesn't spam the alert log.
  for (const r of comparison.regressed) {
    const rule = `finding_regressed:${r.fingerprint}`;
    if (!(await hasRecentAlert(project.id, rule, 3600))) {
      const severity: AlertSeverity = (r.finding.severity as AlertSeverity) ?? "medium";
      await createAlert(project.id, severity, rule, `A previously fixed finding has returned: ${r.finding.title}`);
    }
  }

  res.json({
    ...comparison,
    fixed: hydrateComparisonList(comparison.fixed, detectedTechnology),
    stillOpen: hydrateComparisonList(comparison.stillOpen, detectedTechnology),
    new: hydrateComparisonList(comparison.new, detectedTechnology),
    regressed: hydrateComparisonList(comparison.regressed, detectedTechnology),
    changed: hydrateComparisonList(comparison.changed, detectedTechnology),
    notVerified: hydrateComparisonList(comparison.notVerified, detectedTechnology),
  });
});

projectsRouter.get("/api/projects/:id/findings", ...paywalled, async (req, res) => {
  const project = await ownedProjectOr404(req, res);
  if (!project) return;
  const statuses = await listFindingStatuses(project.id);
  res.json({ findingStatuses: statuses });
});

projectsRouter.patch("/api/projects/:id/findings/:findingHash", ...paywalled, async (req, res) => {
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
});

projectsRouter.get("/api/projects/:id/scans/:scanId/export", ...paywalled, async (req, res) => {
  const project = await ownedProjectOr404(req, res);
  if (!project) return;
  const scans = await listScans(project.id);
  const scan = scans.find((s) => s.id === req.params.scanId);
  if (!scan) return res.status(404).json({ error: "Scan not found" });

  res.setHeader("Content-Type", "application/json");
  res.setHeader("Content-Disposition", `attachment; filename="nettle-report-${scan.id}.json"`);
  res.json(scan.report);
});

projectsRouter.get("/api/overview", ...paywalled, async (req, res) => {
  const projects = await listProjectsByUser(req.userId!);

  let totalCritical = 0;
  let totalHigh = 0;
  let totalNewAlerts = 0;
  let latestScore: number | null = null;
  let latestScanAt: string | null = null;

  // Must be awaited before res.json() below reads totalCritical/totalHigh/
  // totalNewAlerts/latestScore/latestScanAt: a plain projects.map(async...)
  // returns an array of pending Promises immediately, without running any of
  // the callback bodies first. That meant this route always serialized
  // "projects": [{}, {}, ...] (JSON.stringify on a Promise has no enumerable
  // properties) and always reported 0/null for every aggregate stat,
  // regardless of what was actually in the database -- the dashboard has
  // never shown a real badge or a real stat. Caught via an actual browser
  // render (BadgePill crashing on `state.status` of an empty object), not by
  // the existing test, which only asserted totalProjects -- the one field
  // this bug didn't touch, since it comes from projects.length, not the map.
  const projectSummaries = await Promise.all(projects.map(async (p) => {
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
      badge,
      latestScore: latest?.score ?? null,
      lastScannedAt: latest?.scannedAt ?? null,
      newAlerts: alertCounts.new,
    };
  }));

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
});
