import { Router } from "express";
import { createProject, getProject, listAccessibleProjects, updateProject, deleteProject, archiveProject, restoreProject, rotateApiKey, countProjectsByUser, canAccessProject } from "../patrol/projects";
import { isMember } from "../organizations/organizations";
import { listAlerts, getAlert, updateAlertStatus, countAlertsByStatus, createAlert, hasRecentAlert } from "../patrol/alerts";
import { listScans, getLatestScan, type StoredScan } from "../patrol/scans";
import { computeBadgeState } from "../patrol/badge";
import { hashFinding, upsertFindingStatus, listFindingStatuses } from "../patrol/findingStatuses";
import { requireAuth } from "../auth/middleware";
import { requireSubscription, requireProtect, entitledPlan } from "../billing/subscription";
import { canCreateProject, canUseFixCenter, getMaxProjects } from "../billing/entitlements";
import { getUserById } from "../auth/users";
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

// Two gate levels, not one, now that FREE is a real (capped) dashboard tier
// rather than turned away entirely (pricing rework — see billing/
// entitlements.ts):
//   dashboardAccess — requireAuth only. Basic project management (create up
//     to your plan's limit, list, view, edit, archive, delete) is something
//     every signed-in account gets, FREE included.
//   paywalled — requireAuth + requireSubscription (BUILD or PROTECT). Stays
//     on the routes the pricing model marks BUILD+ specifically: Fix Center
//     findings, scan history, comparisons, exports, alert management.
//
// Both run per-route rather than as router-level middleware, for the same
// two reasons as before this split: this router is mounted at the app root
// (a bare .use() would intercept signup etc., before requireAuth has even
// set req.userId), and the public badge endpoints in badge.routes.ts share
// the /api/projects prefix, so even a path-scoped .use() would lock those
// embeds behind auth. Every route below therefore states its gate
// explicitly — new routes must too.
const dashboardAccess = [requireAuth, dashboardLimiter];
const paywalled = [...dashboardAccess, requireSubscription];
// Continuous monitoring's alerts — PROTECT-only (see billing/subscription.ts's requireProtect).
const protectOnly = [...dashboardAccess, requireProtect];

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

projectsRouter.post("/api/projects", ...dashboardAccess, async (req, res) => {
  const name = typeof req.body?.name === "string" ? req.body.name.trim() : "";
  if (!name) {
    return res.status(400).json({ error: "Provide a project 'name'" });
  }

  const organizationId = typeof req.body?.organizationId === "string" ? req.body.organizationId : undefined;
  if (organizationId && !(await isMember(organizationId, req.userId!))) {
    return res.status(403).json({ error: "You are not a member of that organization" });
  }

  // Plan limits stay per-user even for an org project (Phase D scoped MVP
  // doesn't move billing to the organization) — the creating user's own
  // entitled plan/count is what's checked, same as a personal project.
  // entitledPlan(), never req.userPlan: that field is the *recorded* plan
  // (users.plan, what was last purchased), and a lapsed BUILD/PROTECT
  // account reading it here would keep the higher limit indefinitely after
  // its subscription actually ended — the exact bug entitledPlan() exists
  // to prevent (see billing/subscription.ts).
  const requester = await getUserById(req.userId!);
  const plan = entitledPlan(requester);
  const count = await countProjectsByUser(req.userId!);
  if (!canCreateProject(plan, count)) {
    const limit = getMaxProjects(plan);
    return res.status(403).json({
      error: `Project limit reached (${limit}). Upgrade your plan to add more.`,
      projectLimitReached: true,
      limit,
      plan,
    });
  }

  const project = await createProject(req.userId!, name, {
    url: typeof req.body?.url === "string" ? req.body.url.trim() : undefined,
    description: typeof req.body?.description === "string" ? req.body.description.trim() : undefined,
    environment: typeof req.body?.environment === "string" ? req.body.environment : undefined,
    organizationId,
  });
  res.status(201).json(project);
});

projectsRouter.get("/api/projects", ...dashboardAccess, async (req, res) => {
  const includeArchived = req.query.includeArchived === "true";
  res.json({ projects: await listAccessibleProjects(req.userId!, includeArchived) });
});

/**
 * Accessible, not "owned": a project reachable either because the caller
 * owns it personally, or because they're a member of the organization it
 * belongs to (see canAccessProject). Still a 404, not 403, for a project
 * that exists but the caller can't reach — same reasoning as before this
 * became org-aware: don't confirm the id exists to someone with no
 * relationship to it.
 */
async function accessibleProjectOr404(req: import("express").Request, res: import("express").Response) {
  const project = await getProject(req.params.id);
  if (!project || !(await canAccessProject(req.userId!, project))) {
    res.status(404).json({ error: "Project not found" });
    return null;
  }
  return project;
}

/**
 * The project detail view is reachable by any signed-in account (FREE
 * included), but latestScan is Fix Center content — full findings with
 * file-level evidence and remediation — and stays gated to BUILD/PROTECT.
 * This matters specifically for a downgraded account: its historical scans
 * are preserved (never deleted on downgrade), so without this check a
 * lapsed BUILD/PROTECT account would still see its last real Fix Center
 * report here even after losing entitlement to it. badge/alertCounts stay
 * visible to everyone — they're summary-level (a score, a count), not the
 * findings/evidence/remediation detail the pricing model actually restricts.
 */
projectsRouter.get("/api/projects/:id", ...dashboardAccess, async (req, res) => {
  const project = await accessibleProjectOr404(req, res);
  if (!project) return;
  const requester = await getUserById(req.userId!);
  const plan = entitledPlan(requester);
  const badge = await computeBadgeState(project.id);
  const latestScan = canUseFixCenter(plan) ? hydrateStoredScan(await getLatestScan(project.id)) : null;
  const alertCounts = await countAlertsByStatus(project.id);
  res.json({ project, badge, latestScan, alertCounts });
});

projectsRouter.patch("/api/projects/:id", ...dashboardAccess, async (req, res) => {
  const project = await accessibleProjectOr404(req, res);
  if (!project) return;
  const updates: Record<string, string | undefined> = {};
  if (typeof req.body?.name === "string") updates.name = req.body.name.trim();
  if (typeof req.body?.url === "string") updates.url = req.body.url.trim();
  if (typeof req.body?.description === "string") updates.description = req.body.description.trim();
  if (typeof req.body?.environment === "string") updates.environment = req.body.environment;
  const updated = await updateProject(project.id, updates);
  res.json(updated);
});

projectsRouter.delete("/api/projects/:id", ...dashboardAccess, async (req, res) => {
  const project = await accessibleProjectOr404(req, res);
  if (!project) return;
  await deleteProject(project.id);
  res.status(204).end();
});

projectsRouter.post("/api/projects/:id/archive", ...dashboardAccess, async (req, res) => {
  const project = await accessibleProjectOr404(req, res);
  if (!project) return;
  const archived = await archiveProject(project.id);
  res.json(archived);
});

projectsRouter.post("/api/projects/:id/restore", ...dashboardAccess, async (req, res) => {
  const project = await accessibleProjectOr404(req, res);
  if (!project) return;
  const restored = await restoreProject(project.id);
  res.json(restored);
});

projectsRouter.post("/api/projects/:id/rotate-key", ...dashboardAccess, async (req, res) => {
  const project = await accessibleProjectOr404(req, res);
  if (!project) return;
  const updated = await rotateApiKey(project.id);
  res.json(updated);
});

projectsRouter.get("/api/projects/:id/alerts", ...protectOnly, async (req, res) => {
  const project = await accessibleProjectOr404(req, res);
  if (!project) return;
  res.json({ project: { id: project.id, name: project.name }, alerts: await listAlerts(project.id) });
});

projectsRouter.patch("/api/projects/:id/alerts/:alertId", ...protectOnly, async (req, res) => {
  const project = await accessibleProjectOr404(req, res);
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
  const project = await accessibleProjectOr404(req, res);
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
  const project = await accessibleProjectOr404(req, res);
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
  const project = await accessibleProjectOr404(req, res);
  if (!project) return;
  const statuses = await listFindingStatuses(project.id);
  res.json({ findingStatuses: statuses });
});

projectsRouter.patch("/api/projects/:id/findings/:findingHash", ...paywalled, async (req, res) => {
  const project = await accessibleProjectOr404(req, res);
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
  const project = await accessibleProjectOr404(req, res);
  if (!project) return;
  const scans = await listScans(project.id);
  const scan = scans.find((s) => s.id === req.params.scanId);
  if (!scan) return res.status(404).json({ error: "Scan not found" });

  res.setHeader("Content-Type", "application/json");
  res.setHeader("Content-Disposition", `attachment; filename="nettle-report-${scan.id}.json"`);
  res.json(scan.report);
});

// Dashboard summary — reachable by every signed-in account, FREE included
// (see the "Do NOT show a blank application" requirement in the pricing
// spec). Only summary numbers (score, counts, badge state) come back here,
// never findings/evidence/remediation — that stays behind Fix Center
// gating on the routes that actually carry it.
projectsRouter.get("/api/overview", ...dashboardAccess, async (req, res) => {
  const projects = await listAccessibleProjects(req.userId!);

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
