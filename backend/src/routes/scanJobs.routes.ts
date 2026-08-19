import { Router, type Request, type Response } from "express";
import fs from "fs";
import path from "path";
import { createScanJob, getScanJob, getScanJobOwner, cancelScanJob } from "../jobs/scanJobs";
import { findProjectByApiKeyForScope, getDecryptedRepoAccessToken } from "../patrol/projects";
import { recordScan } from "../patrol/scans";
import { requireAuth } from "../auth/middleware";
import { applyScanAccess } from "../billing/scanAccess";
import { releaseScanUsage } from "../billing/scanQuota";
import { scanRateLimit } from "../middleware/rateLimit";
import { reserveOrRespond, planForScan, upload, REPO_URL_PATTERN } from "./scans.routes";
import { asyncHandler } from "../middleware/asyncHandler";

/**
 * The async, worker_thread-backed counterpart to the synchronous scan
 * routes in scans.routes.ts. Those stay exactly as they are — the CLI and
 * any direct API integration depend on getting the full report back in one
 * response — this is an additive path the web UI uses to get real,
 * non-simulated step-by-step progress and a real concurrency-limited queue
 * instead of a request that just blocks until the scan finishes.
 *
 * Always behind requireAuth (unlike /api/scans, which allows anonymous
 * zip uploads for CLI/CI use) — the web UI that calls these is always
 * signed in, so the caller's own plan is what governs the report, with no
 * need to fall back to a project-owner lookup the way the older routes do.
 */
export const scanJobsRouter = Router();

function friendlyUploadError(msg: string): string {
  if (msg.includes("symlink")) return "Archive contains symlinks, which are not allowed";
  if (msg.includes("timeout")) return "Archive appears to be a decompression bomb or is too complex";
  if (msg.includes("exceeds limit")) return msg;
  return "Couldn't extract or scan the uploaded file";
}

function friendlyRepoError(msg: string): string {
  if (msg.includes("not found") || msg.includes("Could not read")) {
    return "Repository not found — check the URL and make sure it's public, or that this project has an access token for it";
  }
  if (msg.includes("not a valid branch") || msg.includes("Remote branch")) {
    return "That branch wasn't found in the repository";
  }
  return "Couldn't clone or scan the repository";
}

/** True (and a 404 already sent) when this job exists but belongs to someone else. */
function ownerCheckFailed(req: Request, res: Response, jobId: string): boolean {
  const owner = getScanJobOwner(jobId);
  if (owner && owner !== req.userId) {
    res.status(404).json({ error: "Scan job not found" });
    return true;
  }
  return false;
}

scanJobsRouter.post("/api/scans/jobs/upload", requireAuth, scanRateLimit, upload.single("codebase"), asyncHandler(async (req: Request, res: Response) => {
  if (!req.file) {
    return res.status(400).json({ error: "Upload a zip file under the 'codebase' field" });
  }
  if (path.extname(req.file.originalname).toLowerCase() !== ".zip") {
    fs.unlinkSync(req.file.path);
    return res.status(400).json({ error: "Only .zip uploads are supported right now" });
  }

  const apiKey = req.header("x-nettle-api-key");
  const project = apiKey ? await findProjectByApiKeyForScope(apiKey, "scan") : null;
  const billedUserId = req.userId;
  // Reserved synchronously here, before the job (whose worker runs and
  // completes asynchronously, well after this request returns) is even
  // created — see billing/scanQuota.ts. Recording usage only in
  // onComplete, as this used to, left a real gap: a second job-creation
  // request could run its own quota check before the first job's worker
  // ever finished and recorded anything.
  const { proceed, usageId } = await reserveOrRespond(billedUserId, project?.id ?? null, "upload", res);
  if (!proceed) {
    fs.unlinkSync(req.file.path);
    return;
  }

  const job = createScanJob(
    { mode: "upload", zipPath: req.file.path },
    {
      ownerUserId: req.userId ?? null,
      projectId: project?.id ?? null,
      billedUserId: billedUserId ?? null,
      onComplete: async (report) => {
        if (project) await recordScan(project.id, report);
      },
      onFailure: () => releaseScanUsage(usageId),
    }
  );
  res.status(202).json({ jobId: job.id });
}));

scanJobsRouter.post("/api/scans/jobs/repo", requireAuth, scanRateLimit, asyncHandler(async (req: Request, res: Response) => {
  const repoUrl = typeof req.body?.repoUrl === "string" ? req.body.repoUrl.trim() : "";
  const branch = typeof req.body?.branch === "string" ? req.body.branch.trim() : "";
  const apiKey = typeof req.body?.apiKey === "string" ? req.body.apiKey.trim() : "";

  if (!repoUrl) {
    return res.status(400).json({ error: "Provide a 'repoUrl' (e.g. https://github.com/owner/repo)" });
  }
  if (!REPO_URL_PATTERN.test(repoUrl)) {
    return res.status(400).json({ error: "Only GitHub, GitLab, and Bitbucket HTTPS URLs are supported" });
  }

  const project = apiKey ? await findProjectByApiKeyForScope(apiKey, "scan") : null;
  const billedUserId = req.userId;
  const { proceed, usageId } = await reserveOrRespond(billedUserId, project?.id ?? null, "repo", res);
  if (!proceed) return;

  const repoToken = project ? await getDecryptedRepoAccessToken(project.id) : null;

  const job = createScanJob(
    { mode: "repo", repoUrl, branch, token: repoToken },
    {
      ownerUserId: req.userId ?? null,
      projectId: project?.id ?? null,
      billedUserId: billedUserId ?? null,
      onComplete: async (report) => {
        if (project) await recordScan(project.id, report);
      },
      onFailure: () => releaseScanUsage(usageId),
    }
  );
  res.status(202).json({ jobId: job.id });
}));

scanJobsRouter.get("/api/scans/jobs/:jobId", requireAuth, asyncHandler(async (req: Request, res: Response) => {
  const job = getScanJob(req.params.jobId);
  if (!job) return res.status(404).json({ error: "Scan job not found" });
  if (ownerCheckFailed(req, res, job.id)) return;

  if (job.status === "failed" && job.error) {
    const friendlyError = job.source === "repo" ? friendlyRepoError(job.error) : friendlyUploadError(job.error);
    return res.json({ ...job, friendlyError });
  }

  if (job.status === "completed" && job.report) {
    return res.json({ ...job, report: applyScanAccess(job.report, await planForScan(req)) });
  }

  res.json(job);
}));

scanJobsRouter.post("/api/scans/jobs/:jobId/cancel", requireAuth, asyncHandler(async (req: Request, res: Response) => {
  const job = getScanJob(req.params.jobId);
  if (!job) return res.status(404).json({ error: "Scan job not found" });
  if (ownerCheckFailed(req, res, job.id)) return;

  const cancelled = cancelScanJob(job.id);
  if (!cancelled) {
    return res.status(409).json({ error: `Job is already ${job.status} and can't be cancelled` });
  }
  res.status(204).end();
}));
